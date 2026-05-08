"""Risk Scenario detail BFF (JNY-12).

Endpoint
--------
GET /api/v1/views/risk/scenario/{id}
    — single risk scenario (FAIR model) with driving findings, mitigations,
      timeline. Read-only investigation view.

Strategy
--------
DB-direct against `risk_scenarios` in the risk DB (no per-scenario engine
endpoint exists — engine only exposes /api/v1/scenarios/{scan_id} for lists).
The DB-direct read mirrors the JNY-06 finding_detail precedent.

Security
--------
- tenant_id resolved from X-Auth-Context (never from query string)
- per-permission gate: risk:read
- 404 (not 403) on cross-tenant probe — OWASP A01 no-enumeration-leak
- parameterized SQL only
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Request
from psycopg2 import OperationalError
from psycopg2.extras import RealDictCursor
from pydantic import BaseModel, Field

try:
    from engine_auth.fastapi.dependencies import require_permission
except ImportError:  # pragma: no cover
    def require_permission(_perm: str):  # type: ignore[no-redef]
        def _denied():
            raise HTTPException(status_code=401, detail="auth module unavailable")
        return _denied

from engine_common.db_connections import get_check_conn, get_risk_conn

from .._auth import resolve_tenant_id


logger = logging.getLogger("api-gateway.bff.risk_scenario_detail")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


# ── ID validation ───────────────────────────────────────────────────────────

# UUID v4 form for scenario_id (PRIMARY KEY in risk_scenarios)
_UUID_REGEX = re.compile(r"^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-"
                          r"[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$")
_SCENARIO_ID_PATH = Path(..., min_length=1, max_length=64)


# ── Pydantic schemas (camelCase) ────────────────────────────────────────────

class DrivingFinding(BaseModel):
    findingId: Optional[str] = None
    sourceEngine: Optional[str] = None
    sourceFindingId: Optional[str] = None
    title: Optional[str] = None


class MitigationItem(BaseModel):
    order: int
    action: str
    status: str = Field("planned", description="planned|in-progress|done")
    expectedReduction: Optional[float] = None


class TimelineEvent(BaseModel):
    timestamp: Optional[str] = None
    label: str
    detail: Optional[str] = None


class RiskScenarioDetailResponse(BaseModel):
    scenarioId: str
    findingId: Optional[str] = None
    name: str
    description: Optional[str] = None
    scenarioType: Optional[str] = None
    riskTier: Optional[str] = None
    riskBand: Optional[str] = None
    fairScore: Optional[float] = Field(
        None, description="Annualized Loss Expectancy (LEF × LM)"
    )
    fairLef: Optional[float] = None
    fairLm: Optional[float] = None
    totalExposureMin: Optional[float] = None
    totalExposureMax: Optional[float] = None
    totalExposureLikely: Optional[float] = None
    blastRadiusScore: Optional[int] = None
    assetId: Optional[str] = None
    assetType: Optional[str] = None
    assetArn: Optional[str] = None
    accountId: Optional[str] = None
    region: Optional[str] = None
    csp: Optional[str] = None
    sourceEngine: Optional[str] = None
    drivingFindings: List[DrivingFinding] = Field(default_factory=list)
    mitigations: List[MitigationItem] = Field(default_factory=list)
    mitreTechniques: List[str] = Field(default_factory=list)
    regulatoryFlags: List[str] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    status: str = "open"


# ── helpers ─────────────────────────────────────────────────────────────────

_RISK_TIER_TO_BAND = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
}

# Per-engine boilerplate mitigation suggestions. The risk engine itself
# doesn't yet store mitigations per scenario; we surface engine-level guidance
# without fabricating data. The list is empty when no source_engine is known.
_ENGINE_MITIGATIONS: Dict[str, List[Dict[str, Any]]] = {
    "iam": [
        {"order": 1, "action": "Rotate offending credentials and enforce MFA"},
        {"order": 2, "action": "Apply least-privilege policy review"},
    ],
    "datasec": [
        {"order": 1, "action": "Encrypt at rest and restrict bucket/object ACLs"},
        {"order": 2, "action": "Apply data-classification tagging"},
    ],
    "network-security": [
        {"order": 1, "action": "Tighten security groups / firewall ingress rules"},
        {"order": 2, "action": "Enable VPC flow logs for affected subnets"},
    ],
    "encryption": [
        {"order": 1, "action": "Enable customer-managed key (CMK) encryption"},
    ],
    "container-security": [
        {"order": 1, "action": "Patch container images and re-deploy"},
    ],
}


def _coerce_jsonb(value: Any) -> Any:
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return None
    return value


def _row_to_response(row: Dict[str, Any]) -> RiskScenarioDetailResponse:
    scenario_type = row.get("scenario_type") or ""
    name = (
        scenario_type.replace("_", " ").title()
        if scenario_type
        else "Risk Scenario"
    )

    description_bits: List[str] = []
    if row.get("asset_type") and row.get("asset_id"):
        description_bits.append(
            f"{row['asset_type']} {row['asset_id']}"
        )
    if row.get("source_engine"):
        description_bits.append(f"sourced from {row['source_engine']}")
    description = " ".join(description_bits) or None

    risk_tier = (row.get("risk_tier") or "low").lower()
    fair_score = row.get("fair_risk_score")

    # Driving findings — currently 1:1 from risk_scenarios row.
    driving = [
        DrivingFinding(
            findingId=row.get("source_finding_id"),
            sourceEngine=row.get("source_engine"),
            sourceFindingId=row.get("source_finding_id"),
            title=name,
        )
    ] if row.get("source_finding_id") else []

    # Mitigations — engine-level boilerplate, no fabrication of per-row state.
    mitigations: List[MitigationItem] = []
    if row.get("source_engine"):
        for item in _ENGINE_MITIGATIONS.get(row["source_engine"], []):
            mitigations.append(MitigationItem(**item))

    mitre = _coerce_jsonb(row.get("mitre_techniques")) or []
    if not isinstance(mitre, list):
        mitre = []

    reg_flags = _coerce_jsonb(row.get("regulatory_flags")) or []
    if not isinstance(reg_flags, list):
        reg_flags = []

    timeline: List[TimelineEvent] = []
    created = row.get("created_at")
    if created is not None:
        timeline.append(
            TimelineEvent(
                timestamp=created.isoformat() if hasattr(created, "isoformat") else str(created),
                label="Scenario calculated",
                detail=f"FAIR model: {row.get('calculation_model') or 'default'}",
            )
        )

    return RiskScenarioDetailResponse(
        scenarioId=str(row["scenario_id"]),
        findingId=row.get("finding_id"),
        name=name,
        description=description,
        scenarioType=row.get("scenario_type"),
        riskTier=row.get("risk_tier"),
        riskBand=_RISK_TIER_TO_BAND.get(risk_tier),
        fairScore=float(fair_score) if fair_score is not None else None,
        fairLef=float(row["fair_lef"]) if row.get("fair_lef") is not None else None,
        fairLm=float(row["fair_lm"]) if row.get("fair_lm") is not None else None,
        totalExposureMin=float(row["total_exposure_min"])
        if row.get("total_exposure_min") is not None
        else None,
        totalExposureMax=float(row["total_exposure_max"])
        if row.get("total_exposure_max") is not None
        else None,
        totalExposureLikely=float(row["total_exposure_likely"])
        if row.get("total_exposure_likely") is not None
        else None,
        blastRadiusScore=row.get("blast_radius_score"),
        assetId=row.get("asset_id"),
        assetType=row.get("asset_type"),
        assetArn=row.get("asset_arn"),
        accountId=row.get("account_id"),
        region=row.get("region"),
        csp=row.get("csp"),
        sourceEngine=row.get("source_engine"),
        drivingFindings=driving,
        mitigations=mitigations,
        mitreTechniques=[str(t) for t in mitre],
        regulatoryFlags=[str(r) for r in reg_flags],
        timeline=timeline,
        status="open",
    )


def _read_scenario_row(scenario_id: str, tenant_id: str) -> Optional[Dict[str, Any]]:
    """Read a single risk_scenarios row scoped by tenant_id.

    Cross-tenant probes return None (handler raises 404 — no enumeration leak).
    """
    sql = (
        "SELECT scenario_id::text, finding_id, scan_run_id::text, tenant_id, "
        "       source_finding_id, source_engine, "
        "       asset_id, asset_type, asset_arn, "
        "       scenario_type, "
        "       loss_event_frequency, "
        "       primary_loss_likely, regulatory_fine_max, "
        "       total_exposure_min, total_exposure_max, total_exposure_likely, "
        "       fair_lef, fair_lm, fair_risk_score, "
        "       risk_tier, calculation_model, "
        "       account_id, region, csp, "
        "       blast_radius_score, regulatory_flags, mitre_techniques, "
        "       attack_path, created_at "
        "FROM risk_scenarios "
        "WHERE (scenario_id::text = %s OR finding_id = %s) "
        "  AND tenant_id = %s "
        "LIMIT 1"
    )
    conn = None
    try:
        conn = get_risk_conn()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, (scenario_id, scenario_id, tenant_id))
            return cur.fetchone()
    except OperationalError as exc:
        logger.error("risk_scenario_detail DB unavailable: %s", exc)
        raise HTTPException(
            status_code=503,
            detail={"detail": "database unavailable", "engine": "risk"},
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ── Endpoint ────────────────────────────────────────────────────────────────

@router.get(
    "/risk/scenario/{id}",
    response_model=RiskScenarioDetailResponse,
    response_model_exclude_none=False,
)
async def get_risk_scenario_detail(
    request: Request,
    id: str = _SCENARIO_ID_PATH,
    _perm: Any = Depends(require_permission("risk:read")),
) -> RiskScenarioDetailResponse:
    # Validate id format — UUID or 16-char hex finding_id.
    if not (_UUID_REGEX.match(id) or re.fullmatch(r"^[A-Fa-f0-9]{16}$", id)):
        raise HTTPException(status_code=400, detail="invalid scenario id")

    tenant_id = resolve_tenant_id(request)
    if tenant_id is None:
        raise HTTPException(
            status_code=400,
            detail="No active tenant in session. Select a tenant first.",
        )

    row = _read_scenario_row(id, tenant_id)
    if row is None:
        # 404 (not 403) on cross-tenant — OWASP A01.
        raise HTTPException(status_code=404, detail="risk scenario not found")

    return _row_to_response(row)
