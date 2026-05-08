"""Universal finding-detail BFF (JNY-06).

Endpoints
---------
GET   /api/v1/views/finding/{engine}/{id}          — read full detail (5 tabs)
PATCH /api/v1/views/finding/{engine}/{id}/status   — mutate status with audit log

Both endpoints:
  - resolve tenant_id from X-Auth-Context (NEVER from query string)
  - apply per-engine `require_permission(<engine>:read)` dependency
  - run all SQL parameterized
  - return 404 (not 403) for cross-tenant probes (OWASP A01:2021)
  - never fabricate, never merge — Constitution §1+§4

Strategy
--------
Tab 1 (header)       — direct DB read against the engine's finding table
Tab 2 (resource)     — None (FE calls /api/v1/asset-context/{uid} separately)
Tab 3 (related)      — cross-engine fan-out, allSettled-style, 800ms per engine
Tab 4 (compliance)   — rule_control_mapping in check DB, 5 min TTL cache
Tab 5 (remediation)  — rule_metadata.remediation_guidance, 5 min TTL cache
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cachetools import TTLCache
from fastapi import APIRouter, Depends, HTTPException, Path, Request
from psycopg2 import OperationalError
from psycopg2.extras import RealDictCursor

# Auth — must be present in production. Falls back to a 401-raising stub
# only when the auth package is genuinely unavailable (dev/test images).
try:
    from engine_auth.fastapi.dependencies import require_permission
except ImportError:  # pragma: no cover
    def require_permission(_perm: str):  # type: ignore[no-redef]
        def _denied():
            raise HTTPException(status_code=401, detail="auth module unavailable")
        return _denied

from .._auth import resolve_tenant_id
from ._finding_engine_map import ENGINE_MAP, STD_COLUMNS
from ._schemas import (
    ComplianceBlock,
    ComplianceMappingItem,
    EngineExtensions,
    FindingDetailResponse,
    FindingHeader,
    RelatedFinding,
    RelatedFindingsBlock,
    RemediationBlock,
    RemediationStep,
    StandardColumns,
    StatusUpdateRequest,
)


logger = logging.getLogger("api-gateway.bff.finding_detail")
audit_logger = logging.getLogger("api-gateway.audit")


router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

# Path-param ID validation: alphanum and . _ : / -, length 1-128.
_ID_REGEX = r"^[A-Za-z0-9._:/\-]+$"
_FINDING_ID_PATH = Path(..., min_length=1, max_length=128, regex=_ID_REGEX)

# Per-engine fan-out timeout for Tab 3.
_TAB3_PER_ENGINE_TIMEOUT = 0.8

# 5-minute caches for Tab 4 / Tab 5 reference data.
_compliance_cache: TTLCache = TTLCache(maxsize=4096, ttl=300)
_remediation_cache: TTLCache = TTLCache(maxsize=4096, ttl=300)


# ── helpers ─────────────────────────────────────────────────────────────────

def _build_select_sql(table: str) -> str:
    """Build the parameterized SELECT for Tab 1.

    Both finding_id AND tenant_id appear in WHERE — cross-tenant probes
    return zero rows and are reported as 404.
    """
    cols = ", ".join(STD_COLUMNS) + ", finding_data, rule_id"
    # Table name comes from a hard-coded ENGINE_MAP, never user input.
    return (
        f"SELECT {cols} FROM {table} "
        f"WHERE finding_id = %s AND tenant_id = %s LIMIT 1"
    )


def _row_to_header(row: Dict[str, Any], engine: str) -> FindingHeader:
    finding_data = row.get("finding_data")
    if isinstance(finding_data, str):
        try:
            finding_data = json.loads(finding_data)
        except (TypeError, ValueError):
            finding_data = {}
    if not isinstance(finding_data, dict):
        finding_data = {}

    std = StandardColumns(
        tenantId=str(row.get("tenant_id")),
        scanRunId=row.get("scan_run_id"),
        credentialRef=row.get("credential_ref"),
        credentialType=row.get("credential_type"),
        findingId=row["finding_id"],
        accountId=row.get("account_id"),
        provider=row.get("provider"),
        region=row.get("region"),
        resourceUid=row.get("resource_uid"),
        resourceType=row.get("resource_type"),
        severity=row.get("severity"),
        status=row.get("status"),
        firstSeenAt=row.get("first_seen_at"),
        lastSeenAt=row.get("last_seen_at"),
    )

    return FindingHeader(
        findingId=row["finding_id"],
        engine=engine,  # type: ignore[arg-type]  validated upstream
        ruleId=row.get("rule_id"),
        severity=row.get("severity"),
        status=row.get("status"),
        title=finding_data.get("title") or finding_data.get("rule_name"),
        description=finding_data.get("description"),
        resourceUid=row.get("resource_uid"),
        resourceType=row.get("resource_type"),
        resourceName=finding_data.get("resource_name"),
        provider=row.get("provider"),
        accountId=row.get("account_id"),
        region=row.get("region"),
        firstSeenAt=row.get("first_seen_at"),
        lastSeenAt=row.get("last_seen_at"),
        riskScore=finding_data.get("risk_score"),
        standardColumns=std,
        findingData=finding_data,
    )


def _validate_engine(engine: str) -> Dict[str, Any]:
    """Validate engine slug and return its config. Raises HTTPException."""
    cfg = ENGINE_MAP.get(engine)
    if cfg is None:
        raise HTTPException(
            status_code=400,
            detail=f"engine must be one of {sorted(ENGINE_MAP.keys())}",
        )
    if not cfg["supported"]:
        raise HTTPException(
            status_code=501,
            detail={
                "detail": f"engine '{engine}' not yet supported",
                "story_ref": "STORY-ENG-SECOPS-FINDING-TABLE",
            },
        )
    return cfg


# Note: previous _check_permission helper removed (CP-B code review NB-1) —
# both handlers call `await perm_dep(request)` directly.


# ── Tab 1: header read ──────────────────────────────────────────────────────

def _read_finding_row(
    cfg: Dict[str, Any], finding_id: str, tenant_id: str
) -> Optional[Dict[str, Any]]:
    sql = _build_select_sql(cfg["table"])
    conn = None
    try:
        conn = cfg["conn"]()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, (finding_id, tenant_id))
            return cur.fetchone()
    except OperationalError as exc:
        logger.error(
            "Tab1 DB unavailable engine=%s err=%s", cfg["table"], exc
        )
        raise HTTPException(
            status_code=503,
            detail={"detail": "database unavailable", "engine": cfg["table"]},
        )
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ── Tab 3: cross-engine related findings ────────────────────────────────────

async def _fetch_related_one_engine(
    engine: str,
    cfg: Dict[str, Any],
    resource_uid: str,
    tenant_id: str,
    exclude_finding_id: str,
) -> Tuple[str, Optional[List[RelatedFinding]]]:
    """Run the related-findings query against one engine. Returns (engine, items)
    or (engine, None) if the call failed/timed out (caller marks unavailable).
    """

    def _do_query() -> List[RelatedFinding]:
        conn = cfg["conn"]()
        try:
            sql = (
                f"SELECT finding_id, severity, rule_id, status "
                f"FROM {cfg['table']} "
                f"WHERE resource_uid = %s AND tenant_id = %s "
                f"AND finding_id <> %s "
                f"ORDER BY CASE LOWER(severity) "
                f"WHEN 'critical' THEN 1 WHEN 'high' THEN 2 "
                f"WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END "
                f"LIMIT 100"
            )
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(sql, (resource_uid, tenant_id, exclude_finding_id))
                rows = cur.fetchall() or []
            return [
                RelatedFinding(
                    engine=engine,  # type: ignore[arg-type]
                    findingId=r["finding_id"],
                    severity=r.get("severity"),
                    ruleId=r.get("rule_id"),
                    status=r.get("status"),
                    title=None,
                )
                for r in rows
            ]
        finally:
            try:
                conn.close()
            except Exception:
                pass

    try:
        items = await asyncio.wait_for(
            asyncio.to_thread(_do_query), timeout=_TAB3_PER_ENGINE_TIMEOUT
        )
        return engine, items
    except (asyncio.TimeoutError, Exception) as exc:
        logger.warning(
            "Tab3 related-findings engine=%s failed: %s", engine, exc
        )
        return engine, None


async def _build_related_findings(
    resource_uid: Optional[str],
    tenant_id: str,
    exclude_finding_id: str,
    permitted_engines: List[str],
    restricted_engines: List[str],
) -> RelatedFindingsBlock:
    if not resource_uid:
        return RelatedFindingsBlock(
            available=False,
            perEngineAvailability={e: False for e in permitted_engines},
            restrictedEngines=restricted_engines,
            items=[],
        )

    coros = []
    targets: List[str] = []
    for eng in permitted_engines:
        cfg = ENGINE_MAP[eng]
        if not cfg["supported"]:
            continue
        coros.append(
            _fetch_related_one_engine(
                eng, cfg, resource_uid, tenant_id, exclude_finding_id
            )
        )
        targets.append(eng)

    results = await asyncio.gather(*coros, return_exceptions=False)

    availability: Dict[str, bool] = {}
    items: List[RelatedFinding] = []
    for engine_name, engine_items in results:
        if engine_items is None:
            availability[engine_name] = False
        else:
            availability[engine_name] = True
            items.extend(engine_items)

    # Sort across engines by severity, cap to 100 total.
    severity_rank = {"critical": 1, "high": 2, "medium": 3, "low": 4}
    items.sort(key=lambda r: severity_rank.get((r.severity or "").lower(), 5))
    items = items[:100]

    available = any(availability.values())
    return RelatedFindingsBlock(
        available=available,
        perEngineAvailability=availability,
        restrictedEngines=restricted_engines,
        items=items,
    )


# ── Tab 4: compliance mappings ─────────────────────────────────────────────

def _build_compliance(rule_id: Optional[str]) -> ComplianceBlock:
    if not rule_id:
        return ComplianceBlock(available=True, controlMappings=[])

    cached = _compliance_cache.get(rule_id)
    if cached is not None:
        return cached

    sql = (
        "SELECT framework, control_id, control_name, status "
        "FROM rule_control_mapping WHERE rule_id = %s"
    )
    conn = None
    try:
        conn = ENGINE_MAP["check"]["conn"]()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, (rule_id,))
            rows = cur.fetchall() or []
        block = ComplianceBlock(
            available=True,
            controlMappings=[
                ComplianceMappingItem(
                    framework=r["framework"],
                    controlId=r["control_id"],
                    controlName=r.get("control_name"),
                    status=r.get("status"),
                )
                for r in rows
            ],
        )
        _compliance_cache[rule_id] = block
        return block
    except Exception as exc:
        logger.warning("Tab4 compliance lookup failed rule_id=%s err=%s", rule_id, exc)
        return ComplianceBlock(available=False, controlMappings=[])
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ── Tab 5: remediation ─────────────────────────────────────────────────────

_SLA_BY_SEVERITY = {
    "critical": "24h",
    "high": "72h",
    "medium": "30d",
    "low": "90d",
}


def _build_remediation(
    rule_id: Optional[str], severity: Optional[str]
) -> RemediationBlock:
    if not rule_id:
        return RemediationBlock(available=True, steps=[], references=[])

    cached = _remediation_cache.get(rule_id)
    if cached is not None:
        return cached

    sql = (
        "SELECT remediation_guidance "
        "FROM rule_metadata WHERE rule_id = %s LIMIT 1"
    )
    conn = None
    try:
        conn = ENGINE_MAP["check"]["conn"]()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, (rule_id,))
            row = cur.fetchone()
        guidance = (row or {}).get("remediation_guidance") or {}
        if isinstance(guidance, str):
            try:
                guidance = json.loads(guidance)
            except (TypeError, ValueError):
                guidance = {}

        steps_in = guidance.get("steps") if isinstance(guidance, dict) else None
        steps: List[RemediationStep] = []
        if isinstance(steps_in, list):
            for idx, s in enumerate(steps_in, start=1):
                if isinstance(s, dict):
                    steps.append(
                        RemediationStep(
                            order=int(s.get("order", idx)),
                            action=str(s.get("action", "")),
                            detail=s.get("detail"),
                        )
                    )
                elif isinstance(s, str):
                    steps.append(RemediationStep(order=idx, action=s))

        refs = guidance.get("references") if isinstance(guidance, dict) else None
        references = [str(r) for r in refs] if isinstance(refs, list) else []

        sla = _SLA_BY_SEVERITY.get((severity or "").lower())
        raw_guidance = guidance.get("estimated_effort") if isinstance(guidance, dict) else None
        plain_text = guidance.get("guidance") or guidance.get("description") or "" if isinstance(guidance, dict) else ""
        block = RemediationBlock(
            available=True,
            steps=steps,
            references=references,
            estimatedEffort=raw_guidance,
            slaPriority=sla,
            guidance=plain_text,
            markdown=guidance.get("markdown") or plain_text if isinstance(guidance, dict) else plain_text,
            runbook_url=guidance.get("runbook_url") or guidance.get("runbook") or "" if isinstance(guidance, dict) else "",
        )
        _remediation_cache[rule_id] = block
        return block
    except Exception as exc:
        logger.warning("Tab5 remediation lookup failed rule_id=%s err=%s", rule_id, exc)
        return RemediationBlock(available=False, steps=[], references=[])
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


# ── Permission filtering for Tab 3 ──────────────────────────────────────────

def _partition_engines_by_permission(request: Request) -> Tuple[List[str], List[str]]:
    """Return (permitted, restricted) engine slug lists based on the caller's
    permissions, drawn from the AuthContext on the request.

    Falls back to permit-all if no AuthContext is found (the GET handler
    already required at least the requested-engine perm).
    """
    ctx = getattr(request.state, "auth_context", None)
    permitted: List[str] = []
    restricted: List[str] = []
    for slug, cfg in ENGINE_MAP.items():
        if not cfg["supported"]:
            continue
        if ctx is None or ctx.has_permission(cfg["perm"]):
            permitted.append(slug)
        else:
            restricted.append(slug)
    return permitted, restricted


# ── GET /finding/{engine}/{id} ──────────────────────────────────────────────

@router.get(
    "/finding/{engine}/{id}",
    response_model=FindingDetailResponse,
    response_model_exclude_none=False,
)
async def get_finding_detail(
    request: Request,
    engine: str,
    id: str = _FINDING_ID_PATH,
) -> FindingDetailResponse:
    cfg = _validate_engine(engine)

    # Per-engine permission check.
    perm_dep = require_permission(cfg["perm"])
    await perm_dep(request)  # raises 401/403 on failure

    # Tenant from auth context only.
    tenant_id = resolve_tenant_id(request)
    if tenant_id is None:
        # Platform-level callers without a selected tenant cannot resolve a
        # single finding row deterministically — require tenant selection.
        raise HTTPException(
            status_code=400,
            detail="No active tenant in session. Select a tenant first.",
        )

    # Tab 1: header
    row = _read_finding_row(cfg, id, tenant_id)
    if row is None:
        # 404 (not 403) on cross-tenant probe — OWASP A01 no-enumeration-leak.
        raise HTTPException(status_code=404, detail="finding not found")

    header = _row_to_header(row, engine)

    # Tab 3: related findings (cross-engine fan-out, permission-filtered)
    permitted, restricted = _partition_engines_by_permission(request)
    related = await _build_related_findings(
        resource_uid=row.get("resource_uid"),
        tenant_id=tenant_id,
        exclude_finding_id=id,
        permitted_engines=permitted,
        restricted_engines=restricted,
    )

    # Tab 4: compliance
    compliance = _build_compliance(row.get("rule_id"))

    # Tab 5: remediation
    remediation = _build_remediation(row.get("rule_id"), row.get("severity"))

    restricted = list(related.restrictedEngines) if related.restrictedEngines else []
    degraded: list = []

    tab_perms = {
        "overview":    True,
        "resource":    True,
        "related":     related.available,
        "compliance":  compliance.available,
        "remediation": remediation.available,
    }

    all_tabs = [
        {"tabId": "overview",    "label": "Overview"},
        {"tabId": "resource",    "label": "Resource"},
        {"tabId": "related",     "label": "Related"},
        {"tabId": "compliance",  "label": "Compliance"},
        {"tabId": "remediation", "label": "Remediation"},
    ]

    return FindingDetailResponse(
        finding=header,
        header=header,
        resourceContext=None,  # FE calls /asset-context separately
        relatedFindings=related,
        related=[item.model_dump() for item in related.items] if related.items else [],
        compliance=compliance,
        remediation=remediation,
        engineExtensions=EngineExtensions(),
        tabPermissions=tab_perms,
        degradedEngines=degraded,
        restrictedEngines=restricted,
        evidence={},
        supporting=[],
        partial=len(degraded) > 0 or len(restricted) > 0,
        allTabs=all_tabs,
    )


# ── PATCH /finding/{engine}/{id}/status (B2 closure) ───────────────────────

def _write_status(
    cfg: Dict[str, Any],
    finding_id: str,
    tenant_id: str,
    new_status: str,
    note: Optional[str],
) -> Optional[Dict[str, Any]]:
    """Update status (and optional notes) on the engine's finding row.

    Returns the updated row dict or None if no row matched.  Parameterized
    SQL only.  notes JSONB is appended as an array of {ts, status, note}.
    """
    note_payload = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "status": new_status,
        "note": note,
    }
    sql = (
        f"UPDATE {cfg['table']} SET "
        f"status = %s, "
        f"last_seen_at = NOW(), "
        f"notes = COALESCE(notes, '[]'::jsonb) || %s::jsonb "
        f"WHERE finding_id = %s AND tenant_id = %s "
        f"RETURNING " + ", ".join(STD_COLUMNS) + ", finding_data, rule_id"
    )
    conn = None
    try:
        conn = cfg["conn"]()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                sql,
                (new_status, json.dumps(note_payload), finding_id, tenant_id),
            )
            row = cur.fetchone()
        conn.commit()
        return row
    except OperationalError as exc:
        logger.error("PATCH DB unavailable engine=%s err=%s", cfg["table"], exc)
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        raise HTTPException(
            status_code=503,
            detail={"detail": "database unavailable", "engine": cfg["table"]},
        )
    except Exception as exc:
        logger.error("PATCH update failed engine=%s err=%s", cfg["table"], exc)
        if conn is not None:
            try:
                conn.rollback()
            except Exception:
                pass
        # If the table lacks a `notes` JSONB column the engine team must add it
        # — surface a 500 rather than silently dropping the audit trail.
        raise HTTPException(status_code=500, detail="status update failed")
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


@router.patch(
    "/finding/{engine}/{id}/status",
    response_model=FindingHeader,
    response_model_exclude_none=False,
)
async def patch_finding_status(
    request: Request,
    body: StatusUpdateRequest,
    engine: str,
    id: str = _FINDING_ID_PATH,
) -> FindingHeader:
    cfg = _validate_engine(engine)

    perm_dep = require_permission(cfg["perm"])
    ctx = await perm_dep(request)

    tenant_id = resolve_tenant_id(request)
    if tenant_id is None:
        raise HTTPException(
            status_code=400,
            detail="No active tenant in session. Select a tenant first.",
        )

    row = _write_status(cfg, id, tenant_id, body.status, body.note)
    if row is None:
        raise HTTPException(status_code=404, detail="finding not found")

    # Centralized audit log — emit BEFORE returning so failures here do not
    # silently lose the trail.  Attackers cannot suppress this without DoS-ing
    # the gateway pod itself.
    audit_logger.info(
        "finding_status_change",
        extra={
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request.headers.get("x-request-id") or str(uuid.uuid4()),
            "user_id": getattr(ctx, "user_id", None),
            "tenant_id": tenant_id,
            "endpoint": "PATCH /api/v1/views/finding/{engine}/{id}/status",
            "engine": engine,
            "finding_id": id,
            "new_status": body.status,
            # We don't have the prior status row read here (atomic UPDATE);
            # downstream auditing can join on the engine table snapshot.
            "old_status": None,
            "note_present": bool(body.note),
        },
    )

    return _row_to_header(row, engine)
