"""
GET /api/v1/asset-context/{resource_uid}

Gateway-native aggregator: fans out to all engine resource-finding endpoints
in parallel (2 s timeout per engine) and returns a unified summary for the
investigation panel. Never called from BFF — called directly from the frontend
via gateway when a finding row is clicked.

Constitution notes:
  - This is NOT a BFF view (no fetchView). It is a gateway aggregator endpoint.
  - Returns partial results (available=False) when an engine times out.
  - Never raises 500 if individual engines are down.
  - Scoped by tenant_id from X-Auth-Context (require_permission: discoveries:read).
"""

import asyncio
import json
import os
from typing import Optional

import httpx
from fastapi import APIRouter, Path, Query, Request
from pydantic import BaseModel

router = APIRouter(tags=["Asset Context"])

# ── Engine resource-finding endpoints ──────────────────────────────────────
# Each engine must expose:
#   GET /api/v1/{path}?resource_uid={uid}&tenant_id={tid}&scan_run_id={sid}&limit=3&status=FAIL
# Engines not yet implementing this endpoint return available=False (graceful).
_ENGINE_CONFIGS: list[dict] = [
    {"key": "check",        "url": os.getenv("CHECK_ENGINE_URL",         "http://engine-check:8002"),      "path": "/api/v1/check/findings"},
    {"key": "network",      "url": os.getenv("NETWORK_ENGINE_URL",       "http://engine-network"),         "path": "/api/v1/network-security/findings"},
    {"key": "iam",          "url": os.getenv("IAM_ENGINE_URL",           "http://engine-iam:8003"),        "path": "/api/v1/iam-security/findings"},
    {"key": "datasec",      "url": os.getenv("DATASEC_ENGINE_URL",       "http://engine-datasec:8004"),    "path": "/api/v1/data-security/findings"},
    {"key": "encryption",   "url": os.getenv("ENCRYPTION_ENGINE_URL",    "http://engine-encryption"),      "path": "/api/v1/encryption/findings"},
    {"key": "threat",       "url": os.getenv("THREAT_ENGINE_URL",        "http://engine-threat:8020"),     "path": "/api/v1/threat/findings"},
    {"key": "vulnerability","url": os.getenv("VULNERABILITY_ENGINE_URL", "http://engine-vulnerability"),   "path": "/api/v1/vulnerability/findings"},
    {"key": "container",    "url": os.getenv("CONTAINER_SEC_ENGINE_URL", "http://engine-container-sec"),  "path": "/api/v1/container-security/findings"},
    {"key": "dbsec",        "url": os.getenv("DBSEC_ENGINE_URL",         "http://engine-dbsec"),           "path": "/api/v1/database-security/findings"},
    {"key": "ai_security",  "url": os.getenv("AI_SECURITY_ENGINE_URL",   "http://engine-ai-security"),    "path": "/api/v1/ai-security/findings"},
    {"key": "ciem",         "url": os.getenv("CIEM_ENGINE_URL",          "http://engine-ciem"),            "path": "/api/v1/ciem/findings"},
]

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_TIMEOUT = httpx.Timeout(connect=1.0, read=2.0, write=1.0, pool=1.0)


# ── Pydantic models ────────────────────────────────────────────────────────

class TopFinding(BaseModel):
    finding_id: str
    title: str
    severity: str
    status: str
    rule_id: Optional[str] = None


class EngineAssetSummary(BaseModel):
    available: bool
    finding_count: int
    max_severity: Optional[str] = None   # None = no findings for this resource
    top_findings: list[TopFinding]       # max 3, sorted by severity desc


class AssetContextResponse(BaseModel):
    resource_uid: str
    resource_name: str
    resource_type: Optional[str] = None
    account_id: Optional[str] = None
    provider: Optional[str] = None
    region: Optional[str] = None
    overall_risk_score: Optional[int] = None  # from risk engine if available

    check:        Optional[EngineAssetSummary] = None
    network:      Optional[EngineAssetSummary] = None
    iam:          Optional[EngineAssetSummary] = None
    datasec:      Optional[EngineAssetSummary] = None
    encryption:   Optional[EngineAssetSummary] = None
    threat:       Optional[EngineAssetSummary] = None
    vulnerability: Optional[EngineAssetSummary] = None
    container:    Optional[EngineAssetSummary] = None
    dbsec:        Optional[EngineAssetSummary] = None
    ai_security:  Optional[EngineAssetSummary] = None
    ciem:         Optional[EngineAssetSummary] = None


# ── Helpers ────────────────────────────────────────────────────────────────

def _derive_resource_name(resource_uid: str) -> str:
    if "/" in resource_uid:
        return resource_uid.rsplit("/", 1)[-1]
    if ":" in resource_uid:
        return resource_uid.rsplit(":", 1)[-1]
    return resource_uid


def _parse_engine_response(raw: dict | Exception) -> EngineAssetSummary:
    """Convert engine /findings response to EngineAssetSummary. Returns available=False on error."""
    if isinstance(raw, Exception):
        return EngineAssetSummary(available=False, finding_count=0, top_findings=[])

    findings: list[dict] = raw.get("findings", [])
    total: int = raw.get("total", len(findings))

    if not findings:
        return EngineAssetSummary(available=True, finding_count=total, top_findings=[])

    sorted_f = sorted(
        findings,
        key=lambda f: _SEVERITY_ORDER.get((f.get("severity") or "low").lower(), 0),
        reverse=True,
    )
    max_sev = (sorted_f[0].get("severity") or "low").lower()
    top = [
        TopFinding(
            finding_id=f.get("finding_id", ""),
            title=f.get("title") or f.get("rule_id") or "",
            severity=(f.get("severity") or "low").lower(),
            status=f.get("status", "FAIL"),
            rule_id=f.get("rule_id"),
        )
        for f in sorted_f[:3]
    ]
    return EngineAssetSummary(
        available=True,
        finding_count=total,
        max_severity=max_sev,
        top_findings=top,
    )


async def _fetch_engine(
    client: httpx.AsyncClient,
    config: dict,
    resource_uid: str,
    tenant_id: str,
    scan_run_id: str,
    auth_header: Optional[str],
) -> tuple[str, dict | Exception]:
    key = config["key"]
    url = config["url"] + config["path"]
    headers = {"X-Auth-Context": auth_header} if auth_header else {}
    params = {
        "resource_uid": resource_uid,
        "tenant_id": tenant_id,
        "scan_run_id": scan_run_id,
        "limit": 3,
        "status": "FAIL",
    }
    try:
        r = await client.get(url, params=params, headers=headers)
        if r.status_code == 404:
            return key, {"findings": [], "total": 0}
        if r.status_code == 405:
            # Engine does not yet implement this endpoint — treat as unavailable
            return key, Exception(f"not implemented")
        if r.status_code != 200:
            return key, Exception(f"HTTP {r.status_code}")
        return key, r.json()
    except Exception as exc:
        return key, exc


# ── Endpoint ───────────────────────────────────────────────────────────────

@router.get("/api/v1/asset-context/{resource_uid}", response_model=AssetContextResponse)
async def get_asset_context(
    request: Request,
    resource_uid: str = Path(..., description="Full cloud resource UID / ARN"),
    scan_run_id: str = Query("latest"),
    tenant_id: Optional[str] = Query(None),
):
    """
    Fan out to all engines and return a per-engine finding summary for resource_uid.

    - Never returns 500 — unavailable engines appear as available=False.
    - 2 s wall-clock timeout per engine.
    - tenant_id is read from X-Auth-Context (AuthMiddleware enriches it);
      query param is a fallback for local dev only.
    """
    auth_header = request.headers.get("X-Auth-Context") or ""

    resolved_tenant: str = tenant_id or ""
    if not resolved_tenant and auth_header:
        try:
            ctx = json.loads(auth_header)
            resolved_tenant = ctx.get("tenant_id", "")
        except Exception:
            pass

    async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
        tasks = [
            _fetch_engine(client, cfg, resource_uid, resolved_tenant, scan_run_id, auth_header)
            for cfg in _ENGINE_CONFIGS
        ]
        results: list[tuple[str, dict | Exception]] = await asyncio.gather(
            *tasks, return_exceptions=False
        )

    engine_results: dict[str, EngineAssetSummary] = {
        key: _parse_engine_response(raw) for key, raw in results
    }

    # Derive resource metadata from the first engine that returned findings
    resource_type: Optional[str] = None
    account_id: Optional[str] = None
    provider: Optional[str] = None
    region: Optional[str] = None
    for _, raw in results:
        if isinstance(raw, dict) and raw.get("findings"):
            f = raw["findings"][0]
            resource_type = resource_type or f.get("resource_type")
            account_id    = account_id    or f.get("account_id") or f.get("account")
            provider      = provider      or f.get("provider")
            region        = region        or f.get("region")
            if resource_type and account_id:
                break

    return AssetContextResponse(
        resource_uid=resource_uid,
        resource_name=_derive_resource_name(resource_uid),
        resource_type=resource_type,
        account_id=account_id,
        provider=provider,
        region=region,
        **{k: engine_results.get(k) for k in (
            "check", "network", "iam", "datasec", "encryption", "threat",
            "vulnerability", "container", "dbsec", "ai_security", "ciem"
        )},
    )
