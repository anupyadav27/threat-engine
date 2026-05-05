"""BFF view: /ciem page.

CIEM (Cloud Infrastructure Entitlement Management) + Log Analysis.
Aggregates: dashboard summary, identity risk, top rules, log sources.

Risk score computation lives here (not in the UI):
  risk_score = min(100, critical×25 + high×10 + medium×2)

Returns standard kpiGroups so the UI reads a single consistent
data shape — no client-side KPI derivation needed.
"""

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get, ENGINE_URLS, _fetch_engine
from ._cache import cache_key, cached_view, TTL_CIEM, auth_level_from_header
from ._common_schemas import CiemViewResponse
import httpx

logger = logging.getLogger("api-gateway.bff.ciem")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

CIEM_URL = ENGINE_URLS.get("ciem", "http://engine-ciem")


@router.get("/ciem", response_model=CiemViewResponse, response_model_exclude_none=False)
async def view_ciem(
    request: Request,
    scan_run_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
):
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    role_level = auth_level_from_header(auth_ctx_header)

    ck = cache_key("ciem", tenant_id, scan_run_id or "latest", provider or "", account or "", region or "", role_level=role_level)
    cached = cached_view(ck)
    if cached is not None:
        return cached

    qs = {"tenant_id": tenant_id}
    if scan_run_id:
        qs["scan_run_id"] = scan_run_id

    results = await fetch_many([
        ("ciem", "/api/v1/ciem/dashboard",    qs),
        ("ciem", "/api/v1/ciem/identities",   {**qs, "limit": "20"}),
        ("ciem", "/api/v1/ciem/top-rules",    {**qs, "limit": "15"}),
        ("ciem", "/api/v1/ciem/log-sources",  qs),
    ], auth_headers=fwd_headers)

    dashboard, identities, top_rules, log_sources_data = results
    stats = None

    summary    = safe_get(dashboard, "summary", {})
    by_severity = safe_get(dashboard, "by_severity", [])

    # ── Risk score per identity (server-side, not UI-side) ────────────────────
    identity_list = safe_get(identities, "identities", [])
    for ident in identity_list:
        crit = int(ident.get("critical", 0))
        high = int(ident.get("high",     0))
        med  = int(ident.get("medium",   0))
        ident["risk_score"] = min(100, crit * 25 + high * 10 + med * 2)
        ident["actorPrincipalType"] = ident.get("actor_principal_type") or "unknown"
        ident["l2Findings"] = ident.get("l2_findings", 0)
        ident["l3Findings"] = ident.get("l3_findings", 0)

    # ── Derive KPI numbers from real data ─────────────────────────────────────
    total_findings = int(summary.get("total_findings", 0))
    sev_map  = {s.get("severity", ""): int(s.get("count", 0)) for s in by_severity}
    critical = sev_map.get("critical", 0)
    high     = sev_map.get("high",     0)
    medium   = sev_map.get("medium",   0)
    low      = sev_map.get("low",      0)

    # Posture score: inverse weighted burden
    if total_findings > 0:
        weight     = critical * 4 + high * 3 + medium * 2 + low * 1
        max_weight = total_findings * 4
        posture_score = max(0, 100 - round((weight / max_weight) * 100))
    else:
        posture_score = 100

    result = {
        # ── KPI envelope (standard shape for all pages) ───────────────────────
        "kpiGroups": [
            {
                "title": "CIEM Posture",
                "items": [
                    {"label": "Posture Score",      "value": posture_score,                           "suffix": "/100"},
                    {"label": "Total Findings",     "value": total_findings},
                    {"label": "Critical",           "value": critical},
                    {"label": "High",               "value": high},
                    {"label": "Medium",             "value": medium},
                    {"label": "Low",                "value": low},
                    {"label": "Identities at Risk", "value": int(summary.get("unique_actors",    0))},
                    {"label": "Rules Triggered",    "value": int(summary.get("rules_triggered",  0))},
                ],
            }
        ],
        # ── Flat fields (backward compat + direct UI reads) ───────────────────
        "totalFindings":  total_findings,
        "rulesTriggered": int(summary.get("rules_triggered",  0)),
        "uniqueActors":   int(summary.get("unique_actors",    0)),
        "uniqueResources":int(summary.get("unique_resources", 0)),
        "l2Findings":     int(summary.get("l2_findings", 0)),
        "l3Findings":     int(summary.get("l3_findings", 0)),
        "postureScore":   posture_score,
        # ── Breakdowns ────────────────────────────────────────────────────────
        "severityBreakdown":   by_severity,
        "engineBreakdown":     safe_get(dashboard, "by_engine",       []),
        "ruleSourceBreakdown": safe_get(dashboard, "by_rule_source",  []),
        "categoryBreakdown":   safe_get(dashboard, "by_category",     []),
        # ── Lists ─────────────────────────────────────────────────────────────
        "topCritical":  safe_get(dashboard,  "top_critical", []),
        "identities":   identity_list,
        "topRules":     safe_get(top_rules,  "rules",        []),
        "logSources":   safe_get(log_sources_data, "sources",      []),
        "eventStats":   safe_get(stats,      "summary",      {}),
        "eventsBySource": safe_get(stats,    "by_source",    []),
        "scanTrend":    safe_get(dashboard,  "scan_trend",   []),
    }

    cached_view(ck, result, ttl=TTL_CIEM)
    return result


@router.get("/ciem/heatmap")
async def view_ciem_heatmap(
    request: Request,
    scan_run_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """BFF proxy: identity risk heatmap (account × principal_type matrix).

    Calls the CIEM engine's heatmap aggregation endpoint and returns the
    response as-is. Gracefully degrades to an empty matrix when the engine
    is unreachable so the UI renders an empty grid rather than an error.

    Args:
        request: FastAPI Request (carries X-Auth-Context header).
        scan_run_id: Optional scan run filter forwarded to the engine.

    Returns:
        Dict with 'matrix', 'accounts', and 'principal_types' keys.
    """
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    params: Dict[str, str] = {}
    if scan_run_id:
        params["scan_run_id"] = scan_run_id

    _empty: Dict[str, Any] = {"matrix": [], "accounts": [], "principal_types": []}
    try:
        async with httpx.AsyncClient() as client:
            result = await _fetch_engine(
                client,
                "ciem",
                "/api/v1/ciem/identities/heatmap",
                params=params or None,
                auth_headers=fwd_headers,
            )
    except Exception as exc:
        logger.warning("ciem heatmap BFF fetch failed: %s", exc)
        return _empty

    if result is None:
        return _empty
    return result
