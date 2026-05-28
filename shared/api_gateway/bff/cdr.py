"""BFF view: /cdr page.

CDR (Cloud Detection & Response) — multi-layer log analysis.
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
from ._shared import fetch_many, safe_get, ENGINE_URLS, _fetch_engine, read_findings
from ._cache import cache_key, cached_view, TTL_CIEM, auth_level_from_header
from ._common_schemas import CdrViewResponse
import httpx

logger = logging.getLogger("api-gateway.bff.cdr")

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

CDR_URL = ENGINE_URLS.get("cdr", "http://engine-cdr")


@router.get("/cdr", response_model=CdrViewResponse, response_model_exclude_none=False)
async def view_cdr(
    request: Request,
    scan_run_id: Optional[str] = Query(None),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    tenant_ids: Optional[str] = Query(None),
    account_ids: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
):
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    role_level = auth_level_from_header(auth_ctx_header)

    ck = cache_key("cdr", tenant_id, scan_run_id or "latest", provider or "", account or "", region or "", role_level=role_level)
    cached = cached_view(ck)
    if cached is not None:
        return cached

    qs = {"tenant_id": tenant_id}
    if scan_run_id:
        qs["scan_run_id"] = scan_run_id

    results = await fetch_many([
        ("cdr", "/api/v1/cdr/dashboard",    qs),
        ("cdr", "/api/v1/cdr/identities",   {**qs, "limit": "20"}),
        ("cdr", "/api/v1/cdr/top-rules",    {**qs, "limit": "15"}),
        ("cdr", "/api/v1/cdr/log-sources",  qs),
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
        fc = ident.get("finding_count") or ident.get("total_findings", crit + high + med)
        ident["finding_count"]  = fc
        ident["total_findings"] = fc
        ident["event_time"]     = ident.get("event_time") or ident.get("last_seen", "")
        ident["earliest"]       = ident.get("earliest") or ident.get("first_seen", "")
        ap = ident.get("actor_principal") or ident.get("principal", "")
        ident["actor_principal"] = ap
        ident["principal"]       = ap
        ident["event_count"]    = ident.get("event_count", 0)
        ident["resource_uid"]   = ident.get("resource_uid", "")
        ident["rule_id"]        = ident.get("rule_id", "")
        ident["rule_source"]    = ident.get("rule_source") or ident.get("source", "l1")
        ident["services_used"]  = ident.get("services_used") or ident.get("services", [])
        rs = ident["risk_score"]
        ident["severity"]       = ident.get("severity") or (
            "critical" if rs >= 75 else "high" if rs >= 40 else "medium" if rs >= 10 else "low"
        )
        ident["source_bucket"]  = ident.get("source_bucket", "")
        ident["source_region"]  = ident.get("source_region") or ident.get("region", "")
        ident["source_type"]    = ident.get("source_type", "")
        ident["unique_actors"]  = ident.get("unique_actors", 0)
        ident["unique_resources"] = ident.get("unique_resources", 0)
        ident["original"]       = {
            "actor_principal": ap,
            "rule_source":     ident["rule_source"],
            "source_type":     ident["source_type"],
            "event_time":      ident["event_time"],
        }

    # ── Derive KPI numbers from real data ─────────────────────────────────────
    total_findings = int(summary.get("total_findings", 0))
    sev_map  = {s.get("severity", ""): int(s.get("count", 0)) for s in by_severity}
    critical = sev_map.get("critical", 0)
    high     = sev_map.get("high",     0)
    medium   = sev_map.get("medium",   0)
    low      = sev_map.get("low",      0)

    if total_findings > 0:
        weight     = critical * 4 + high * 3 + medium * 2 + low * 1
        max_weight = total_findings * 4
        posture_score = max(0, 100 - round((weight / max_weight) * 100))
    else:
        posture_score = 100

    raw_trend = safe_get(dashboard, "scan_trend", [])
    color_map = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#eab308', 'low': '#3b82f6'}
    scan_trend = []
    for pt in raw_trend:
        sev_pt   = pt.get("by_severity") or {}
        total_pt = pt.get("total_findings") or pt.get("total", 0)
        scan_trend.append({
            "date":     pt.get("scan_date") or pt.get("date", ""),
            "critical": sev_pt.get("critical", pt.get("critical", 0)),
            "high":     sev_pt.get("high",     pt.get("high",     0)),
            "medium":   sev_pt.get("medium",   pt.get("medium",   0)),
            "low":      sev_pt.get("low",      pt.get("low",      0)),
            "passRate": pt.get("pass_rate") or pt.get("passRate", 0),
            "total":    total_pt,
            "earliest": pt.get("earliest", ""),
            "latest":   pt.get("latest", ""),
        })
    first_pt  = scan_trend[0]  if scan_trend else {}
    last_pt   = scan_trend[-1] if scan_trend else {}
    first_obj = {"date": first_pt.get("date", ""), "critical": first_pt.get("critical", 0)}
    last_obj  = {"date": last_pt.get("date",  ""), "critical": last_pt.get("critical",  0)}

    sev_counts = {"critical": critical, "high": high, "medium": medium, "low": low}
    donut_slices = [
        {"name": sev.title(), "value": sev_counts[sev], "color": color_map[sev]}
        for sev in ("critical", "high", "medium", "low")
        if sev_counts[sev] > 0
    ]

    filters = {
        "account": safe_get(dashboard, "accounts", []),
    }

    result = {
        "kpiGroups": [
            {
                "title": "CDR Posture",
                "items": [
                    {"label": "Posture Score",      "value": posture_score,                          "suffix": "/100"},
                    {"label": "Total Findings",     "value": total_findings},
                    {"label": "Critical",           "value": critical},
                    {"label": "High",               "value": high},
                    {"label": "Medium",             "value": medium},
                    {"label": "Low",                "value": low},
                    {"label": "Identities at Risk", "value": int(summary.get("unique_actors",   0))},
                    {"label": "Rules Triggered",    "value": int(summary.get("rules_triggered", 0))},
                ],
            }
        ],
        "totalFindings":   total_findings,
        "rulesTriggered":  int(summary.get("rules_triggered",  0)),
        "uniqueActors":    int(summary.get("unique_actors",    0)),
        "uniqueResources": int(summary.get("unique_resources", 0)),
        "l2Findings":      int(summary.get("l2_findings", 0)),
        "l3Findings":      int(summary.get("l3_findings", 0)),
        "postureScore":    posture_score,
        "severityBreakdown":   by_severity,
        "engineBreakdown":     safe_get(dashboard, "by_engine",      []),
        "ruleSourceBreakdown": safe_get(dashboard, "by_rule_source", []),
        "categoryBreakdown":   safe_get(dashboard, "by_category",    []),
        "topCritical":    safe_get(dashboard,        "top_critical", []),
        "identities":     identity_list,
        "topRules":       safe_get(top_rules,        "rules",        []),
        "logSources":     safe_get(log_sources_data, "sources",      []),
        "eventStats":     safe_get(stats,            "summary",      {}),
        "eventsBySource": safe_get(stats,            "by_source",    []),
        "scanTrend":       scan_trend,
        "activeScanTrend": scan_trend,
        "first":           first_obj,
        "last":            last_obj,
        "donutSlices":     donut_slices,
        "filters":         filters,
        "data": {
            "identities":     identity_list,
            "totalFindings":  total_findings,
            "postureScore":   posture_score,
            "scanTrend":      scan_trend,
            "donutSlices":    donut_slices,
            "topRules":       safe_get(top_rules,        "rules",  []),
            "logSources":     safe_get(log_sources_data, "sources", []),
        },
    }

    # ARCH-05: supplement from security_findings table (fallback when CDR engine empty)
    sf = read_findings(tenant_id=tenant_id, source_engines=["cdr"], limit=500)
    if sf["total"] > 0 and not result.get("topCritical"):
        result["topCritical"] = [
            {"title": f.get("title", ""), "severity": f.get("severity", "medium"),
             "resource_uid": f.get("resource_uid", ""), "finding_type": f.get("finding_type", "")}
            for f in sf["findings"][:20]
        ]
    result["securityFindings"] = sf["findings"]

    cached_view(ck, result, ttl=TTL_CIEM)
    return result


@router.get("/cdr/heatmap")
async def view_cdr_heatmap(
    request: Request,
    scan_run_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """BFF proxy: identity risk heatmap (account × principal_type matrix).

    Calls the CDR engine's heatmap aggregation endpoint and returns the
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
                "cdr",
                "/api/v1/cdr/identities/heatmap",
                params=params or None,
                auth_headers=fwd_headers,
            )
    except Exception as exc:
        logger.warning("cdr heatmap BFF fetch failed: %s", exc)
        return _empty

    if result is None:
        return _empty
    return result
