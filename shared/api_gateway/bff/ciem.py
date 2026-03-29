"""BFF view: /ciem page.

CIEM (Cloud Infrastructure Entitlement Management) + Log Analysis.
Aggregates: dashboard summary, identity risk, top rules, log sources.
"""

from typing import Optional

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get, ENGINE_URLS, mock_fallback, is_empty_or_health

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

CIEM_URL = ENGINE_URLS.get("ciem", "http://engine-ciem")


@router.get("/ciem")
async def view_ciem(
    tenant_id: str = Query(...),
    scan_run_id: Optional[str] = Query(None),
):
    qs = {"tenant_id": tenant_id}
    if scan_run_id:
        qs["scan_run_id"] = scan_run_id

    results = await fetch_many([
        ("ciem", "/api/v1/ciem/dashboard", qs),
        ("ciem", "/api/v1/ciem/identities", {**qs, "limit": "20"}),
        ("ciem", "/api/v1/ciem/top-rules", {**qs, "limit": "15"}),
        ("ciem", "/api/v1/log-collection/sources", qs),
        ("ciem", "/api/v1/log-collection/stats", qs),
    ])

    dashboard, identities, top_rules, sources, stats = results

    # Mock fallback when all engine calls return empty
    if all(is_empty_or_health(r) for r in results):
        m = mock_fallback("ciem")
        if m is not None:
            return m

    summary = safe_get(dashboard, "summary", {})
    by_severity = safe_get(dashboard, "by_severity", [])

    # Compute risk score per identity
    identity_list = safe_get(identities, "identities", [])
    for ident in identity_list:
        crit = ident.get("critical", 0)
        high = ident.get("high", 0)
        med = ident.get("medium", 0)
        ident["risk_score"] = min(100, crit * 25 + high * 10 + med * 2)

    return {
        # Summary KPIs
        "totalFindings": summary.get("total_findings", 0),
        "rulesTriggered": summary.get("rules_triggered", 0),
        "uniqueActors": summary.get("unique_actors", 0),
        "uniqueResources": summary.get("unique_resources", 0),
        "l2Findings": summary.get("l2_findings", 0),
        "l3Findings": summary.get("l3_findings", 0),

        # Breakdowns
        "severityBreakdown": by_severity,
        "engineBreakdown": safe_get(dashboard, "by_engine", []),
        "ruleSourceBreakdown": safe_get(dashboard, "by_rule_source", []),
        "categoryBreakdown": safe_get(dashboard, "by_category", []),

        # Top critical/high findings
        "topCritical": safe_get(dashboard, "top_critical", []),

        # Identity risk table
        "identities": identity_list,

        # Detection rules table
        "topRules": safe_get(top_rules, "rules", []),

        # Log collection info
        "logSources": safe_get(sources, "sources", []),
        "eventStats": safe_get(stats, "summary", {}),
        "eventsBySource": safe_get(stats, "by_source", []),
    }
