"""BFF view: /network-security page.

Uses the network security engine's /ui-data endpoint which returns all network
security data pre-organized: findings, security groups, internet exposure,
topology, WAF status, and a summary with KPI-ready metrics.

Single call to engine-network/api/v1/network-security/ui-data.
"""

from typing import Optional

from fastapi import APIRouter, Query

from ._shared import fetch_many, safe_get, mock_fallback, is_empty_or_health
from ._transforms import apply_global_filters
from ._page_context import network_security_page_context, network_security_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/network-security")
async def view_network_security(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_id: str = Query("latest"),
):
    """Single endpoint returning everything the network security page needs."""

    results = await fetch_many([
        ("network", "/api/v1/network-security/ui-data", {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
        }),
    ])

    net_data = results[0]
    if not isinstance(net_data, dict):
        net_data = {}

    # Mock fallback when engine data is empty
    if is_empty_or_health(net_data):
        m = mock_fallback("network_security")
        if m is not None:
            return m

    summary = safe_get(net_data, "summary", {})

    # -- Findings ----------------------------------------------------------------
    raw_findings = safe_get(net_data, "findings", [])
    filtered_findings = apply_global_filters(raw_findings, provider, account, region)

    # -- Security Groups ---------------------------------------------------------
    raw_sg = safe_get(net_data, "security_groups", [])
    filtered_sg = apply_global_filters(raw_sg, provider, account, region)

    # -- Internet Exposure -------------------------------------------------------
    raw_exposure = safe_get(net_data, "internet_exposure", [])
    filtered_exposure = apply_global_filters(raw_exposure, provider, account, region)

    # -- Topology ----------------------------------------------------------------
    topology = safe_get(net_data, "topology", [])

    # -- WAF ---------------------------------------------------------------------
    raw_waf = safe_get(net_data, "waf", [])
    filtered_waf = apply_global_filters(raw_waf, provider, account, region)

    # -- KPI derivation ----------------------------------------------------------
    posture_score = safe_get(summary, "posture_score", 0)
    if not posture_score and filtered_findings:
        sev_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        total_weight = sum(
            sev_weights.get((f.get("severity") or "medium").lower(), 2)
            for f in filtered_findings
        )
        max_weight = len(filtered_findings) * 4
        posture_score = max(0, 100 - round((total_weight / max_weight) * 100)) if max_weight else 100

    internet_exposed = safe_get(summary, "internet_exposed_resources", None)
    if internet_exposed is None:
        internet_exposed = len(filtered_exposure)

    open_sgs = safe_get(summary, "open_security_groups", None)
    if open_sgs is None:
        open_sgs = sum(
            1 for sg in filtered_sg
            if sg.get("open_to_internet") or sg.get("unrestricted")
        )

    total_findings = safe_get(summary, "total_findings", len(filtered_findings))

    # Findings by severity
    by_severity = safe_get(summary, "by_severity", {})
    if not by_severity and filtered_findings:
        by_severity = {}
        for f in filtered_findings:
            sev = (f.get("severity") or "medium").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1

    # Module scores
    module_scores = safe_get(summary, "module_scores", {})
    modules = [
        ("network_isolation", "Network Isolation"),
        ("network_reachability", "Reachability"),
        ("network_acl", "Network ACLs"),
        ("security_group_rules", "Security Groups"),
        ("load_balancer_security", "Load Balancers"),
        ("waf_protection", "WAF / Shield"),
        ("internet_exposure", "Internet Exposure"),
        ("network_monitoring", "Flow Analysis"),
    ]

    module_items = []
    for mod_key, mod_label in modules:
        score = module_scores.get(mod_key, None)
        module_items.append({
            "label": mod_label,
            "key": mod_key,
            "value": score if score is not None else "N/A",
            "suffix": "/100" if score is not None else "",
        })

    # -- Page context ------------------------------------------------------------
    page_ctx = network_security_page_context(summary)
    page_ctx["brief"] = (
        f"{total_findings} findings — "
        f"{internet_exposed} internet-exposed, {open_sgs} open security groups"
    )
    page_ctx["tabs"] = [
        {"id": "overview", "label": "Overview", "count": total_findings},
        {"id": "findings", "label": "Findings", "count": len(filtered_findings)},
        {"id": "security_groups", "label": "Security Groups", "count": len(filtered_sg)},
        {"id": "internet_exposure", "label": "Internet Exposure", "count": len(filtered_exposure)},
        {"id": "topology", "label": "Topology", "count": len(topology)},
        {"id": "waf", "label": "WAF", "count": len(filtered_waf)},
    ]

    return {
        "pageContext": page_ctx,
        "filterSchema": network_security_filter_schema(),
        "kpiGroups": [
            {
                "title": "Network Posture",
                "items": [
                    {"label": "Posture Score", "value": posture_score, "suffix": "/100"},
                    {"label": "Internet-Exposed", "value": internet_exposed},
                    {"label": "Open Security Groups", "value": open_sgs},
                    {"label": "Total Findings", "value": total_findings},
                ],
            },
            {
                "title": "Findings by Severity",
                "items": [
                    {"label": "Critical", "value": by_severity.get("critical", 0)},
                    {"label": "High", "value": by_severity.get("high", 0)},
                    {"label": "Medium", "value": by_severity.get("medium", 0)},
                    {"label": "Low", "value": by_severity.get("low", 0)},
                ],
            },
            {
                "title": "Module Scores",
                "items": module_items,
            },
        ],
        "data": {
            "findings": filtered_findings,
            "security_groups": filtered_sg,
            "internet_exposure": filtered_exposure,
            "topology": topology,
            "waf": filtered_waf,
        },
    }
