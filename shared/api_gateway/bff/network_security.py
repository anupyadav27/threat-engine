"""BFF view: /network-security page.

Primary source: engine-network /api/v1/network-security/ui-data

The engine classifies findings into security_groups, internet_exposure, waf,
and topology sub-tab arrays using network_layer / effective_exposure columns.
No BFF-side re-classification or check-engine fallback is performed — see
ADR-NET-01 and the no-bff-fallbacks constitution.
"""

from typing import Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get
from ._cache import cache_key, cached_view, TTL_NETWORK, auth_level_from_header
from ._transforms import apply_global_filters
from ._page_context import network_security_page_context, network_security_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


def _enrich_for_ui(f: dict) -> dict:
    """Add UI column fields that check engine findings don't natively carry."""
    uid = f.get('resource_arn') or f.get('resource_uid') or ''
    # resource_name = friendly last segment of ARN / resource ID
    name = uid.rsplit('/', 1)[-1] if '/' in uid else uid.rsplit(':', 1)[-1]
    f['resource_name'] = name or uid
    # module = service name shown in Module column
    f['module'] = f.get('service') or ''
    # account_id alias (normalize_check_finding stores it as 'account')
    if not f.get('account_id'):
        f['account_id'] = f.get('account') or ''
    return f


@router.get("/network-security")
async def view_network_security(
    request: Request,
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_id: str = Query("latest"),
):
    """Single endpoint returning everything the network security page needs."""

    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    role_level = auth_level_from_header(auth_ctx_header)

    ck = cache_key("network-security", tenant_id, scan_id, provider or "", account or "", region or "", role_level=role_level)
    cached = cached_view(ck)
    if cached is not None:
        return cached

    results = await fetch_many([
        ("network", "/api/v1/network-security/ui-data", {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
        }),
    ], auth_headers=fwd_headers)

    net_data = results[0]
    if not isinstance(net_data, dict):
        net_data = {}

    summary = safe_get(net_data, "summary", {})

    # -- Findings ----------------------------------------------------------------
    raw_findings = safe_get(net_data, "findings", [])
    filtered_findings = apply_global_filters(raw_findings, provider, account, region)

    # -- Sub-tab arrays (engine-classified) -------------------------------------
    raw_sg       = safe_get(net_data, "security_groups",   [])
    raw_exposure = safe_get(net_data, "internet_exposure",  [])
    raw_topology = safe_get(net_data, "topology",           [])
    raw_waf      = safe_get(net_data, "waf",                [])

    # -- Security Groups ---------------------------------------------------------
    filtered_sg = apply_global_filters(raw_sg, provider, account, region)

    # -- Internet Exposure -------------------------------------------------------
    filtered_exposure = apply_global_filters(raw_exposure, provider, account, region)

    # -- Topology (findings sub-tab) --------------------------------------------
    topology = apply_global_filters(raw_topology, provider, account, region)

    # -- Topology Snapshots (VPC snapshot dicts) --------------------------------
    topology_snapshots = safe_get(net_data, "topology_snapshots", [])

    # -- WAF ---------------------------------------------------------------------
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
            if sg.get("open_to_internet") or sg.get("unrestricted") or sg.get("status") == "FAIL"
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
        ("network_isolation",    "Network Isolation"),
        ("network_reachability", "Reachability"),
        ("network_acl",          "Network ACLs"),
        ("security_group_rules", "Security Groups"),
        ("load_balancer_security","Load Balancers"),
        ("waf_protection",       "WAF / Shield"),
        ("internet_exposure",    "Internet Exposure"),
        ("network_monitoring",   "Flow Analysis"),
    ]
    module_items = [
        {
            "label": label,
            "key": key,
            "value": module_scores.get(key) if module_scores.get(key) is not None else "N/A",
            "suffix": "/100" if module_scores.get(key) is not None else "",
        }
        for key, label in modules
    ]

    # -- Page context ------------------------------------------------------------
    page_ctx = network_security_page_context(summary)
    page_ctx["brief"] = (
        f"{total_findings} findings — "
        f"{internet_exposed} internet-exposed, {open_sgs} open security groups"
    )
    page_ctx["tabs"] = [
        {"id": "overview",          "label": "Overview"                                            },
        {"id": "findings",          "label": "Findings",          "count": len(filtered_findings)  },
        {"id": "security_groups",   "label": "Security Groups",   "count": len(filtered_sg)        },
        {"id": "internet_exposure", "label": "Internet Exposure", "count": len(filtered_exposure)  },
        {"id": "topology",          "label": "VPC Topology",      "count": len(topology)           },
        {"id": "waf",               "label": "WAF / DDoS",        "count": len(filtered_waf)       },
    ]

    result = {
        "pageContext": page_ctx,
        "filterSchema": network_security_filter_schema(),
        "kpiGroups": [
            {
                "title": "Network Posture",
                "items": [
                    {"label": "Posture Score",  "value": posture_score, "suffix": "/100"},
                    {"label": "Total Findings", "value": total_findings},
                    {"label": "Critical",       "value": by_severity.get("critical", 0)},
                    {"label": "High",           "value": by_severity.get("high",     0)},
                    {"label": "Medium",         "value": by_severity.get("medium",   0)},
                    {"label": "Low",            "value": by_severity.get("low",      0)},
                ],
            },
            {
                "title": "Exposure & Coverage",
                "items": [
                    {"label": "Exposed Resources", "value": internet_exposed},
                    {"label": "Internet Exposed",  "value": internet_exposed},
                    {"label": "Open SGs",          "value": open_sgs},
                    {"label": "WAF Coverage",      "value": round(len(filtered_waf) / max(len(filtered_findings), 1) * 100)},
                ],
            },
            {
                "title": "Module Scores",
                "items": module_items,
            },
        ],
        "findings":          filtered_findings,
        "security_groups":   filtered_sg,
        "internet_exposure": filtered_exposure,
        "topology":          topology,
        "topology_snapshots": topology_snapshots,
        "waf":               filtered_waf,
        "domainBreakdown": safe_get(net_data, "domain_breakdown", []),
        "scanTrend":        safe_get(net_data, "scan_trend",       []),
    }
    cached_view(ck, result, ttl=TTL_NETWORK)
    return result
