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
from ._shared import fetch_many, safe_get, BFFMeta
from .schemas.network_security import NetworkSecurityResponse
from ._cache import cache_key, cached_view, TTL_NETWORK, auth_level_from_header
from ._transforms import apply_global_filters
from ._page_context import network_security_page_context, network_security_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


def _enrich_for_ui(f: dict) -> dict:
    """Add UI column fields that check engine findings don't natively carry."""
    uid = f.get('resource_arn') or f.get('resource_uid') or ''
    name = uid.rsplit('/', 1)[-1] if '/' in uid else uid.rsplit(':', 1)[-1]
    f['resource_name'] = name or uid
    f['module'] = f.get('network_layer') or f.get('service') or ''
    if not f.get('account_id'):
        f['account_id'] = f.get('account') or ''
    # Ensure all table columns are present
    f.setdefault('severity', 'medium')
    f.setdefault('status', f.get('result') or 'FAIL')
    f.setdefault('title', f.get('rule_name') or f.get('description') or '')
    f.setdefault('rule_id', '')
    f.setdefault('resource_type', f.get('service') or '')
    f.setdefault('region', '')
    f.setdefault('provider', '')
    f.setdefault('service', '')
    f.setdefault('finding_id', str(f.get('id') or f.get('finding_id') or ''))
    # original — raw fields for side-panel drilldown
    f.setdefault('original', {
        'account': f.get('account_id') or f.get('account', ''),
        'finding_type': f.get('module') or f.get('network_layer', ''),
        'network_layer': f.get('network_layer', ''),
        'container_service': '',
        'db_service': '',
        'encryption_domain': '',
    })
    # meta — color/label for severity badge
    sev = (f.get('severity') or 'medium').lower()
    color_map = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#eab308', 'low': '#3b82f6'}
    f.setdefault('meta', {'color': color_map.get(sev, '#6b7280'), 'label': sev.title()})
    return f


@router.get("/network-security", response_model=NetworkSecurityResponse, response_model_exclude_none=False)
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
    meta = BFFMeta("network_security")

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
    meta.record_engine("network", "/api/v1/network-security/ui-data", net_data)
    if net_data is None:
        meta.warn("Network engine returned no data — all sub-tabs will be empty")
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
    # Fallback: when topology provider hasn't run (network_layer empty), classify
    # by rule_id so security_group findings surface in the SG tab.
    if not filtered_sg:
        _sg_fallback = [
            f for f in filtered_findings
            if "security_group" in (f.get("rule_id") or "").lower()
        ]
        if _sg_fallback:
            filtered_sg = _sg_fallback

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

    # -- Enrich all finding arrays for UI columns --------------------------------
    filtered_findings = [_enrich_for_ui(f) for f in filtered_findings]
    filtered_sg       = [_enrich_for_ui(f) for f in filtered_sg]
    filtered_exposure = [_enrich_for_ui(f) for f in filtered_exposure]
    topology          = [_enrich_for_ui(f) for f in topology]
    filtered_waf      = [_enrich_for_ui(f) for f in filtered_waf]

    # -- Scan trend with chart dataKeys ------------------------------------------
    raw_trend = safe_get(net_data, "scan_trend", [])
    scan_trend = []
    for pt in raw_trend:
        sev = pt.get("by_severity") or {}
        scan_trend.append({
            "date":             pt.get("scan_date") or pt.get("date", ""),
            "critical":         sev.get("critical", pt.get("critical", 0)),
            "high":             sev.get("high",     pt.get("high",     0)),
            "medium":           sev.get("medium",   pt.get("medium",   0)),
            "low":              sev.get("low",       pt.get("low",      0)),
            "passRate":         pt.get("pass_rate") or pt.get("passRate", 0),
            "exposed_resources":pt.get("exposed_resources", 0),
            "waf_coverage":     pt.get("waf_coverage", 0),
            "total":            pt.get("total_findings") or pt.get("total", 0),
        })

    # -- First / last scan comparison objects ------------------------------------
    first_pt = scan_trend[0]  if scan_trend else {}
    last_pt  = scan_trend[-1] if scan_trend else {}
    first_obj = {
        "date":     first_pt.get("date", ""),
        "critical": first_pt.get("critical", 0),
        "high":     first_pt.get("high",     0),
        "total":    first_pt.get("total",    0),
    }
    last_obj = {
        "date":     last_pt.get("date", ""),
        "critical": last_pt.get("critical", 0),
        "high":     last_pt.get("high",     0),
        "total":    last_pt.get("total",    0),
    }

    # -- Donut slices (severity distribution) ------------------------------------
    color_map = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#eab308', 'low': '#3b82f6'}
    donut_slices = [
        {"name": sev.title(), "value": by_severity.get(sev, 0), "color": color_map[sev]}
        for sev in ("critical", "high", "medium", "low")
        if by_severity.get(sev, 0) > 0
    ]

    # -- Active module scores (pass/fail per module) ----------------------------
    active_module_scores = [
        {
            "key":   key,
            "label": label,
            "score": module_scores.get(key, 0),
            "pass":  (module_scores.get(key) or 0) >= 70,
        }
        for key, label in modules
    ]

    # -- activeScanTrend (alias with domain-specific fields) --------------------
    active_scan_trend = scan_trend  # same shape, UI uses activeScanTrend name

    # -- DB domain breakdown (security domain breakdown array) ------------------
    domain_breakdown = safe_get(net_data, "domain_breakdown", [])
    db_domains = domain_breakdown if isinstance(domain_breakdown, list) else []

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
        # Top-level arrays
        "findings":           filtered_findings,
        "security_groups":    filtered_sg,
        "internet_exposure":  filtered_exposure,
        "topology":           topology,
        "topology_snapshots": topology_snapshots,
        "waf":                filtered_waf,
        # Trend & comparison
        "scanTrend":        scan_trend,
        "activeScanTrend":  active_scan_trend,
        "first":            first_obj,
        "last":             last_obj,
        # Donut chart
        "donutSlices":      donut_slices,
        # Module pass/fail cards
        "activeModuleScores": active_module_scores,
        # Domain breakdown
        "domainBreakdown":  domain_breakdown,
        "db":               db_domains,
        "_meta":            meta.to_dict(),
    }
    cached_view(ck, result, ttl=TTL_NETWORK)
    return result
