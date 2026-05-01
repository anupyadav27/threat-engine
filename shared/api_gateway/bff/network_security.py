"""BFF view: /network-security page.

Primary:  engine-network /api/v1/network-security/ui-data
Fallback: engine-check  /api/v1/check/findings?domain=network_security_and_connectivity

All network-security pages (Security Groups, Internet Exposure, Topology, WAF)
are filtered sub-views of the same check findings — split here by service.
"""

from typing import Optional, List

from fastapi import APIRouter, Query, Request

from ._shared import fetch_many, fetch_all_check_findings, safe_get, is_empty_or_health
from ._cache import cache_key, cached_view, TTL_NETWORK, auth_level_from_header
from ._transforms import apply_global_filters, normalize_check_finding
from ._page_context import network_security_page_context, network_security_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])

# ── Service sets for sub-table classification ──────────────────────────────
_WAF_SVCS      = frozenset({'waf', 'wafv2', 'shield', 'globalaccelerator', 'networkfirewall'})
_TOPOLOGY_SVCS = frozenset({'vpc', 'vpcflowlogs', 'directconnect', 'route53', 'transitgateway'})
_EXPOSURE_SVCS = frozenset({'elb', 'elbv2', 'cloudfront', 'eip', 'lightsail'})
_SG_SVCS       = frozenset({'ec2'})


def _classify(f: dict) -> str:
    """Classify a check/network finding into a network sub-table."""
    svc  = (f.get('service')          or '').lower()
    rt   = (f.get('resource_type')    or '').lower().replace('-', '').replace('_', '')
    rule = (f.get('rule_id')          or '').lower()
    cat  = (f.get('posture_category') or '').lower()
    layer = (f.get('network_layer')   or '').lower()

    # WAF / DDoS
    if (svc in _WAF_SVCS or 'waf' in svc or 'shield' in svc
            or 'waf' in rule or 'shield' in rule or 'firewall' in rule
            or '.dos' in rule or 'networkfirewall' in rule or 'networkfirewall' in rt):
        return 'waf'

    # VPC / Topology
    if (svc in _TOPOLOGY_SVCS or 'vpc' in rule or 'flowlog' in rule
            or 'vcn' in rule or 'route_table' in rule or 'topology' in rule
            or 'transit' in rule or 'directconnect' in rule
            or 'vcn' in rt or 'routetable' in rt
            or layer in ('network_isolation', 'network_reachability')):
        return 'topology'

    # Internet Exposure
    if (svc in _EXPOSURE_SVCS or 'public' in cat or 'exposure' in cat
            or 'public' in rule or 'internet' in rule or 'exposure' in rule
            or 'ingress.tls' in rule or 'ingress.controller' in rule
            or 'eip' in rule or 'publicip' in rt
            or layer in ('load_balancer_security',)):
        return 'exposure'

    # Security Groups / network ACLs
    if (svc in _SG_SVCS
            or 'securitygroup' in rt or 'security_group' in rule or '.sg.' in rule or '_sg_' in rule
            or 'security_list' in rule or 'security_list' in rt
            or 'network_policy' in rule or 'network.restrict' in rule
            or 'nacl' in rule or 'networkacl' in rt
            or layer in ('network_acl', 'security_group_rules')):
        return 'sg'

    return 'general'


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


def _check_findings_to_net_data(findings: List[dict]) -> dict:
    """Split flat check findings list into the net_data sub-table structure."""
    sgs, exposure, topology, waf = [], [], [], []
    for f in findings:
        t = _classify(f)
        if t == 'sg':         sgs.append(f)
        elif t == 'topology': topology.append(f)
        elif t == 'exposure': exposure.append(f)
        elif t == 'waf':      waf.append(f)
    return {
        "findings":         findings,
        "security_groups":  sgs,
        "internet_exposure": exposure,
        "topology":         topology,
        "waf":              waf,
        "summary":          {},
    }


@router.get("/network-security")
async def view_network_security(
    request: Request,
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_id: str = Query("latest"),
):
    """Single endpoint returning everything the network security page needs."""

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

    # ── Fallback: use check engine filtered by network domain ───────────────
    # Also fall back when engine returns a valid structure but 0 findings
    if is_empty_or_health(net_data) or not safe_get(net_data, "findings", []):
        check_raw = await fetch_all_check_findings({
            "tenant_id": tenant_id,
            "domain": "network_security_and_connectivity",
        }, auth_headers=fwd_headers)
        if check_raw:
            normalized = [_enrich_for_ui(normalize_check_finding(f)) for f in check_raw]
            net_data = _check_findings_to_net_data(normalized)

    summary = safe_get(net_data, "summary", {})

    # -- Findings ----------------------------------------------------------------
    raw_findings = safe_get(net_data, "findings", [])
    filtered_findings = apply_global_filters(raw_findings, provider, account, region)

    # -- Sub-tab classification --------------------------------------------------
    # Network engine may return findings but empty sub-tab arrays (it leaves
    # classification to the consumer).  Re-classify whenever sub-tabs are empty
    # but findings are present so the UI tabs are always populated.
    raw_sg       = safe_get(net_data, "security_groups",   [])
    raw_exposure = safe_get(net_data, "internet_exposure",  [])
    raw_topology = safe_get(net_data, "topology",           [])
    raw_waf      = safe_get(net_data, "waf",                [])

    if raw_findings and not (raw_sg or raw_exposure or raw_topology or raw_waf):
        sub = _check_findings_to_net_data(raw_findings)
        raw_sg       = sub["security_groups"]
        raw_exposure = sub["internet_exposure"]
        raw_topology = sub["topology"]
        raw_waf      = sub["waf"]

    # -- Security Groups ---------------------------------------------------------
    filtered_sg = apply_global_filters(raw_sg, provider, account, region)

    # -- Internet Exposure -------------------------------------------------------
    filtered_exposure = apply_global_filters(raw_exposure, provider, account, region)

    # -- Topology ----------------------------------------------------------------
    topology = apply_global_filters(raw_topology, provider, account, region)

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
        "findings":         filtered_findings,
        "security_groups":  filtered_sg,
        "internet_exposure": filtered_exposure,
        "topology":         topology,
        "waf":              filtered_waf,
        "domainBreakdown": safe_get(net_data, "domain_breakdown", []),
        "scanTrend":        safe_get(net_data, "scan_trend",       []),
    }
    cached_view(ck, result, ttl=TTL_NETWORK)
    return result
