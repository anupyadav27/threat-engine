"""BFF view: /container-security page.

Uses the container-security engine's /ui-data endpoint which returns all
container security data pre-organized: clusters, findings, domain scores,
and a summary with KPI-ready metrics.

Single call to engine-container-sec/api/v1/container-security/ui-data.
"""

from typing import Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, fetch_all_check_findings, safe_get, is_empty_or_health, BFFMeta
from .schemas.container_security import ContainerSecurityResponse
from ._transforms import apply_global_filters
from ._page_context import container_security_page_context, container_security_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/container-security", response_model=ContainerSecurityResponse, response_model_exclude_none=False)
async def view_container_security(
    request: Request,
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_id: str = Query("latest"),
):
    """Single endpoint returning everything the container security page needs."""

    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None
    meta = BFFMeta("container_security")

    results = await fetch_many([
        ("container_sec", "/api/v1/container-security/ui-data", {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
        }),
    ], auth_headers=fwd_headers)

    csec_data = results[0]
    meta.record_engine("container_sec", "/api/v1/container-security/ui-data", csec_data)
    if not isinstance(csec_data, dict):
        csec_data = {}

    # Fallback: check engine (container_and_kubernetes_security domain) when engine has no data
    _has_csec_data = safe_get(csec_data, "findings", []) or safe_get(csec_data, "clusters", [])
    if is_empty_or_health(csec_data) or not _has_csec_data:
        check_raw = await fetch_all_check_findings({
            "tenant_id": tenant_id,
            "domain": "container_and_kubernetes_security",
        }, auth_headers=fwd_headers)
        if check_raw:
            meta.set_fallback("container_sec engine returned no data; using check engine container_and_kubernetes_security domain")
            csec_data = {"findings": check_raw, "clusters": [], "summary": {}}
        else:
            meta.warn("Both container_sec engine and check engine fallback returned no data")

    summary = safe_get(csec_data, "summary", {})

    # ── Clusters ──────────────────────────────────────────────────────────
    raw_clusters = safe_get(csec_data, "clusters", [])
    filtered_clusters = apply_global_filters(raw_clusters, provider, account, region)

    # ── Findings ──────────────────────────────────────────────────────────
    raw_findings = safe_get(csec_data, "findings", [])
    filtered_findings = apply_global_filters(raw_findings, provider, account, region)

    # ── Domain scores ─────────────────────────────────────────────────────
    domain_scores = safe_get(csec_data, "domain_scores", {})

    # ── KPI derivation ────────────────────────────────────────────────────
    total_clusters = safe_get(summary, "total_clusters", None)
    if total_clusters is None:
        total_clusters = len(filtered_clusters)

    public_clusters = safe_get(summary, "public_clusters", None)
    if public_clusters is None:
        public_clusters = sum(
            1 for c in filtered_clusters
            if c.get("publicly_accessible") in (True, "true", "True", "yes")
        )

    total_images = safe_get(summary, "total_images", 0)

    # Posture score from summary or derived from findings
    posture_score = safe_get(summary, "posture_score", 0)
    if not posture_score and filtered_findings:
        sev_weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        total_weight = sum(
            sev_weights.get((f.get("severity") or "medium").lower(), 2)
            for f in filtered_findings
        )
        max_weight = len(filtered_findings) * 4
        posture_score = max(0, 100 - round((total_weight / max_weight) * 100)) if max_weight else 100

    # Findings by severity
    by_severity = safe_get(summary, "by_severity", {})
    if not by_severity and filtered_findings:
        by_severity = {}
        for f in filtered_findings:
            sev = (f.get("severity") or "medium").lower()
            by_severity[sev] = by_severity.get(sev, 0) + 1

    # Default domain scores if not provided
    default_domains = [
        "cluster_security", "workload_security", "image_security",
        "network_exposure", "rbac_access", "runtime_audit",
    ]
    if not domain_scores:
        domain_scores = {d: 0 for d in default_domains}

    # ── Page context ──────────────────────────────────────────────────────
    page_ctx = container_security_page_context(summary)
    page_ctx["brief"] = (
        f"{total_clusters} clusters monitored — "
        f"{public_clusters} publicly accessible, posture score {posture_score}/100"
    )
    page_ctx["tabs"] = [
        {"id": "overview", "label": "Overview"},
        {"id": "inventory", "label": "Inventory", "count": len(filtered_clusters)},
        {"id": "findings", "label": "Findings", "count": len(filtered_findings)},
        {"id": "cluster_security", "label": "Cluster Security"},
        {"id": "image_security", "label": "Image Security"},
        {"id": "rbac", "label": "RBAC"},
    ]

    # -- Enrich cluster rows with required table columns ----------------------
    enriched_clusters = []
    for c in filtered_clusters:
        row = {
            **c,
            'name':            c.get('name') or c.get('cluster_name') or c.get('resource_uid', ''),
            'provider':        (c.get('provider') or '').upper(),
            'region':          c.get('region', ''),
            'account_id':      c.get('account_id') or c.get('account', ''),
            'version':         c.get('version') or c.get('kubernetes_version', ''),
            'node_count':      c.get('node_count') or c.get('node_count_total', 0),
            'pod_count':       c.get('pod_count') or c.get('running_pods', 0),
            'posture_score':   c.get('posture_score') or c.get('security_score', 0),
            'risk_score':      c.get('risk_score', 0),
            'endpoint_public': c.get('endpoint_public') or c.get('publicly_accessible', False),
            'logging_enabled': c.get('logging_enabled') or c.get('control_plane_logging', False),
            'etcd_encrypted':  c.get('secrets_encryption') or c.get('etcd_encrypted') or c.get('envelope_encryption', False),
            'status':          c.get('status', ''),
        }
        # Remove the raw DB column that maps to etcd_encrypted; the scrubber
        # allows 'secrets_encrypted' now but explicit removal is cleaner.
        row.pop('secrets_encrypted', None)
        row.pop('secrets_encryption', None)
        enriched_clusters.append(row)

    # -- Enrich finding rows with required table columns -----------------------
    color_map = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#eab308', 'low': '#3b82f6'}
    enriched_findings = []
    for f in filtered_findings:
        uid = f.get('resource_arn') or f.get('resource_uid') or ''
        sev = (f.get('severity') or 'medium').lower()
        enriched_findings.append({
            **f,
            'resource_name':     f.get('resource_name') or uid.rsplit('/', 1)[-1] or uid,
            'severity':          sev,
            'status':            f.get('status') or f.get('result') or 'FAIL',
            'title':             f.get('title') or f.get('rule_name') or '',
            'rule_id':           f.get('rule_id', ''),
            'account_id':        f.get('account_id') or f.get('account', ''),
            'region':            f.get('region', ''),
            'provider':          f.get('provider', ''),
            'resource_type':     f.get('resource_type', ''),
            'cluster_name':      f.get('cluster_name') or f.get('resource_name', ''),
            'container_service': f.get('container_service') or f.get('service', ''),
            'security_domain':   f.get('security_domain') or f.get('domain', ''),
            'finding_id':        str(f.get('finding_id') or f.get('id') or ''),
            'original':          {'account': f.get('account_id') or f.get('account', ''),
                                   'container_service': f.get('container_service') or f.get('service', ''),
                                   'security_domain': f.get('security_domain', '')},
            'meta':              {'color': color_map.get(sev, '#6b7280'), 'label': sev.title()},
        })

    # -- Scan trend with chart dataKeys ----------------------------------------
    raw_trend = safe_get(csec_data, "scan_trend", [])
    scan_trend = []
    for pt in raw_trend:
        sev_pt = pt.get("by_severity") or {}
        total_pt = pt.get("total_findings") or pt.get("total", 0)
        scan_trend.append({
            "date":     pt.get("scan_date") or pt.get("date", ""),
            "critical": sev_pt.get("critical", pt.get("critical", 0)),
            "high":     sev_pt.get("high",     pt.get("high",     0)),
            "medium":   sev_pt.get("medium",   pt.get("medium",   0)),
            "low":      sev_pt.get("low",      pt.get("low",      0)),
            "passRate": pt.get("pass_rate") or pt.get("passRate", 0),
            "total":    total_pt,
        })

    first_pt  = scan_trend[0]  if scan_trend else {}
    last_pt   = scan_trend[-1] if scan_trend else {}
    first_obj = {k: first_pt.get(k, 0) for k in ("date", "critical", "high", "total")}
    last_obj  = {k: last_pt.get(k, 0)  for k in ("date", "critical", "high", "total")}

    # -- Donut slices ----------------------------------------------------------
    donut_slices = [
        {"name": sev.title(), "value": by_severity.get(sev, 0), "color": color_map[sev]}
        for sev in ("critical", "high", "medium", "low")
        if by_severity.get(sev, 0) > 0
    ]

    # -- Active module scores (domain scores as module cards) ------------------
    active_module_scores = [
        {
            "key":   domain,
            "label": domain.replace("_", " ").title(),
            "score": domain_scores.get(domain, 0),
            "pass":  (domain_scores.get(domain) or 0) >= 70,
        }
        for domain in default_domains
    ]

    # -- DB security domain breakdown -----------------------------------------
    domain_breakdown = safe_get(csec_data, "domain_breakdown", [])
    db_domains = domain_breakdown if isinstance(domain_breakdown, list) else []

    meta.expect_fields(
        csec_data,
        ["findings", "clusters", "summary"],
        context="container_sec engine ui-data",
    )

    return {
        "pageContext": page_ctx,
        "filterSchema": container_security_filter_schema(),
        "kpiGroups": [
            {
                "title": "Container Posture",
                "items": [
                    {"label": "Posture Score",   "value": posture_score, "suffix": "/100"},
                    {"label": "Clusters",        "value": total_clusters},
                    {"label": "Public Clusters", "value": public_clusters},
                    {"label": "Images",          "value": total_images},
                    {"label": "Critical",        "value": by_severity.get("critical", 0)},
                    {"label": "High",            "value": by_severity.get("high", 0)},
                    {"label": "Medium",          "value": by_severity.get("medium", 0)},
                    {"label": "Low",             "value": by_severity.get("low", 0)},
                ],
            },
        ],
        "clusters":           enriched_clusters,
        "findings":           enriched_findings,
        "domain_scores":      domain_scores,
        "domainBreakdown":    domain_breakdown,
        "db":                 db_domains,
        "scanTrend":          scan_trend,
        "activeScanTrend":    scan_trend,
        "first":              first_obj,
        "last":               last_obj,
        "donutSlices":        donut_slices,
        "activeModuleScores": active_module_scores,
        "_meta":              meta.to_dict(),
    }
