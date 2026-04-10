"""BFF view: /container-security page.

Uses the container-security engine's /ui-data endpoint which returns all
container security data pre-organized: clusters, findings, domain scores,
and a summary with KPI-ready metrics.

Single call to engine-container-sec/api/v1/container-security/ui-data.
"""

from typing import Optional

from fastapi import APIRouter, Query

from ._shared import fetch_many, fetch_all_check_findings, safe_get, mock_fallback, is_empty_or_health
from ._transforms import apply_global_filters
from ._page_context import container_security_page_context, container_security_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/container-security")
async def view_container_security(
    tenant_id: str = Query(...),
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_id: str = Query("latest"),
):
    """Single endpoint returning everything the container security page needs."""

    results = await fetch_many([
        ("container_sec", "/api/v1/container-security/ui-data", {
            "tenant_id": tenant_id,
            "scan_id": scan_id,
        }),
    ])

    csec_data = results[0]
    if not isinstance(csec_data, dict):
        csec_data = {}

    # Fallback: check engine (container_and_kubernetes_security domain) when engine has no data
    _has_csec_data = safe_get(csec_data, "findings", []) or safe_get(csec_data, "clusters", [])
    if is_empty_or_health(csec_data) or not _has_csec_data:
        check_raw = await fetch_all_check_findings({
            "tenant_id": tenant_id,
            "domain": "container_and_kubernetes_security",
        })
        if check_raw:
            csec_data = {"findings": check_raw, "clusters": [], "summary": {}}
        else:
            m = mock_fallback("container_security")
            if m is not None:
                return m

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
        "data": {
            "clusters": filtered_clusters,
            "findings": filtered_findings,
            "domain_scores": domain_scores,
        },
        "domainBreakdown": safe_get(csec_data, "domain_breakdown", []),
        "scanTrend": safe_get(csec_data, "scan_trend", []),
    }
