"""BFF view: /cwpp page — Cloud Workload Protection Platform.

Delegates to the CWPP engine (/api/v1/cwpp/ui-data) which aggregates
all 5 workload types in parallel:
  containers  — K8s / EKS / ECS / AKS / GKE cluster + pod security
  images      — Image posture + CVE scanning (placeholder for Trivy/Grype)
  hosts       — OS / VM / middleware CVEs via vul_engine (agent-based)
  serverless  — Lambda / Azure Functions / GCF
  runtime     — Privileged containers, host-network, CIEM runtime events

Single call: engine-cwpp /api/v1/cwpp/ui-data
"""

from typing import Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get, is_empty_or_health
from ._page_context import cwpp_page_context, cwpp_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/cwpp")
async def view_cwpp(
    request: Request,
    provider: Optional[str] = Query(None),
    account: Optional[str] = Query(None),
    region: Optional[str] = Query(None),
    scan_id: str = Query("latest"),
):
    """Single endpoint returning everything the CWPP workload protection page needs."""

    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    results = await fetch_many([
        ("cwpp", "/api/v1/cwpp/ui-data", {
            "tenant_id": tenant_id,
            "scan_run_id": scan_id,
        }),
    ], auth_headers=fwd_headers)

    cwpp_data = results[0]
    if not isinstance(cwpp_data, dict) or is_empty_or_health(cwpp_data):
        cwpp_data = {}

    # ── Top-level ─────────────────────────────────────────────────────────────
    cwpp_score   = safe_get(cwpp_data, "cwpp_posture_score", 0) or 0
    risk_band    = safe_get(cwpp_data, "risk_band", "unknown")
    workloads    = safe_get(cwpp_data, "workloads", {})
    total_findings   = safe_get(cwpp_data, "total_findings", 0) or 0
    critical_findings = safe_get(cwpp_data, "critical_findings", 0) or 0

    # ── Per-workload summary ──────────────────────────────────────────────────
    workload_items = []
    for wid, wdata in workloads.items():
        score   = wdata.get("posture_score")
        status  = wdata.get("status", "unavailable")
        summary = wdata.get("summary", {})
        workload_items.append({
            "id": wid,
            "name": _WORKLOAD_NAMES.get(wid, wid),
            "status": status,
            "posture_score": score,
            "risk_band": _score_band(score),
            "total_findings": summary.get("total_findings", 0),
            "critical": summary.get("critical", summary.get("critical_findings", 0)),
            "high": summary.get("high", summary.get("high_findings", 0)),
            "summary": summary,
            # surface image scan status explicitly for UI
            "image_scan_status": summary.get("image_scan_status") if wid == "images" else None,
        })

    # ── Workload extraction for sub-tables ────────────────────────────────────
    containers_data = workloads.get("containers", {}).get("data", {})
    images_data     = workloads.get("images",     {}).get("data", {})
    hosts_data      = workloads.get("hosts",      {}).get("data", {})
    serverless_data = workloads.get("serverless", {}).get("data", {})
    runtime_data    = workloads.get("runtime",    {}).get("data", {})

    # ── KPI groups ────────────────────────────────────────────────────────────
    containers_summary  = workloads.get("containers", {}).get("summary", {})
    images_summary      = workloads.get("images",     {}).get("summary", {})
    hosts_summary       = workloads.get("hosts",      {}).get("summary", {})
    serverless_summary  = workloads.get("serverless", {}).get("summary", {})

    # ── Page context ──────────────────────────────────────────────────────────
    page_ctx = cwpp_page_context({
        "cwpp_posture_score": cwpp_score,
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "risk_band": risk_band,
    })
    page_ctx["brief"] = (
        f"CWPP posture score {cwpp_score}/100 — "
        f"{total_findings} findings, {critical_findings} critical across all workload types"
    )
    page_ctx["tabs"] = [
        {"id": "overview",    "label": "Overview"},
        {"id": "containers",  "label": "Containers",
         "count": containers_summary.get("total_findings", 0)},
        {"id": "images",      "label": "Images",
         "count": images_summary.get("total_findings", 0)},
        {"id": "hosts",       "label": "Hosts / VMs",
         "count": hosts_summary.get("total_vulnerabilities", 0)},
        {"id": "serverless",  "label": "Serverless",
         "count": serverless_summary.get("total_findings", 0)},
        {"id": "runtime",     "label": "Runtime"},
    ]

    return {
        "pageContext": page_ctx,
        "filterSchema": cwpp_filter_schema(),
        "kpiGroups": [
            {
                "title": "CWPP Posture",
                "items": [
                    {"label": "CWPP Score",     "value": cwpp_score, "suffix": "/100"},
                    {"label": "Risk Band",       "value": risk_band},
                    {"label": "Total Findings",  "value": total_findings},
                    {"label": "Critical",        "value": critical_findings},
                ],
            },
            {
                "title": "Containers",
                "items": [
                    {"label": "Score",           "value": workloads.get("containers", {}).get("posture_score"), "suffix": "/100"},
                    {"label": "Clusters",        "value": containers_summary.get("total_clusters", 0)},
                    {"label": "Public Clusters", "value": containers_summary.get("public_clusters", 0)},
                    {"label": "Findings",        "value": containers_summary.get("total_findings", 0)},
                ],
            },
            {
                "title": "Images",
                "items": [
                    {"label": "Score",           "value": workloads.get("images", {}).get("posture_score"), "suffix": "/100"},
                    {"label": "Total Images",    "value": images_summary.get("total_images", 0)},
                    {"label": "Image Findings",  "value": images_summary.get("total_findings", 0)},
                    {"label": "CVE Scan",        "value": images_summary.get("image_scan_status", "not_implemented")},
                ],
            },
            {
                "title": "Hosts & Middleware",
                "items": [
                    {"label": "Score",         "value": workloads.get("hosts", {}).get("posture_score"), "suffix": "/100"},
                    {"label": "Host Scans",    "value": hosts_summary.get("total_host_scans", 0)},
                    {"label": "CVEs",          "value": hosts_summary.get("total_vulnerabilities", 0)},
                    {"label": "Critical CVEs", "value": hosts_summary.get("critical", 0)},
                    {"label": "Middleware",    "value": hosts_summary.get("middleware_vulnerabilities", 0)},
                ],
            },
        ],
        "data": {
            "workloads": workload_items,
            "cwpp_posture_score": cwpp_score,
            "risk_band": risk_band,
            "containers": {
                "clusters": containers_data.get("clusters", []),
                "findings": containers_data.get("findings", []),
                "domain_breakdown": containers_data.get("domain_breakdown", []),
            },
            "images": {
                "inventory": images_data.get("image_inventory", []),
                "findings": images_data.get("posture_findings", []),
                "cve_scan": images_data.get("cve_scan", {}),
            },
            "hosts": {
                "scans": hosts_data.get("host_scans", []),
                "os_vulnerabilities": hosts_data.get("os_vulnerabilities", []),
                "middleware_vulnerabilities": hosts_data.get("middleware_vulnerabilities", []),
                "middleware_breakdown": hosts_data.get("middleware_breakdown", {}),
                "sbom_summary": hosts_data.get("sbom_summary", {}),
            },
            "serverless": {
                "functions": serverless_data.get("functions", []),
                "findings": serverless_data.get("findings", []),
                "runtime_breakdown": serverless_data.get("runtime_breakdown", {}),
            },
            "runtime": {
                "findings": runtime_data.get("runtime_findings", []),
            },
        },
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

_WORKLOAD_NAMES = {
    "containers": "Containers & Kubernetes",
    "images":     "Container Images",
    "hosts":      "Hosts / VMs / Middleware",
    "serverless": "Serverless Functions",
    "runtime":    "Runtime Threat Detection",
}


def _score_band(score) -> str:
    if score is None:
        return "unknown"
    s = float(score)
    if s >= 80:
        return "low"
    if s >= 60:
        return "medium"
    if s >= 40:
        return "high"
    return "critical"
