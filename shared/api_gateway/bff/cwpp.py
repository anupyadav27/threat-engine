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

from collections import defaultdict
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Query, Request

from ._auth import resolve_tenant_id
from ._shared import fetch_many, safe_get, is_empty_or_health, BFFMeta
from .schemas.cwpp import CWPPResponse
from ._page_context import cwpp_page_context, cwpp_filter_schema

router = APIRouter(prefix="/api/v1/views", tags=["BFF Views"])


@router.get("/cwpp", response_model=CWPPResponse, response_model_exclude_none=False)
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
    meta = BFFMeta("cwpp")

    results = await fetch_many([
        ("cwpp", "/api/v1/cwpp/ui-data", {
            "tenant_id": tenant_id,
            "scan_run_id": scan_id,
        }),
    ], auth_headers=fwd_headers)

    cwpp_data = results[0]
    meta.record_engine("cwpp", "/api/v1/cwpp/ui-data", cwpp_data)
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
            "meta": {
                "color": _WORKLOAD_COLORS.get(wid, "#6b7280"),
                "desc":  _WORKLOAD_DESCRIPTIONS.get(wid, ""),
                "icon":  wid,
            },
        })

    # ── Workload extraction for sub-tables ────────────────────────────────────
    containers_data = workloads.get("containers", {}).get("data", {}) or {}
    images_data     = workloads.get("images",     {}).get("data", {}) or {}
    hosts_data      = workloads.get("hosts",      {}).get("data", {}) or {}
    serverless_data = workloads.get("serverless", {}).get("data", {}) or {}
    runtime_data    = workloads.get("runtime",    {}).get("data", {}) or {}

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

    # -- Top-level summary object (UI accesses summary.critical, summary.total_clusters, etc.) --
    summary = {
        "cwpp_posture_score":     cwpp_score,
        "risk_band":              risk_band,
        "total_findings":         total_findings,
        "critical":               critical_findings,
        "high":                   safe_get(cwpp_data, "high_findings", 0),
        "total_clusters":         containers_summary.get("total_clusters", 0),
        "public_clusters":        containers_summary.get("public_clusters", 0),
        "total_images":           images_summary.get("total_images", 0),
        "total_host_scans":       hosts_summary.get("total_host_scans", 0),
        "total_vulnerabilities":  hosts_summary.get("total_vulnerabilities", 0),
        "total_functions":        serverless_summary.get("total_functions", 0),
        "privileged_containers":  containers_summary.get("privileged_containers", 0),
        "host_network_findings":  containers_summary.get("host_network_findings", 0),
        "deprecated_runtimes":    serverless_summary.get("deprecated_runtimes", 0),
    }

    return {
        "pageContext": page_ctx,
        "filterSchema": cwpp_filter_schema(),
        "summary": summary,
        # Top-level workload object for UI direct access (workload.posture_score, etc.)
        "workload": {
            "posture_score": cwpp_score,
            "risk_band": risk_band,
            "status": "ok" if cwpp_score > 0 else "unavailable",
            "summary": summary,
        },
        # Top-level sub-type aliases for UI direct access without data.* wrapper
        "containers": {
            "clusters": containers_data.get("clusters", []),
            "findings": containers_data.get("findings", []),
            "domain_breakdown": containers_data.get("domain_breakdown", []),
        },
        "images": {
            "inventory": images_data.get("image_inventory", []),
            "findings": images_data.get("posture_findings", []),
        },
        "hosts": {
            "scans": hosts_data.get("host_scans", []),
            "os_vulnerabilities": hosts_data.get("os_vulnerabilities", []),
            "middleware_vulnerabilities": hosts_data.get("middleware_vulnerabilities", []),
        },
        "serverless": {
            "functions": serverless_data.get("functions", []),
            "findings": serverless_data.get("findings", []),
        },
        "runtime": {
            "findings": (runtime_data.get("runtime_findings", []) + runtime_data.get("runtime_keyword_findings", [])),
        },
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
                "scanTrend": containers_data.get("scan_trend", []),
                "priorPostureScore": (
                    containers_data["scan_trend"][-2]["pass_rate"]
                    if len(containers_data.get("scan_trend", [])) >= 2 else None
                ),
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
                "findings": (runtime_data.get("runtime_findings", []) + runtime_data.get("runtime_keyword_findings", [])),
                "cdrRuntimeEvents": workloads.get("runtime", {}).get("cdr_runtime_events", {
                    "count": 0, "critical": 0, "high": 0, "medium": 0, "low": 0,
                    "link_available": False, "sample_findings": [],
                }),
            },
        },
        "_meta": meta.to_dict(),
    }


@router.get("/cwpp/cve-crosswalk")
async def view_cwpp_cve_crosswalk(
    request: Request,
    scan_run_id: str = Query("latest"),
):
    """Two-track CVE crosswalk: config issues by rule_id + CVE vulnerabilities by cve_id.

    Track A (configurationCrosswalk): container/serverless/runtime posture findings
    grouped by rule_id — no CVE mapping, grouped by config check.

    Track B (cveCrosswalk): host OS/middleware CVEs grouped by cve_id. Images pending
    Trivy/Grype integration (Sprint 3).

    Returns:
        Dict with configurationCrosswalk and cveCrosswalk lists.
    """
    tenant_id = resolve_tenant_id(request)
    auth_ctx_header = request.headers.get("X-Auth-Context") or getattr(request.state, "auth_header", None)
    fwd_headers = {"X-Auth-Context": auth_ctx_header} if auth_ctx_header else None

    results = await fetch_many([
        ("cwpp", "/api/v1/cwpp/ui-data", {
            "tenant_id": tenant_id,
            "scan_run_id": scan_run_id,
        }),
    ], auth_headers=fwd_headers)

    cwpp_data = results[0]
    if not isinstance(cwpp_data, dict) or is_empty_or_health(cwpp_data):
        cwpp_data = {}

    workloads = cwpp_data.get("workloads", {})

    # Helper: severity rank for max-severity comparison
    def _sev_rank(s: str) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get((s or "").lower(), 0)

    # Track A: configuration issues (rule_id-based) across containers/images/serverless/runtime
    rule_crosswalk: Dict[str, Any] = defaultdict(lambda: {
        "workload_types": set(),
        "affected_resources": 0,
        "severity": "low",
        "mitre_technique": "",
        "title": "",
    })
    for wtype in ("containers", "images", "serverless", "runtime"):
        wdata = workloads.get(wtype, {})
        for f in wdata.get("data", {}).get("findings", []) or []:
            rule_id = f.get("rule_id", "")
            if not rule_id:
                continue
            rule_crosswalk[rule_id]["workload_types"].add(wtype)
            rule_crosswalk[rule_id]["affected_resources"] += 1
            rule_crosswalk[rule_id]["title"] = f.get("title", rule_id)
            rule_crosswalk[rule_id]["mitre_technique"] = (
                f.get("mitre_technique") or rule_crosswalk[rule_id]["mitre_technique"]
            )
            current_sev = rule_crosswalk[rule_id]["severity"]
            new_sev = (f.get("severity") or "low").lower()
            if _sev_rank(new_sev) > _sev_rank(current_sev):
                rule_crosswalk[rule_id]["severity"] = new_sev

    # Track B: CVE vulnerabilities (cve_id-based), hosts only until Trivy/Grype lands
    hosts_data = workloads.get("hosts", {}).get("data", {}) or {}
    all_host_vulns: List[Dict[str, Any]] = (
        hosts_data.get("os_vulnerabilities", [])
        + hosts_data.get("middleware_vulnerabilities", [])
    )
    cve_crosswalk: Dict[str, Any] = {}
    for v in all_host_vulns:
        cid = v.get("cve_id", "")
        if not cid:
            continue
        cve_crosswalk[cid] = {
            "workload_types": ["hosts"],   # images pending Trivy/Grype — Sprint 3
            "severity":           v.get("severity"),
            "cvss_score":         v.get("cvss_score"),
            "epss_score":         None,    # Sprint 3 — not yet ingested
            "epss_note":          "EPSS not yet ingested — Sprint 3",
            "affected_resources": v.get("affected_hosts_count", 1),
        }

    return {
        "configurationCrosswalk": [
            {
                "id": rid,
                "type": "config",
                "workload_types": list(v["workload_types"]),
                "affected_resources": v["affected_resources"],
                "severity": v["severity"],
                "mitre_technique": v["mitre_technique"],
                "title": v["title"],
            }
            for rid, v in rule_crosswalk.items()
        ],
        "cveCrosswalk": [
            {"id": cid, "type": "cve", **v}
            for cid, v in cve_crosswalk.items()
        ],
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

_WORKLOAD_NAMES = {
    "containers": "Containers & Kubernetes",
    "images":     "Container Images",
    "hosts":      "Hosts / VMs / Middleware",
    "serverless": "Serverless Functions",
    "runtime":    "Runtime Threat Detection",
}

_WORKLOAD_COLORS = {
    "containers": "#3b82f6",
    "images":     "#8b5cf6",
    "hosts":      "#f97316",
    "serverless": "#10b981",
    "runtime":    "#ef4444",
}

_WORKLOAD_DESCRIPTIONS = {
    "containers": "K8s / EKS / ECS cluster and pod security posture",
    "images":     "Container image CVE scanning and posture",
    "hosts":      "OS / VM / middleware CVEs from agent-based scanning",
    "serverless": "Lambda / Azure Functions / GCF security posture",
    "runtime":    "Privileged containers, host-network, CIEM runtime events",
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
