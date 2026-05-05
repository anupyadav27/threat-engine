"""
CWPP Engine — Cloud Workload Protection Platform API.
Port: 8016

Pure aggregation layer — no database. Calls sibling engine APIs to collect
data for each workload type and returns a unified workload protection view.

CWPP covers every compute surface in the cloud estate:
  containers  — K8s / EKS / ECS / AKS / GKE / ACK / OKE cluster + pod security
  images      — Container image posture checks + CVE scan (placeholder)
  hosts       — OS/VM/middleware CVEs via vul_engine (agent-based)
  serverless  — Lambda / Azure Functions / GCF / OCI Functions
  runtime     — Privileged containers, host-network, CIEM runtime events

Source engines (all called via internal K8s ClusterIP services):
  container-security  → containers, images, serverless, runtime workloads
  vul_engine          → hosts (OS + middleware CVEs)
  sbom_engine         → hosts (dependency/library CVEs)
  secops              → images (image-scan placeholder)

Endpoints:
  GET /api/v1/cwpp/dashboard           — full unified dashboard (all workload types)
  GET /api/v1/cwpp/workloads           — catalog of workload types
  GET /api/v1/cwpp/workloads/{type}    — single workload type data
  GET /api/v1/cwpp/posture             — CWPP posture score only (fast)
  GET /api/v1/health/live
  GET /api/v1/health/ready
  GET /api/v1/health
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware

from .workloads import containers, images, hosts, serverless, runtime
from .core.scorer import compute_cwpp_score, risk_band
from .core.pillar_health import (
    CWPP_PILLAR_HEALTH_ENDPOINTS,
    check_pillar_health,
    fetch_all_pillar_scores,
    extract_container_sec_score,
    extract_ai_security_score,
    extract_findings_count,
)

try:
    import sys as _sys
    _sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "shared"))
    from engine_common.telemetry import configure_telemetry
    from engine_common.middleware import RequestLoggingMiddleware, CorrelationIDMiddleware
except ImportError:
    configure_telemetry = None
    RequestLoggingMiddleware = None
    CorrelationIDMiddleware = None

# ── Auth imports (engine_auth is COPY shared/auth/ ./engine_auth/ in Dockerfile) ──
try:
    from engine_auth.fastapi.middleware import AuthMiddleware
    from engine_auth.fastapi.dependencies import require_permission
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    def require_permission(perm: str):  # type: ignore[misc]
        """No-op permission checker used when engine_auth is unavailable."""
        return lambda: None
    class AuthMiddleware:  # type: ignore[no-redef]
        """Stub middleware used when engine_auth is unavailable."""
        pass

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("cwpp.api_server")

app = FastAPI(
    title="CWPP Engine API",
    description=(
        "Cloud Workload Protection Platform — unified workload security across "
        "containers, container images, hosts/VMs, serverless, and runtime threats."
    ),
    version="1.0.0",
)

if configure_telemetry:
    configure_telemetry("engine-cwpp", app)
if CorrelationIDMiddleware:
    app.add_middleware(CorrelationIDMiddleware)
if RequestLoggingMiddleware:
    app.add_middleware(RequestLoggingMiddleware, engine_name="engine-cwpp")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# AuthMiddleware validates access_token / X-Auth-Context for every non-health path
if _AUTH_AVAILABLE:
    app.add_middleware(AuthMiddleware)

# ── Workload registry ─────────────────────────────────────────────────────────

WORKLOADS = {
    "containers": containers.fetch,
    "images":     images.fetch,
    "hosts":      hosts.fetch,
    "serverless": serverless.fetch,
    "runtime":    runtime.fetch,
}

WORKLOAD_META = {
    "containers": {
        "name": "Container & Kubernetes Security",
        "description": "K8s cluster config, pod security, RBAC, network policies (EKS/ECS/AKS/GKE/ACK/OKE)",
        "source_engines": ["container-security"],
        "security_domains": ["cluster_security", "workload_security", "rbac_access", "network_security"],
    },
    "images": {
        "name": "Container Image Security",
        "description": "Image posture checks (scan-on-push, policy webhooks) + CVE scanning (placeholder)",
        "source_engines": ["container-security", "secops"],
        "security_domains": ["image_security"],
        "cve_scan_status": "not_implemented",
    },
    "hosts": {
        "name": "Host / VM / Middleware Security",
        "description": "Agent-based OS CVE scanning + middleware (Tomcat, Nginx, JBoss) + dependency SBOMs",
        "source_engines": ["vul-engine", "sbom-engine"],
        "security_domains": ["os_vulnerabilities", "middleware_vulnerabilities", "sbom_dependencies"],
    },
    "serverless": {
        "name": "Serverless Security",
        "description": "Lambda / Azure Functions / GCF: IAM roles, public URLs, deprecated runtimes",
        "source_engines": ["container-security"],
        "security_domains": ["workload_security", "runtime_audit"],
    },
    "runtime": {
        "name": "Runtime Threat Detection",
        "description": "Privileged containers, host-network, seccomp/AppArmor, CIEM runtime events",
        "source_engines": ["container-security"],
        "security_domains": ["runtime_audit"],
    },
}


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/")
@app.get("/health")
async def root():
    return {
        "service": "engine-cwpp",
        "version": "1.0.0",
        "workload_types": list(WORKLOADS.keys()),
        "status": "operational",
    }


@app.get("/api/v1/health/live")
async def liveness():
    return {"status": "alive"}


@app.get("/api/v1/health/ready")
async def readiness():
    return {"status": "ready", "note": "no local DB — aggregation only"}


@app.get("/api/v1/health")
async def health():
    return {
        "status": "healthy",
        "service": "engine-cwpp",
        "version": "1.0.0",
        "workload_types": list(WORKLOADS.keys()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Dashboard ─────────────────────────────────────────────────────────────────

async def _run_dashboard(
    scan_run_id: str,
    tenant_id: str,
    auth_header: Optional[str],
    workload_types: Optional[str],
) -> Dict[str, Any]:
    """Core dashboard aggregation logic shared by /dashboard and /ui-data.

    Args:
        scan_run_id: Pipeline run identifier used to scope all workload queries.
        tenant_id: Tenant identifier extracted from AuthContext.
        auth_header: Serialised X-Auth-Context value forwarded to upstream engines.
        workload_types: Optional comma-separated workload type filter.

    Returns:
        Unified CWPP dashboard payload dict.
    """
    requested = (
        [w.strip() for w in workload_types.split(",") if w.strip() in WORKLOADS]
        if workload_types
        else list(WORKLOADS.keys())
    )

    tasks = [WORKLOADS[w](scan_run_id, tenant_id, auth_header) for w in requested]
    results: List[Dict[str, Any]] = await asyncio.gather(*tasks)

    cwpp_score = compute_cwpp_score(results)
    band = risk_band(cwpp_score)

    # Aggregate top-level counts across all workload types
    total_findings = sum(
        r.get("summary", {}).get("total_findings", 0)
        for r in results
        if r.get("status") == "ok"
    )
    critical_findings = sum(
        r.get("summary", {}).get("critical", r.get("summary", {}).get("critical_findings", 0))
        for r in results
        if r.get("status") == "ok"
    )

    available_wt = [r["workload_type"] for r in results if r.get("status") == "ok"]
    unavailable_wt = [r["workload_type"] for r in results if r.get("status") == "unavailable"]
    no_data_wt = [r["workload_type"] for r in results if r.get("status") == "no_data"]
    available_count = len(available_wt)
    total_count = len(requested)
    scoring_note = (
        f"Score based on {available_count} of {total_count} workload types"
        if available_count < total_count
        else "Score based on all workload types"
    )

    return {
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "cwpp_posture_score": cwpp_score,
        "overall_score": cwpp_score,
        "risk_band": band,
        "available_workload_types": available_count,
        "total_workload_types": total_count,
        "scoring_note": scoring_note,
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "workload_types_requested": requested,
        "workload_types_available": available_wt,
        "workload_types_unavailable": unavailable_wt,
        "workload_types_no_data": no_data_wt,
        "workloads": {r["workload_type"]: r for r in results},
    }


@app.get("/api/v1/cwpp/dashboard")
async def dashboard(
    request: Request,
    scan_run_id: str = Query(..., description="scan_run_id to scope all workload queries"),
    workload_types: Optional[str] = Query(
        default=None,
        description="Comma-separated workload types (default: all). "
                    "Options: containers, images, hosts, serverless, runtime",
    ),
    auth: Any = Depends(require_permission("cwpp:read") if _AUTH_AVAILABLE else (lambda: None)),
):
    """
    Fetch all CWPP workload data concurrently and return a unified dashboard.

    All workload-type calls run in parallel. Unavailable engines are gracefully
    skipped — their type returns status='unavailable' with null score.
    """
    tenant_id: str = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
        or os.getenv("DEFAULT_TENANT_ID", "default-tenant")
    )
    auth_header = request.headers.get("X-Auth-Context") or request.headers.get("x-auth-context")
    return await _run_dashboard(scan_run_id, tenant_id, auth_header, workload_types)


# ── Single workload type ──────────────────────────────────────────────────────

@app.get("/api/v1/cwpp/workloads/{workload_type}")
async def get_workload(
    request: Request,
    workload_type: str,
    scan_run_id: str = Query(...),
    auth: Any = Depends(require_permission("cwpp:read") if _AUTH_AVAILABLE else (lambda: None)),
):
    """Fetch data for a single CWPP workload type."""
    tenant_id: str = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
        or os.getenv("DEFAULT_TENANT_ID", "default-tenant")
    )
    if workload_type not in WORKLOADS:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown workload type '{workload_type}'. Valid: {list(WORKLOADS.keys())}",
        )
    auth_header = request.headers.get("X-Auth-Context") or request.headers.get("x-auth-context")
    result = await WORKLOADS[workload_type](scan_run_id, tenant_id, auth_header)
    meta = WORKLOAD_META.get(workload_type, {})
    return {**result, "meta": meta}


# ── Posture score (fast) ──────────────────────────────────────────────────────

@app.get("/api/v1/cwpp/posture")
async def posture_score(
    scan_run_id: str = Query(...),
    auth: Any = Depends(require_permission("cwpp:read") if _AUTH_AVAILABLE else (lambda: None)),
):
    """
    Returns only the CWPP posture score across all workload types (parallel calls).
    Faster than /dashboard — extracts scores only, not full data.
    """
    tenant_id: str = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
        or os.getenv("DEFAULT_TENANT_ID", "default-tenant")
    )
    tasks = [fn(scan_run_id, tenant_id) for fn in WORKLOADS.values()]
    results = await asyncio.gather(*tasks)

    cwpp_score = compute_cwpp_score(results)
    band = risk_band(cwpp_score)

    available_count = len([r for r in results if r.get("status") == "ok"])
    total_count = len(results)
    scoring_note = (
        f"Score based on {available_count} of {total_count} workload types"
        if available_count < total_count
        else "Score based on all workload types"
    )

    return {
        "scan_run_id": scan_run_id,
        "cwpp_posture_score": cwpp_score,
        "overall_score": cwpp_score,
        "risk_band": band,
        "available_workload_types": available_count,
        "total_workload_types": total_count,
        "scoring_note": scoring_note,
        "workload_scores": {r["workload_type"]: r.get("posture_score") for r in results},
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Unified CWPP score (graceful degradation) ────────────────────────────────

# CWPP logical pillar names → source engine key
_SCORE_PILLAR_MAP = {
    "workload_security": "container_sec",
    "ai_security":       "ai_security",
}


@app.get("/api/v1/cwpp/score")
async def cwpp_score(
    scan_run_id: str = Query(..., description="scan_run_id to scope all pillar score queries"),
    provider: str = Query(default="aws"),
    auth: Any = Depends(require_permission("cwpp:read") if _AUTH_AVAILABLE else (lambda: None)),
):
    """
    Unified CWPP score with graceful degradation.

    Steps:
      1. Health-check container_sec + ai_security concurrently (5s timeout each).
      2. For available pillars only, fetch score data (5s timeout, tenant_id scoped).
      3. Compute overall_score from available pillars only — unavailable pillars
         contribute score=None and are EXCLUDED from the denominator.
      4. Return available_pillars / total_pillars for operator visibility.

    Unavailable pillar → score=null, findings=null, reason="engine_unavailable".
    If ALL pillars unavailable → overall_score=null (never 0).
    """
    tenant_id: str = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
        or os.getenv("DEFAULT_TENANT_ID", "default-tenant")
    )
    # Step 1 — parallel health checks (5s per pillar)
    health = await check_pillar_health(CWPP_PILLAR_HEALTH_ENDPOINTS)

    # Step 2 — parallel score fetches for available pillars only (tenant_id scoped)
    score_data = await fetch_all_pillar_scores(health, scan_run_id, tenant_id)

    # Step 3 — build pillar dict
    pillars: Dict[str, Any] = {}
    available_scores: list = []

    for pillar_name, source_key in _SCORE_PILLAR_MAP.items():
        is_available = health.get(source_key, False)
        raw = score_data.get(source_key)

        if not is_available:
            pillars[pillar_name] = {
                "score": None,
                "findings": None,
                "source": source_key,
                "reason": "engine_unavailable",
            }
            continue

        if source_key == "container_sec":
            score = extract_container_sec_score(raw)
        else:
            score = extract_ai_security_score(raw)

        findings = extract_findings_count(raw)

        if score is not None:
            available_scores.append(score)

        pillars[pillar_name] = {
            "score": score,
            "findings": findings,
            "source": source_key,
            "reason": None,
        }

    # Step 4 — overall score from available pillars only (never 0 for unavailable)
    if available_scores:
        overall_score: Optional[int] = round(sum(available_scores) / len(available_scores))
    else:
        overall_score = None  # All pillars down — never return 0

    available_count = sum(
        1 for p in pillars.values() if p["score"] is not None
    )
    total_count = len(_SCORE_PILLAR_MAP)

    return {
        "overall_score": overall_score,
        "provider": provider,
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "risk_band": risk_band(overall_score),
        "pillars": pillars,
        "available_pillars": available_count,
        "total_pillars": total_count,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Workload catalog ──────────────────────────────────────────────────────────

@app.get("/api/v1/cwpp/workloads")
async def list_workloads():
    """List all CWPP workload types with metadata about which engines they call."""
    return {
        "workload_types": [
            {
                "id": wid,
                "name": meta["name"],
                "description": meta["description"],
                "source_engines": meta["source_engines"],
                "endpoint": f"/api/v1/cwpp/workloads/{wid}",
            }
            for wid, meta in WORKLOAD_META.items()
        ]
    }


# ── CNAPP integration ─────────────────────────────────────────────────────────

@app.get("/api/v1/cwpp/ui-data")
async def ui_data(
    request: Request,
    scan_run_id: str = Query(...),
    auth: Any = Depends(require_permission("cwpp:read") if _AUTH_AVAILABLE else (lambda: None)),
):
    """
    Alias for /dashboard — used by the CNAPP engine CWPP pillar.
    Returns the same unified payload under a standard 'ui-data' path
    so the CNAPP pillar can call this with the same pattern as other engines.
    """
    tenant_id: str = (
        getattr(auth, "engine_tenant_id", None)
        or getattr(auth, "tenant_id", None)
        or os.getenv("DEFAULT_TENANT_ID", "default-tenant")
    )
    auth_header = request.headers.get("X-Auth-Context") or request.headers.get("x-auth-context")
    return await _run_dashboard(scan_run_id, tenant_id, auth_header, workload_types=None)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("CWPP_PORT", "8016"))
    uvicorn.run(app, host="0.0.0.0", port=port)
