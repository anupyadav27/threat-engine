"""
SecOps Scanner API — Unified code security platform.

Sub-routers:
  /api/v1/secops/sast/*   — Static Application Security Testing (14 languages, ~2,900 rules)
  /api/v1/secops/dast/*   — Dynamic Application Security Testing (OWASP Top 10, 479 payloads)
  /api/v1/secops/sca/*    — Software Composition Analysis / SBOM (planned)

Health:
  GET /api/v1/health/live   — Liveness probe
  GET /api/v1/health/ready  — Readiness probe (DB ping)
  GET /api/v1/health        — Full health
  GET /health               — Legacy health

Legacy (backward compat):
  POST /api/v1/secops/scan  — Redirects to /api/v1/secops/sast/scan
  POST /scan                — Scan pre-staged project folder
  GET  /results/{name}      — Get latest local results
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from scanner_plugin import get_supported_languages
from scan_local import scan_path

# ── Routers ──────────────────────────────────────────────────────────────────
from routers.sast import router as sast_router
from routers.dast import router as dast_router
from routers.sca import get_sca_app

try:
    import sys as _sys, os as _os
    _sys.path.insert(0, _os.path.join(_os.path.dirname(__file__), '..', '..', '..'))
    from engine_common.telemetry import configure_telemetry as _configure_telemetry
except ImportError:
    _configure_telemetry = None

logger = logging.getLogger("secops")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

# Folders
INPUT_FOLDER = os.getenv("SCAN_INPUT_PATH", "/app/scan_input")
OUTPUT_FOLDER = os.getenv("SCAN_OUTPUT_PATH", "/app/scan_output")
os.makedirs(INPUT_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

app = FastAPI(
    title="SecOps Scanner Engine API",
    description="Unified code security platform — SAST (14 languages), DAST (OWASP Top 10), SCA/SBOM",
    version="4.0.0",
)
if _configure_telemetry:
    _configure_telemetry("engine-secops", app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Include sub-routers ──────────────────────────────────────────────────────

app.include_router(sast_router, prefix="/api/v1/secops/sast", tags=["SAST"])
app.include_router(dast_router, prefix="/api/v1/secops/dast", tags=["DAST"])

# SCA/SBOM: mounted as a sub-application (has its own lifespan, asyncpg pool, etc.)
try:
    sca_app = get_sca_app()
    app.mount("/api/v1/secops/sca", sca_app)
    logger.info("SCA/SBOM sub-application mounted at /api/v1/secops/sca")
except Exception as e:
    logger.warning(f"SCA/SBOM sub-application not available: {e} — SCA endpoints disabled")


# ── Rule Cache (DB-primary) ─────────────────────────────────────────────────

try:
    from database.rule_cache import rule_cache
except ImportError:
    rule_cache = None


@app.on_event("startup")
async def _init_sca_engine():
    """Initialize SCA/SBOM engine DB pool and enrichers (sub-app lifespan doesn't auto-run)."""
    try:
        import sys as _s
        # Ensure sca_sbom_engine internal imports (from main import ...) resolve
        sca_pkg_dir = os.path.join(os.environ.get("PYTHONPATH", "/app"), "sca_sbom_engine")
        if os.path.isdir(sca_pkg_dir) and sca_pkg_dir not in _s.path:
            _s.path.insert(0, sca_pkg_dir)

        import sca_sbom_engine.main as sca_main
        from sca_sbom_engine.core.database import SBOMDatabaseManager
        from sca_sbom_engine.core.vuln_enricher import VulnEnricher
        from sca_sbom_engine.core.threat_intel import ThreatIntelProvider

        sca_main.db_manager = SBOMDatabaseManager()
        await sca_main.db_manager.initialize()

        sca_main.threat_intel_provider = ThreatIntelProvider(sca_main.db_manager)
        sca_main.vuln_enricher = VulnEnricher(sca_main.db_manager, threat_intel=sca_main.threat_intel_provider)

        # Routes use `from main import db_manager` (bare import).
        # Register sca_sbom_engine.main as the bare `main` module so those imports resolve.
        _s.modules["main"] = sca_main

        logger.info("SCA/SBOM engine initialized — DB pool ready")
    except Exception as e:
        logger.warning(f"SCA/SBOM engine init failed: {e} — SCA endpoints will return unhealthy")


@app.on_event("startup")
async def _load_rule_cache():
    """Full-load all SAST rules from DB into memory on startup."""
    if rule_cache is None:
        logger.warning("RuleCache not available — scanners will use local JSON files")
        return
    try:
        totals = rule_cache.load_all()
        logger.info(f"RuleCache ready: {sum(totals.values())} rules, {len(totals)} scanners")
    except Exception as e:
        logger.error(f"RuleCache startup failed: {e} — scanners will load from DB on first use")


# ── Root & Health ────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "service": "SecOps Scanner Engine",
        "version": "4.0.0",
        "capabilities": ["sast", "dast", "sca"],
        "status": "operational",
        "supported_languages": list(get_supported_languages()),
        "endpoints": {
            "sast": "/api/v1/secops/sast/",
            "dast": "/api/v1/secops/dast/",
            "sca": "/api/v1/secops/sca/",
            "health": "/api/v1/health",
            "docs": "/docs",
        },
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "supported_languages": list(get_supported_languages()),
        "input_folder": INPUT_FOLDER,
        "output_folder": OUTPUT_FOLDER,
    }


@app.get("/api/v1/health/live")
async def liveness():
    """Kubernetes liveness probe — returns 200 if process is alive."""
    return {"status": "alive"}


@app.get("/api/v1/health/ready")
async def readiness():
    """Kubernetes readiness probe — DB ping."""
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=os.getenv("SECOPS_DB_HOST", "localhost"),
            port=int(os.getenv("SECOPS_DB_PORT", "5432")),
            dbname=os.getenv("SECOPS_DB_NAME", "secops"),
            user=os.getenv("SECOPS_DB_USER", "postgres"),
            password=os.getenv("SECOPS_DB_PASSWORD", ""),
            connect_timeout=3,
        )
        conn.close()
        return {"status": "ready"}
    except Exception as e:
        return JSONResponse(status_code=503, content={"status": "not ready", "error": str(e)})


@app.get("/api/v1/health")
async def api_health():
    """Full health check with DB connectivity."""
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=os.getenv("SECOPS_DB_HOST", "localhost"),
            port=int(os.getenv("SECOPS_DB_PORT", "5432")),
            dbname=os.getenv("SECOPS_DB_NAME", "secops"),
            user=os.getenv("SECOPS_DB_USER", "postgres"),
            password=os.getenv("SECOPS_DB_PASSWORD", ""),
            connect_timeout=3,
        )
        conn.close()
        return {"status": "healthy", "database": "connected", "service": "engine-secops", "version": "4.0.0"}
    except Exception as e:
        return {"status": "degraded", "database": "disconnected", "error": str(e), "service": "engine-secops", "version": "4.0.0"}


# ── Backward-compat redirects ───────────────────────────────────────────────
# Old callers hitting /api/v1/secops/scan get forwarded to /sast

@app.post("/api/v1/secops/scan")
async def compat_scan(request: Request):
    """Backward compat: redirect to SAST scan endpoint."""
    return RedirectResponse(url="/api/v1/secops/sast/scan", status_code=307)


@app.get("/api/v1/secops/scan/{scan_id}/status")
async def compat_status(scan_id: str):
    """Backward compat: redirect to SAST status."""
    return RedirectResponse(url=f"/api/v1/secops/sast/scan/{scan_id}/status", status_code=307)


@app.get("/api/v1/secops/scan/{scan_id}/findings")
async def compat_findings(scan_id: str, request: Request):
    """Backward compat: redirect to SAST findings."""
    qs = str(request.query_params)
    url = f"/api/v1/secops/sast/scan/{scan_id}/findings"
    if qs:
        url += f"?{qs}"
    return RedirectResponse(url=url, status_code=307)


@app.get("/api/v1/secops/scans")
async def compat_scans(request: Request):
    """Backward compat: redirect to SAST scans list."""
    qs = str(request.query_params)
    url = "/api/v1/secops/sast/scans"
    if qs:
        url += f"?{qs}"
    return RedirectResponse(url=url, status_code=307)


@app.get("/api/v1/secops/rules/stats")
async def compat_rules_stats():
    """Backward compat: redirect to SAST rules stats."""
    return RedirectResponse(url="/api/v1/secops/sast/rules/stats", status_code=307)


@app.post("/api/v1/secops/rules/sync")
async def compat_rules_sync():
    """Backward compat: redirect to SAST rules sync."""
    return RedirectResponse(url="/api/v1/secops/sast/rules/sync", status_code=307)


# ── Legacy endpoints (pre-v3 compat) ────────────────────────────────────────

class LegacyScanRequest(BaseModel):
    """Backward-compatible: scan from pre-staged input folder."""
    project_name: str
    save_results: Optional[bool] = True
    fail_on_findings: Optional[bool] = False


@app.post("/scan")
async def scan_project_legacy(request: LegacyScanRequest):
    """Legacy: Scan a project already staged in input folder."""
    project_name = request.project_name.strip()
    if not project_name:
        raise HTTPException(status_code=400, detail="project_name is required")
    if ".." in project_name or "/" in project_name or "\\" in project_name:
        raise HTTPException(status_code=400, detail="Invalid project_name")

    input_path = os.path.join(INPUT_FOLDER, project_name)
    if not os.path.exists(input_path):
        raise HTTPException(status_code=404, detail=f"Project not found: {project_name}")

    try:
        scan_result = scan_path(input_path)
        total_files = len(scan_result.get("results", []))
        total_findings = sum(len(r.get("findings", [])) for r in scan_result.get("results", []))
        total_errors = len(scan_result.get("errors", []))

        response = {
            "success": True,
            "project_name": project_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "summary": {
                "files_scanned": total_files,
                "total_findings": total_findings,
                "total_errors": total_errors,
            },
            "scan_data": scan_result,
        }

        if request.save_results:
            output_path = os.path.join(OUTPUT_FOLDER, project_name)
            os.makedirs(output_path, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
            result_file = os.path.join(output_path, f"scan_results_{ts}.json")
            latest_file = os.path.join(output_path, "scan_results_latest.json")
            with open(result_file, "w") as f:
                json.dump(response, f, indent=2)
            with open(latest_file, "w") as f:
                json.dump(response, f, indent=2)
            response["output_file"] = result_file
            response["latest_file"] = latest_file

        if request.fail_on_findings and total_findings > 0:
            raise HTTPException(status_code=422, detail=f"Found {total_findings} findings")

        return JSONResponse(content=response)

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")


@app.get("/results/{project_name}")
async def get_latest_results(project_name: str):
    """Legacy: Get latest scan results from local files."""
    if ".." in project_name or "/" in project_name or "\\" in project_name:
        raise HTTPException(status_code=400, detail="Invalid project_name")
    latest_file = os.path.join(OUTPUT_FOLDER, project_name, "scan_results_latest.json")
    if not os.path.exists(latest_file):
        raise HTTPException(status_code=404, detail=f"No results for: {project_name}")
    with open(latest_file) as f:
        return JSONResponse(content=json.load(f))


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("SECOPS_PORT", "8009"))
    uvicorn.run(app, host="0.0.0.0", port=port)
