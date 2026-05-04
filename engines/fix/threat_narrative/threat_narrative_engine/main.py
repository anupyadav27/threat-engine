"""
Threat Narrative Engine API — LLM-powered chain of consequence generator.

Endpoints:
  POST /api/v1/generate/{scan_run_id}  — manual or pipeline-triggered generation
  GET  /api/v1/health/live             — liveness probe (no auth)
  GET  /api/v1/health/ready            — readiness probe (checks threat DB)

Security:
  - Health endpoints require no authentication.
  - POST /generate requires scans:create permission (RBAC via engine_auth).
  - ANTHROPIC_API_KEY sourced from Kubernetes secret (never baked into image).
  - LLM prompt injection: data appears only in user prompt, not system prompt.

Failure model:
  - Missing LLM key: service starts, all detections skipped (200 returned).
  - LLM timeout/rate-limit: individual detection marked failed, service continues.
  - DB unreachable: 503 returned (genuine infrastructure failure).
"""

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException, Path
from fastapi.middleware.cors import CORSMiddleware

# JSON logging must be configured FIRST — before any other module touches logging
from threat_narrative_engine.logging_config import configure_logging

configure_logging("threat_narrative")

from threat_narrative_engine.db_writer import check_threat_db_connection
from threat_narrative_engine.narrative_generator import generate_for_scan, get_llm_provider

# ── Auth imports (engine_auth is COPY shared/auth/ ./engine_auth/ in Dockerfile) ──
try:
    from engine_auth.fastapi.middleware import AuthMiddleware as _AuthMiddleware
    from engine_auth.fastapi.dependencies import require_permission as _require_permission
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    _require_permission = None  # type: ignore[assignment]

logger = logging.getLogger("threat_narrative")
_audit = logging.getLogger("audit.threat_narrative")


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def _lifespan(app: FastAPI):
    """Log startup state and close DB connections on shutdown."""
    provider = get_llm_provider()

    if provider == "anthropic":
        llm_status = f"Anthropic Claude ({os.getenv('ANTHROPIC_API_KEY', '')[:8]}...)"
    elif provider == "mistral":
        llm_status = "Mistral (fallback)"
    else:
        llm_status = "NONE — set ANTHROPIC_API_KEY or MISTRAL_API_KEY to enable generation"

    logger.info(
        "Threat Narrative Engine ready",
        extra={
            "port": 8040,
            "llm_provider": provider or "none",
            "llm_status": llm_status,
            "auth_available": _AUTH_AVAILABLE,
        },
    )

    yield  # ── application runs ─────────────────────────────────────────────

    logger.info("Threat Narrative Engine shutdown complete")


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Threat Narrative Engine API",
    description=(
        "LLM-powered chain of consequence generator. "
        "Reads from threat, risk, datasec, ciem, compliance, and discovery databases. "
        "Generates and stores executive-level narrative summaries for threat detections. "
        "Best-effort: missing LLM key returns 200 with all detections skipped."
    ),
    version="1.0.0",
    lifespan=_lifespan,
)

# ── Middleware ─────────────────────────────────────────────────────────────────
# Middleware executes in reverse registration order (last added = outermost).

# 1. CORS (innermost — registered first)
_allowed_origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
)

# 2. JWT/session auth from engine_auth
if _AUTH_AVAILABLE:
    app.add_middleware(_AuthMiddleware)


# ── Health endpoints (no auth) ─────────────────────────────────────────────────

@app.get("/api/v1/health/live", tags=["Health"])
async def liveness() -> dict:
    """Liveness probe — always returns 200 while the process is alive.

    Returns:
        JSON with status and timestamp.
    """
    return {
        "status": "alive",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "engine-threat-narrative",
    }


@app.get("/api/v1/health/ready", tags=["Health"])
async def readiness() -> dict:
    """Readiness probe — checks threat DB connectivity.

    Returns:
        JSON with status and timestamp.

    Raises:
        HTTPException: 503 if threat DB is unreachable.
    """
    db_ok = check_threat_db_connection()
    if not db_ok:
        raise HTTPException(
            status_code=503,
            detail="Threat DB unreachable — service not ready",
        )
    return {
        "status": "ready",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "service": "engine-threat-narrative",
        "threat_db": "connected",
    }


# ── Generate endpoint ──────────────────────────────────────────────────────────

def _get_generate_deps() -> list:
    """Return dependency list for the generate endpoint.

    Returns scans:create permission check if auth is available, else empty list.
    """
    if _AUTH_AVAILABLE and _require_permission is not None:
        return [Depends(_require_permission("scans:create"))]
    return []


@app.post(
    "/api/v1/generate/{scan_run_id}",
    tags=["Narrative"],
    dependencies=_get_generate_deps(),
)
async def generate_narratives(
    scan_run_id: str = Path(..., description="Pipeline scan run UUID"),
) -> dict:
    """Trigger narrative generation for all detections in a scan run.

    Reads all threat_detections rows for the scan_run_id and attempts LLM
    generation for each. Processes sequentially to respect LLM rate limits.

    If LLM keys are not configured, all detections are skipped and 200 is
    returned — this is expected behaviour (best-effort service).

    Args:
        scan_run_id: The pipeline scan run UUID.

    Returns:
        JSON summary with processed, skipped, failed counts.

    Raises:
        HTTPException: 503 if threat DB is unreachable (infrastructure failure).
    """
    import psycopg2

    _audit.info(
        "generate_narratives called",
        extra={"scan_run_id": scan_run_id},
    )

    try:
        summary = await generate_for_scan(scan_run_id)
    except psycopg2.OperationalError as exc:
        logger.error(
            "Threat DB unreachable during narrative generation",
            extra={"scan_run_id": scan_run_id, "error": str(exc)},
        )
        raise HTTPException(
            status_code=503,
            detail="Threat DB unreachable — cannot generate narratives",
        )

    return {
        "scan_run_id": scan_run_id,
        "processed": summary["processed"],
        "skipped": summary["skipped"],
        "failed": summary["failed"],
        "total": summary["total"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Root ──────────────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def root() -> dict:
    """Service info endpoint."""
    provider = get_llm_provider()
    return {
        "service": "Threat Narrative Engine",
        "version": "1.0.0",
        "llm_provider": provider or "none (set ANTHROPIC_API_KEY to enable)",
        "status": "operational",
        "endpoints": {
            "generate": "/api/v1/generate/{scan_run_id}",
            "health_live": "/api/v1/health/live",
            "health_ready": "/api/v1/health/ready",
            "docs": "/docs",
        },
    }


# ── Prometheus metrics ─────────────────────────────────────────────────────────
from prometheus_fastapi_instrumentator import Instrumentator as _Instrumentator  # noqa: E402

_Instrumentator(
    should_group_status_codes=False,
    should_ignore_untemplated=True,
    excluded_handlers=["/metrics"],
).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "threat_narrative_engine.main:app",
        host="0.0.0.0",
        port=8040,
        workers=1,
        log_level="info",
    )
