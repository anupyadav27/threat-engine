"""
SecOps Fix Engine API — automated remediation for SecOps scanner findings.

Endpoints:
  POST /api/v1/secops-fix/remediate           — trigger remediation for a scan
  GET  /api/v1/secops-fix/remediate/{scan_id} — get remediation status
  GET  /api/v1/secops-fix/findings/{scan_id}  — list findings for a scan
  GET  /api/v1/secops-fix/findings/{scan_id}/summary
  GET  /api/v1/health/live                    — liveness probe (no auth)
  GET  /api/v1/health/ready                   — readiness probe (no auth)
  GET  /api/v1/health                         — full health (no auth)

Security:
  - All non-health endpoints require X-API-Key header (SECOPS_FIX_API_KEY env var).
  - Git repo token passed per-request in X-Repo-Token header (never in body or logs).
  - Engine refuses to start if SECOPS_FIX_API_KEY is not set.

Concurrency:
  - SECOPS_FIX_MAX_CONCURRENT (default 3) limits simultaneous pipeline runs.
  - SECOPS_FIX_PIPELINE_TIMEOUT (default 600s) caps each run's wall-clock time.
"""

import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# JSON logging must be configured FIRST — before any other module touches logging
from logging_config import configure_logging
configure_logging("secops_fix")

from middleware.auth import APIKeyMiddleware
from middleware.correlation import CorrelationIDMiddleware
from routers.remediation import router as remediation_router
from routers.findings import router as findings_router
from routers.health import router as health_router
from db.db_config import close_pool

logger = logging.getLogger("secops_fix")
_audit = logging.getLogger("audit.secops_fix")   # dedicated audit stream


# ── Startup guard — refuse to run with missing critical config ─────────────────
def _check_required_env() -> None:
    missing = []
    if not os.getenv("SECOPS_FIX_API_KEY", "").strip():
        missing.append("SECOPS_FIX_API_KEY")
    if not os.getenv("MISTRAL_API_KEY", "").strip():
        missing.append("MISTRAL_API_KEY")
    if missing:
        for var in missing:
            logger.critical(
                f"FATAL: required environment variable '{var}' is not set. "
                "Set it via Kubernetes secret and restart the pod."
            )
        sys.exit(1)


_check_required_env()


# ── Lifespan (replaces deprecated on_event) ───────────────────────────────────
@asynccontextmanager
async def _lifespan(app: FastAPI):
    # ── startup ───────────────────────────────────────────────────────────────
    ai_enabled  = bool(os.getenv("MISTRAL_API_KEY", "").strip())
    key_ok      = bool(os.getenv("SECOPS_FIX_API_KEY", "").strip())
    max_c       = int(os.getenv("SECOPS_FIX_MAX_CONCURRENT", "3"))
    timeout_s   = int(os.getenv("SECOPS_FIX_PIPELINE_TIMEOUT", "600"))

    logger.info(
        f"SecOps Fix Engine v2 ready — "
        f"API_KEY={'set' if key_ok else 'MISSING'} | "
        f"AI_FIX={'Mistral enabled' if ai_enabled else 'DISABLED — set MISTRAL_API_KEY'} | "
        f"rules_source=secops_rule_metadata (DB) | "
        f"max_concurrent={max_c} | pipeline_timeout={timeout_s}s"
    )

    yield  # ── application runs ─────────────────────────────────────────────

    # ── shutdown ──────────────────────────────────────────────────────────────
    close_pool()
    logger.info("SecOps Fix Engine shutdown complete — DB pool closed")


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SecOps Fix Engine API",
    description=(
        "Automated remediation engine — fetches SecOps scanner findings from DB, "
        "pulls rule metadata from secops_rule_metadata (single source of truth), "
        "calls Mistral AI with full code context to generate precise fixes, "
        "and commits the patched code to a new branch in the source repo. "
        "Requires X-API-Key header. Git repo token passed via X-Repo-Token header."
    ),
    version="2.0.0",
    lifespan=_lifespan,
)

# ── Middleware ─────────────────────────────────────────────────────────────────
# Middleware executes in reverse registration order (last added = outermost).
# Desired order: CorrelationID → APIKey → CORS

# 1. CORS (innermost — registered first)
_allowed_origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Repo-Token", "X-Request-ID"],
)

# 2. API key auth (all non-health endpoints)
_api_key = os.getenv("SECOPS_FIX_API_KEY", "").strip()
app.add_middleware(APIKeyMiddleware, api_key=_api_key)

# 3. Correlation ID (outermost — sets request_id for all log lines in the request)
app.add_middleware(CorrelationIDMiddleware)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(remediation_router, prefix="/api/v1/secops-fix/remediate", tags=["Remediation"])
app.include_router(findings_router,    prefix="/api/v1/secops-fix/findings",   tags=["Findings"])
app.include_router(health_router,      prefix="/api/v1/health",                tags=["Health"])

# ── Prometheus metrics ─────────────────────────────────────────────────────────
# Exposes GET /metrics in Prometheus text format.
# Metrics: http_requests_total, http_request_duration_seconds, http_requests_in_progress
from prometheus_fastapi_instrumentator import Instrumentator as _Instrumentator
_Instrumentator(
    should_group_status_codes=False,
    should_ignore_untemplated=True,
    excluded_handlers=["/metrics"],
).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)


# ── Root ──────────────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def root():
    return {
        "service":      "SecOps Fix Engine",
        "version":      "2.0.0",
        "rules_source": "secops_rule_metadata table (same DB as SAST scanner)",
        "ai_fix":       bool(os.getenv("MISTRAL_API_KEY", "").strip()),
        "auth":         "X-API-Key header required on all /api/* endpoints",
        "git_token":    "Pass per-request via X-Repo-Token header (never in body)",
        "status":       "operational",
        "endpoints": {
            "remediate": "/api/v1/secops-fix/remediate",
            "findings":  "/api/v1/secops-fix/findings/{secops_scan_id}",
            "health":    "/api/v1/health",
            "docs":      "/docs",
        },
    }


@app.get("/health", include_in_schema=False)
async def legacy_health():
    """Legacy health endpoint — no auth required."""
    return {
        "status":           "healthy",
        "timestamp":        datetime.now(timezone.utc).isoformat(),
        "rules_source":     "secops_rule_metadata (DB)",
        "ai_fix_enabled":   bool(os.getenv("MISTRAL_API_KEY", "").strip()),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("SECOPS_FIX_PORT", "8006"))
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=port,
        workers=1,
        log_level="info",
    )
