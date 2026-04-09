"""
VulFix Engine API v2 — Ansible-based CVE remediation via Git.

Endpoints:
  POST /api/v1/vul-fix/remediate           — generate Ansible playbooks + push Git branch
  GET  /api/v1/vul-fix/remediate/{scan_id} — get scan metadata (playbooks are in Git)
  GET  /api/v1/health/live                 — liveness probe  (no auth required)
  GET  /api/v1/health/ready                — readiness probe (no auth required)

Security:
  - All non-health endpoints require X-API-Key header.
  - Git token sourced from GIT_TOKEN env var only (never from request body).
  - Mistral key sourced from MISTRAL_API_KEY env var only.
  - VUL_FIX_API_KEY must be set before startup — engine refuses to start without it.

Concurrency:
  - VUL_FIX_MAX_CONCURRENT (default 3) limits simultaneous pipeline runs.

Flow:
  vulnerability_db → Mistral AI → Ansible YAML
  → yamllint/ansible-lint → Git branch vulfix/{scan_id} → GitHub/GitLab PR
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
configure_logging("vul_fix")

from middleware.auth import APIKeyMiddleware
from middleware.correlation import CorrelationIDMiddleware
from routers.remediation import router as remediation_router
from routers.health import router as health_router
from db.db_config import close_pool

logger = logging.getLogger("vul_fix")
_audit = logging.getLogger("audit.vul_fix")   # dedicated audit stream


# ── Startup guard — refuse to start with missing critical config ───────────────
def _check_required_env() -> None:
    """Exit non-zero immediately if critical env vars are absent.

    Running without VUL_FIX_API_KEY means every endpoint is unprotected
    (middleware still rejects, but the misconfiguration should be surfaced at
    boot, not silently swallowed).  Kubernetes will restart the pod and alert.
    """
    missing = []
    if not os.getenv("VUL_FIX_API_KEY", "").strip():
        missing.append("VUL_FIX_API_KEY")
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
    ai_ok  = bool(os.getenv("MISTRAL_API_KEY", "").strip())
    git_ok = bool(os.getenv("GIT_TOKEN", "").strip())
    key_ok = bool(os.getenv("VUL_FIX_API_KEY", "").strip())
    max_c  = int(os.getenv("VUL_FIX_MAX_CONCURRENT", "3"))

    logger.info(
        f"VulFix Engine v2 ready — "
        f"API_KEY={'set' if key_ok else 'MISSING'} | "
        f"Mistral={'enabled' if ai_ok else 'DISABLED'} | "
        f"GIT_TOKEN={'set' if git_ok else 'not set'} | "
        f"max_concurrent={max_c}"
    )
    if not git_ok:
        logger.warning(
            "GIT_TOKEN is not set. Remediation requests will fail at the git-push step. "
            "Configure it as a Kubernetes secret."
        )

    yield  # ── application runs ─────────────────────────────────────────────

    # ── shutdown ──────────────────────────────────────────────────────────────
    close_pool()
    logger.info("VulFix Engine shutdown complete — DB pool closed")


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="VulFix Engine API",
    description=(
        "Ansible-based CVE remediation engine. "
        "Reads vulnerability findings from vulnerability_db, calls Mistral AI to generate "
        "production-ready Ansible playbooks, validates with yamllint/ansible-lint, "
        "and pushes them to a new branch (vulfix/{scan_id}) in the org's Ansible Git repo. "
        "Optionally opens a PR/MR for human review. "
        "No playbook is executed automatically — human review and approval are mandatory."
    ),
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
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
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-API-Key", "X-Request-ID"],
)

# 2. API key auth (all non-health endpoints)
_api_key = os.getenv("VUL_FIX_API_KEY", "").strip()
app.add_middleware(APIKeyMiddleware, api_key=_api_key)

# 3. Correlation ID (outermost — sets request_id for all log lines in the request)
app.add_middleware(CorrelationIDMiddleware)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(
    remediation_router,
    prefix="/api/v1/vul-fix/remediate",
    tags=["Remediation"],
)
app.include_router(
    health_router,
    prefix="/api/v1/health",
    tags=["Health"],
)

# ── Prometheus metrics ─────────────────────────────────────────────────────────
# Exposes GET /metrics in Prometheus text format.
# Kubernetes ServiceMonitor / Grafana Agent scrapes this endpoint.
# Metrics exposed:
#   http_requests_total          — request count by method, path, status code
#   http_request_duration_seconds — request latency histogram (p50/p95/p99)
#   http_requests_in_progress    — currently active requests (concurrency gauge)
#
# No auth required — /metrics is scraped by internal monitoring, not external callers.
# If your cluster exposes it externally, add it to _EXEMPT_PREFIXES in auth middleware.
from prometheus_fastapi_instrumentator import Instrumentator as _Instrumentator
_Instrumentator(
    should_group_status_codes=False,   # keep 200/404/429/502/504 separate
    should_ignore_untemplated=True,    # ignore unknown paths (avoid cardinality explosion)
    excluded_handlers=["/metrics"],    # don't instrument the metrics endpoint itself
).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)


# ── Root ──────────────────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def root():
    return {
        "service":     "VulFix Engine",
        "version":     "2.0.0",
        "description": (
            "Ansible-based CVE remediation — "
            "generates playbooks, pushes Git branch, opens PR. "
            "NO auto-execution."
        ),
        "ai_enabled":      bool(os.getenv("MISTRAL_API_KEY", "").strip()),
        "git_token_set":   bool(os.getenv("GIT_TOKEN", "").strip()),
        "auth_required":   "X-API-Key header on all /api/* endpoints",
        "max_concurrent":  int(os.getenv("VUL_FIX_MAX_CONCURRENT", "3")),
        "endpoints": {
            "POST remediate":  "/api/v1/vul-fix/remediate",
            "GET  scan_info":  "/api/v1/vul-fix/remediate/{scan_id}",
            "GET  health":     "/api/v1/health/live",
            "GET  docs":       "/docs",
        },
    }


@app.get("/health", include_in_schema=False)
async def legacy_health():
    """Legacy health endpoint — no auth required."""
    return {
        "status":    "healthy",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version":   "2.0.0",
        "ai_enabled": bool(os.getenv("MISTRAL_API_KEY", "").strip()),
    }


# ── Entrypoint ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("VUL_FIX_PORT", "8007"))
    uvicorn.run(
        "api_server:app",
        host="0.0.0.0",
        port=port,
        workers=1,       # single worker — async concurrency managed by semaphore
        log_level="info",
    )
