"""
Platform Admin Engine — Port 8041

Operator dashboard: engine health grid, Argo pipeline status, per-org
subscription management (tier override, trial extension, suspend/unsuspend),
and platform-wide metrics.

All endpoints under /api/v1/padmin require the platform:admin permission.
Auth is enforced by engine_auth.fastapi.middleware.AuthMiddleware.
"""

from __future__ import annotations

import logging
import os
import sys

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Allow importing shared libraries from both Docker (COPY shared/auth/ engine_auth/)
# and local dev (shared/auth/ relative to repo root).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

# Auth middleware — optional import so the engine can start locally without
# engine_auth installed (individual router unit tests).
try:
    from engine_auth.fastapi.middleware import AuthMiddleware  # type: ignore
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    logger.warning("engine_auth not found — running WITHOUT auth enforcement")

from routers import audit, billing, engines, health, metrics, orgs, pipelines  # noqa: E402

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="engine-platform-admin",
    description=(
        "Platform Admin Engine — engine health grid, Argo pipeline history, "
        "org subscription management, platform metrics. "
        "All /padmin endpoints require platform:admin permission."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

if _AUTH_AVAILABLE:
    app.add_middleware(AuthMiddleware)

# ---------------------------------------------------------------------------
# Router registration
# ---------------------------------------------------------------------------

# Health checks — no prefix, no auth gate (probes call these directly)
app.include_router(health.router)

# Platform admin sub-routers — all under /api/v1/padmin
app.include_router(engines.router,   prefix="/api/v1/padmin")
app.include_router(pipelines.router, prefix="/api/v1/padmin")
app.include_router(orgs.router,      prefix="/api/v1/padmin")
app.include_router(metrics.router,   prefix="/api/v1/padmin")
app.include_router(audit.router,     prefix="/api/v1/padmin")
app.include_router(billing.router,   prefix="/api/v1/padmin")

# ---------------------------------------------------------------------------
# Background scheduler — daily billing snapshot at 01:00 UTC
# ---------------------------------------------------------------------------

try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from background.billing_snapshot import run_billing_snapshot

    _scheduler = BackgroundScheduler(timezone="UTC")
    _scheduler.add_job(run_billing_snapshot, "cron", hour=1, minute=0, id="billing_snapshot")
    _scheduler.start()
    logger.info("billing_snapshot scheduler started (daily 01:00 UTC)")
except Exception as _sched_err:
    logger.warning("billing_snapshot scheduler failed to start: %s", _sched_err)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8041, log_level="info")
