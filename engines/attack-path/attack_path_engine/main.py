"""
Attack Path Engine — FastAPI application factory.

Pipeline stage: 6.5 — runs after graph-build, before risk.
Port: 8025 (K8s service port 80 → targetPort 8025).
DB: threat_engine_attack_path (new database).

Middleware order (critical — see CLAUDE.md feedback_gateway_middleware_order):
  @app.middleware("http")  →  route_requests  (outermost decorator)
  app.add_middleware(AuthMiddleware)           runs FIRST because add_middleware
  ...                                          layers are applied last-in-first-out.
"""

from __future__ import annotations

import logging
import os
import sys

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Shared utilities live at /app/engine_common in Docker; use fallback for local runs.
_common = os.path.join(os.path.dirname(__file__), "..", "..", "..", "shared", "common")
if os.path.isdir(_common):
    sys.path.insert(0, os.path.dirname(_common))

from .api.routes import router

logger = logging.getLogger("attack-path.main")

# ── Auth imports ──────────────────────────────────────────────────────────────
try:
    from engine_auth.fastapi.middleware import AuthMiddleware as _AuthMiddleware
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    logger.warning("engine_auth not available — AuthMiddleware skipped (dev mode only)")

app = FastAPI(
    title="Attack Path Engine",
    description=(
        "Reverse BFS from crown jewels to internet entry points. "
        "Computes P×I scores, deduplicates paths, detects choke points."
    ),
    version="1.0.0",
    docs_url="/api/v1/docs",
    openapi_url="/api/v1/openapi.json",
)

# CORS — all origins allowed at engine layer (gateway enforces policy externally)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# AuthMiddleware validates access_token / X-Auth-Context for every non-health path.
# Must be added AFTER the route decorator that forms the outermost middleware layer.
if _AUTH_AVAILABLE:
    app.add_middleware(_AuthMiddleware)

# Register all API routes
app.include_router(router)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all: return generic 500 — never leak stack traces or DB credentials."""
    logger.exception("Unhandled exception: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error"},
    )
