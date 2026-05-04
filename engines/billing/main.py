"""
Billing Engine — Port 8040

Manages subscription plans, org subscriptions, usage metering, and trial
lifecycle. Stripe integration is added in BILL-03.

Auth: all endpoints except /api/v1/health/* and /api/v1/billing/trial/provision
require a valid X-Auth-Context header forwarded by the API Gateway.

Background task: APScheduler runs run_trial_expiry_check every 60 minutes to
downgrade expired trials (no Stripe payment method) to the Free plan.

Rate limiting (BILL-08):
  - 60 requests/minute per org_id on all /api/v1/billing/* endpoints.
  - 100 requests/minute per source IP on POST /api/v1/billing/webhooks/stripe.
  - Returns HTTP 429 with {"error": "rate_limit_exceeded", "retry_after_seconds": 60}.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import sys
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from threading import Lock
from typing import AsyncIterator, Dict, Tuple

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Make shared libraries importable in both Docker (COPY shared/auth/ engine_auth/)
# and local dev (shared/auth/ relative to repo root).
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger(__name__)

# Auth middleware — optional import so the engine starts without engine_auth
# installed locally (helpful for unit-testing individual routers).
try:
    from engine_auth.fastapi.middleware import AuthMiddleware
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    logger.warning("engine_auth not found — running WITHOUT auth enforcement")

from background.trial_expiry import run_trial_expiry_check
from routers import checkout, health, invoices, plans, subscriptions, trial, usage, webhooks

# ---------------------------------------------------------------------------
# In-process sliding-window rate limiter (token bucket per key)
# ---------------------------------------------------------------------------
# Uses a simple fixed-window counter (1-minute buckets) per key.
# Thread-safe via a Lock; suitable for single-process uvicorn workers.
# For multi-worker deployments, swap the dict for a Redis backend.
# ---------------------------------------------------------------------------

_RL_WINDOW_SECONDS: int = 60
# (count, window_start_timestamp)
_rl_store: Dict[str, Tuple[int, float]] = defaultdict(lambda: (0, 0.0))
_rl_lock: Lock = Lock()


def _check_rate_limit(key: str, limit: int) -> bool:
    """Return True if the request is allowed; False if the limit is exceeded.

    Uses a fixed 60-second window reset strategy.  Thread-safe.

    Args:
        key: Rate-limit bucket identifier (org_id or source IP).
        limit: Maximum allowed requests per 60-second window.

    Returns:
        True if the request is within the limit, False otherwise.
    """
    now = time.monotonic()
    with _rl_lock:
        count, window_start = _rl_store[key]
        if now - window_start >= _RL_WINDOW_SECONDS:
            # Window expired — reset counter.
            _rl_store[key] = (1, now)
            return True
        if count >= limit:
            return False
        _rl_store[key] = (count + 1, window_start)
        return True


def _extract_org_id(request: Request) -> str:
    """Extract org_id from X-Auth-Context header.

    Falls back to the client source IP if the header is absent or unparseable.

    Args:
        request: Incoming FastAPI/Starlette request.

    Returns:
        org_id string, or client IP as the rate-limit key.
    """
    auth_ctx_raw = request.headers.get("X-Auth-Context", "")
    if auth_ctx_raw:
        try:
            ctx = json.loads(base64.b64decode(auth_ctx_raw).decode())
            org_ids = ctx.get("org_ids") or []
            if org_ids:
                return f"org:{org_ids[0]}"
        except Exception:
            pass
    client = request.client
    return f"ip:{client.host if client else 'unknown'}"


def _get_source_ip(request: Request) -> str:
    """Return the client source IP as a rate-limit key.

    Checks X-Forwarded-For (first hop) before falling back to the ASGI
    scope client address.

    Args:
        request: Incoming FastAPI/Starlette request.

    Returns:
        Source IP string prefixed with 'ip:'.
    """
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return f"ip:{forwarded.split(',')[0].strip()}"
    client = request.client
    return f"ip:{client.host if client else 'unknown'}"


# ---------------------------------------------------------------------------
# APScheduler
# ---------------------------------------------------------------------------

scheduler = AsyncIOScheduler()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Configure background jobs and manage the APScheduler lifecycle.

    Args:
        app: The FastAPI application instance.

    Yields:
        Control to the request-handling loop.
    """
    scheduler.add_job(
        run_trial_expiry_check,
        "interval",
        minutes=60,
        id="trial_expiry",
        replace_existing=True,
    )
    scheduler.start()
    logger.info("Billing engine started on port 8040 — trial_expiry job scheduled (60 min)")
    yield
    scheduler.shutdown(wait=False)
    logger.info("Billing engine shutting down")


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="engine-billing",
    description=(
        "Billing Engine — subscription plans, usage metering, trial lifecycle. "
        "Stripe integration: BILL-03."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# AuthMiddleware validates access_token / X-Auth-Context for every non-health path.
# The Stripe webhook path (/api/v1/billing/webhooks/stripe) must be added to
# AUTH_SKIP_PATHS in BILL-03 so raw payloads are not rejected.
if _AUTH_AVAILABLE:
    app.add_middleware(AuthMiddleware)

# ---------------------------------------------------------------------------
# Router registration
# ---------------------------------------------------------------------------

# Health checks — no prefix, no auth
app.include_router(health.router)

# Billing sub-routers — all under /api/v1/billing
app.include_router(plans.router,         prefix="/api/v1/billing")
app.include_router(subscriptions.router, prefix="/api/v1/billing")
app.include_router(usage.router,         prefix="/api/v1/billing")
app.include_router(invoices.router,      prefix="/api/v1/billing")
app.include_router(trial.router,         prefix="/api/v1/billing")
app.include_router(checkout.router,      prefix="/api/v1/billing")
app.include_router(webhooks.router,      prefix="/api/v1/billing")


# ---------------------------------------------------------------------------
# Rate-limiting middleware (applied AFTER router registration so the paths
# are resolvable; Starlette middleware runs before routing regardless)
# ---------------------------------------------------------------------------

@app.middleware("http")
async def billing_rate_limit_middleware(request: Request, call_next):
    """Apply rate limits to all /api/v1/billing/* endpoints.

    Rules:
    - POST /api/v1/billing/webhooks/stripe: 100 req/min per source IP.
    - All other /api/v1/billing/* endpoints: 60 req/min per org_id
      (falls back to source IP for unauthenticated callers).

    Health check paths (/api/v1/health/*) are not rate-limited.

    Args:
        request: Incoming HTTP request.
        call_next: Next ASGI handler.

    Returns:
        JSONResponse with HTTP 429 if limit exceeded, otherwise the
        downstream response.
    """
    path = request.url.path

    # Skip non-billing paths
    if not path.startswith("/api/v1/billing/"):
        return await call_next(request)

    # Stripe webhook: 100 req/min per source IP
    if path.startswith("/api/v1/billing/webhooks/"):
        key = _get_source_ip(request)
        allowed = _check_rate_limit(key, limit=100)
    else:
        # All other billing endpoints: 60 req/min per org_id
        key = _extract_org_id(request)
        allowed = _check_rate_limit(key, limit=60)

    if not allowed:
        logger.warning(
            "Rate limit exceeded path=%s key=%s", path, key
        )
        return JSONResponse(
            status_code=429,
            content={
                "error": "rate_limit_exceeded",
                "retry_after_seconds": _RL_WINDOW_SECONDS,
            },
            headers={"Retry-After": str(_RL_WINDOW_SECONDS)},
        )

    return await call_next(request)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8040, log_level="info")
