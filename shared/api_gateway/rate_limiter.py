"""
Rate limiting for threat-engine API endpoints.

Uses slowapi (built on limits library) for per-endpoint rate limiting
and a custom ExternalApiBudget class for managing external API call budgets.

Usage::

    from shared.api_gateway.rate_limiter import setup_rate_limiter, get_limiter

    app = FastAPI()
    limiter = setup_rate_limiter(app)

    @app.post("/api/v1/scan")
    @limiter.limit("5/hour")
    async def scan(request: Request):
        ...
"""
from __future__ import annotations

import logging
import os
import time
from typing import TYPE_CHECKING, Dict, Optional

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from fastapi import FastAPI

# ── Rate limiter singleton ────────────────────────────────────────────────────

_limiter = None


def setup_rate_limiter(app: "FastAPI", default_limit: str = "200/day;50/hour") -> "any":
    """Initialize and attach slowapi rate limiter to FastAPI app.

    Args:
        app: FastAPI application instance.
        default_limit: Default rate limit string (e.g. "200/day;50/hour").

    Returns:
        Limiter instance for use as a decorator.
    """
    global _limiter

    try:
        from slowapi import Limiter, _rate_limit_exceeded_handler  # type: ignore[import]
        from slowapi.util import get_remote_address  # type: ignore[import]
        from slowapi.errors import RateLimitExceeded  # type: ignore[import]

        _limiter = Limiter(
            key_func=get_remote_address,
            default_limits=[default_limit],
            storage_uri=os.getenv("RATE_LIMIT_STORAGE_URI", "memory://"),
            strategy="fixed-window",
        )

        app.state.limiter = _limiter
        app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

        logger.info("Rate limiter initialized default_limit=%s", default_limit)
        return _limiter

    except ImportError:
        logger.warning(
            "slowapi not installed — rate limiting disabled. "
            "Add slowapi to requirements.txt."
        )
        return _NoopLimiter()


def get_limiter():
    """Return the active limiter instance (or noop)."""
    return _limiter or _NoopLimiter()


# ── Endpoint-specific limit recommendations ──────────────────────────────────

ENDPOINT_LIMITS = {
    "/api/v1/scan": "5/hour",
    "/api/v1/health/live": "100/minute",
    "/api/v1/health/ready": "100/minute",
    "/api/v1/metrics": "100/minute",
}


# ── External API call budget ─────────────────────────────────────────────────


class ExternalApiBudget:
    """Track and enforce external API call budgets.

    Prevents exceeding rate limits on third-party APIs like GitHub, NVD,
    Docker Hub, npm, and PyPI.

    Usage::

        budget = ExternalApiBudget()
        if budget.can_call("github"):
            # make API call
            budget.record_call("github", status=200, latency_ms=150)
    """

    # Default budgets: (per_hour, per_day)
    DEFAULT_BUDGETS: Dict[str, tuple] = {
        "github":     (60, 1000),
        "docker_hub": (100, 2000),
        "nvd":        (50, 500),
        "npm":        (100, 5000),
        "pypi":       (100, 5000),
    }

    def __init__(self, budgets: Optional[Dict[str, tuple]] = None):
        self._budgets = budgets or self.DEFAULT_BUDGETS
        # Sliding window: list of timestamps per source
        self._calls: Dict[str, list] = {src: [] for src in self._budgets}

    def can_call(self, source: str) -> bool:
        """Check if we're within budget for the given source.

        Args:
            source: API source name (e.g. "github").

        Returns:
            True if the call is within budget.
        """
        if source not in self._budgets:
            return True

        per_hour, per_day = self._budgets[source]
        now = time.time()
        calls = self._calls.get(source, [])

        # Prune calls older than 24h
        calls = [t for t in calls if now - t < 86400]
        self._calls[source] = calls

        # Check hourly budget
        hourly_calls = sum(1 for t in calls if now - t < 3600)
        if hourly_calls >= per_hour:
            logger.warning("API budget exhausted (hourly) source=%s count=%d limit=%d",
                         source, hourly_calls, per_hour)
            return False

        # Check daily budget
        if len(calls) >= per_day:
            logger.warning("API budget exhausted (daily) source=%s count=%d limit=%d",
                         source, len(calls), per_day)
            return False

        return True

    def record_call(
        self,
        source: str,
        status: int = 200,
        latency_ms: int = 0,
    ) -> None:
        """Record an API call for budget tracking.

        Args:
            source: API source name.
            status: HTTP response status code.
            latency_ms: Response latency in milliseconds.
        """
        if source not in self._calls:
            self._calls[source] = []
        self._calls[source].append(time.time())

    def get_remaining(self, source: str) -> Dict[str, int]:
        """Get remaining budget for a source.

        Returns:
            Dict with 'hourly_remaining' and 'daily_remaining' counts.
        """
        if source not in self._budgets:
            return {"hourly_remaining": -1, "daily_remaining": -1}

        per_hour, per_day = self._budgets[source]
        now = time.time()
        calls = self._calls.get(source, [])
        calls = [t for t in calls if now - t < 86400]

        hourly_calls = sum(1 for t in calls if now - t < 3600)
        return {
            "hourly_remaining": max(0, per_hour - hourly_calls),
            "daily_remaining": max(0, per_day - len(calls)),
        }

    def get_all_budgets(self) -> Dict[str, Dict]:
        """Get remaining budgets for all sources."""
        return {src: self.get_remaining(src) for src in self._budgets}


# ── Noop fallback ─────────────────────────────────────────────────────────────


class _NoopLimiter:
    """Noop limiter when slowapi is not installed."""
    def limit(self, limit_value: str, **kw):
        def decorator(func):
            return func
        return decorator

    def shared_limit(self, limit_value: str, **kw):
        return self.limit(limit_value, **kw)
