"""
SubscriptionMiddleware — runs after AuthMiddleware in the ASGI stack.

Reads the org subscription from engine-billing (60-second TTL cache, max
10,000 entries).  Injects an X-Subscription-Context header (base64-encoded
JSON) on every authenticated request so downstream engines can access plan
metadata without hitting the billing engine themselves.

Enforcement rules (fail-CLOSED):
  - status=suspended  →  HTTP 402 immediately
  - engine not in allowlist for org tier  →  HTTP 402
  - account creation attempted at limit  →  HTTP 402
  - scan-frequency token exhausted  →  HTTP 429

Grace period:
  - status=past_due AND grace_period_end_at > now()  →  treated as 'active'
    (access not blocked during the 7-day grace window).
  - status=past_due AND grace_period_end_at <= now() →  enforced as 'free' tier
    (access downgraded without changing the DB value).

Fail-OPEN conditions (billing engine unavailable, unknown tier, etc.) let
the request through with tier="unknown" and no enforcement applied.

X-Subscription-Context shape (base64 JSON):
  {
    "org_id": str | null,
    "tier": "free" | "starter" | "pro" | "enterprise" | "unknown",
    "status": "active" | "trialing" | "past_due" | "suspended" | "cancelled" | "unknown",
    "max_accounts": int,          # -1 = unlimited
    "accounts_connected": int,
    "engine_allowlist": list[str] | null,   # null = unrestricted
    "scan_freq_per_day": int,     # -1 = unlimited
    "trial_end_at": str | null,
    "is_overridden": bool,
    "grandfathered": bool,
    "grandfathered_until": str | null
  }
"""

from __future__ import annotations

import base64
import json
import logging
import os
from typing import Optional

import httpx
from cachetools import TTLCache
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# LRU+TTL cache — 10,000 entries, 60-second TTL
# ---------------------------------------------------------------------------

_sub_cache: TTLCache = TTLCache(maxsize=10_000, ttl=60)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BILLING_ENGINE_URL: str = os.getenv(
    "BILLING_ENGINE_URL", "http://engine-billing:8040"
)

# Paths that skip subscription enforcement entirely (in addition to the auth
# skip list already handled by AuthMiddleware).
_SUBSCRIPTION_SKIP_PREFIXES: tuple[str, ...] = (
    "/gateway/",
    "/api/v1/health",
    "/api/auth/",
    "/api/v1/billing/webhooks/",
    "/argo/",
)

# Minimum tier required per engine name.
# Engines NOT listed here are available on Free (the base tier).
_ENGINE_REQUIRED_TIER: dict[str, str] = {
    "datasec": "pro",
    "secops": "pro",
    "vulnerability": "pro",
    "ai-security": "enterprise",
    "encryption": "enterprise",
    "dbsec": "enterprise",
    "container-security": "enterprise",
    "fix": "enterprise",
}

# Map URL path prefixes (as they appear in SERVICE_ROUTES) to logical engine
# names used in engine_allowlist checks.
_PATH_TO_ENGINE: dict[str, str] = {
    "/api/v1/data-security": "datasec",
    "/api/v1/secops": "secops",
    "/api/v1/vulnerabilities": "vulnerability",
    "/api/v1/agents": "vulnerability",
    "/api/v1/reports": "vulnerability",
    "/api/v1/ai-security": "ai-security",
    "/api/v1/encryption": "encryption",
    "/api/v1/database-security": "dbsec",
    "/api/v1/container-security": "container-security",
    "/api/v1/fix": "fix",
}

# Default engine allowlist per tier (used when billing engine returns
# no allowlist or allowlist is null).
_TIER_ALLOWLIST: dict[str, list[str]] = {
    "free": [
        "discoveries",
        "check",
        "threat",
        "inventory",
        "compliance",
        "iam",
        "risk",
        "network-security",
        "rule",
    ],
    "starter": [
        "discoveries",
        "check",
        "threat",
        "inventory",
        "compliance",
        "iam",
        "risk",
        "network-security",
        "rule",
    ],
    "pro": [
        "discoveries",
        "check",
        "threat",
        "inventory",
        "compliance",
        "iam",
        "risk",
        "network-security",
        "rule",
        "datasec",
        "secops",
        "vulnerability",
    ],
    "enterprise": [
        "discoveries",
        "check",
        "threat",
        "inventory",
        "compliance",
        "iam",
        "risk",
        "network-security",
        "rule",
        "datasec",
        "secops",
        "vulnerability",
        "ai-security",
        "encryption",
        "dbsec",
        "container-security",
        "fix",
    ],
}

# Fail-open stub returned when billing engine is unreachable.
_FAIL_OPEN_CONTEXT: dict = {
    "org_id": None,
    "tier": "unknown",
    "status": "unknown",
    "max_accounts": -1,
    "accounts_connected": 0,
    "engine_allowlist": None,
    "scan_freq_per_day": -1,
    "trial_end_at": None,
    "is_overridden": False,
    "grandfathered": False,
    "grandfathered_until": None,
    "payment_failed_at": None,
    "grace_period_end_at": None,
}

# Enterprise stub returned for platform_admin / users with no org_id.
_ENTERPRISE_STUB: dict = {
    "org_id": None,
    "tier": "enterprise",
    "status": "active",
    "max_accounts": -1,
    "accounts_connected": 0,
    "engine_allowlist": None,
    "scan_freq_per_day": -1,
    "trial_end_at": None,
    "is_overridden": False,
    "grandfathered": False,
    "grandfathered_until": None,
    "payment_failed_at": None,
    "grace_period_end_at": None,
}


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------


class SubscriptionMiddleware(BaseHTTPMiddleware):
    """Inject X-Subscription-Context and enforce subscription limits.

    Designed to run AFTER AuthMiddleware — relies on X-Auth-Context already
    being present in the request scope headers when AuthMiddleware authenticates
    via cookie, or passed directly for service-to-service calls.
    """

    async def dispatch(self, request: Request, call_next):
        """Process the request through subscription enforcement.

        Args:
            request: Incoming Starlette request.
            call_next: Next ASGI handler in the chain.

        Returns:
            JSONResponse (402/429) if enforcement blocks the request,
            otherwise the downstream response with X-Subscription-Context
            injected.
        """
        # --- Skip enforcement for health / webhook / gateway paths -----------
        path = request.url.path
        if any(path.startswith(prefix) for prefix in _SUBSCRIPTION_SKIP_PREFIXES):
            return await call_next(request)

        # --- Strip any inbound X-Subscription-Context (prevent spoofing) -----
        scope = request.scope
        scope["headers"] = [
            h for h in scope.get("headers", [])
            if h[0].lower() != b"x-subscription-context"
        ]

        # --- Require AuthContext (unauthenticated pass-through) ---------------
        auth_ctx_raw = request.headers.get("x-auth-context")
        if not auth_ctx_raw:
            # No auth context — AuthMiddleware handles 401; pass through here.
            return await call_next(request)

        try:
            auth_ctx = json.loads(auth_ctx_raw)
        except (json.JSONDecodeError, ValueError):
            logger.warning("SubscriptionMiddleware: malformed X-Auth-Context — passing through")
            return await call_next(request)

        # --- Derive org_id from AuthContext ----------------------------------
        # AuthContext carries org_ids (list). Use first element as the billing
        # lookup key.  platform_admin has org_ids=None → unrestricted.
        org_ids: Optional[list] = auth_ctx.get("org_ids")
        org_id: Optional[str] = org_ids[0] if org_ids else None

        # --- Resolve subscription context ------------------------------------
        if org_id is None:
            # Platform-admin or system call — treat as enterprise, unrestricted.
            sub_ctx = dict(_ENTERPRISE_STUB)
        else:
            sub_ctx = await self._get_subscription(org_id)

        # --- Grace period enforcement ----------------------------------------
        # If status=past_due but the org is still within the 7-day grace window,
        # treat as 'active' for this request (no DB change — in-memory override).
        # If grace period has expired, downgrade effective tier to 'free' so
        # paid-tier engine access is blocked without waiting for a DB update.
        sub_ctx = _apply_grace_period_logic(sub_ctx, org_id)

        # --- Fail-CLOSED: suspended org blocks immediately -------------------
        if sub_ctx.get("status") == "suspended":
            return JSONResponse(
                status_code=402,
                content={
                    "error": "org_suspended",
                    "message": (
                        "Your organization access has been suspended. Contact support."
                    ),
                },
            )

        # --- Inject X-Subscription-Context header into the ASGI scope -------
        sub_header_bytes = base64.b64encode(json.dumps(sub_ctx).encode()).decode()
        scope["headers"].append(
            (b"x-subscription-context", sub_header_bytes.encode())
        )

        # --- Engine tier enforcement -----------------------------------------
        engine_name = _resolve_engine(path)
        if engine_name is not None:
            response = self._check_engine_access(sub_ctx, engine_name)
            if response is not None:
                return response

        # --- Account creation limit enforcement ------------------------------
        if request.method == "POST" and _is_account_creation(path):
            response = _check_account_limit(sub_ctx)
            if response is not None:
                return response

        # --- Scan-frequency enforcement (before forwarding) ------------------
        scan_trigger = request.method == "POST" and _is_scan_trigger(path)
        if scan_trigger:
            response = await self._check_scan_frequency(sub_ctx, org_id)
            if response is not None:
                return response

        # --- Forward to downstream service -----------------------------------
        downstream_response = await call_next(request)

        # --- Consume scan token after successful scan trigger ----------------
        if scan_trigger and downstream_response.status_code < 300 and org_id:
            await self._consume_scan_token(org_id)

        return downstream_response

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    async def _get_subscription(self, org_id: str) -> dict:
        """Return subscription context for org_id, using in-process cache.

        Args:
            org_id: Organisation identifier to look up.

        Returns:
            Subscription context dict.  Returns fail-open stub on any error.
        """
        cached = _sub_cache.get(org_id)
        if cached is not None:
            return cached

        ctx = await _fetch_subscription_from_billing(org_id)
        _sub_cache[org_id] = ctx
        return ctx

    def _check_engine_access(
        self, sub_ctx: dict, engine_name: str
    ) -> Optional[JSONResponse]:
        """Return HTTP 402 response if engine is not in the org's allowlist.

        Args:
            sub_ctx: Subscription context dict.
            engine_name: Logical engine name (e.g. "datasec").

        Returns:
            JSONResponse or None (None = access granted / fail-open).
        """
        tier = sub_ctx.get("tier", "unknown")
        if tier == "unknown":
            return None  # Fail-open: billing unavailable

        allowlist: Optional[list] = sub_ctx.get("engine_allowlist")
        if allowlist is None:
            # Billing engine returned null → fall back to tier defaults.
            allowlist = _TIER_ALLOWLIST.get(tier, _TIER_ALLOWLIST["free"])

        if engine_name in allowlist:
            return None  # Access granted

        required_tier = _ENGINE_REQUIRED_TIER.get(engine_name, "pro")
        return JSONResponse(
            status_code=402,
            content={
                "error": "engine_not_in_plan",
                "engine": engine_name,
                "current_tier": tier,
                "required_tier": required_tier,
                "limit_type": "engine_tier",
                "upgrade_url": (
                    f"/billing/upgrade?from=engine&engine={engine_name}"
                ),
            },
        )

    async def _check_scan_frequency(
        self, sub_ctx: dict, org_id: Optional[str]
    ) -> Optional[JSONResponse]:
        """Return HTTP 429 response if org has exhausted its scan token.

        Args:
            sub_ctx: Subscription context dict.
            org_id: Organisation identifier.

        Returns:
            JSONResponse or None.
        """
        tier = sub_ctx.get("tier", "unknown")
        scan_freq = sub_ctx.get("scan_freq_per_day", -1)

        if tier == "unknown" or scan_freq == -1 or org_id is None:
            return None  # Unlimited or fail-open

        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.get(
                    f"{BILLING_ENGINE_URL}/api/v1/billing/usage/check-scan-frequency",
                    params={"org_id": org_id},
                    headers={"X-Internal-Call": "gateway"},
                )
                data = resp.json()
                if not data.get("allowed", True):
                    # Determine window label: if limit is 1 it's weekly (free tier)
                    window = "week" if scan_freq <= 1 else "day"
                    return JSONResponse(
                        status_code=429,
                        content={
                            "error": "scan_frequency_exceeded",
                            "current_tier": tier,
                            "limit": scan_freq,
                            "window": window,
                            "reset_at": data.get("reset_at"),
                            "upgrade_url": "/billing/upgrade?from=scan_frequency",
                        },
                    )
        except httpx.TimeoutException:
            logger.warning(
                "Scan frequency check timed out for org %s — failing open", org_id
            )
        except Exception as exc:
            logger.warning(
                "Scan frequency check failed for org %s: %s — failing open",
                org_id,
                exc,
            )

        return None

    async def _consume_scan_token(self, org_id: str) -> None:
        """Fire-and-forget POST to billing engine to decrement scan token.

        Args:
            org_id: Organisation whose token is consumed.
        """
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.post(
                    f"{BILLING_ENGINE_URL}/api/v1/billing/usage/consume-scan-token",
                    json={"org_id": org_id},
                    headers={"X-Internal-Call": "gateway"},
                )
        except Exception as exc:
            logger.warning(
                "Failed to consume scan token for org %s: %s", org_id, exc
            )


# ---------------------------------------------------------------------------
# Module-level helpers (no self)
# ---------------------------------------------------------------------------


async def _fetch_subscription_from_billing(org_id: str) -> dict:
    """Fetch subscription context from the billing engine /context/{org_id} endpoint.

    Returns the fail-open stub on any network or parsing error so the
    caller never raises.

    Args:
        org_id: Organisation identifier to fetch.

    Returns:
        Subscription context dict with all enforcement fields populated.
    """
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"{BILLING_ENGINE_URL}/api/v1/billing/context/{org_id}",
                headers={"X-Internal-Call": "gateway"},
            )
            resp.raise_for_status()
            data = resp.json()

        # /context/{org_id} returns a flat dict — map directly.
        # Preserve scan_freq_per_day from the plan if present; the context
        # endpoint includes it via the plan join.  Fall back to -1 (unlimited)
        # to stay fail-open if the field is absent.
        return {
            "org_id": org_id,
            "tier": data.get("tier", "unknown"),
            "status": data.get("status", "unknown"),
            "max_accounts": data.get("account_limit", -1),
            "accounts_connected": data.get("accounts_connected", 0),
            "engine_allowlist": data.get("engine_allowlist"),
            "scan_freq_per_day": data.get("scan_freq_per_day", -1),
            "trial_end_at": data.get("trial_end_at"),
            "is_overridden": data.get("grandfathered", False),
            "grandfathered": data.get("grandfathered", False),
            "grandfathered_until": data.get("grandfathered_until"),
            "payment_failed_at": data.get("payment_failed_at"),
            "grace_period_end_at": data.get("grace_period_end_at"),
        }
    except httpx.TimeoutException:
        logger.warning(
            "Billing engine timed out for org %s — failing open", org_id
        )
    except Exception as exc:
        logger.warning(
            "Billing engine unreachable for org %s: %s — failing open",
            org_id,
            exc,
        )

    stub = dict(_FAIL_OPEN_CONTEXT)
    stub["org_id"] = org_id
    return stub


def _apply_grace_period_logic(sub_ctx: dict, org_id: Optional[str]) -> dict:
    """Evaluate grace period state and return an adjusted subscription context.

    Rules (in-memory only — no DB writes):
    - status=past_due AND grace_period_end_at > now()   → treat as 'active'
      (access continues during the 7-day grace window).
    - status=past_due AND grace_period_end_at <= now()  → override tier='free'
      (enforce as free tier; org access to paid engines is blocked).
    - All other statuses: return sub_ctx unchanged.

    Args:
        sub_ctx: Subscription context dict as returned by the billing engine.
        org_id: Organisation identifier (used for log messages only).

    Returns:
        Possibly-modified copy of sub_ctx. The original dict is never mutated.
    """
    from datetime import datetime, timezone

    status = sub_ctx.get("status", "unknown")
    if status != "past_due":
        return sub_ctx

    grace_end_raw = sub_ctx.get("grace_period_end_at")
    now = datetime.now(timezone.utc)

    if grace_end_raw:
        try:
            grace_end = datetime.fromisoformat(
                str(grace_end_raw).replace("Z", "+00:00")
            )
            if grace_end.tzinfo is None:
                grace_end = grace_end.replace(tzinfo=timezone.utc)

            if grace_end > now:
                # Within grace period — treat as active, no downgrade.
                ctx = dict(sub_ctx)
                ctx["status"] = "active"
                logger.info(
                    "org %s is past_due but within grace period — treating as active "
                    "(grace expires %s)",
                    org_id,
                    grace_end.isoformat(),
                )
                return ctx
        except (ValueError, TypeError) as exc:
            # Fail-open: if we cannot parse the date, do not downgrade.
            logger.warning(
                "org %s: could not parse grace_period_end_at=%r (%s) — failing open",
                org_id,
                grace_end_raw,
                exc,
            )
            return sub_ctx

    # Grace period has expired (or was never set) — enforce as free tier.
    ctx = dict(sub_ctx)
    ctx["tier"] = "free"
    ctx["engine_allowlist"] = _TIER_ALLOWLIST["free"]
    logger.warning(
        "org %s past grace period — enforcing as free tier", org_id
    )
    return ctx


def _resolve_engine(path: str) -> Optional[str]:
    """Map a URL path to a logical engine name for tier-access checking.

    Args:
        path: Request URL path.

    Returns:
        Engine name string, or None if the path is not tier-restricted.
    """
    for prefix, engine in _PATH_TO_ENGINE.items():
        if path.startswith(prefix):
            return engine
    return None


def _is_account_creation(path: str) -> bool:
    """Return True if the path represents a cloud-account creation endpoint.

    Args:
        path: Request URL path.

    Returns:
        True if this is a cloud-accounts POST endpoint.
    """
    # Match /api/v1/cloud-accounts (and with trailing slash)
    stripped = path.rstrip("/")
    return stripped == "/api/v1/cloud-accounts" or stripped.endswith(
        "/cloud-accounts"
    )


def _check_account_limit(sub_ctx: dict) -> Optional[JSONResponse]:
    """Return HTTP 402 if accounts_connected >= max_accounts.

    Args:
        sub_ctx: Subscription context dict.

    Returns:
        JSONResponse or None.
    """
    tier = sub_ctx.get("tier", "unknown")
    if tier == "unknown":
        return None  # Fail-open

    limit: int = sub_ctx.get("max_accounts", -1)
    if limit == -1:
        return None  # Unlimited

    connected: int = sub_ctx.get("accounts_connected", 0)
    if connected < limit:
        return None  # Under limit

    # Determine upgrade target: free → starter, starter/pro → pro/enterprise
    if tier == "free":
        required_tier = "starter"
    elif tier in ("starter",):
        required_tier = "pro"
    else:
        required_tier = "enterprise"

    return JSONResponse(
        status_code=402,
        content={
            "error": "account_limit_exceeded",
            "current": connected,
            "limit": limit,
            "current_tier": tier,
            "required_tier": required_tier,
            "limit_type": "max_accounts",
            "upgrade_url": "/billing/upgrade?from=account_limit",
        },
    )


def _is_scan_trigger(path: str) -> bool:
    """Return True for the scan-run creation endpoint.

    Args:
        path: Request URL path.

    Returns:
        True if the path matches a scan trigger endpoint.
    """
    return "/scan-runs" in path
