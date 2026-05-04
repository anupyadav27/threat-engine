"""
Billing Engine — Organisation subscription endpoints.

GET  /api/v1/billing/subscription          — requires billing:read
GET  /api/v1/billing/context/{org_id}      — internal Gateway call (no user auth)
POST /api/v1/billing/cancel                — requires billing:write
POST /api/v1/billing/reactivate            — requires billing:write
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from db import get_conn, put_conn
from models import CancelRequest, ReactivateRequest

try:
    from engine_auth.fastapi.dependencies import require_permission
    from engine_auth.core.models import AuthContext
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)
router = APIRouter(tags=["subscriptions"])


def _row_to_sub_dict(row: tuple, cols: list) -> Dict[str, Any]:
    """Serialise a subscription + nested plan row to a JSON-safe dict.

    Args:
        row: psycopg2 result tuple.
        cols: Column names from cursor.description.

    Returns:
        Dict with iso-formatted timestamps and float Decimals.
    """
    d: Dict[str, Any] = {}
    for key, val in zip(cols, row):
        if hasattr(val, "isoformat"):
            d[key] = val.isoformat()
        elif hasattr(val, "__class__") and val.__class__.__name__ == "Decimal":
            d[key] = float(val)
        else:
            d[key] = val
    return d


@router.get("/subscription")
async def get_subscription(
    org_id: str = Query(..., description="Organisation UUID"),
    auth: Any = Depends(
        require_permission("billing:read") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Return the subscription for an organisation, including the nested plan object.

    org_id must match auth.org_id unless the caller holds platform:admin.
    trial_days_remaining is computed live (not stored) — max(0, (trial_end_at - now).days).

    Args:
        org_id: Organisation identifier.
        auth: AuthContext injected by require_permission.

    Returns:
        Subscription dict with nested 'plan' object, 'trial_days_remaining',
        'accounts_connected', and 'max_accounts'.

    Raises:
        HTTPException: 404 if subscription not found.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
                os.subscription_id,
                os.org_id,
                os.plan_id,
                os.stripe_customer_id,
                os.stripe_subscription_id,
                os.status,
                os.trial_start_at,
                os.trial_end_at,
                os.current_period_start,
                os.current_period_end,
                os.cancel_at_period_end,
                os.cancelled_at,
                os.accounts_connected,
                os.users_count,
                os.org_email_domain,
                os.created_at,
                os.updated_at,
                row_to_json(sp) AS plan
            FROM org_subscriptions os
            JOIN subscription_plans sp ON sp.plan_id = os.plan_id
            WHERE os.org_id = %s
            """,
            (org_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Subscription not found")

        cols = [d[0] for d in cur.description]
        sub = _row_to_sub_dict(row, cols)

        # Compute max_accounts from nested plan
        plan_data = sub.get("plan") or {}
        if isinstance(plan_data, str):
            try:
                plan_data = json.loads(plan_data)
            except (json.JSONDecodeError, TypeError):
                plan_data = {}
        sub["max_accounts"] = plan_data.get("max_accounts", 0)

        # Compute trial_days_remaining
        if sub.get("status") == "trialing" and sub.get("trial_end_at"):
            trial_end = row[cols.index("trial_end_at")]
            if trial_end is not None:
                if trial_end.tzinfo is None:
                    trial_end = trial_end.replace(tzinfo=timezone.utc)
                delta = trial_end - datetime.now(timezone.utc)
                sub["trial_days_remaining"] = max(0, delta.days)
            else:
                sub["trial_days_remaining"] = 0
        else:
            sub["trial_days_remaining"] = 0

        cur.close()
        return sub
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("get_subscription failed org_id=%s: %s", org_id, exc)
        raise HTTPException(status_code=500, detail="Failed to retrieve subscription")
    finally:
        put_conn(conn)


@router.post("/cancel")
async def cancel_subscription(
    body: CancelRequest,
    auth: Any = Depends(
        require_permission("billing:write") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Schedule a subscription for cancellation at the end of the current period.

    Sets cancel_at_period_end=true. Writes entries to billing_events and
    billing_audit_log for SOC 2 compliance.

    Args:
        body: CancelRequest with org_id and optional reason.
        auth: AuthContext injected by require_permission.

    Returns:
        Confirmation dict with org_id and updated cancel_at_period_end flag.

    Raises:
        HTTPException: 404 if subscription not found.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()

        # Fetch current state for audit
        cur.execute(
            "SELECT subscription_id, plan_id, status FROM org_subscriptions WHERE org_id = %s",
            (body.org_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Subscription not found")

        sub_id, plan_id, status = row

        cur.execute(
            """
            UPDATE org_subscriptions
            SET cancel_at_period_end = true, updated_at = now()
            WHERE org_id = %s
            """,
            (body.org_id,),
        )

        # Billing event
        cur.execute(
            """
            INSERT INTO billing_events
                (org_id, event_type, actor_type, actor_id, previous_state, new_state)
            VALUES (%s, 'subscription.cancel_scheduled', 'user', %s, %s, %s)
            """,
            (
                body.org_id,
                getattr(auth, "user_id", "unknown") if auth else "unknown",
                json.dumps({"cancel_at_period_end": False, "status": status}),
                json.dumps({"cancel_at_period_end": True, "status": status,
                            "reason": body.reason}),
            ),
        )

        # Audit log
        cur.execute(
            """
            INSERT INTO billing_audit_log
                (org_id, event_type, actor_id, previous_state, new_state, change_summary)
            VALUES (%s, 'subscription.cancel_scheduled', %s, %s, %s, %s)
            """,
            (
                body.org_id,
                getattr(auth, "user_id", "unknown") if auth else "unknown",
                json.dumps({"cancel_at_period_end": False}),
                json.dumps({"cancel_at_period_end": True}),
                f"Cancellation scheduled. Reason: {body.reason or 'not provided'}",
            ),
        )

        conn.commit()
        cur.close()
        return {"org_id": body.org_id, "cancel_at_period_end": True, "status": status}
    except HTTPException:
        raise
    except Exception as exc:
        conn.rollback()
        logger.error("cancel_subscription failed org_id=%s: %s", body.org_id, exc)
        raise HTTPException(status_code=500, detail="Failed to schedule cancellation")
    finally:
        put_conn(conn)


@router.post("/reactivate")
async def reactivate_subscription(
    body: ReactivateRequest,
    auth: Any = Depends(
        require_permission("billing:write") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Remove a pending cancellation — clears cancel_at_period_end.

    Args:
        body: ReactivateRequest with org_id.
        auth: AuthContext injected by require_permission.

    Returns:
        Confirmation dict with org_id and cancel_at_period_end=False.

    Raises:
        HTTPException: 404 if subscription not found.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()

        cur.execute(
            "SELECT subscription_id, status FROM org_subscriptions WHERE org_id = %s",
            (body.org_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Subscription not found")

        status = row[1]

        cur.execute(
            """
            UPDATE org_subscriptions
            SET cancel_at_period_end = false, updated_at = now()
            WHERE org_id = %s
            """,
            (body.org_id,),
        )

        cur.execute(
            """
            INSERT INTO billing_events
                (org_id, event_type, actor_type, actor_id, previous_state, new_state)
            VALUES (%s, 'subscription.reactivated', 'user', %s, %s, %s)
            """,
            (
                body.org_id,
                getattr(auth, "user_id", "unknown") if auth else "unknown",
                json.dumps({"cancel_at_period_end": True}),
                json.dumps({"cancel_at_period_end": False}),
            ),
        )

        conn.commit()
        cur.close()
        return {"org_id": body.org_id, "cancel_at_period_end": False, "status": status}
    except HTTPException:
        raise
    except Exception as exc:
        conn.rollback()
        logger.error("reactivate_subscription failed org_id=%s: %s", body.org_id, exc)
        raise HTTPException(status_code=500, detail="Failed to reactivate subscription")
    finally:
        put_conn(conn)


# ---------------------------------------------------------------------------
# Free-tier defaults returned when org has no subscription row.
# ---------------------------------------------------------------------------
_FREE_TIER_DEFAULTS: Dict[str, Any] = {
    "tier": "free",
    "status": "active",
    "account_limit": 1,
    "accounts_connected": 0,
    "engine_allowlist": [
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
    "scan_freq_per_day": -1,
    "trial_days_remaining": 0,
    "payment_failed_at": None,
    "grace_period_end_at": None,
    "grandfathered": False,
    "grandfathered_until": None,
}


@router.get("/context/{org_id}")
async def get_subscription_context(org_id: str) -> Dict[str, Any]:
    """Return a flat subscription context dict for the API Gateway.

    This endpoint is called by the Gateway's SubscriptionMiddleware on every
    authenticated request (cached with a 60-second TTL per org_id).  It is an
    internal call — no end-user auth header is required.

    If the org has no subscription row the response is HTTP 200 with Free-tier
    defaults (not HTTP 404) so the Gateway can apply fail-safe enforcement
    without special-casing a missing org.

    Response shape (all fields always present):
        {
            "org_id": str,
            "tier": "free" | "starter" | "pro" | "enterprise",
            "status": "active" | "trialing" | "past_due" | "suspended" | "cancelled",
            "account_limit": int,          # -1 = unlimited
            "accounts_connected": int,
            "engine_allowlist": list[str],
            "trial_days_remaining": int,
            "payment_failed_at": str | null,  # ISO-8601 timestamp
            "grandfathered": bool,
            "grandfathered_until": str | null  # ISO-8601 timestamp
        }

    Args:
        org_id: Organisation identifier (path parameter).

    Returns:
        Subscription context dict with all required fields.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT
                os.org_id,
                sp.plan_name,
                os.status,
                sp.max_accounts,
                os.accounts_connected,
                sp.engine_allowlist,
                sp.scan_freq_per_day,
                os.trial_end_at,
                os.payment_failed_at,
                os.grace_period_end_at,
                os.is_overridden,
                os.grandfathered_until
            FROM org_subscriptions os
            JOIN subscription_plans sp ON sp.plan_id = os.plan_id
            WHERE os.org_id = %s
            """,
            (org_id,),
        )
        row = cur.fetchone()
        cur.close()

        if not row:
            # No subscription row — return Free-tier defaults (never 404).
            result = dict(_FREE_TIER_DEFAULTS)
            result["org_id"] = org_id
            result["scan_freq_per_day"] = -1
            result["grace_period_end_at"] = None
            return result

        (
            _org_id,
            plan_name,
            status,
            max_accounts,
            accounts_connected,
            engine_allowlist_raw,
            scan_freq_per_day,
            trial_end_at,
            payment_failed_at,
            grace_period_end_at,
            is_overridden,
            grandfathered_until,
        ) = row

        # Parse JSONB engine_allowlist (psycopg2 deserialises JSONB automatically).
        if isinstance(engine_allowlist_raw, list):
            engine_allowlist = engine_allowlist_raw
        elif engine_allowlist_raw:
            try:
                engine_allowlist = json.loads(engine_allowlist_raw)
            except (json.JSONDecodeError, TypeError):
                engine_allowlist = _FREE_TIER_DEFAULTS["engine_allowlist"]
        else:
            engine_allowlist = _FREE_TIER_DEFAULTS["engine_allowlist"]

        # Compute trial_days_remaining.
        trial_days_remaining: int = 0
        if status == "trialing" and trial_end_at is not None:
            if trial_end_at.tzinfo is None:
                trial_end_at = trial_end_at.replace(tzinfo=timezone.utc)
            delta = trial_end_at - datetime.now(timezone.utc)
            trial_days_remaining = max(0, delta.days)

        # Serialise timestamps to ISO-8601 strings (or None).
        def _ts(dt: Any) -> Any:
            if dt is None:
                return None
            if hasattr(dt, "isoformat"):
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.isoformat()
            return str(dt)

        return {
            "org_id": org_id,
            "tier": plan_name or "free",
            "status": status or "active",
            "account_limit": max_accounts if max_accounts is not None else 1,
            "accounts_connected": accounts_connected or 0,
            "engine_allowlist": engine_allowlist,
            "scan_freq_per_day": scan_freq_per_day if scan_freq_per_day is not None else -1,
            "trial_days_remaining": trial_days_remaining,
            "payment_failed_at": _ts(payment_failed_at),
            "grace_period_end_at": _ts(grace_period_end_at),
            "grandfathered": bool(is_overridden),
            "grandfathered_until": _ts(grandfathered_until),
        }

    except Exception as exc:
        logger.error("get_subscription_context failed org_id=%s: %s", org_id, exc)
        # Fail-open: return Free-tier defaults rather than 500 so the Gateway
        # can continue enforcing basic limits even when the billing DB is slow.
        result = dict(_FREE_TIER_DEFAULTS)
        result["org_id"] = org_id
        result["scan_freq_per_day"] = -1
        result["grace_period_end_at"] = None
        return result
    finally:
        put_conn(conn)
