"""
Billing Engine — Stripe Checkout, cancel, and reactivate endpoints.

POST /api/v1/billing/checkout    — create Stripe Checkout Session (billing:write)
POST /api/v1/billing/cancel      — schedule subscription cancellation via Stripe (billing:write)
POST /api/v1/billing/reactivate  — undo pending cancellation via Stripe (billing:write)

org_id is always taken from the authenticated AuthContext, never from the request
body, to prevent horizontal privilege escalation.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

import stripe
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from db import get_conn, put_conn
from stripe_client import load_stripe_secrets

try:
    from engine_auth.fastapi.dependencies import require_permission
    from engine_auth.core.models import AuthContext

    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)
router = APIRouter(tags=["checkout"])


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CheckoutRequest(BaseModel):
    """Body for POST /checkout."""

    plan_id: str
    success_url: str
    cancel_url: str


class StripeCancelRequest(BaseModel):
    """Body for POST /cancel (Stripe-backed)."""

    reason: Optional[str] = None


class StripeReactivateRequest(BaseModel):
    """Body for POST /reactivate (Stripe-backed)."""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_or_create_stripe_customer(cur: Any, conn: Any, org_id: str) -> str:
    """Return the Stripe customer ID for an org, creating one in Stripe if absent.

    Args:
        cur: Active psycopg2 cursor.
        conn: psycopg2 connection (used to commit the customer ID write-back).
        org_id: Organisation identifier.

    Returns:
        Stripe customer ID string (cus_xxx).

    Raises:
        HTTPException: 404 if the org has no subscription row.
        stripe.error.StripeError: Propagated if the Stripe API call fails.
    """
    cur.execute(
        "SELECT stripe_customer_id FROM org_subscriptions WHERE org_id = %s",
        (org_id,),
    )
    row = cur.fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Subscription not found for org")

    stripe_customer_id: Optional[str] = row[0]

    if not stripe_customer_id:
        customer = stripe.Customer.create(metadata={"org_id": org_id})
        stripe_customer_id = customer.id
        cur.execute(
            "UPDATE org_subscriptions SET stripe_customer_id = %s WHERE org_id = %s",
            (stripe_customer_id, org_id),
        )
        conn.commit()
        logger.info("Created Stripe customer org_id=%s customer_id=%s", org_id, stripe_customer_id)

    return stripe_customer_id


def _write_billing_event(
    cur: Any,
    org_id: str,
    event_type: str,
    actor_type: str,
    actor_id: str,
    previous_state: Dict[str, Any],
    new_state: Dict[str, Any],
    stripe_event_id: Optional[str] = None,
) -> None:
    """Insert a row into billing_events.

    Args:
        cur: Active psycopg2 cursor.
        org_id: Organisation identifier.
        event_type: Event type slug (e.g. 'subscription.cancel_scheduled').
        actor_type: 'user' or 'stripe_webhook'.
        actor_id: User ID or Stripe event ID string.
        previous_state: Dict describing the state before the change.
        new_state: Dict describing the state after the change.
        stripe_event_id: Optional Stripe event ID for correlation.
    """
    cur.execute(
        """
        INSERT INTO billing_events
            (org_id, event_type, actor_type, actor_id, stripe_event_id,
             previous_state, new_state)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (
            org_id,
            event_type,
            actor_type,
            actor_id,
            stripe_event_id,
            json.dumps(previous_state),
            json.dumps(new_state),
        ),
    )


def _write_audit_log(
    cur: Any,
    org_id: str,
    event_type: str,
    actor_id: str,
    previous_state: Dict[str, Any],
    new_state: Dict[str, Any],
    change_summary: str,
) -> None:
    """Insert a row into billing_audit_log.

    Args:
        cur: Active psycopg2 cursor.
        org_id: Organisation identifier.
        event_type: Event type slug.
        actor_id: User ID or system actor string.
        previous_state: Dict describing the state before the change.
        new_state: Dict describing the state after the change.
        change_summary: Human-readable summary.
    """
    cur.execute(
        """
        INSERT INTO billing_audit_log
            (org_id, event_type, actor_id, actor_role,
             previous_state, new_state, change_summary)
        VALUES (%s, %s, %s, 'user', %s, %s, %s)
        """,
        (
            org_id,
            event_type,
            actor_id,
            json.dumps(previous_state),
            json.dumps(new_state),
            change_summary,
        ),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/checkout")
async def create_checkout_session(
    body: CheckoutRequest,
    auth: Any = Depends(
        require_permission("billing:write") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Create a Stripe Checkout Session for the requested plan.

    Steps:
    1. Validate the plan exists and is active.
    2. Get or create a Stripe Customer for the organisation.
    3. Create a Stripe Checkout Session in subscription mode.
    4. Return the hosted checkout URL and session ID.

    org_id is always taken from the AuthContext, never from the request body.

    Args:
        body: CheckoutRequest with plan_id, success_url, cancel_url.
        auth: AuthContext injected by require_permission.

    Returns:
        Dict with 'checkout_url' (Stripe-hosted URL) and 'session_id'.

    Raises:
        HTTPException: 400 if the plan is unavailable or has no stripe_price_id.
        HTTPException: 404 if the organisation has no subscription row.
        HTTPException: 500 on unexpected errors.
    """
    load_stripe_secrets()
    org_id: str = auth.org_id if auth and hasattr(auth, "org_id") else "unknown"
    actor_id: str = (
        getattr(auth, "user_id", "unknown") if auth else "unknown"
    )

    conn = get_conn()
    try:
        cur = conn.cursor()

        # Step 1 — validate plan
        cur.execute(
            """
            SELECT stripe_price_id
            FROM subscription_plans
            WHERE plan_id = %s AND is_active = true
            """,
            (body.plan_id,),
        )
        plan_row = cur.fetchone()
        if plan_row is None or not plan_row[0]:
            raise HTTPException(
                status_code=400,
                detail="Plan not available for checkout — missing stripe_price_id or inactive",
            )
        stripe_price_id: str = plan_row[0]

        # Step 2 — get or create Stripe Customer
        stripe_customer_id = _get_or_create_stripe_customer(cur, conn, org_id)

        # Step 3 — create Checkout Session
        session = stripe.checkout.Session.create(
            customer=stripe_customer_id,
            mode="subscription",
            line_items=[{"price": stripe_price_id, "quantity": 1}],
            success_url=body.success_url + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=body.cancel_url,
            metadata={"org_id": org_id, "plan_id": body.plan_id},
        )

        logger.info(
            "Checkout session created org_id=%s plan_id=%s session_id=%s",
            org_id,
            body.plan_id,
            session.id,
        )
        cur.close()
        return {"checkout_url": session.url, "session_id": session.id}

    except HTTPException:
        raise
    except stripe.error.StripeError as exc:
        logger.error("Stripe API error during checkout org_id=%s: %s", org_id, exc)
        raise HTTPException(status_code=502, detail="Stripe API error — see logs")
    except Exception as exc:
        logger.error("create_checkout_session failed org_id=%s: %s", org_id, exc)
        raise HTTPException(status_code=500, detail="Failed to create checkout session")
    finally:
        put_conn(conn)


@router.post("/cancel")
async def cancel_subscription_stripe(
    body: StripeCancelRequest,
    auth: Any = Depends(
        require_permission("billing:write") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Schedule a subscription cancellation via Stripe (cancel_at_period_end=true).

    Updates both Stripe and the local org_subscriptions row.  Writes entries
    to billing_events and billing_audit_log.

    Args:
        body: StripeCancelRequest with optional reason string.
        auth: AuthContext injected by require_permission.

    Returns:
        Dict with 'cancel_at' ISO timestamp (Stripe period end).

    Raises:
        HTTPException: 404 if subscription not found or no Stripe subscription ID.
        HTTPException: 500 on unexpected errors.
    """
    load_stripe_secrets()
    org_id: str = auth.org_id if auth and hasattr(auth, "org_id") else "unknown"
    actor_id: str = getattr(auth, "user_id", "unknown") if auth else "unknown"

    conn = get_conn()
    try:
        cur = conn.cursor()

        cur.execute(
            """
            SELECT stripe_subscription_id, status, cancel_at_period_end
            FROM org_subscriptions
            WHERE org_id = %s
            """,
            (org_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Subscription not found")

        stripe_sub_id: Optional[str] = row[0]
        current_status: str = row[1] or "unknown"
        prev_cancel_at_period_end: bool = row[2] or False

        if not stripe_sub_id:
            raise HTTPException(
                status_code=400,
                detail="No active Stripe subscription — cannot cancel via Stripe",
            )

        # Update Stripe
        updated_sub = stripe.Subscription.modify(
            stripe_sub_id,
            cancel_at_period_end=True,
        )
        period_end_ts = updated_sub.current_period_end
        from datetime import datetime, timezone as _tz

        cancel_at_iso = datetime.fromtimestamp(period_end_ts, tz=_tz.utc).isoformat()

        # Update local DB
        cur.execute(
            """
            UPDATE org_subscriptions
            SET cancel_at_period_end = true, updated_at = now()
            WHERE org_id = %s
            """,
            (org_id,),
        )

        _write_billing_event(
            cur,
            org_id,
            "subscription.cancel_scheduled",
            "user",
            actor_id,
            {"cancel_at_period_end": prev_cancel_at_period_end, "status": current_status},
            {
                "cancel_at_period_end": True,
                "status": current_status,
                "reason": body.reason,
            },
        )
        _write_audit_log(
            cur,
            org_id,
            "subscription.cancel_scheduled",
            actor_id,
            {"cancel_at_period_end": prev_cancel_at_period_end},
            {"cancel_at_period_end": True},
            f"Cancellation scheduled at period end. Reason: {body.reason or 'not provided'}",
        )

        conn.commit()
        cur.close()
        logger.info(
            "Subscription cancel_at_period_end set org_id=%s cancel_at=%s",
            org_id,
            cancel_at_iso,
        )
        return {"cancel_at": cancel_at_iso}

    except HTTPException:
        raise
    except stripe.error.StripeError as exc:
        conn.rollback()
        logger.error("Stripe cancel failed org_id=%s: %s", org_id, exc)
        raise HTTPException(status_code=502, detail="Stripe API error — see logs")
    except Exception as exc:
        conn.rollback()
        logger.error("cancel_subscription_stripe failed org_id=%s: %s", org_id, exc)
        raise HTTPException(status_code=500, detail="Failed to schedule cancellation")
    finally:
        put_conn(conn)


@router.post("/reactivate")
async def reactivate_subscription_stripe(
    body: StripeReactivateRequest,
    auth: Any = Depends(
        require_permission("billing:write") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Undo a pending cancellation — sets cancel_at_period_end=false on Stripe.

    Args:
        body: StripeReactivateRequest (empty body, org_id from auth context).
        auth: AuthContext injected by require_permission.

    Returns:
        Dict confirming cancel_at_period_end=False.

    Raises:
        HTTPException: 404 if subscription not found.
        HTTPException: 400 if no Stripe subscription ID is present.
        HTTPException: 500 on unexpected errors.
    """
    load_stripe_secrets()
    org_id: str = auth.org_id if auth and hasattr(auth, "org_id") else "unknown"
    actor_id: str = getattr(auth, "user_id", "unknown") if auth else "unknown"

    conn = get_conn()
    try:
        cur = conn.cursor()

        cur.execute(
            """
            SELECT stripe_subscription_id, status
            FROM org_subscriptions
            WHERE org_id = %s
            """,
            (org_id,),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Subscription not found")

        stripe_sub_id: Optional[str] = row[0]
        current_status: str = row[1] or "unknown"

        if not stripe_sub_id:
            raise HTTPException(
                status_code=400,
                detail="No active Stripe subscription — cannot reactivate via Stripe",
            )

        # Update Stripe
        stripe.Subscription.modify(stripe_sub_id, cancel_at_period_end=False)

        # Update local DB
        cur.execute(
            """
            UPDATE org_subscriptions
            SET cancel_at_period_end = false, updated_at = now()
            WHERE org_id = %s
            """,
            (org_id,),
        )

        _write_billing_event(
            cur,
            org_id,
            "subscription.reactivated",
            "user",
            actor_id,
            {"cancel_at_period_end": True, "status": current_status},
            {"cancel_at_period_end": False, "status": current_status},
        )
        _write_audit_log(
            cur,
            org_id,
            "subscription.reactivated",
            actor_id,
            {"cancel_at_period_end": True},
            {"cancel_at_period_end": False},
            "Pending cancellation reversed — subscription reactivated",
        )

        conn.commit()
        cur.close()
        logger.info("Subscription reactivated org_id=%s", org_id)
        return {"org_id": org_id, "cancel_at_period_end": False, "status": current_status}

    except HTTPException:
        raise
    except stripe.error.StripeError as exc:
        conn.rollback()
        logger.error("Stripe reactivate failed org_id=%s: %s", org_id, exc)
        raise HTTPException(status_code=502, detail="Stripe API error — see logs")
    except Exception as exc:
        conn.rollback()
        logger.error("reactivate_subscription_stripe failed org_id=%s: %s", org_id, exc)
        raise HTTPException(status_code=500, detail="Failed to reactivate subscription")
    finally:
        put_conn(conn)
