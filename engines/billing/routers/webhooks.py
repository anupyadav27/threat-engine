"""
Billing Engine — Stripe webhook handler.

POST /api/v1/billing/webhooks/stripe

This endpoint must be accessible WITHOUT authentication — Stripe calls it
directly from the internet.  The AuthMiddleware must skip this path
(it is registered in PUBLIC_PREFIXES / PUBLIC_PATHS in the gateway middleware).

Security model:
    Authenticity is verified exclusively via Stripe-Signature HMAC-SHA256
    header using stripe.Webhook.construct_event().  An invalid signature
    returns HTTP 400 immediately with no DB writes.

Idempotency:
    stripe_webhook_log has a UNIQUE constraint on stripe_event_id.
    The INSERT … ON CONFLICT DO NOTHING pattern guarantees at-most-once
    processing even if Stripe retries the same event_id.

PCI compliance:
    Raw webhook payloads are NEVER stored in any table or log output.
    Only the SHA-256 digest is stored in stripe_webhook_log.payload_hash.

Error handling:
    Processing errors return HTTP 200 (so Stripe stops retrying an
    un-handleable event), log the error, and write status='failed' to
    stripe_webhook_log.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

import stripe
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from db import get_conn, put_conn
from stripe_client import get_webhook_secret

logger = logging.getLogger(__name__)
router = APIRouter(tags=["webhooks"])


# ---------------------------------------------------------------------------
# Webhook endpoint
# ---------------------------------------------------------------------------


@router.post("/webhooks/stripe")
async def stripe_webhook(request: Request) -> JSONResponse:
    """Handle incoming Stripe webhook events.

    No X-Auth-Context header is required — this path must be in the
    gateway's AUTH_SKIP_PATHS (PUBLIC_PREFIXES) list.

    Steps:
    1. Validate Stripe-Signature header with HMAC-SHA256.
    2. INSERT into stripe_webhook_log with ON CONFLICT DO NOTHING (idempotency gate).
    3. If 0 rows affected: event already processed — return 200 + duplicate:true.
    4. Dispatch to the appropriate event handler.
    5. UPDATE stripe_webhook_log.processing_status to 'processed' or 'failed'.

    Args:
        request: Raw FastAPI request — body read once for signature verification.

    Returns:
        JSONResponse with {"received": true} on success,
        {"received": true, "duplicate": true} on duplicate, or
        {"error": "invalid_signature"} (HTTP 400) on bad signature.
    """
    payload: bytes = await request.body()
    sig_header: str = request.headers.get("Stripe-Signature", "")

    # Step 1 — validate signature
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, get_webhook_secret()
        )
    except stripe.error.SignatureVerificationError:
        logger.warning("Invalid Stripe webhook signature received")
        return JSONResponse(
            status_code=400, content={"error": "invalid_signature"}
        )
    except Exception as exc:
        logger.error("Webhook construct_event failed: %s", exc)
        return JSONResponse(
            status_code=400, content={"error": "invalid_signature"}
        )

    event_id: str = event["id"]
    event_type: str = event["type"]

    # PCI: store only the SHA-256 hash of the raw payload
    payload_hash: str = hashlib.sha256(payload).hexdigest()

    conn = get_conn()
    try:
        cur = conn.cursor()

        # Step 2 — idempotency gate
        cur.execute(
            """
            INSERT INTO stripe_webhook_log
                (stripe_event_id, event_type, payload_hash, processing_status)
            VALUES (%s, %s, %s, 'processing')
            ON CONFLICT (stripe_event_id) DO NOTHING
            """,
            (event_id, event_type, payload_hash),
        )
        affected: int = cur.rowcount
        conn.commit()

        # Step 3 — duplicate detection
        if affected == 0:
            logger.info(
                "Duplicate Stripe event ignored event_id=%s type=%s",
                event_id,
                event_type,
            )
            cur.close()
            return JSONResponse(content={"received": True, "duplicate": True})

        # Step 4 — dispatch
        try:
            await _handle_stripe_event(event, conn)
            cur.execute(
                """
                UPDATE stripe_webhook_log
                SET processing_status = 'processed', processed_at = now()
                WHERE stripe_event_id = %s
                """,
                (event_id,),
            )
            conn.commit()
            logger.info(
                "Stripe event processed event_id=%s type=%s", event_id, event_type
            )
        except Exception as exc:
            # Step 5 — mark failed; return 200 so Stripe does not retry
            logger.error(
                "Stripe event handler error event_id=%s type=%s: %s",
                event_id,
                event_type,
                exc,
            )
            try:
                cur.execute(
                    """
                    UPDATE stripe_webhook_log
                    SET processing_status = 'failed',
                        error_message = %s
                    WHERE stripe_event_id = %s
                    """,
                    (str(exc)[:500], event_id),
                )
                conn.commit()
            except Exception as db_exc:
                logger.error(
                    "Failed to write error status to webhook log: %s", db_exc
                )

        cur.close()
        return JSONResponse(content={"received": True})

    except Exception as exc:
        logger.error(
            "Unhandled exception in stripe_webhook event_id=%s: %s", event_id, exc
        )
        return JSONResponse(content={"received": True})
    finally:
        put_conn(conn)


# ---------------------------------------------------------------------------
# Event dispatcher
# ---------------------------------------------------------------------------


async def _handle_stripe_event(event: Dict[str, Any], conn: Any) -> None:
    """Dispatch a validated Stripe event to its specific handler.

    Args:
        event: Stripe event dict from construct_event.
        conn: Active psycopg2 connection.
    """
    event_type: str = event["type"]
    obj: Dict[str, Any] = event["data"]["object"]
    event_id: str = event["id"]

    handlers = {
        "checkout.session.completed": _on_checkout_session_completed,
        "customer.subscription.created": _on_subscription_created,
        "customer.subscription.updated": _on_subscription_updated,
        "customer.subscription.deleted": _on_subscription_deleted,
        "invoice.payment_succeeded": _on_payment_succeeded,
        "invoice.payment_failed": _on_payment_failed,
        "customer.subscription.trial_will_end": _on_trial_will_end,
    }

    handler = handlers.get(event_type)
    if handler is not None:
        await handler(obj, conn, event_id)
    else:
        logger.debug("Unhandled Stripe event type: %s", event_type)


# ---------------------------------------------------------------------------
# Individual event handlers
# ---------------------------------------------------------------------------


async def _on_checkout_session_completed(
    obj: Dict[str, Any], conn: Any, stripe_event_id: str
) -> None:
    """Handle checkout.session.completed.

    Activates the subscription and records the Stripe subscription ID
    that Stripe assigned after the checkout was completed.

    Args:
        obj: Stripe CheckoutSession object.
        conn: Active psycopg2 connection.
        stripe_event_id: Stripe event ID for audit correlation.
    """
    stripe_customer_id: str = obj.get("customer", "")
    stripe_sub_id: Optional[str] = obj.get("subscription")
    metadata: Dict[str, Any] = obj.get("metadata") or {}
    org_id: Optional[str] = metadata.get("org_id")
    plan_id_meta: Optional[str] = metadata.get("plan_id")

    if not stripe_sub_id:
        logger.warning(
            "checkout.session.completed has no subscription ID event_id=%s",
            stripe_event_id,
        )
        return

    cur = conn.cursor()
    cur.execute(
        """
        UPDATE org_subscriptions
        SET stripe_subscription_id = %s,
            status = 'active',
            plan_id = COALESCE(
                (SELECT plan_id FROM subscription_plans
                 WHERE plan_id::text = %s AND is_active = true),
                plan_id
            ),
            updated_at = now()
        WHERE stripe_customer_id = %s
        RETURNING org_id, plan_id
        """,
        (stripe_sub_id, plan_id_meta or "", stripe_customer_id),
    )
    row = cur.fetchone()
    if row:
        resolved_org_id: str = str(row[0])
        new_plan_id: str = str(row[1])
        _write_billing_event(
            cur,
            resolved_org_id,
            "subscription.upgraded",
            "stripe_webhook",
            stripe_event_id,
            {"status": "trialing"},
            {"status": "active", "plan_id": new_plan_id},
        )
        _write_audit_log(
            cur,
            resolved_org_id,
            "subscription.upgraded",
            "stripe",
            {"status": "trialing"},
            {"status": "active"},
            f"Stripe webhook: checkout.session.completed",
        )
        logger.info(
            "Checkout completed org_id=%s plan_id=%s sub_id=%s",
            resolved_org_id,
            new_plan_id,
            stripe_sub_id,
        )
    else:
        logger.warning(
            "No org_subscriptions row found for stripe_customer_id=%s event_id=%s",
            stripe_customer_id,
            stripe_event_id,
        )


async def _on_subscription_created(
    obj: Dict[str, Any], conn: Any, stripe_event_id: str
) -> None:
    """Handle customer.subscription.created.

    Updates org_subscriptions with the new Stripe subscription ID, sets
    status to 'active', and records billing events / audit log.

    Args:
        obj: Stripe Subscription object.
        conn: Active psycopg2 connection.
        stripe_event_id: Stripe event ID for audit correlation.
    """
    stripe_sub_id: str = obj["id"]
    stripe_customer_id: str = obj["customer"]
    period_start = datetime.fromtimestamp(
        obj["current_period_start"], tz=timezone.utc
    )
    period_end = datetime.fromtimestamp(
        obj["current_period_end"], tz=timezone.utc
    )
    metadata: Dict[str, Any] = obj.get("metadata") or {}
    plan_id_meta: Optional[str] = metadata.get("plan_id")

    cur = conn.cursor()
    cur.execute(
        """
        UPDATE org_subscriptions
        SET stripe_subscription_id  = %s,
            status                  = 'active',
            current_period_start    = %s,
            current_period_end      = %s,
            plan_id                 = COALESCE(
                (SELECT plan_id FROM subscription_plans
                 WHERE plan_id::text = %s AND is_active = true),
                plan_id
            ),
            updated_at              = now()
        WHERE stripe_customer_id = %s
        RETURNING org_id, plan_id
        """,
        (
            stripe_sub_id,
            period_start,
            period_end,
            plan_id_meta or "",
            stripe_customer_id,
        ),
    )
    row = cur.fetchone()
    if row:
        resolved_org_id: str = str(row[0])
        new_plan_id: str = str(row[1])
        _write_billing_event(
            cur,
            resolved_org_id,
            "subscription.upgraded",
            "stripe_webhook",
            stripe_event_id,
            {"status": "trialing"},
            {"status": "active", "plan_id": new_plan_id},
        )
        _write_audit_log(
            cur,
            resolved_org_id,
            "subscription.upgraded",
            "stripe",
            {"status": "trialing"},
            {"status": "active"},
            "Stripe webhook: customer.subscription.created",
        )


async def _on_subscription_updated(
    obj: Dict[str, Any], conn: Any, stripe_event_id: str
) -> None:
    """Handle customer.subscription.updated.

    Refreshes subscription period and status in org_subscriptions.
    If the Stripe status changed to 'active' from 'past_due' it also
    clears payment_failed_at.

    Args:
        obj: Stripe Subscription object.
        conn: Active psycopg2 connection.
        stripe_event_id: Stripe event ID for audit correlation.
    """
    stripe_sub_id: str = obj["id"]
    stripe_status: str = obj.get("status", "")
    cancel_at_period_end: bool = obj.get("cancel_at_period_end", False)
    period_start = datetime.fromtimestamp(
        obj["current_period_start"], tz=timezone.utc
    )
    period_end = datetime.fromtimestamp(
        obj["current_period_end"], tz=timezone.utc
    )

    # Map Stripe status to internal status
    status_map = {
        "active": "active",
        "trialing": "trialing",
        "past_due": "past_due",
        "canceled": "cancelled",
        "unpaid": "past_due",
        "paused": "paused",
    }
    internal_status: str = status_map.get(stripe_status, stripe_status)

    cur = conn.cursor()
    cur.execute(
        """
        UPDATE org_subscriptions
        SET status                = %s,
            cancel_at_period_end  = %s,
            current_period_start  = %s,
            current_period_end    = %s,
            updated_at            = now()
        WHERE stripe_subscription_id = %s
        RETURNING org_id
        """,
        (
            internal_status,
            cancel_at_period_end,
            period_start,
            period_end,
            stripe_sub_id,
        ),
    )
    row = cur.fetchone()
    if row:
        resolved_org_id: str = str(row[0])
        _write_billing_event(
            cur,
            resolved_org_id,
            "subscription.updated",
            "stripe_webhook",
            stripe_event_id,
            {},
            {
                "status": internal_status,
                "cancel_at_period_end": cancel_at_period_end,
            },
        )


async def _on_subscription_deleted(
    obj: Dict[str, Any], conn: Any, stripe_event_id: str
) -> None:
    """Handle customer.subscription.deleted.

    Sets org_subscriptions to cancelled and records billing events.

    Args:
        obj: Stripe Subscription object.
        conn: Active psycopg2 connection.
        stripe_event_id: Stripe event ID for audit correlation.
    """
    stripe_sub_id: str = obj["id"]
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE org_subscriptions
        SET status        = 'cancelled',
            cancelled_at  = now(),
            updated_at    = now()
        WHERE stripe_subscription_id = %s
        RETURNING org_id
        """,
        (stripe_sub_id,),
    )
    row = cur.fetchone()
    if row:
        resolved_org_id: str = str(row[0])
        _write_billing_event(
            cur,
            resolved_org_id,
            "subscription.cancelled",
            "stripe_webhook",
            stripe_event_id,
            {"status": "active"},
            {"status": "cancelled"},
        )
        _write_audit_log(
            cur,
            resolved_org_id,
            "subscription.cancelled",
            "stripe",
            {"status": "active"},
            {"status": "cancelled"},
            "Stripe webhook: customer.subscription.deleted",
        )


async def _on_payment_failed(
    obj: Dict[str, Any], conn: Any, stripe_event_id: str
) -> None:
    """Handle invoice.payment_failed.

    Sets payment_failed_at, increments payment_retry_count, sets
    grace_period_end_at = now() + 7 days, and transitions status to
    'past_due'.  Does NOT immediately downgrade (grace period handled
    by BILL-08).

    Args:
        obj: Stripe Invoice object.
        conn: Active psycopg2 connection.
        stripe_event_id: Stripe event ID for audit correlation.
    """
    stripe_customer_id: str = obj.get("customer", "")
    grace_end = datetime.now(timezone.utc) + timedelta(days=7)

    cur = conn.cursor()
    cur.execute(
        """
        UPDATE org_subscriptions
        SET payment_failed_at    = now(),
            grace_period_end_at  = %s,
            payment_retry_count  = payment_retry_count + 1,
            status               = 'past_due',
            updated_at           = now()
        WHERE stripe_customer_id = %s
        RETURNING org_id
        """,
        (grace_end, stripe_customer_id),
    )
    row = cur.fetchone()
    if row:
        resolved_org_id: str = str(row[0])
        _write_billing_event(
            cur,
            resolved_org_id,
            "payment.failed",
            "stripe_webhook",
            stripe_event_id,
            {"status": "active"},
            {"status": "past_due"},
        )
        _write_audit_log(
            cur,
            resolved_org_id,
            "payment.failed",
            "stripe",
            {"status": "active"},
            {"status": "past_due"},
            "Stripe webhook: invoice.payment_failed — grace period started",
        )


async def _on_payment_succeeded(
    obj: Dict[str, Any], conn: Any, stripe_event_id: str
) -> None:
    """Handle invoice.payment_succeeded.

    Clears payment_failed_at, resets payment_retry_count to 0, and
    ensures status is 'active'.

    Args:
        obj: Stripe Invoice object.
        conn: Active psycopg2 connection.
        stripe_event_id: Stripe event ID for audit correlation.
    """
    stripe_customer_id: str = obj.get("customer", "")

    cur = conn.cursor()
    cur.execute(
        """
        UPDATE org_subscriptions
        SET payment_failed_at   = NULL,
            grace_period_end_at = NULL,
            payment_retry_count = 0,
            status              = 'active',
            updated_at          = now()
        WHERE stripe_customer_id = %s
        RETURNING org_id
        """,
        (stripe_customer_id,),
    )
    row = cur.fetchone()
    if row:
        resolved_org_id: str = str(row[0])
        _write_billing_event(
            cur,
            resolved_org_id,
            "payment.succeeded",
            "stripe_webhook",
            stripe_event_id,
            {"status": "past_due"},
            {"status": "active"},
        )
        _write_audit_log(
            cur,
            resolved_org_id,
            "payment.succeeded",
            "stripe",
            {"status": "past_due"},
            {"status": "active"},
            "Stripe webhook: invoice.payment_succeeded — subscription reinstated",
        )


async def _on_trial_will_end(
    obj: Dict[str, Any], conn: Any, stripe_event_id: str
) -> None:
    """Handle customer.subscription.trial_will_end.

    Writes an advance-warning billing_events row only — no state change.
    Email notification is deferred to BILL-08.

    Args:
        obj: Stripe Subscription object.
        conn: Active psycopg2 connection.
        stripe_event_id: Stripe event ID for audit correlation.
    """
    stripe_customer_id: str = obj.get("customer", "")
    cur = conn.cursor()
    cur.execute(
        "SELECT org_id FROM org_subscriptions WHERE stripe_customer_id = %s",
        (stripe_customer_id,),
    )
    row = cur.fetchone()
    if row:
        resolved_org_id: str = str(row[0])
        _write_billing_event(
            cur,
            resolved_org_id,
            "trial.will_end",
            "stripe_webhook",
            stripe_event_id,
            {},
            {},
        )


# ---------------------------------------------------------------------------
# DB write helpers (shared with checkout.py via re-use from webhooks context)
# ---------------------------------------------------------------------------


def _write_billing_event(
    cur: Any,
    org_id: str,
    event_type: str,
    actor_type: str,
    stripe_event_id: str,
    previous_state: Dict[str, Any],
    new_state: Dict[str, Any],
) -> None:
    """Insert a row into billing_events.

    Args:
        cur: Active psycopg2 cursor.
        org_id: Organisation identifier.
        event_type: Event type slug.
        actor_type: 'stripe_webhook' for Stripe-initiated events.
        stripe_event_id: Stripe event ID for de-duplication / correlation.
        previous_state: Dict describing the state before the change.
        new_state: Dict describing the state after the change.
    """
    cur.execute(
        """
        INSERT INTO billing_events
            (org_id, event_type, actor_type, actor_id, stripe_event_id,
             previous_state, new_state)
        VALUES (%s, %s, %s, 'stripe', %s, %s, %s)
        """,
        (
            org_id,
            event_type,
            actor_type,
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
        actor_id: System actor identifier (e.g. 'stripe').
        previous_state: Dict describing the state before the change.
        new_state: Dict describing the state after the change.
        change_summary: Human-readable summary for SOC 2 / audit trail.
    """
    cur.execute(
        """
        INSERT INTO billing_audit_log
            (org_id, event_type, actor_id, actor_role,
             previous_state, new_state, change_summary)
        VALUES (%s, %s, %s, 'system', %s, %s, %s)
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
