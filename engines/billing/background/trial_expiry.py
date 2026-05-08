"""
Billing Engine — Trial expiry background job.

Runs every 60 minutes via APScheduler (AsyncIOScheduler).
Finds orgs where status='trialing', trial_end_at < now(), and
stripe_customer_id IS NULL, then downgrades them to the Free plan
and writes a billing_events row with event_type='trial.expired'.

Also provides run_trial_warning_check() (daily 09:00 UTC) which sends
SES warning emails to orgs 0-3 days from trial expiry, idempotently.
"""

import json
import logging
import os
from datetime import datetime
from datetime import timezone as _tz
from typing import List, Optional, Tuple

import boto3
from botocore.exceptions import ClientError

from db import get_conn, put_conn

logger = logging.getLogger(__name__)

_SES_FROM: str = os.environ.get("SES_FROM_EMAIL", "noreply@cspm.local")
_SES_REGION: str = os.environ.get("AWS_REGION", "ap-south-1")
_FRONTEND_URL: str = os.environ.get("FRONTEND_URL", "https://your-cspm-domain")


# ---------------------------------------------------------------------------
# Email recipient helper
# ---------------------------------------------------------------------------


def _get_admin_email(org_id: str, conn) -> Optional[str]:
    """Fetch the contact email for an org from the tenants table.

    Joins tenants to users on contact_email to get the primary admin address.

    Args:
        org_id: Organisation identifier (matches tenants.id).
        conn: Active psycopg2 DB connection.

    Returns:
        Admin email string, or None if no matching record exists.
    """
    cur = conn.cursor()
    cur.execute(
        """
        SELECT u.email
        FROM users u
        JOIN tenants t ON t.contact_email = u.email
        WHERE t.id = %s
        LIMIT 1
        """,
        (org_id,),
    )
    row = cur.fetchone()
    return row[0] if row else None


# ---------------------------------------------------------------------------
# Idempotency helpers
# ---------------------------------------------------------------------------


def _idempotency_check(org_id: str, event_type: str, conn) -> bool:
    """Return True if a billing_events row for this org+event already exists.

    Args:
        org_id: Organisation identifier.
        event_type: One of 'trial.expiry_warning_sent', 'trial.expiry_notice_sent'.
        conn: Active psycopg2 DB connection.

    Returns:
        True if already sent (skip), False if safe to send.
    """
    cur = conn.cursor()
    cur.execute(
        "SELECT COUNT(*) FROM billing_events WHERE org_id = %s AND event_type = %s",
        (org_id, event_type),
    )
    return cur.fetchone()[0] > 0


def _record_event(org_id: str, event_type: str, conn) -> None:
    """Insert an idempotency sentinel row into billing_events.

    Args:
        org_id: Organisation identifier.
        event_type: Event type string to record.
        conn: Active psycopg2 DB connection.
    """
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO billing_events
            (org_id, event_type, actor_type, actor_id, previous_state, new_state)
        VALUES (%s, %s, 'system', 'system', '{}', '{}')
        """,
        (org_id, event_type),
    )


# ---------------------------------------------------------------------------
# SES email senders
# ---------------------------------------------------------------------------


def _send_expiry_warning(org_id: str, admin_email: str, days_left: int) -> None:
    """Send trial expiry warning email via SES.

    Email body contains only days_left and a static upgrade URL — no
    subscription_id, plan_id, or stripe_customer_id is included.

    Args:
        org_id: Organisation identifier (for logging only).
        admin_email: Recipient email address.
        days_left: Number of days remaining in the trial.
    """
    try:
        ses = boto3.client("ses", region_name=_SES_REGION)
        ses.send_email(
            Source=_SES_FROM,
            Destination={"ToAddresses": [admin_email]},
            Message={
                "Subject": {
                    "Data": f"Your CSPM trial expires in {days_left} day(s)"
                },
                "Body": {
                    "Text": {
                        "Data": (
                            f"Your CSPM Pro trial ends in {days_left} day(s).\n\n"
                            "Upgrade now to keep access to all Pro features:\n"
                            f"{_FRONTEND_URL}/billing\n\n"
                            "If you have questions, contact support@cspm.local"
                        )
                    }
                },
            },
        )
        logger.info(
            "trial.expiry_warning sent to %s (org=%s, days=%d)",
            admin_email,
            org_id,
            days_left,
        )
    except ClientError as exc:
        logger.error("SES send_expiry_warning failed for org %s: %s", org_id, exc)


def _send_expiry_notice(org_id: str, admin_email: str) -> None:
    """Send trial expired / downgraded-to-Free notice via SES.

    Args:
        org_id: Organisation identifier (for logging only).
        admin_email: Recipient email address.
    """
    try:
        ses = boto3.client("ses", region_name=_SES_REGION)
        ses.send_email(
            Source=_SES_FROM,
            Destination={"ToAddresses": [admin_email]},
            Message={
                "Subject": {"Data": "Your CSPM trial has ended"},
                "Body": {
                    "Text": {
                        "Data": (
                            "Your CSPM Pro trial has ended and your account has been "
                            "moved to the Free plan.\n\n"
                            "To restore Pro features, upgrade at:\n"
                            f"{_FRONTEND_URL}/billing\n\n"
                            "If you have questions, contact support@cspm.local"
                        )
                    }
                },
            },
        )
        logger.info("trial.expiry_notice sent to %s (org=%s)", admin_email, org_id)
    except ClientError as exc:
        logger.error("SES send_expiry_notice failed for org %s: %s", org_id, exc)


# ---------------------------------------------------------------------------
# Warning check job (daily 09:00 UTC)
# ---------------------------------------------------------------------------


async def run_trial_warning_check() -> None:
    """Send warning emails to orgs whose trial expires within 3 days.

    Idempotent: checks billing_events for 'trial.expiry_warning_sent' before
    sending. Designed to run daily at 09:00 UTC via APScheduler.

    Raises:
        No exceptions are propagated — all errors are logged and the job
        continues to the next scheduled interval.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT org_id, trial_end_at
            FROM org_subscriptions
            WHERE status = 'trialing'
              AND trial_end_at BETWEEN now() AND now() + INTERVAL '3 days'
            """
        )
        expiring: List[Tuple] = cur.fetchall()

        if not expiring:
            logger.info("trial_warning: no orgs expiring within 3 days")
            return

        logger.info("trial_warning: %d org(s) expiring within 3 days", len(expiring))

        for org_id, trial_end_at in expiring:
            try:
                org_id_str = str(org_id)

                # Idempotency check — skip if warning already sent
                if _idempotency_check(org_id_str, "trial.expiry_warning_sent", conn):
                    logger.debug("trial_warning: already sent for org %s — skipping", org_id_str)
                    continue

                admin_email = _get_admin_email(org_id_str, conn)
                if not admin_email:
                    logger.warning(
                        "trial_warning: no admin email for org %s — skipping", org_id_str
                    )
                    continue

                days_left = max(0, (trial_end_at - datetime.now(_tz.utc)).days)
                _send_expiry_warning(org_id_str, admin_email, days_left)
                _record_event(org_id_str, "trial.expiry_warning_sent", conn)
                conn.commit()

            except Exception as row_exc:
                logger.error(
                    "trial_warning: failed for org %s: %s", org_id, row_exc
                )
                conn.rollback()

    except Exception as exc:
        conn.rollback()
        logger.exception("trial_warning: background task failed: %s", exc)
    finally:
        put_conn(conn)


async def run_trial_expiry_check() -> None:
    """Downgrade all expired free-trial orgs to the Free plan.

    This function is idempotent: re-running it on already-downgraded orgs
    is a no-op because their status is 'active' after the first run.

    Raises:
        No exceptions are propagated — all errors are logged and the job
        continues to the next scheduled interval.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()

        # Resolve the free plan_id once
        cur.execute(
            "SELECT plan_id FROM subscription_plans WHERE plan_name = 'free' AND is_active = true"
        )
        free_row = cur.fetchone()
        if not free_row:
            logger.error(
                "trial_expiry: Free plan not found in subscription_plans — skipping run"
            )
            return
        free_plan_id = free_row[0]

        # Find all expired trials with no payment method
        cur.execute(
            """
            SELECT subscription_id, org_id, plan_id
            FROM org_subscriptions
            WHERE status = 'trialing'
              AND trial_end_at < now()
              AND stripe_customer_id IS NULL
            """
        )
        expired: List[Tuple] = cur.fetchall()

        if not expired:
            logger.info("trial_expiry: no expired trials found")
            return

        logger.info("trial_expiry: found %d expired trial(s) to downgrade", len(expired))

        for sub_id, org_id, old_plan_id in expired:
            try:
                # Downgrade subscription
                cur.execute(
                    """
                    UPDATE org_subscriptions
                    SET plan_id   = %s,
                        status    = 'active',
                        updated_at = now()
                    WHERE subscription_id = %s
                    """,
                    (free_plan_id, sub_id),
                )

                # Immutable billing event
                cur.execute(
                    """
                    INSERT INTO billing_events
                        (org_id, event_type, actor_type, actor_id,
                         previous_state, new_state)
                    VALUES (%s, 'trial.expired', 'system', 'system', %s, %s)
                    """,
                    (
                        org_id,
                        json.dumps({"status": "trialing", "plan_id": str(old_plan_id)}),
                        json.dumps({"status": "active",   "plan_id": str(free_plan_id)}),
                    ),
                )

                logger.info(
                    "trial_expiry: org %s downgraded to Free (sub_id=%s)", org_id, sub_id
                )

                # Send expiry notice — idempotent via billing_events
                org_id_str = str(org_id)
                if not _idempotency_check(org_id_str, "trial.expiry_notice_sent", conn):
                    admin_email = _get_admin_email(org_id_str, conn)
                    if admin_email:
                        _send_expiry_notice(org_id_str, admin_email)
                        _record_event(org_id_str, "trial.expiry_notice_sent", conn)
                    else:
                        logger.warning(
                            "trial_expiry: no admin email for org %s — notice skipped",
                            org_id_str,
                        )

            except Exception as row_exc:
                # Log and continue — do not let one bad row abort the whole batch
                logger.error(
                    "trial_expiry: failed to downgrade org %s: %s", org_id, row_exc
                )

        conn.commit()
        logger.info("trial_expiry: committed downgrades for %d org(s)", len(expired))

    except Exception as exc:
        conn.rollback()
        logger.exception("trial_expiry: background task failed: %s", exc)
    finally:
        put_conn(conn)
