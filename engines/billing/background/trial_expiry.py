"""
Billing Engine — Trial expiry background job.

Runs every 60 minutes via APScheduler (AsyncIOScheduler).
Finds orgs where status='trialing', trial_end_at < now(), and
stripe_customer_id IS NULL, then downgrades them to the Free plan
and writes a billing_events row with event_type='trial.expired'.
"""

import json
import logging
from typing import List, Tuple

from db import get_conn, put_conn

logger = logging.getLogger(__name__)


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
