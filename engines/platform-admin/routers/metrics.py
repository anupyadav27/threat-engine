"""
Platform Admin Engine — Platform-wide metrics router.

GET /api/v1/padmin/metrics

Returns aggregate stats from the billing DB:
  - total_orgs: all rows in org_subscriptions
  - orgs_by_tier: count per plan_name
  - orgs_by_status: count per status
  - trials_expiring_7d: trialing orgs whose trial_end_at is within 7 days
  - past_due_orgs: orgs with status='past_due'

Requires platform:admin permission.
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from db import get_conn, put_conn
from _schemas import PlatformAdminLenientResponse

try:
    from engine_auth.fastapi.dependencies import require_permission  # type: ignore
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

logger = logging.getLogger(__name__)
router = APIRouter(tags=["metrics"])


@router.get("/metrics", response_model=PlatformAdminLenientResponse, response_model_exclude_none=False)
async def platform_metrics(
    auth: Any = Depends(
        require_permission("platform:admin") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Return platform-wide aggregate metrics from the billing DB.

    All queries run against billing_readonly. No writes are performed.

    Requires platform:admin permission.

    Args:
        auth: AuthContext injected by require_permission.

    Returns:
        Dict with total_orgs (int), orgs_by_tier (dict), orgs_by_status (dict),
        trials_expiring_7d (int), past_due_orgs (int).
    """
    conn = get_conn()
    try:
        cur = conn.cursor()

        # Total orgs
        cur.execute("SELECT COUNT(*) FROM org_subscriptions")
        total_orgs: int = cur.fetchone()[0]

        # Orgs by tier (plan_name)
        cur.execute(
            """
            SELECT sp.plan_name, COUNT(os.org_id)
            FROM org_subscriptions os
            JOIN subscription_plans sp ON sp.plan_id = os.plan_id
            GROUP BY sp.plan_name
            ORDER BY sp.plan_name
            """
        )
        orgs_by_tier: Dict[str, int] = {row[0]: row[1] for row in cur.fetchall()}

        # Orgs by status
        cur.execute(
            "SELECT status, COUNT(*) FROM org_subscriptions GROUP BY status ORDER BY status"
        )
        orgs_by_status: Dict[str, int] = {row[0]: row[1] for row in cur.fetchall()}

        # Trials expiring within 7 days
        cur.execute(
            """
            SELECT COUNT(*)
            FROM org_subscriptions
            WHERE status = 'trialing'
              AND trial_end_at BETWEEN now() AND now() + INTERVAL '7 days'
            """
        )
        trials_expiring_7d: int = cur.fetchone()[0]

        # Past-due orgs
        cur.execute(
            "SELECT COUNT(*) FROM org_subscriptions WHERE status = 'past_due'"
        )
        past_due_orgs: int = cur.fetchone()[0]

        cur.close()
        return {
            "total_orgs": total_orgs,
            "orgs_by_tier": orgs_by_tier,
            "orgs_by_status": orgs_by_status,
            "trials_expiring_7d": trials_expiring_7d,
            "past_due_orgs": past_due_orgs,
        }
    except Exception as exc:
        logger.error("platform_metrics failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to retrieve metrics")
    finally:
        put_conn(conn)
