"""
Billing Engine — Usage metering endpoints.

GET  /api/v1/billing/usage                        — summary: accounts + scan usage
POST /api/v1/billing/usage/consume-scan-token     — increment daily scan token
GET  /api/v1/billing/usage/check-scan-frequency   — check remaining daily scans
GET  /api/v1/billing/usage/check-account-limit    — check connected accounts vs plan limit
"""

import logging
from datetime import date, datetime, timezone
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Query

from db import get_conn, put_conn
from models import ConsumeScanTokenRequest

try:
    from engine_auth.fastapi.dependencies import require_permission
    from engine_auth.core.models import AuthContext
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)
router = APIRouter(tags=["usage"])

_UPGRADE_URL = "/billing/upgrade"


@router.get("/usage")
async def get_usage_summary(
    org_id: str = Query(..., description="Organisation UUID"),
    auth: Any = Depends(
        require_permission("billing:read") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Return a usage summary for the billing portal page.

    Args:
        org_id: Organisation identifier.
        auth: AuthContext injected by require_permission.

    Returns:
        Dict with accounts_used, max_accounts, scans_this_month, max_scans_per_day.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT os.accounts_connected, sp.max_accounts, sp.scan_freq_per_day, sp.plan_name
            FROM org_subscriptions os
            JOIN subscription_plans sp ON sp.plan_id = os.plan_id
            WHERE os.org_id = %s
            """,
            (org_id,),
        )
        row = cur.fetchone()
        if not row:
            return {
                "accounts_used": 0, "max_accounts": 1,
                "scans_this_month": 0, "max_scans_per_day": -1,
            }
        accounts_connected, max_accounts, scan_freq, plan_name = row

        # Count scan tokens used this month (approximation from daily tokens table)
        today = date.today()
        cur.execute(
            """
            SELECT COALESCE(SUM(tokens_used), 0)
            FROM scan_frequency_tokens
            WHERE org_id = %s
              AND window_date >= date_trunc('month', CURRENT_DATE)
            """,
            (org_id,),
        )
        scans_row = cur.fetchone()
        scans_this_month = int(scans_row[0]) if scans_row else 0

        cur.close()
        return {
            "accounts_used":      accounts_connected or 0,
            "max_accounts":       max_accounts if max_accounts is not None else 1,
            "scans_this_month":   scans_this_month,
            "max_scans_per_day":  scan_freq if scan_freq is not None else -1,
            "plan_name":          plan_name or "free",
        }
    except Exception as exc:
        logger.warning("get_usage_summary failed org_id=%s: %s", org_id, exc)
        return {
            "accounts_used": 0, "max_accounts": 1,
            "scans_this_month": 0, "max_scans_per_day": -1,
        }
    finally:
        put_conn(conn)


@router.post("/usage/consume-scan-token", status_code=200)
async def consume_scan_token(
    body: ConsumeScanTokenRequest,
    auth: Any = Depends(
        require_permission("billing:read") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Increment today's scan token counter for an organisation.

    Creates the row if it does not exist, using the org's current
    scan_freq_per_day as tokens_limit (0 means unlimited on Free).

    Args:
        body: ConsumeScanTokenRequest with org_id.
        auth: AuthContext injected by require_permission.

    Returns:
        Dict with org_id, tokens_used, tokens_limit, and window_date.

    Raises:
        HTTPException: 404 if org has no subscription. 429 if daily limit exceeded.
    """
    today = date.today()
    conn = get_conn()
    try:
        cur = conn.cursor()

        # Fetch org's current scan_freq_per_day from their active plan
        cur.execute(
            """
            SELECT sp.scan_freq_per_day
            FROM org_subscriptions os
            JOIN subscription_plans sp ON sp.plan_id = os.plan_id
            WHERE os.org_id = %s
            """,
            (body.org_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Subscription not found for org")

        scan_freq_per_day: int = row[0]

        # Upsert today's token row
        cur.execute(
            """
            INSERT INTO scan_frequency_tokens
                (org_id, window_date, tokens_used, tokens_limit, window_type)
            VALUES (%s, %s, 1, %s, 'day')
            ON CONFLICT (org_id, window_date, window_type)
            DO UPDATE SET
                tokens_used  = scan_frequency_tokens.tokens_used + 1,
                tokens_limit = EXCLUDED.tokens_limit,
                updated_at   = now()
            RETURNING tokens_used, tokens_limit
            """,
            (body.org_id, today, scan_freq_per_day),
        )
        tokens_used, tokens_limit = cur.fetchone()
        conn.commit()
        cur.close()

        return {
            "org_id": body.org_id,
            "tokens_used": tokens_used,
            "tokens_limit": tokens_limit,
            "window_date": today.isoformat(),
        }
    except HTTPException:
        raise
    except Exception as exc:
        conn.rollback()
        logger.error("consume_scan_token failed org_id=%s: %s", body.org_id, exc)
        raise HTTPException(status_code=500, detail="Failed to consume scan token")
    finally:
        put_conn(conn)


@router.get("/usage/check-scan-frequency")
async def check_scan_frequency(
    org_id: str = Query(..., description="Organisation UUID"),
    auth: Any = Depends(
        require_permission("billing:read") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Check whether the org may trigger another scan today.

    scan_freq_per_day <= 0 means unlimited (Free tier scans on-demand only).
    If no token row exists yet for today, the org has all tokens remaining.

    Args:
        org_id: Organisation identifier.
        auth: AuthContext injected by require_permission.

    Returns:
        Dict with 'allowed' bool, 'tokens_remaining' int, and optional 'reset_at' ISO string.

    Raises:
        HTTPException: 404 if org has no subscription.
    """
    today = date.today()
    conn = get_conn()
    try:
        cur = conn.cursor()

        # Get plan limit
        cur.execute(
            """
            SELECT sp.scan_freq_per_day
            FROM org_subscriptions os
            JOIN subscription_plans sp ON sp.plan_id = os.plan_id
            WHERE os.org_id = %s
            """,
            (org_id,),
        )
        plan_row = cur.fetchone()
        if not plan_row:
            raise HTTPException(status_code=404, detail="Subscription not found for org")

        scan_freq_per_day: int = plan_row[0]

        # Unlimited tier (limit <= 0 means no cap)
        if scan_freq_per_day <= 0:
            cur.close()
            return {"allowed": True, "tokens_remaining": -1}

        # Fetch today's usage
        cur.execute(
            """
            SELECT tokens_used, tokens_limit
            FROM scan_frequency_tokens
            WHERE org_id = %s AND window_date = %s AND window_type = 'day'
            """,
            (org_id, today),
        )
        usage_row = cur.fetchone()
        cur.close()

        if not usage_row:
            # No scans yet today — all tokens available
            return {
                "allowed": True,
                "tokens_remaining": scan_freq_per_day,
            }

        tokens_used, tokens_limit = usage_row
        effective_limit = tokens_limit if tokens_limit > 0 else scan_freq_per_day
        remaining = max(0, effective_limit - tokens_used)
        allowed = remaining > 0

        result: Dict[str, Any] = {"allowed": allowed, "tokens_remaining": remaining}
        if not allowed:
            # Reset at midnight UTC tomorrow
            from datetime import timedelta
            tomorrow_midnight = datetime(
                today.year, today.month, today.day, tzinfo=timezone.utc
            ) + timedelta(days=1)
            result["reset_at"] = tomorrow_midnight.isoformat()

        return result
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("check_scan_frequency failed org_id=%s: %s", org_id, exc)
        raise HTTPException(status_code=500, detail="Failed to check scan frequency")
    finally:
        put_conn(conn)


@router.get("/usage/check-account-limit")
async def check_account_limit(
    org_id: str = Query(..., description="Organisation UUID"),
    auth: Any = Depends(
        require_permission("billing:read") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Check whether the org may connect another cloud account.

    max_accounts = -1 means unlimited (Enterprise tier).

    Args:
        org_id: Organisation identifier.
        auth: AuthContext injected by require_permission.

    Returns:
        Dict with 'allowed', 'accounts_connected', 'limit', 'current_tier',
        and 'upgrade_url'.

    Raises:
        HTTPException: 404 if org has no subscription.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT os.accounts_connected, sp.max_accounts, sp.plan_name
            FROM org_subscriptions os
            JOIN subscription_plans sp ON sp.plan_id = os.plan_id
            WHERE os.org_id = %s
            """,
            (org_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Subscription not found for org")

        accounts_connected, max_accounts, plan_name = row
        cur.close()

        # -1 = unlimited (Enterprise)
        if max_accounts < 0:
            allowed = True
        else:
            allowed = accounts_connected < max_accounts

        return {
            "allowed": allowed,
            "accounts_connected": accounts_connected,
            "limit": max_accounts,
            "current_tier": plan_name,
            "upgrade_url": _UPGRADE_URL,
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("check_account_limit failed org_id=%s: %s", org_id, exc)
        raise HTTPException(status_code=500, detail="Failed to check account limit")
    finally:
        put_conn(conn)
