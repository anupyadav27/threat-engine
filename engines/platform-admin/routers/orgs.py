"""
Platform Admin Engine — Org subscription management router.

GET    /api/v1/padmin/orgs                           — list all orgs
PATCH  /api/v1/padmin/orgs/{org_id}/subscription     — override tier
PATCH  /api/v1/padmin/orgs/{org_id}/trial            — extend trial
PATCH  /api/v1/padmin/orgs/{org_id}/suspend          — suspend org
PATCH  /api/v1/padmin/orgs/{org_id}/unsuspend        — unsuspend org

All endpoints require platform:admin permission.
Reads use billing_readonly pool (via get_conn / put_conn).
Mutations use billing_app pool (via get_write_conn / put_write_conn).
Every mutation writes a row to platform_admin_audit.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from db import get_conn, get_write_conn, put_conn, put_write_conn
from _schemas import PlatformAdminLenientResponse

try:
    from engine_auth.fastapi.dependencies import require_permission  # type: ignore
    from engine_auth.core.models import AuthContext  # type: ignore
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)
router = APIRouter(tags=["orgs"])


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class SubscriptionOverrideRequest(BaseModel):
    """Body for PATCH /orgs/{org_id}/subscription."""

    plan_name: str
    reason: Optional[str] = ""


class TrialExtendRequest(BaseModel):
    """Body for PATCH /orgs/{org_id}/trial."""

    extend_days: int
    reason: Optional[str] = ""


class SuspendRequest(BaseModel):
    """Body for PATCH /orgs/{org_id}/suspend."""

    reason: Optional[str] = ""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serialize_row(row: tuple, cols: list) -> Dict[str, Any]:
    """Convert a psycopg2 result tuple into a JSON-safe dict.

    Timestamps are converted to ISO 8601 strings. Decimal values are
    converted to float.

    Args:
        row: psycopg2 result tuple.
        cols: Column names from cursor.description.

    Returns:
        JSON-safe dict.
    """
    d: Dict[str, Any] = {}
    for key, val in zip(cols, row):
        if hasattr(val, "isoformat"):
            d[key] = val.isoformat()
        elif val.__class__.__name__ == "Decimal":
            d[key] = float(val)
        else:
            d[key] = val
    return d


def _write_audit(
    cur: Any,
    admin_user_id: str,
    action: str,
    target_org_id: str,
    payload: Dict[str, Any],
) -> None:
    """Insert a row into platform_admin_audit.

    Args:
        cur: Open psycopg2 cursor on the billing_app connection.
        admin_user_id: User ID of the acting admin.
        action: Audit action string (e.g. 'org.tier_override').
        target_org_id: The org being modified.
        payload: Additional context dict stored as JSON.
    """
    cur.execute(
        """
        INSERT INTO platform_admin_audit
            (admin_user_id, action, target_org_id, target_entity, payload)
        VALUES (%s, %s, %s, 'org', %s)
        """,
        (admin_user_id, action, target_org_id, json.dumps(payload)),
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/orgs", response_model=PlatformAdminLenientResponse, response_model_exclude_none=False)
async def list_orgs(
    status: Optional[str] = Query(None, description="Filter by subscription status"),
    tier: Optional[str] = Query(None, description="Filter by plan_name"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    auth: Any = Depends(
        require_permission("platform:admin") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Return a paginated list of all orgs with their subscription status.

    Reads from billing_readonly pool. Response includes a summary dict
    with per-status counts across the entire dataset.

    Requires platform:admin permission.

    Args:
        status: Optional filter on org_subscriptions.status.
        tier: Optional filter on subscription_plans.plan_name.
        limit: Page size (default 50, max 500).
        offset: Page offset for pagination.
        auth: AuthContext injected by require_permission.

    Returns:
        Dict with 'orgs' list, 'total' int, and 'summary' status-count dict.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()

        where_clauses = []
        params: list = []
        if status:
            where_clauses.append("os.status = %s")
            params.append(status)
        if tier:
            where_clauses.append("sp.plan_name = %s")
            params.append(tier)

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        cur.execute(
            f"""
            SELECT
                os.org_id,
                COALESCE(os.org_name, os.org_id) AS org_name,
                sp.plan_name,
                os.status,
                os.accounts_connected,
                os.users_count,
                os.trial_end_at,
                os.payment_failed_at,
                os.is_overridden,
                os.created_at,
                os.updated_at
            FROM org_subscriptions os
            JOIN subscription_plans sp ON sp.plan_id = os.plan_id
            {where_sql}
            ORDER BY os.created_at DESC
            LIMIT %s OFFSET %s
            """,
            params + [limit, offset],
        )
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        orgs = [_serialize_row(r, cols) for r in rows]

        # Full-table status summary (unfiltered)
        cur.execute(
            "SELECT status, COUNT(*) FROM org_subscriptions GROUP BY status"
        )
        summary = {row[0]: row[1] for row in cur.fetchall()}

        cur.close()
        return {"orgs": orgs, "total": len(orgs), "summary": summary}
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("list_orgs failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to list orgs")
    finally:
        put_conn(conn)


@router.patch("/orgs/{org_id}/subscription")
async def override_subscription(
    org_id: str,
    body: SubscriptionOverrideRequest,
    auth: Any = Depends(
        require_permission("platform:admin") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Override an org's subscription tier without going through Stripe.

    Sets is_overridden=true and records the acting admin in
    override_by_user_id. Writes platform_admin_audit.

    Requires platform:admin permission.

    Args:
        org_id: Target org UUID.
        body: SubscriptionOverrideRequest with plan_name and reason.
        auth: AuthContext injected by require_permission.

    Returns:
        Dict confirming the new plan name.

    Raises:
        HTTPException: 400 if plan_name not found, 404 if org not found.
    """
    admin_id = getattr(auth, "user_id", "unknown") if auth else "unknown"
    conn = get_write_conn()
    try:
        cur = conn.cursor()

        cur.execute(
            "SELECT plan_id FROM subscription_plans WHERE plan_name = %s AND is_active = true",
            (body.plan_name,),
        )
        plan_row = cur.fetchone()
        if not plan_row:
            raise HTTPException(
                status_code=400, detail=f"Plan '{body.plan_name}' not found or inactive"
            )
        new_plan_id = plan_row[0]

        cur.execute(
            """
            UPDATE org_subscriptions
            SET plan_id = %s,
                is_overridden = true,
                override_reason = %s,
                override_by_user_id = %s,
                status = 'active',
                updated_at = now()
            WHERE org_id = %s
            RETURNING subscription_id
            """,
            (new_plan_id, body.reason, admin_id, org_id),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Subscription not found for org")

        _write_audit(
            cur,
            admin_id,
            "org.tier_override",
            org_id,
            {"plan_name": body.plan_name, "reason": body.reason},
        )
        conn.commit()
        cur.close()
        return {
            "message": "Subscription overridden",
            "org_id": org_id,
            "new_plan": body.plan_name,
        }
    except HTTPException:
        conn.rollback()
        raise
    except Exception as exc:
        conn.rollback()
        logger.error("override_subscription failed org_id=%s: %s", org_id, exc)
        raise HTTPException(status_code=500, detail="Failed to override subscription")
    finally:
        put_write_conn(conn)


@router.patch("/orgs/{org_id}/trial")
async def extend_trial(
    org_id: str,
    body: TrialExtendRequest,
    auth: Any = Depends(
        require_permission("platform:admin") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Extend the trial period for a trialing org.

    Adds extend_days to the later of trial_end_at or now(). Only applies
    if the org subscription status is 'trialing'. Writes platform_admin_audit.

    Requires platform:admin permission.

    Args:
        org_id: Target org UUID.
        body: TrialExtendRequest with extend_days and reason.
        auth: AuthContext injected by require_permission.

    Returns:
        Dict with new_trial_end_at ISO timestamp.

    Raises:
        HTTPException: 404 if org not found or not in trialing state.
    """
    admin_id = getattr(auth, "user_id", "unknown") if auth else "unknown"
    conn = get_write_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE org_subscriptions
            SET trial_end_at = GREATEST(trial_end_at, now()) + (%s || ' days')::INTERVAL,
                updated_at = now()
            WHERE org_id = %s AND status = 'trialing'
            RETURNING trial_end_at
            """,
            (str(body.extend_days), org_id),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(
                status_code=404, detail="Org not found or not in trialing state"
            )

        _write_audit(
            cur,
            admin_id,
            "org.trial_extend",
            org_id,
            {"extend_days": body.extend_days, "reason": body.reason},
        )
        conn.commit()
        cur.close()
        return {"org_id": org_id, "new_trial_end_at": row[0].isoformat()}
    except HTTPException:
        conn.rollback()
        raise
    except Exception as exc:
        conn.rollback()
        logger.error("extend_trial failed org_id=%s: %s", org_id, exc)
        raise HTTPException(status_code=500, detail="Failed to extend trial")
    finally:
        put_write_conn(conn)


@router.patch("/orgs/{org_id}/suspend")
async def suspend_org(
    org_id: str,
    body: SuspendRequest,
    auth: Any = Depends(
        require_permission("platform:admin") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Suspend an org — sets status='suspended' in org_subscriptions.

    The Gateway's billing middleware will reject all API calls from a
    suspended org with HTTP 402. Writes platform_admin_audit.

    Requires platform:admin permission.

    Args:
        org_id: Target org UUID.
        body: SuspendRequest with optional reason.
        auth: AuthContext injected by require_permission.

    Returns:
        Confirmation dict.
    """
    admin_id = getattr(auth, "user_id", "unknown") if auth else "unknown"
    conn = get_write_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE org_subscriptions SET status = 'suspended', updated_at = now()
            WHERE org_id = %s
            """,
            (org_id,),
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Org subscription not found")

        _write_audit(cur, admin_id, "org.suspend", org_id, {"reason": body.reason})
        conn.commit()
        cur.close()
        return {"message": "Org suspended", "org_id": org_id}
    except HTTPException:
        conn.rollback()
        raise
    except Exception as exc:
        conn.rollback()
        logger.error("suspend_org failed org_id=%s: %s", org_id, exc)
        raise HTTPException(status_code=500, detail="Failed to suspend org")
    finally:
        put_write_conn(conn)


@router.patch("/orgs/{org_id}/unsuspend")
async def unsuspend_org(
    org_id: str,
    auth: Any = Depends(
        require_permission("platform:admin") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Restore a suspended org to 'active' status.

    Only applies if the current status is 'suspended'. Writes
    platform_admin_audit.

    Requires platform:admin permission.

    Args:
        org_id: Target org UUID.
        auth: AuthContext injected by require_permission.

    Returns:
        Confirmation dict.

    Raises:
        HTTPException: 404 if org not found or not currently suspended.
    """
    admin_id = getattr(auth, "user_id", "unknown") if auth else "unknown"
    conn = get_write_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE org_subscriptions
            SET status = 'active', updated_at = now()
            WHERE org_id = %s AND status = 'suspended'
            """,
            (org_id,),
        )
        if cur.rowcount == 0:
            raise HTTPException(
                status_code=404, detail="Org not found or not currently suspended"
            )

        _write_audit(cur, admin_id, "org.unsuspend", org_id, {})
        conn.commit()
        cur.close()
        return {"message": "Org unsuspended", "org_id": org_id}
    except HTTPException:
        conn.rollback()
        raise
    except Exception as exc:
        conn.rollback()
        logger.error("unsuspend_org failed org_id=%s: %s", org_id, exc)
        raise HTTPException(status_code=500, detail="Failed to unsuspend org")
    finally:
        put_write_conn(conn)
