"""
Billing Engine — Subscription plan CRUD endpoints.

GET    /api/v1/billing/plans              — public, no auth required
GET    /api/v1/billing/plans/{plan_id}    — public, no auth required
POST   /api/v1/billing/plans              — platform:admin only
PATCH  /api/v1/billing/plans/{plan_id}    — platform:admin only
DELETE /api/v1/billing/plans/{plan_id}    — platform:admin only (soft delete)
"""

import json
import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException

from db import get_conn, put_conn
from models import CreatePlanRequest, UpdatePlanRequest
from _schemas import BillingLenientResponse

try:
    from engine_auth.fastapi.dependencies import require_permission
    from engine_auth.core.models import AuthContext
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False
    AuthContext = None  # type: ignore[assignment,misc]

logger = logging.getLogger(__name__)
router = APIRouter(tags=["plans"])

# Column list shared by list/get queries
_PLAN_COLS = (
    "plan_id",
    "plan_name",
    "display_name",
    "price_monthly",
    "price_annual",
    "stripe_price_id",
    "max_accounts",
    "max_users",
    "scan_freq_per_day",
    "data_retention_days",
    "engine_allowlist",
    "is_active",
    "is_public",
    "sort_order",
    "created_at",
    "updated_at",
)


def _row_to_dict(row: tuple, cols: list) -> Dict[str, Any]:
    """Convert a DB row tuple to a dict, serialising non-JSON-safe types.

    Args:
        row: Raw psycopg2 result tuple.
        cols: Column name list from cursor.description.

    Returns:
        Dict with string-safe values.
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


@router.get("/plans", response_model=BillingLenientResponse, response_model_exclude_none=False)
async def list_plans() -> Dict[str, Any]:
    """Return all active public subscription plans ordered by sort_order.

    No authentication required — used by the pricing page.

    Returns:
        Dict containing a 'plans' list.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT plan_id, plan_name, display_name, price_monthly, price_annual,
                   stripe_price_id, max_accounts, max_users, scan_freq_per_day,
                   data_retention_days, engine_allowlist, is_active, is_public,
                   sort_order, created_at, updated_at
            FROM subscription_plans
            WHERE is_active = true AND is_public = true
            ORDER BY sort_order
            """
        )
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        cur.close()
        return {"plans": [_row_to_dict(r, cols) for r in rows]}
    except Exception as exc:
        logger.error("list_plans failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to retrieve plans")
    finally:
        put_conn(conn)


@router.get("/plans/{plan_id}", response_model=BillingLenientResponse, response_model_exclude_none=False)
async def get_plan(plan_id: str) -> Dict[str, Any]:
    """Return a single subscription plan by plan_id.

    Args:
        plan_id: UUID string of the plan.

    Returns:
        Plan dict.

    Raises:
        HTTPException: 404 if plan not found.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT plan_id, plan_name, display_name, price_monthly, price_annual,
                   stripe_price_id, max_accounts, max_users, scan_freq_per_day,
                   data_retention_days, engine_allowlist, is_active, is_public,
                   sort_order, created_at, updated_at
            FROM subscription_plans
            WHERE plan_id = %s
            """,
            (plan_id,),
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Plan not found")
        cols = [d[0] for d in cur.description]
        cur.close()
        return _row_to_dict(row, cols)
    except HTTPException:
        raise
    except Exception as exc:
        logger.error("get_plan failed plan_id=%s: %s", plan_id, exc)
        raise HTTPException(status_code=500, detail="Failed to retrieve plan")
    finally:
        put_conn(conn)


@router.post("/plans", status_code=201)
async def create_plan(
    body: CreatePlanRequest,
    auth: Any = Depends(require_permission("platform:admin") if _AUTH_AVAILABLE else (lambda: None)),
) -> Dict[str, Any]:
    """Create a new subscription plan.

    Requires platform:admin permission.

    Args:
        body: CreatePlanRequest with plan fields.
        auth: AuthContext injected by require_permission.

    Returns:
        Created plan dict with HTTP 201.

    Raises:
        HTTPException: 409 if plan_name already exists.
    """
    engine_allowlist = body.engine_allowlist or [
        "discoveries", "check", "threat", "inventory", "compliance",
        "iam", "ciem", "network-security", "risk",
    ]
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO subscription_plans
                (plan_name, display_name, price_monthly, price_annual,
                 max_accounts, max_users, scan_freq_per_day,
                 data_retention_days, engine_allowlist, sort_order, is_public)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING plan_id, plan_name, display_name, price_monthly, price_annual,
                      stripe_price_id, max_accounts, max_users, scan_freq_per_day,
                      data_retention_days, engine_allowlist, is_active, is_public,
                      sort_order, created_at, updated_at
            """,
            (
                body.plan_name,
                body.display_name,
                body.price_monthly,
                body.price_annual,
                body.max_accounts,
                body.max_users,
                body.scan_freq_per_day,
                body.data_retention_days,
                json.dumps(engine_allowlist),
                body.sort_order,
                body.is_public,
            ),
        )
        row = cur.fetchone()
        cols = [d[0] for d in cur.description]
        conn.commit()
        cur.close()
        return _row_to_dict(row, cols)
    except Exception as exc:
        conn.rollback()
        err_str = str(exc)
        if "uq_plan_name" in err_str or "unique" in err_str.lower():
            raise HTTPException(status_code=409, detail="Plan name already exists")
        logger.error("create_plan failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to create plan")
    finally:
        put_conn(conn)


@router.patch("/plans/{plan_id}")
async def update_plan(
    plan_id: str,
    body: UpdatePlanRequest,
    auth: Any = Depends(require_permission("platform:admin") if _AUTH_AVAILABLE else (lambda: None)),
) -> Dict[str, Any]:
    """Partially update a subscription plan.

    Only fields present in the request body are updated.
    Requires platform:admin permission.

    Args:
        plan_id: UUID string of the plan to update.
        body: UpdatePlanRequest with optional fields.
        auth: AuthContext injected by require_permission.

    Returns:
        Updated plan dict.

    Raises:
        HTTPException: 404 if plan not found.
    """
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields provided for update")

    set_clauses = []
    values = []
    for field, value in updates.items():
        if field == "engine_allowlist":
            set_clauses.append(f"{field} = %s")
            values.append(json.dumps(value))
        else:
            set_clauses.append(f"{field} = %s")
            values.append(value)

    set_clauses.append("updated_at = now()")
    values.append(plan_id)

    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            f"""
            UPDATE subscription_plans
            SET {", ".join(set_clauses)}
            WHERE plan_id = %s
            RETURNING plan_id, plan_name, display_name, price_monthly, price_annual,
                      stripe_price_id, max_accounts, max_users, scan_freq_per_day,
                      data_retention_days, engine_allowlist, is_active, is_public,
                      sort_order, created_at, updated_at
            """,
            values,
        )
        row = cur.fetchone()
        if not row:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Plan not found")
        cols = [d[0] for d in cur.description]
        conn.commit()
        cur.close()
        return _row_to_dict(row, cols)
    except HTTPException:
        raise
    except Exception as exc:
        conn.rollback()
        logger.error("update_plan failed plan_id=%s: %s", plan_id, exc)
        raise HTTPException(status_code=500, detail="Failed to update plan")
    finally:
        put_conn(conn)


@router.delete("/plans/{plan_id}", status_code=204)
async def deactivate_plan(
    plan_id: str,
    auth: Any = Depends(require_permission("platform:admin") if _AUTH_AVAILABLE else (lambda: None)),
) -> None:
    """Soft-delete a plan by setting is_active=false.

    Requires platform:admin permission. Does not physically delete the row
    so existing subscriptions remain referentially intact.

    Args:
        plan_id: UUID string of the plan to deactivate.
        auth: AuthContext injected by require_permission.

    Raises:
        HTTPException: 404 if plan not found.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE subscription_plans SET is_active = false, updated_at = now() WHERE plan_id = %s",
            (plan_id,),
        )
        if cur.rowcount == 0:
            conn.rollback()
            raise HTTPException(status_code=404, detail="Plan not found")
        conn.commit()
        cur.close()
    except HTTPException:
        raise
    except Exception as exc:
        conn.rollback()
        logger.error("deactivate_plan failed plan_id=%s: %s", plan_id, exc)
        raise HTTPException(status_code=500, detail="Failed to deactivate plan")
    finally:
        put_conn(conn)
