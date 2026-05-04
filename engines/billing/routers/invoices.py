"""
Billing Engine — Invoice history endpoints.

GET /api/v1/billing/invoices   — last N invoices for an org
"""

import logging
from typing import Any, Dict

from fastapi import APIRouter, Depends, Query

from db import get_conn, put_conn

try:
    from engine_auth.fastapi.dependencies import require_permission
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

logger = logging.getLogger(__name__)
router = APIRouter(tags=["invoices"])


@router.get("/invoices")
async def list_invoices(
    org_id: str = Query(..., description="Organisation UUID"),
    limit: int = Query(10, ge=1, le=100),
    auth: Any = Depends(
        require_permission("billing:read") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Return the most recent invoices for an organisation.

    Args:
        org_id: Organisation identifier.
        limit: Max rows to return (default 10).
        auth: AuthContext injected by require_permission.

    Returns:
        Dict with 'invoices' list.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT invoice_id, org_id, amount, currency, status,
                   period_start, period_end, created_at, hosted_invoice_url
            FROM billing_invoices
            WHERE org_id = %s
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (org_id, limit),
        )
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]
        invoices = []
        for row in rows:
            d: Dict[str, Any] = {}
            for key, val in zip(cols, row):
                if hasattr(val, "isoformat"):
                    d[key] = val.isoformat()
                else:
                    d[key] = val
            invoices.append({
                "id":                 d.get("invoice_id", ""),
                "date":               d.get("created_at", ""),
                "amount":             d.get("amount", 0),
                "currency":           (d.get("currency") or "USD").upper(),
                "status":             d.get("status", "paid"),
                "hosted_invoice_url": d.get("hosted_invoice_url", ""),
                "period_start":       d.get("period_start", ""),
                "period_end":         d.get("period_end", ""),
            })
        cur.close()
        return {"invoices": invoices}
    except Exception as exc:
        logger.warning("list_invoices failed org_id=%s: %s", org_id, exc)
        return {"invoices": []}
    finally:
        put_conn(conn)
