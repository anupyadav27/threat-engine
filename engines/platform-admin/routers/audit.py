"""
Platform Admin Engine — Audit log router.

GET /api/v1/padmin/audit-log

Returns the most recent platform_admin_audit rows. Supports filtering by
org_id, action, and admin_user_id. Requires platform:admin permission.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from db import get_conn, put_conn

try:
    from engine_auth.fastapi.dependencies import require_permission  # type: ignore
    _AUTH_AVAILABLE = True
except ImportError:
    _AUTH_AVAILABLE = False

logger = logging.getLogger(__name__)
router = APIRouter(tags=["audit"])


@router.get("/audit-log")
async def get_audit_log(
    org_id: Optional[str] = Query(None, description="Filter by target org_id"),
    action: Optional[str] = Query(None, description="Filter by action string prefix"),
    admin_user_id: Optional[str] = Query(None, description="Filter by admin user ID"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    auth: Any = Depends(
        require_permission("platform:admin") if _AUTH_AVAILABLE else (lambda: None)
    ),
) -> Dict[str, Any]:
    """Return recent platform_admin_audit entries.

    Reads from billing_readonly pool. All timestamps are returned as ISO
    8601 strings.

    Requires platform:admin permission.

    Args:
        org_id: Filter to a specific target org.
        action: LIKE prefix filter on the action column.
        admin_user_id: Filter to a specific admin actor.
        limit: Page size (default 100, max 1000).
        offset: Page offset.
        auth: AuthContext injected by require_permission.

    Returns:
        Dict with 'entries' list and 'total' count.
    """
    conn = get_conn()
    try:
        cur = conn.cursor()

        where_clauses: List[str] = []
        params: List[Any] = []

        if org_id:
            where_clauses.append("target_org_id = %s")
            params.append(org_id)
        if action:
            where_clauses.append("action LIKE %s")
            params.append(f"{action}%")
        if admin_user_id:
            where_clauses.append("admin_user_id = %s")
            params.append(admin_user_id)

        where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

        cur.execute(
            f"""
            SELECT
                audit_id,
                admin_user_id,
                action,
                target_org_id,
                target_entity,
                payload,
                created_at
            FROM platform_admin_audit
            {where_sql}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
            """,
            params + [limit, offset],
        )
        rows = cur.fetchall()
        cols = [d[0] for d in cur.description]

        entries: List[Dict[str, Any]] = []
        for row in rows:
            entry: Dict[str, Any] = {}
            for key, val in zip(cols, row):
                if hasattr(val, "isoformat"):
                    entry[key] = val.isoformat()
                else:
                    entry[key] = val
            entries.append(entry)

        cur.close()
        return {"entries": entries, "total": len(entries)}
    except Exception as exc:
        logger.error("get_audit_log failed: %s", exc)
        raise HTTPException(status_code=500, detail="Failed to retrieve audit log")
    finally:
        put_conn(conn)
