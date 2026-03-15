"""
Users API stub — user management lives in the Django CSPM backend.
This endpoint returns tenant-scoped users derived from cloud_accounts owners
until the UI is updated to call the CSPM backend directly.
"""
from fastapi import APIRouter, Query
from typing import Optional

try:
    from engine_common.logger import setup_logger
    logger = setup_logger(__name__, engine_name="onboarding")
except ImportError:
    import logging
    logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["users"])


@router.get("/users")
async def list_users(
    tenant_id: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
):
    """
    List platform users for the tenant.

    NOTE: Full user management is handled by the Django CSPM backend.
    This endpoint returns a minimal placeholder so the Settings > Users page
    renders without error. Wire to /cspm/api/users/ for full RBAC data.
    """
    try:
        import psycopg2
        from psycopg2.extras import RealDictCursor
        from engine_onboarding.database.connection_config.database_config import get_connection_string

        users = []
        conn = psycopg2.connect(get_connection_string("onboarding"))
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT DISTINCT
                        account_name,
                        provider,
                        created_by,
                        created_at,
                        account_status
                    FROM cloud_accounts
                    WHERE tenant_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s
                    """,
                    (tenant_id, limit),
                )
                rows = cur.fetchall()
        finally:
            conn.close()

        for r in rows:
            creator = r.get("created_by") or "system"
            users.append({
                "id": creator,
                "name": creator.replace("_", " ").title(),
                "email": f"{creator}@tenant.local",
                "role": "tenant_admin",
                "status": "active" if r.get("account_status") == "active" else "inactive",
                "last_login": (r.get("created_at") or "").isoformat()
                    if hasattr(r.get("created_at"), "isoformat") else str(r.get("created_at") or ""),
            })

        # Deduplicate by email
        seen = set()
        unique_users = []
        for u in users:
            if u["email"] not in seen:
                seen.add(u["email"])
                unique_users.append(u)

    except Exception as exc:
        logger.warning("users endpoint: DB query failed: %s", exc)
        unique_users = []

    return {"users": unique_users, "total": len(unique_users)}
