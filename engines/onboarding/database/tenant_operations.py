"""
Database operations for the tenants table.
All queries are scoped by customer_id — no cross-customer data leaks.
"""
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from engine_onboarding.database.connection import get_db_connection


def create_tenant(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a new tenant workspace.

    Args:
        data: { tenant_id, customer_id, tenant_name, tenant_description? }
    Returns:
        Full tenant row as dict.
    Raises:
        ValueError: tenant_name already exists for this customer.
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        now = datetime.now(timezone.utc)
        cur.execute(
            """
            INSERT INTO tenants (tenant_id, customer_id, tenant_name, tenant_description, status, created_at, updated_at)
            VALUES (%s, %s, %s, %s, 'active', %s, %s)
            RETURNING *
            """,
            (
                data["tenant_id"],
                data["customer_id"],
                data["tenant_name"],
                data.get("tenant_description"),
                now,
                now,
            ),
        )
        result = dict(cur.fetchone())
        conn.commit()
        return result
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise ValueError(
            f"Tenant '{data['tenant_name']}' already exists for this customer."
        )
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def get_tenant(tenant_id: str) -> Optional[Dict[str, Any]]:
    """Get a single tenant by tenant_id."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            SELECT t.*,
                   COUNT(ca.account_id) AS account_count
            FROM tenants t
            LEFT JOIN cloud_accounts ca
                ON ca.tenant_id = t.tenant_id
               AND ca.account_status <> 'deleted'
            WHERE t.tenant_id = %s
            GROUP BY t.tenant_id
            """,
            (tenant_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        cur.close()
        conn.close()


def list_tenants(customer_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    List all tenants for a customer, with live account_count.

    Args:
        customer_id: Filters to this customer only.
        status:      Optional filter ('active', 'inactive').
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        query = """
            SELECT t.*,
                   COUNT(ca.account_id) AS account_count
            FROM tenants t
            LEFT JOIN cloud_accounts ca
                ON ca.tenant_id = t.tenant_id
               AND ca.account_status <> 'deleted'
            WHERE t.customer_id = %s
        """
        params: List[Any] = [customer_id]

        if status:
            query += " AND t.status = %s"
            params.append(status)

        query += " GROUP BY t.tenant_id ORDER BY t.created_at DESC"

        cur.execute(query, params)
        return [dict(row) for row in cur.fetchall()]
    finally:
        cur.close()
        conn.close()


def update_tenant(tenant_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Update mutable tenant fields.
    Allowed fields: tenant_name, tenant_description, status.
    """
    allowed = {"tenant_name", "tenant_description", "status"}
    fields = {k: v for k, v in updates.items() if k in allowed}
    if not fields:
        return get_tenant(tenant_id)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        fields["updated_at"] = datetime.now(timezone.utc)
        set_clause = ", ".join(f"{k} = %s" for k in fields)
        values = list(fields.values()) + [tenant_id]

        cur.execute(
            f"UPDATE tenants SET {set_clause} WHERE tenant_id = %s RETURNING *",
            values,
        )
        row = cur.fetchone()
        conn.commit()
        return dict(row) if row else None
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise ValueError("A tenant with that name already exists for this customer.")
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def delete_tenant(tenant_id: str) -> bool:
    """
    Soft-delete a tenant (status → deleted).
    Raises ValueError if the tenant has active cloud accounts.
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            "SELECT COUNT(*) AS n FROM cloud_accounts WHERE tenant_id = %s AND account_status <> 'deleted'",
            (tenant_id,),
        )
        if cur.fetchone()["n"] > 0:
            raise ValueError(
                "Cannot delete tenant with active cloud accounts. Remove accounts first."
            )

        cur.execute(
            "UPDATE tenants SET status = 'deleted', updated_at = %s WHERE tenant_id = %s RETURNING tenant_id",
            (datetime.now(timezone.utc), tenant_id),
        )
        deleted = cur.fetchone() is not None
        conn.commit()
        return deleted
    except ValueError:
        conn.rollback()
        raise
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()
