"""
Database operations for the cloud_accounts table.
Schema after migration 004: no schedule_* columns, tenant_id FK to tenants.
"""
import json
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from engine_onboarding.database.connection import get_db_connection


def create_cloud_account(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a new cloud account (Phase 1 of onboarding).

    Required keys: account_id, customer_id, tenant_id, account_name, provider
    Optional keys: account_number, credential_type, credential_ref,
                   account_status, onboarding_status
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        now = datetime.now(timezone.utc)
        cur.execute(
            """
            INSERT INTO cloud_accounts (
                account_id, customer_id, tenant_id,
                account_name, account_number, account_hierarchy_name,
                provider,
                credential_type, credential_ref,
                account_status, account_onboarding_status,
                credential_validation_status,
                created_at, updated_at
            ) VALUES (
                %s, %s, %s,
                %s, %s, %s,
                %s,
                %s, %s,
                %s, %s,
                'pending',
                %s, %s
            )
            RETURNING *
            """,
            (
                data["account_id"],
                data["customer_id"],
                data["tenant_id"],
                data["account_name"],
                data.get("account_number"),
                data.get("account_hierarchy_name"),
                data["provider"],
                data.get("credential_type", "pending"),
                data.get("credential_ref", "pending"),
                data.get("account_status", "pending"),
                data.get("onboarding_status", "pending"),
                now,
                now,
            ),
        )
        result = dict(cur.fetchone())
        conn.commit()
        return result
    except psycopg2.errors.UniqueViolation:
        conn.rollback()
        raise ValueError(f"Account '{data['account_name']}' already exists for this tenant.")
    except psycopg2.errors.ForeignKeyViolation:
        conn.rollback()
        raise ValueError(f"Tenant '{data['tenant_id']}' does not exist. Create the tenant first.")
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def get_cloud_account(account_id: str) -> Optional[Dict[str, Any]]:
    """
    Get a cloud account by ID, enriched with tenant_name and active schedule.
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            SELECT ca.*,
                   t.tenant_name,
                   s.schedule_id,
                   s.cron_expression      AS schedule_cron_expression,
                   s.enabled              AS schedule_enabled,
                   s.next_run_at          AS schedule_next_run_at,
                   s.last_run_at          AS schedule_last_run_at,
                   s.run_count            AS schedule_run_count,
                   s.success_count        AS schedule_success_count,
                   s.failure_count        AS schedule_failure_count
            FROM cloud_accounts ca
            LEFT JOIN tenants t ON t.tenant_id = ca.tenant_id
            LEFT JOIN LATERAL (
                SELECT * FROM schedules
                WHERE account_id = ca.account_id
                ORDER BY created_at DESC
                LIMIT 1
            ) s ON true
            WHERE ca.account_id = %s
            """,
            (account_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        cur.close()
        conn.close()


def list_cloud_accounts(
    filters: Optional[Dict[str, Any]] = None,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """
    List cloud accounts with optional filters and pagination.
    Enriches each row with tenant_name and latest schedule info.
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        query = """
            SELECT ca.*,
                   t.tenant_name,
                   s.schedule_id,
                   s.cron_expression  AS schedule_cron_expression,
                   s.enabled          AS schedule_enabled,
                   s.next_run_at      AS schedule_next_run_at
            FROM cloud_accounts ca
            LEFT JOIN tenants t ON t.tenant_id = ca.tenant_id
            LEFT JOIN LATERAL (
                SELECT * FROM schedules
                WHERE account_id = ca.account_id
                ORDER BY created_at DESC
                LIMIT 1
            ) s ON true
            WHERE ca.account_status <> 'deleted'
        """
        params: List[Any] = []

        if filters:
            if "customer_id" in filters:
                query += " AND ca.customer_id = %s"
                params.append(filters["customer_id"])
            if "tenant_id" in filters:
                query += " AND ca.tenant_id = %s"
                params.append(filters["tenant_id"])
            if "provider" in filters:
                query += " AND ca.provider = %s"
                params.append(filters["provider"])
            if "account_status" in filters:
                query += " AND ca.account_status = %s"
                params.append(filters["account_status"])
            if "onboarding_status" in filters:
                query += " AND ca.account_onboarding_status = %s"
                params.append(filters["onboarding_status"])

        query += " ORDER BY ca.created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        cur.execute(query, params)
        return [dict(row) for row in cur.fetchall()]
    finally:
        cur.close()
        conn.close()


def update_cloud_account(
    account_id: str, updates: Dict[str, Any]
) -> Optional[Dict[str, Any]]:
    """
    Update allowed cloud account fields.
    Skips unknown / read-only columns automatically.
    """
    # Columns that exist in the new schema
    allowed = {
        "account_name", "account_number", "account_hierarchy_name",
        "provider", "credential_type", "credential_ref",
        "account_status", "account_onboarding_status", "account_onboarding_id",
        "account_last_validated_at",
        "credential_validation_status", "credential_validation_message",
        "credential_validated_at", "credential_validation_errors",
        "log_sources", "last_scan_at", "updated_at",
    }
    fields = {k: v for k, v in updates.items() if k in allowed}
    if not fields:
        return get_cloud_account(account_id)

    fields.setdefault("updated_at", datetime.now(timezone.utc))

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        set_clause = ", ".join(f"{k} = %s" for k in fields)
        values = []
        for v in fields.values():
            values.append(json.dumps(v) if isinstance(v, (dict, list)) else v)
        values.append(account_id)

        cur.execute(
            f"UPDATE cloud_accounts SET {set_clause} WHERE account_id = %s RETURNING *",
            values,
        )
        row = cur.fetchone()
        conn.commit()
        return dict(row) if row else None
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def soft_delete_cloud_account(account_id: str) -> bool:
    """Soft-delete — sets account_status = 'deleted'."""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE cloud_accounts SET account_status = 'deleted', updated_at = %s WHERE account_id = %s RETURNING account_id",
            (datetime.now(timezone.utc), account_id),
        )
        deleted = cur.fetchone() is not None
        conn.commit()
        return deleted
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


# Keep old name as alias so existing callers don't break
def delete_cloud_account(account_id: str) -> bool:
    return soft_delete_cloud_account(account_id)
