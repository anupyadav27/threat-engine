"""
Database operations for cloud_accounts table
"""
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
import json

from engine_onboarding.database.connection import get_db_connection


def create_cloud_account(account_data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new cloud account"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        # Required fields
        account_id = account_data['account_id']
        customer_id = account_data['customer_id']
        tenant_id = account_data['tenant_id']
        account_name = account_data['account_name']
        provider = account_data['provider']

        # Optional fields with defaults
        credential_type = account_data.get('credential_type', 'iam_role')
        credential_ref = account_data.get('credential_ref', 'pending')
        account_status = account_data.get('account_status', 'pending')
        account_onboarding_status = account_data.get('account_onboarding_status', 'pending')

        cur.execute("""
            INSERT INTO cloud_accounts (
                account_id, customer_id, customer_email, tenant_id, tenant_name,
                account_name, provider, credential_type, credential_ref,
                account_status, account_onboarding_status,
                credential_validation_status, created_at, updated_at
            ) VALUES (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s,
                %s, %s, %s
            )
            RETURNING *
        """, (
            account_id,
            customer_id,
            account_data.get('customer_email', ''),
            tenant_id,
            account_data.get('tenant_name', ''),
            account_name,
            provider,
            credential_type,
            credential_ref,
            account_status,
            account_onboarding_status,
            'pending',
            datetime.now(timezone.utc),
            datetime.now(timezone.utc)
        ))

        account = dict(cur.fetchone())
        conn.commit()
        return account

    except psycopg2.IntegrityError as e:
        conn.rollback()
        raise ValueError(f"Account {account_id} already exists")
    except Exception as e:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def get_cloud_account(account_id: str) -> Optional[Dict[str, Any]]:
    """Get cloud account by ID"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        cur.execute("SELECT * FROM cloud_accounts WHERE account_id = %s", (account_id,))
        result = cur.fetchone()
        return dict(result) if result else None
    finally:
        cur.close()
        conn.close()


def list_cloud_accounts(filters: Optional[Dict[str, Any]] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """List cloud accounts with optional filters"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        query = "SELECT * FROM cloud_accounts WHERE 1=1"
        params = []

        if filters:
            if 'customer_id' in filters:
                query += " AND customer_id = %s"
                params.append(filters['customer_id'])
            if 'tenant_id' in filters:
                query += " AND tenant_id = %s"
                params.append(filters['tenant_id'])
            if 'provider' in filters:
                query += " AND provider = %s"
                params.append(filters['provider'])
            if 'account_status' in filters:
                query += " AND account_status = %s"
                params.append(filters['account_status'])

        query += " ORDER BY created_at DESC LIMIT %s"
        params.append(limit)

        cur.execute(query, params)
        results = cur.fetchall()
        return [dict(row) for row in results]
    finally:
        cur.close()
        conn.close()


def update_cloud_account(account_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Update cloud account"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        # Build dynamic UPDATE query
        set_clauses = []
        params = []

        for key, value in updates.items():
            if key == 'account_id':
                continue  # Skip primary key
            set_clauses.append(f"{key} = %s")
            # Handle JSON fields
            if isinstance(value, (list, dict)):
                params.append(json.dumps(value))
            else:
                params.append(value)

        if not set_clauses:
            return get_cloud_account(account_id)

        # Add updated_at
        if 'updated_at' not in updates:
            set_clauses.append("updated_at = %s")
            params.append(datetime.now(timezone.utc))

        params.append(account_id)

        query = f"""
            UPDATE cloud_accounts
            SET {', '.join(set_clauses)}
            WHERE account_id = %s
            RETURNING *
        """

        cur.execute(query, params)
        result = cur.fetchone()
        conn.commit()

        return dict(result) if result else None

    except Exception as e:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def delete_cloud_account(account_id: str) -> bool:
    """Hard delete cloud account (use with caution)"""
    conn = get_db_connection()
    cur = conn.cursor()

    try:
        cur.execute("DELETE FROM cloud_accounts WHERE account_id = %s RETURNING account_id", (account_id,))
        result = cur.fetchone()
        conn.commit()
        return result is not None
    except Exception as e:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def get_accounts_for_scheduling() -> List[Dict[str, Any]]:
    """Get accounts that are ready for scheduled scans"""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        cur.execute("""
            SELECT * FROM cloud_accounts
            WHERE account_status = 'active'
              AND schedule_enabled = true
              AND schedule_next_run_at <= NOW()
            ORDER BY schedule_next_run_at ASC
        """)
        results = cur.fetchall()
        return [dict(row) for row in results]
    finally:
        cur.close()
        conn.close()
