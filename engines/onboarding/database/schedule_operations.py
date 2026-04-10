"""
Database operations for the schedules table.
"""
import json
import uuid
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from engine_onboarding.database.connection import get_db_connection


# ── Allowed update fields ─────────────────────────────────────────────────────
_ALLOWED_UPDATE = {
    "schedule_name", "cron_expression", "timezone", "enabled",
    "include_regions", "include_services", "exclude_services", "engines_requested",
    "next_run_at", "last_run_at", "run_count", "success_count", "failure_count",
    "notify_on_success", "notify_on_failure", "notification_emails",
    "updated_at",
}


def create_schedule(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a new scan schedule.

    Required: account_id, tenant_id, customer_id, cron_expression
    Optional: schedule_name, timezone, enabled, include_regions, include_services,
              exclude_services, engines_requested, notify_*, notification_emails,
              next_run_at
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        now = datetime.now(timezone.utc)
        default_engines = [
            "discovery", "check", "inventory",
            "threat", "compliance", "iam", "datasec",
        ]

        cur.execute(
            """
            INSERT INTO schedules (
                schedule_id, account_id, tenant_id, customer_id,
                schedule_name, cron_expression, timezone, enabled,
                include_regions, include_services, exclude_services, engines_requested,
                next_run_at,
                notify_on_success, notify_on_failure, notification_emails,
                created_at, updated_at
            ) VALUES (
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s, %s, %s, %s,
                %s,
                %s, %s, %s,
                %s, %s
            )
            RETURNING *
            """,
            (
                str(uuid.uuid4()),
                data["account_id"],
                data["tenant_id"],
                data["customer_id"],
                data.get("schedule_name"),
                data.get("cron_expression", "0 2 * * 0"),
                data.get("timezone", "UTC"),
                data.get("enabled", True),
                json.dumps(data["include_regions"]) if data.get("include_regions") is not None else None,
                json.dumps(data["include_services"]) if data.get("include_services") is not None else None,
                json.dumps(data["exclude_services"]) if data.get("exclude_services") is not None else None,
                json.dumps(data.get("engines_requested", default_engines)),
                data.get("next_run_at"),
                data.get("notify_on_success", False),
                data.get("notify_on_failure", True),
                json.dumps(data["notification_emails"]) if data.get("notification_emails") is not None else None,
                now,
                now,
            ),
        )
        row = cur.fetchone()
        conn.commit()
        return dict(row)
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def get_schedule(schedule_id: str) -> Optional[Dict[str, Any]]:
    """Get a schedule by UUID string."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            "SELECT s.*, ca.account_name, ca.provider FROM schedules s "
            "LEFT JOIN cloud_accounts ca ON ca.account_id = s.account_id "
            "WHERE s.schedule_id = %s",
            (schedule_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        cur.close()
        conn.close()


def list_schedules(
    account_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    enabled_only: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """List schedules with optional filters."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        query = (
            "SELECT s.*, ca.account_name, ca.provider "
            "FROM schedules s "
            "LEFT JOIN cloud_accounts ca ON ca.account_id = s.account_id "
            "WHERE 1=1 "
        )
        params: List[Any] = []

        if account_id:
            query += " AND s.account_id = %s"
            params.append(account_id)
        if tenant_id:
            query += " AND s.tenant_id = %s"
            params.append(tenant_id)
        if customer_id:
            query += " AND s.customer_id = %s"
            params.append(customer_id)
        if enabled_only:
            query += " AND s.enabled = true"

        query += " ORDER BY s.created_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        cur.execute(query, params)
        return [dict(row) for row in cur.fetchall()]
    finally:
        cur.close()
        conn.close()


def update_schedule(schedule_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Update allowed schedule fields."""
    fields = {k: v for k, v in updates.items() if k in _ALLOWED_UPDATE}
    if not fields:
        return get_schedule(schedule_id)

    fields.setdefault("updated_at", datetime.now(timezone.utc))

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        set_clause = ", ".join(f"{k} = %s" for k in fields)
        values = []
        for v in fields.values():
            values.append(json.dumps(v) if isinstance(v, (dict, list)) else v)
        values.append(schedule_id)

        cur.execute(
            f"UPDATE schedules SET {set_clause} WHERE schedule_id = %s RETURNING *",
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


def delete_schedule(schedule_id: str) -> bool:
    """Hard-delete a schedule."""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "DELETE FROM schedules WHERE schedule_id = %s RETURNING schedule_id",
            (schedule_id,),
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


def get_due_schedules(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Return schedules where enabled=true AND next_run_at <= NOW().
    Used by the scheduler service poll loop.
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            SELECT s.*, ca.provider, ca.credential_type, ca.credential_ref
            FROM schedules s
            JOIN cloud_accounts ca ON ca.account_id = s.account_id
            WHERE s.enabled = true
              AND s.next_run_at IS NOT NULL
              AND s.next_run_at <= NOW()
            ORDER BY s.next_run_at ASC
            LIMIT %s
            """,
            (limit,),
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        cur.close()
        conn.close()


def bump_schedule_after_run(
    schedule_id: str,
    success: bool,
    next_run_at: Optional[datetime] = None,
) -> None:
    """
    Increment run/success/failure counters and update last_run_at + next_run_at.
    Called by the scheduler after triggering an Argo workflow.
    """
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        now = datetime.now(timezone.utc)
        success_inc = 1 if success else 0
        failure_inc = 0 if success else 1
        cur.execute(
            """
            UPDATE schedules SET
                last_run_at   = %s,
                next_run_at   = %s,
                run_count     = run_count + 1,
                success_count = success_count + %s,
                failure_count = failure_count + %s,
                updated_at    = %s
            WHERE schedule_id = %s
            """,
            (now, next_run_at, success_inc, failure_inc, now, schedule_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()
