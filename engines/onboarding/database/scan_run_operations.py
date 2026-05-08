"""
Database operations for the scan_runs table.
Replaces the old scan_orchestration table.
"""
import json
import uuid
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from engine_onboarding.database.connection import get_db_connection


_ALLOWED_UPDATE = {
    "overall_status", "engines_completed", "engine_statuses",
    "results_summary", "error_details", "completed_at",
    "scan_name",
}


def create_scan_run(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a scan_run record at scan trigger time.

    Required: customer_id, tenant_id, account_id, provider, credential_type,
              credential_ref, engines_requested
    Optional: scan_run_id (auto-generated if absent), schedule_uuid, schedule_id,
              scan_type, trigger_type, scan_name, include_regions, include_services,
              exclude_services
    """
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        now = datetime.now(timezone.utc)
        scan_run_id = data.get("scan_run_id") or str(uuid.uuid4())

        cur.execute(
            """
            INSERT INTO scan_runs (
                scan_run_id,
                customer_id, tenant_id, account_id,
                schedule_id, schedule_uuid,
                provider, credential_type, credential_ref,
                scan_name, scan_type, trigger_type,
                include_regions, include_services, exclude_services,
                engines_requested,
                engines_completed, engine_statuses,
                overall_status,
                started_at, created_at
            ) VALUES (
                %s,
                %s, %s, %s,
                %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s, %s, %s,
                %s,
                '[]'::jsonb, '{}'::jsonb,
                'pending',
                %s, %s
            )
            RETURNING *
            """,
            (
                scan_run_id,
                data["customer_id"],
                data["tenant_id"],
                data.get("account_id"),
                data.get("schedule_id"),
                data.get("schedule_uuid"),
                data["provider"],
                data["credential_type"],
                data["credential_ref"],
                data.get("scan_name"),
                data.get("scan_type", "full"),
                data.get("trigger_type", "manual"),
                json.dumps(data["include_regions"]) if data.get("include_regions") else None,
                json.dumps(data["include_services"]) if data.get("include_services") else None,
                json.dumps(data["exclude_services"]) if data.get("exclude_services") else None,
                json.dumps(data.get("engines_requested", [])),
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


def get_scan_run(scan_run_id: str) -> Optional[Dict[str, Any]]:
    """Get a scan run by ID."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            SELECT sr.*, ca.account_name, ca.provider AS account_provider
            FROM scan_runs sr
            LEFT JOIN cloud_accounts ca ON ca.account_id = sr.account_id
            WHERE sr.scan_run_id = %s
            """,
            (scan_run_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        cur.close()
        conn.close()


def list_scan_runs(
    account_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> List[Dict[str, Any]]:
    """List scan runs with optional filters, most recent first."""
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        query = """
            SELECT sr.*, ca.account_name
            FROM scan_runs sr
            LEFT JOIN cloud_accounts ca ON ca.account_id = sr.account_id
            WHERE 1=1
        """
        params: List[Any] = []

        if account_id:
            query += " AND sr.account_id = %s"
            params.append(account_id)
        if tenant_id:
            query += " AND sr.tenant_id = %s"
            params.append(tenant_id)
        if customer_id:
            query += " AND sr.customer_id = %s"
            params.append(customer_id)
        if status:
            query += " AND sr.overall_status = %s"
            params.append(status)

        query += " ORDER BY sr.started_at DESC LIMIT %s OFFSET %s"
        params.extend([limit, offset])

        cur.execute(query, params)
        return [dict(row) for row in cur.fetchall()]
    finally:
        cur.close()
        conn.close()


def update_scan_run(scan_run_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Update scan run status/counters. Called by webhook or scheduler."""
    fields = {k: v for k, v in updates.items() if k in _ALLOWED_UPDATE}
    if not fields:
        return get_scan_run(scan_run_id)

    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        set_clause = ", ".join(f"{k} = %s" for k in fields)
        values = []
        for v in fields.values():
            values.append(json.dumps(v) if isinstance(v, (dict, list)) else v)
        values.append(scan_run_id)

        cur.execute(
            f"UPDATE scan_runs SET {set_clause} WHERE scan_run_id = %s RETURNING *",
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


def mark_scan_run_started(scan_run_id: str) -> None:
    """Set overall_status = running."""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE scan_runs SET overall_status = 'running', started_at = %s WHERE scan_run_id = %s",
            (datetime.now(timezone.utc), scan_run_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def mark_scan_run_completed(
    scan_run_id: str,
    success: bool,
    results_summary: Optional[Dict] = None,
    error_details: Optional[Dict] = None,
) -> None:
    """Set overall_status = completed / failed and stamp completed_at."""
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        status = "completed" if success else "failed"
        now = datetime.now(timezone.utc)
        cur.execute(
            """
            UPDATE scan_runs SET
                overall_status  = %s,
                completed_at    = %s,
                results_summary = %s,
                error_details   = %s
            WHERE scan_run_id = %s
            """,
            (
                status,
                now,
                json.dumps(results_summary or {}),
                json.dumps(error_details or {}),
                scan_run_id,
            ),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()
