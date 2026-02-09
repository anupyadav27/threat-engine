"""
SecOps DB - Persist scans/findings to engine_secops schema (consolidated DB).
Uses ONLY consolidated database system from consolidated_services/database.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    psycopg2 = None
    RealDictCursor = None

# Import local database config
from database.connection.database_config import get_database_config


def _conn():
    """Get database connection using consolidated database system."""
    if not psycopg2:
        raise RuntimeError("psycopg2 must be installed")
    
    # Get shared database config (secops uses shared DB with engine_secops schema)
    try:
        db_config = get_database_config("shared")
    except Exception as e:
        raise RuntimeError(f"Failed to get consolidated DB config: {e}") from e
    
    conn = psycopg2.connect(
        host=db_config.host,
        port=db_config.port,
        dbname=db_config.database,
        user=db_config.username,
        password=db_config.password,
        keepalives=1,
        keepalives_idle=30,
        keepalives_interval=10,
        keepalives_count=5,
    )
    
    # Set schema search_path for engine_secops and engine_shared
    schema = os.getenv("DB_SCHEMA", "engine_secops,engine_shared")
    parts = [p.strip() for p in schema.split(",") if p.strip()]
    if parts:
        with conn.cursor() as cur:
            cur.execute(
                "SET search_path TO %s" % ", ".join(["%s"] * len(parts)),
                tuple(parts),
            )
    return conn


def persist_scan(
    scan_id: str,
    tenant_id: str,
    project_name: str,
    status: str,
    started_at: datetime,
    completed_at: Optional[datetime],
    customer_id: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    """Insert secops_scans row."""
    conn = _conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO engine_secops.secops_scans
                (scan_id, tenant_id, customer_id, project_name, status, started_at, completed_at, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (scan_id) DO UPDATE SET
                    status = EXCLUDED.status,
                    completed_at = EXCLUDED.completed_at,
                    metadata = EXCLUDED.metadata
                """,
                (
                    scan_id,
                    tenant_id,
                    customer_id,
                    project_name,
                    status,
                    started_at,
                    completed_at,
                    json.dumps(metadata or {}, default=str),
                ),
            )
        conn.commit()
    finally:
        conn.close()


def persist_findings(
    scan_id: str,
    tenant_id: str,
    project_name: str,
    results: List[Dict[str, Any]],
    customer_id: Optional[str] = None,
) -> int:
    """Insert secops_findings from scan results. Returns count inserted."""
    count = 0
    conn = _conn()
    try:
        with conn.cursor() as cur:
            for item in results:
                file_path = item.get("file", "")
                findings = item.get("findings") or []
                for f in findings:
                    rule_id = f.get("rule_id") or "unknown"
                    severity = f.get("severity") or "medium"
                    message = f.get("message") or ""
                    meta = {k: v for k, v in f.items() if k not in ("rule_id", "severity", "message")}
                    cur.execute(
                        """
                        INSERT INTO engine_secops.secops_findings
                        (scan_id, tenant_id, customer_id, rule_id, severity, file_path, message, metadata)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            scan_id,
                            tenant_id,
                            customer_id,
                            rule_id,
                            severity,
                            file_path,
                            message,
                            json.dumps(meta, default=str),
                        ),
                    )
                    count += 1
        conn.commit()
    finally:
        conn.close()
    return count


def _row_to_dict(row: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for k, v in row.items():
        if hasattr(v, "isoformat"):
            out[k] = v.isoformat()
        else:
            out[k] = v
    return out


def list_scans(
    tenant_id: Optional[str] = None,
    customer_id: Optional[str] = None,
    scan_id: Optional[str] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List secops scans with optional filters."""
    conn = _conn()
    try:
        q = "SELECT * FROM engine_secops.secops_scans WHERE 1=1"
        params: List[Any] = []
        if tenant_id:
            q += " AND tenant_id = %s"
            params.append(tenant_id)
        if customer_id:
            q += " AND customer_id = %s"
            params.append(customer_id)
        if scan_id:
            q += " AND scan_id = %s"
            params.append(scan_id)
        q += " ORDER BY started_at DESC LIMIT %s"
        params.append(limit)
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(q, params)
            return [_row_to_dict(dict(r)) for r in cur.fetchall()]
    finally:
        conn.close()


def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    """Get single scan by scan_id."""
    rows = list_scans(scan_id=scan_id, limit=1)
    return rows[0] if rows else None


def get_findings(scan_id: str, limit: int = 500) -> List[Dict[str, Any]]:
    """Get findings for a scan."""
    conn = _conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, scan_id, tenant_id, customer_id, rule_id, severity, file_path, message, metadata, created_at
                FROM engine_secops.secops_findings
                WHERE scan_id = %s
                ORDER BY severity DESC, id
                LIMIT %s
                """,
                (scan_id, limit),
            )
            return [_row_to_dict(dict(r)) for r in cur.fetchall()]
    finally:
        conn.close()
