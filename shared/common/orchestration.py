"""
Orchestration metadata helper for engines.

Allows engines to receive ONLY scan_run_id and query
all other metadata from scan_orchestration table (single source of truth).

This eliminates parameter passing errors and ensures consistency.
"""
import psycopg2
import os
from typing import Dict, Any, Optional


def _get_orchestration_conn():
    """Return a psycopg2 connection to scan_orchestration in threat_engine_onboarding."""
    return psycopg2.connect(
        host=os.getenv("ONBOARDING_DB_HOST"),
        port=int(os.getenv("ONBOARDING_DB_PORT", "5432")),
        database=os.getenv("ONBOARDING_DB_NAME", "threat_engine_onboarding"),
        user=os.getenv("ONBOARDING_DB_USER", "postgres"),
        password=os.getenv("ONBOARDING_DB_PASSWORD"),
    )


def get_orchestration_metadata(scan_run_id: str) -> Dict[str, Any]:
    """
    Get complete orchestration metadata from scan_orchestration table.

    Reads from threat_engine_onboarding (scan_orchestration table).

    Args:
        scan_run_id: Scan run UUID (pipeline-wide identifier)

    Returns:
        Dictionary with all orchestration metadata:
        {
            "scan_run_id": "...",
            "tenant_id": "...",
            "account_id": "...",
            "provider_type": "...",  <- CSP (aws / azure / gcp / ...)
            "status": "...",
            "first_seen_at": "...",
            "completed_at": "...",
        }

    Raises:
        ValueError: If scan_run_id not found in database
    """
    conn = _get_orchestration_conn()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT
                scan_run_id,
                tenant_id,
                account_id,
                provider,
                overall_status,
                started_at,
                completed_at,
                credential_type,
                credential_ref,
                include_services,
                include_regions
            FROM scan_orchestration
            WHERE scan_run_id = %s::uuid
        """, (scan_run_id,))

        row = cursor.fetchone()
        if not row:
            raise ValueError(f"Scan run ID {scan_run_id} not found in scan_orchestration table")

        sid = str(row[0])
        return {
            "scan_run_id": sid,
            "discovery_scan_run_id": sid,  # alias — check engine uses this
            "discovery_scan_id": sid,      # alias — inventory engine uses this
            "tenant_id": row[1],
            "account_id": row[2],
            "provider_type": row[3],   # alias kept for callers
            "provider": row[3],
            "status": row[4],          # alias kept for callers
            "overall_status": row[4],
            "first_seen_at": row[5].isoformat() if row[5] else None,
            "completed_at": row[6].isoformat() if row[6] else None,
            "credential_type": row[7],
            "credential_ref": row[8],
            "include_services": row[9],
            "include_regions": row[10],
        }
    finally:
        cursor.close()
        conn.close()
