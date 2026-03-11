"""
Orchestration metadata helper for engines.

Allows engines to receive ONLY orchestration_id or engine_scan_id and query
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


def get_orchestration_metadata(orchestration_id: str) -> Dict[str, Any]:
    """
    Get complete orchestration metadata from scan_orchestration table.

    Reads from threat_engine_onboarding (scan_orchestration table).

    Args:
        orchestration_id: Orchestration UUID

    Returns:
        Dictionary with all orchestration metadata:
        {
            "orchestration_id": "...",
            "tenant_id": "...",
            "account_id": "...",
            "provider_type": "...",  ← CSP (aws / azure / gcp / …)
            "status": "...",
            "discovery_scan_id": "...",
            "check_scan_id": "...",
            "threat_scan_id": "...",
            "compliance_scan_id": "...",
            "iam_scan_id": "...",
            "datasec_scan_id": "...",
            "inventory_scan_id": "...",
            "started_at": "...",
            "completed_at": "...",
            "updated_at": "..."
        }

    Raises:
        ValueError: If orchestration_id not found in database
    """
    conn = _get_orchestration_conn()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT
                orchestration_id,
                tenant_id,
                account_id,
                provider,
                overall_status,
                discovery_scan_id,
                check_scan_id,
                threat_scan_id,
                compliance_scan_id,
                iam_scan_id,
                datasec_scan_id,
                inventory_scan_id,
                started_at,
                completed_at
            FROM scan_orchestration
            WHERE orchestration_id = %s::uuid
        """, (orchestration_id,))

        row = cursor.fetchone()
        if not row:
            raise ValueError(f"Orchestration ID {orchestration_id} not found in scan_orchestration table")

        return {
            "orchestration_id": str(row[0]),
            "tenant_id": row[1],
            "account_id": row[2],
            "provider_type": row[3],   # alias kept for callers
            "provider": row[3],
            "status": row[4],          # alias kept for callers
            "overall_status": row[4],
            "discovery_scan_id": row[5],
            "check_scan_id": row[6],
            "threat_scan_id": row[7],
            "compliance_scan_id": row[8],
            "iam_scan_id": row[9],
            "datasec_scan_id": row[10],
            "inventory_scan_id": row[11],
            "started_at": row[12].isoformat() if row[12] else None,
            "completed_at": row[13].isoformat() if row[13] else None,
        }
    finally:
        cursor.close()
        conn.close()


def update_orchestration_scan_id(orchestration_id: str, engine: str, scan_id: str) -> None:
    """
    Write an engine's completed scan_id back into scan_orchestration.

    Called by each engine after it finishes its work so downstream engines
    can find the upstream scan_id via get_orchestration_metadata().

    Args:
        orchestration_id: Orchestration UUID
        engine: Engine name — discovery | check | inventory | threat |
                compliance | iam | datasec
        scan_id: The scan_id produced by this engine (written to its own DB)

    Raises:
        ValueError: If engine name is invalid
        RuntimeError: If the orchestration row is not found
    """
    column_map = {
        "discovery": "discovery_scan_id",
        "check":     "check_scan_id",
        "inventory": "inventory_scan_id",
        "threat":    "threat_scan_id",
        "compliance":"compliance_scan_id",
        "iam":       "iam_scan_id",
        "datasec":   "datasec_scan_id",
    }
    if engine not in column_map:
        raise ValueError(f"Invalid engine: {engine}. Valid: {list(column_map.keys())}")

    column = column_map[engine]
    conn = _get_orchestration_conn()
    cursor = conn.cursor()
    try:
        cursor.execute(
            f"UPDATE scan_orchestration SET {column} = %s WHERE orchestration_id = %s::uuid",
            (scan_id, orchestration_id),
        )
        if cursor.rowcount == 0:
            raise RuntimeError(
                f"Orchestration ID {orchestration_id} not found when writing {engine} scan_id"
            )
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def get_previous_engine_scan_id(orchestration_id: str, engine: str) -> Optional[str]:
    """
    Get the scan_id of a specific engine from orchestration record.

    Args:
        orchestration_id: Orchestration UUID
        engine: Engine name (discovery, check, threat, compliance, iam, datasec, inventory)

    Returns:
        Engine's scan_id if available, None otherwise

    Raises:
        ValueError: If engine name is invalid
    """
    engine_column_map = {
        "discovery": "discovery_scan_id",
        "check": "check_scan_id",
        "threat": "threat_scan_id",
        "compliance": "compliance_scan_id",
        "iam": "iam_scan_id",
        "datasec": "datasec_scan_id",
        "inventory": "inventory_scan_id"
    }

    if engine not in engine_column_map:
        raise ValueError(f"Invalid engine: {engine}. Valid engines: {list(engine_column_map.keys())}")

    metadata = get_orchestration_metadata(orchestration_id)
    return metadata.get(f"{engine}_scan_id")
