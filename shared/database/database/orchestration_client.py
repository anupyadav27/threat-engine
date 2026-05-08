"""
Orchestration Client — interface to scan_runs table in threat_engine_onboarding DB.

Provides get_scan_context() so engines receive ONLY scan_run_id and can
hydrate all scan parameters from a single source of truth.

History:
  - Formerly queried scan_orchestration (orchestration_id) in threat_engine_shared.
  - After 2026-03 standardisation: table = scan_runs, PK = scan_run_id, DB = threat_engine_onboarding.
"""

import logging
from typing import Dict, Optional, Any

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


def _get_onboarding_db_connection():
    """Return a psycopg2 connection to threat_engine_onboarding."""
    try:
        from .config.database_config import get_onboarding_config

        config = get_onboarding_config()
        return psycopg2.connect(
            host=config.host,
            port=config.port,
            database=config.database,
            user=config.username,
            password=config.password,
            connect_timeout=10,
        )
    except Exception as e:
        logger.error(f"Failed to connect to onboarding database: {e}")
        raise


def get_scan_context(scan_run_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve scan context from scan_runs table by scan_run_id.

    Args:
        scan_run_id: Pipeline-wide scan UUID (same for ALL engines in one pipeline run).

    Returns:
        Dict with scan parameters, or None if not found.
    """
    if not scan_run_id:
        logger.warning("get_scan_context called with empty scan_run_id")
        return None

    conn = None
    try:
        conn = _get_onboarding_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute(
                """
                SELECT
                    scan_run_id,
                    tenant_id,
                    customer_id,
                    provider,
                    account_id,
                    credential_type,
                    credential_ref,
                    include_services,
                    include_regions,
                    exclude_services,
                    exclude_regions,
                    engines_requested,
                    engines_completed,
                    overall_status,
                    started_at,
                    completed_at,
                    schedule_id,
                    execution_id
                FROM scan_runs
                WHERE scan_run_id = %s
                """,
                (scan_run_id,),
            )
            row = cursor.fetchone()
            if row:
                result = dict(row)
                # Alias fields for backward-compat with callers that use old names
                result.setdefault("scan_run_id", result.get("scan_run_id"))
                result["hierarchy_type"] = "account"   # default; scan_runs has no hierarchy_type
                logger.info(f"Retrieved scan context for scan_run_id={scan_run_id}")
                return result
            else:
                logger.warning(f"No scan context found for scan_run_id={scan_run_id}")
                return None
    except Exception as e:
        logger.error(f"Failed to retrieve scan context for scan_run_id={scan_run_id}: {e}", exc_info=True)
        return None
    finally:
        if conn:
            conn.close()


def update_engine_scan_id(
    scan_run_id: str,
    engine: str,
    engine_scan_id: str,
) -> bool:
    """
    Mark an engine as completed in scan_runs.engines_completed.

    In the new design ALL engines use the same scan_run_id — there are no
    separate per-engine scan IDs.  This function is kept for backward-compat
    but simply appends the engine name to engines_completed.
    """
    if not scan_run_id or not engine:
        return False

    conn = None
    try:
        conn = _get_onboarding_db_connection()
        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE scan_runs
                SET engines_completed = COALESCE(engines_completed, '[]'::jsonb)
                                        || to_jsonb(%s::text)
                WHERE scan_run_id = %s
                """,
                (engine, scan_run_id),
            )
            conn.commit()
            logger.info(f"Marked engine '{engine}' completed for scan_run_id={scan_run_id}")
            return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"Failed to update engine '{engine}' for scan_run_id={scan_run_id}: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()


def get_engine_scan_id(scan_run_id: str, engine: str) -> Optional[str]:
    """
    In the new design, ALL engines share the same scan_run_id.
    Returns scan_run_id directly (no per-engine scan ID columns).
    """
    return scan_run_id if scan_run_id else None
