"""
Retention module — archive old scan data to S3, keep last 5 in DB.

Usage (at end of each engine's run_scan):

    from engine_common.retention import run_retention
    run_retention("discoveries", scan_run_id)

Policy (default):
    DB  — last 5 scan_run_ids  (hot, queryable)
    S3  — next 5 scan_run_ids  (cold, recoverable)
    Old — beyond 10 scans      (purged from both)
"""

import importlib
import logging
import os
from typing import Optional

from .cleaner import clean_table
from .policy import ENGINE_POLICY, KEEP_IN_DB, KEEP_IN_S3

logger = logging.getLogger(__name__)


def run_retention(
    engine: str,
    scan_run_id: Optional[str] = None,  # unused but accepted for symmetry
    keep_in_db: int = KEEP_IN_DB,
    keep_in_s3: int = KEEP_IN_S3,
    s3_bucket: Optional[str] = None,
    s3_prefix: Optional[str] = None,
) -> dict:
    """Run archive + cleanup for all tables of the given engine.

    Non-fatal: any error is logged but never propagated — retention must not
    crash a scan that completed successfully.

    Returns summary dict with per-table results.
    """
    policy = ENGINE_POLICY.get(engine)
    if not policy:
        logger.warning("[retention] no policy for engine '%s' — skipping", engine)
        return {}

    # Get DB connection via shared factory
    try:
        db_module = importlib.import_module("engine_common.db_connections")
        conn_factory = getattr(db_module, policy["conn_factory"])
        conn = conn_factory()
    except Exception as e:
        logger.error("[retention] cannot connect for engine '%s': %s", engine, e)
        return {}

    results = {}
    for table_cfg in policy["tables"]:
        table = table_cfg["name"]
        ts_col = table_cfg["timestamp_col"]
        try:
            results[table] = clean_table(
                conn=conn,
                engine=engine,
                table=table,
                timestamp_col=ts_col,
                keep_in_db=keep_in_db,
                keep_in_s3=keep_in_s3,
                s3_bucket=s3_bucket,
                s3_prefix=s3_prefix,
                partition_by=table_cfg.get("partition_by"),
            )
        except Exception as e:
            logger.error("[retention] failed for %s.%s: %s", engine, table, e)
            results[table] = {"error": str(e)}

    try:
        conn.close()
    except Exception:
        pass

    logger.info("[retention] %s complete: %s", engine, results)
    return results
