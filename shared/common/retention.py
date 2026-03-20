"""
Data retention utility — keeps only the last N scans per tenant per engine.

Called at the end of each engine's run_scan.py after successful completion.
Deletes findings first (child rows), then report rows (parent).

Usage:
    from engine_common.retention import cleanup_old_scans
    deleted = cleanup_old_scans("check", tenant_id="tenant-123", keep=3)
"""

import logging
import os
import psycopg2

logger = logging.getLogger(__name__)

# ── Engine table map ─────────────────────────────────────────────────────────
# Each engine: report table, scan_id column, timestamp column, dependent tables

ENGINE_TABLES = {
    "discovery": {
        "db_env": "DISCOVERIES",
        "db_name": "threat_engine_discoveries",
        "report_table": "discovery_report",
        "scan_id_col": "discovery_scan_id",
        "tenant_col": "tenant_id",
        "timestamp_col": "scan_timestamp",
        "dependent_tables": [
            ("discovery_findings", "discovery_scan_id"),
        ],
    },
    "check": {
        "db_env": "CHECK",
        "db_name": "threat_engine_check",
        "report_table": "check_report",
        "scan_id_col": "check_scan_id",
        "tenant_col": "tenant_id",
        "timestamp_col": "scan_timestamp",
        "dependent_tables": [
            ("check_findings", "check_scan_id"),
        ],
    },
    "inventory": {
        "db_env": "INVENTORY",
        "db_name": "threat_engine_inventory",
        "report_table": "inventory_report",
        "scan_id_col": "inventory_scan_id",
        "tenant_col": "tenant_id",
        "timestamp_col": "started_at",
        "dependent_tables": [
            # inventory_findings NOT deleted (UPSERT by resource_uid, latest state)
            ("inventory_relationships", "inventory_scan_id"),
            ("inventory_drift", "inventory_scan_id"),
        ],
    },
    "threat": {
        "db_env": "THREAT",
        "db_name": "threat_engine_threat",
        "report_table": "threat_report",
        "scan_id_col": "threat_scan_id",
        "tenant_col": "tenant_id",
        "timestamp_col": "started_at",
        "dependent_tables": [
            ("threat_findings", "threat_scan_id"),
            ("threat_detections", "scan_id"),
        ],
    },
    "compliance": {
        "db_env": "COMPLIANCE",
        "db_name": "threat_engine_compliance",
        "report_table": "compliance_report",
        "scan_id_col": "compliance_scan_id",
        "tenant_col": "tenant_id",
        "timestamp_col": "completed_at",
        "dependent_tables": [
            ("compliance_findings", "compliance_scan_id"),
        ],
    },
    "iam": {
        "db_env": "IAM",
        "db_name": "threat_engine_iam",
        "report_table": "iam_report",
        "scan_id_col": "iam_scan_id",
        "tenant_col": "tenant_id",
        "timestamp_col": "generated_at",
        "dependent_tables": [
            ("iam_findings", "iam_scan_id"),
        ],
    },
    "datasec": {
        "db_env": "DATASEC",
        "db_name": "threat_engine_datasec",
        "report_table": "datasec_report",
        "scan_id_col": "datasec_scan_id",
        "tenant_col": "tenant_id",
        "timestamp_col": "generated_at",
        "dependent_tables": [
            ("datasec_findings", "datasec_scan_id"),
            ("datasec_data_stores", "datasec_scan_id"),
        ],
    },
}


def _get_connection(engine: str):
    """Get a psycopg2 connection for the engine's database."""
    config = ENGINE_TABLES[engine]
    db_env = config["db_env"]
    host = os.getenv("DB_HOST", os.getenv(f"{db_env}_DB_HOST", "localhost"))
    port = os.getenv("DB_PORT", os.getenv(f"{db_env}_DB_PORT", "5432"))
    user = os.getenv("DB_USER", os.getenv(f"{db_env}_DB_USER", "postgres"))
    password = os.getenv(f"{db_env}_DB_PASSWORD", os.getenv("DB_PASSWORD", ""))
    dbname = os.getenv(f"{db_env}_DB_NAME", config["db_name"])

    return psycopg2.connect(host=host, port=port, dbname=dbname, user=user, password=password)


def cleanup_old_scans(engine: str, tenant_id: str, keep: int = 3) -> int:
    """Delete scans older than the most recent `keep` scans for a tenant.

    Args:
        engine: Engine name (e.g., "check", "threat")
        tenant_id: Tenant identifier
        keep: Number of most recent scans to retain (default: 3)

    Returns:
        Number of deleted scans
    """
    if engine not in ENGINE_TABLES:
        logger.warning(f"Unknown engine '{engine}' — skipping retention cleanup")
        return 0

    config = ENGINE_TABLES[engine]
    report_table = config["report_table"]
    scan_id_col = config["scan_id_col"]
    tenant_col = config["tenant_col"]
    timestamp_col = config["timestamp_col"]

    conn = None
    try:
        conn = _get_connection(engine)
        conn.autocommit = False
        cur = conn.cursor()

        # Find scan IDs to delete (older than the most recent `keep`)
        cur.execute(
            f"SELECT {scan_id_col} FROM {report_table} "
            f"WHERE {tenant_col} = %s "
            f"ORDER BY {timestamp_col} DESC NULLS LAST "
            f"OFFSET %s",
            (tenant_id, keep),
        )
        old_scan_ids = [row[0] for row in cur.fetchall()]

        if not old_scan_ids:
            conn.rollback()
            return 0

        logger.info(
            f"Retention cleanup: {engine} tenant={tenant_id} — "
            f"deleting {len(old_scan_ids)} old scans (keeping latest {keep})"
        )

        # Delete dependent tables first (child rows)
        for dep_table, dep_scan_col in config["dependent_tables"]:
            try:
                cur.execute(
                    f"DELETE FROM {dep_table} WHERE {dep_scan_col} = ANY(%s)",
                    (old_scan_ids,),
                )
                deleted_rows = cur.rowcount
                if deleted_rows > 0:
                    logger.info(f"  Deleted {deleted_rows} rows from {dep_table}")
            except (psycopg2.errors.UndefinedTable, psycopg2.errors.UndefinedColumn) as e:
                logger.warning(f"  Skipping {dep_table}: {e.diag.message_primary}")
                conn.rollback()
                conn.autocommit = False

        # Delete report rows
        cur.execute(
            f"DELETE FROM {report_table} WHERE {scan_id_col} = ANY(%s)",
            (old_scan_ids,),
        )
        deleted_reports = cur.rowcount
        logger.info(f"  Deleted {deleted_reports} rows from {report_table}")

        conn.commit()
        logger.info(f"Retention cleanup complete: {engine} — {len(old_scan_ids)} scans removed")
        return len(old_scan_ids)

    except Exception as e:
        logger.error(f"Retention cleanup failed for {engine}: {e}", exc_info=True)
        if conn:
            conn.rollback()
        return 0
    finally:
        if conn:
            conn.close()


def cleanup_old_orchestrations(tenant_id: str, keep: int = 3) -> int:
    """Delete old scan_orchestration rows beyond the latest `keep` per tenant."""
    try:
        host = os.getenv("ONBOARDING_DB_HOST", os.getenv("DB_HOST", "localhost"))
        port = os.getenv("ONBOARDING_DB_PORT", os.getenv("DB_PORT", "5432"))
        user = os.getenv("ONBOARDING_DB_USER", os.getenv("DB_USER", "postgres"))
        password = os.getenv("ONBOARDING_DB_PASSWORD", os.getenv("DB_PASSWORD", ""))
        dbname = os.getenv("ONBOARDING_DB_NAME", "threat_engine_onboarding")

        conn = psycopg2.connect(host=host, port=port, dbname=dbname, user=user, password=password)
        conn.autocommit = False
        cur = conn.cursor()

        cur.execute(
            "DELETE FROM scan_orchestration WHERE tenant_id = %s "
            "AND orchestration_id NOT IN ("
            "  SELECT orchestration_id FROM scan_orchestration "
            "  WHERE tenant_id = %s ORDER BY created_at DESC LIMIT %s"
            ")",
            (tenant_id, tenant_id, keep),
        )
        deleted = cur.rowcount
        conn.commit()

        if deleted > 0:
            logger.info(f"Orchestration retention: deleted {deleted} old rows for tenant={tenant_id}")
        conn.close()
        return deleted

    except Exception as e:
        logger.error(f"Orchestration retention failed: {e}", exc_info=True)
        return 0
