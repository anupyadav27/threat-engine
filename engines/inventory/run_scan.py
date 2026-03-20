"""
Inventory Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --orchestration-id X --inventory-scan-id Y

Reads discovery_findings from DB, normalizes to assets/relationships,
detects drift, writes results to inventory DB. No cloud credentials needed.
"""

import argparse
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone

# Ensure /app is on PYTHONPATH
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from engine_common.logger import setup_logger
from engine_common.orchestration import get_orchestration_metadata, update_orchestration_scan_id
from engine_common.retention import cleanup_old_scans

from inventory_engine.api.orchestrator import ScanOrchestrator
from inventory_engine.database.connection.database_config import get_database_config

logger = setup_logger(__name__, engine_name="inventory-scanner")


def _get_db_url() -> str:
    """Build inventory DB URL from config."""
    db_config = get_database_config("inventory")
    db_url = db_config.connection_string
    schema = os.getenv("DB_SCHEMA", "public")
    sep = "&" if "?" in db_url else "?"
    return f"{db_url}{sep}options=-c%20search_path%3D{schema.replace(',', '%2C')}"


def _update_report_status(db_url: str, inventory_scan_id: str, status: str, error: str = None):
    """Update inventory_report status in DB."""
    try:
        import psycopg2
        conn = psycopg2.connect(db_url)
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE inventory_report
                   SET status = %s, completed_at = NOW()
                   WHERE inventory_scan_id = %s""",
                (status, inventory_scan_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to update report status: {e}")


def _create_report_row(db_url: str, inventory_scan_id: str, tenant_id: str,
                       provider: str, discovery_scan_id: str, metadata: dict):
    """Pre-create inventory_report row with status='running'."""
    try:
        import psycopg2
        conn = psycopg2.connect(db_url)
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO inventory_report
                   (inventory_scan_id, tenant_id, discovery_scan_id, status, started_at, scan_metadata)
                   VALUES (%s, %s, %s, 'running', NOW(), %s)
                   ON CONFLICT (inventory_scan_id) DO UPDATE SET status = 'running', discovery_scan_id = EXCLUDED.discovery_scan_id""",
                (inventory_scan_id, tenant_id, discovery_scan_id, json.dumps({
                    "orchestration_id": metadata.get("orchestration_id"),
                    "mode": "job",
                    "provider": provider,
                })),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to pre-create report row: {e}")


def _preload_arn_patterns(db_url: str):
    """Pre-load identifier patterns (same as api_server startup hook)."""
    try:
        import psycopg2
        from engine_common.arn import preload_identifier_patterns

        conn = psycopg2.connect(db_url, connect_timeout=5)
        try:
            total = 0
            for csp in ("aws", "azure", "gcp", "oci", "ibm", "alicloud"):
                count = preload_identifier_patterns(conn, csp)
                total += count
            logger.info(f"ARN identifier patterns preloaded: {total}")
        finally:
            conn.close()
    except Exception as exc:
        logger.warning(f"Failed to preload ARN patterns (non-fatal): {exc}")


def main():
    parser = argparse.ArgumentParser(description="Inventory Engine Scanner")
    parser.add_argument("--orchestration-id", required=True, help="Pipeline orchestration ID")
    parser.add_argument("--inventory-scan-id", required=True, help="Pre-assigned inventory scan ID")
    args = parser.parse_args()

    orchestration_id = args.orchestration_id
    inventory_scan_id = args.inventory_scan_id

    logger.info(f"Inventory scanner starting orchestration_id={orchestration_id} scan_id={inventory_scan_id}")

    db_url = _get_db_url()

    # SIGTERM handler — mark scan failed on preemption/timeout
    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking inventory scan {inventory_scan_id} as failed")
        _update_report_status(db_url, inventory_scan_id, "failed", "Terminated by SIGTERM (spot preemption or timeout)")
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        # 1. Get orchestration metadata
        logger.info("Resolving orchestration metadata...")
        metadata = get_orchestration_metadata(orchestration_id)
        if not metadata:
            raise ValueError(f"No orchestration metadata for {orchestration_id}")

        discovery_scan_id = metadata.get("discovery_scan_id")
        if not discovery_scan_id:
            raise ValueError(f"Discovery scan not completed for orchestration_id={orchestration_id}")

        tenant_id = metadata.get("tenant_id", "default-tenant")
        provider = (metadata.get("provider") or metadata.get("provider_type", "aws")).lower()
        account_id = metadata.get("hierarchy_id") or metadata.get("account_id", "")
        check_scan_id = metadata.get("check_scan_id")

        logger.info(
            f"Resolved: tenant={tenant_id} provider={provider} "
            f"discovery={discovery_scan_id} account={account_id} check={check_scan_id}"
        )

        # 2. Pre-create report row
        _create_report_row(db_url, inventory_scan_id, tenant_id, provider, discovery_scan_id, {
            "orchestration_id": orchestration_id,
        })

        # 3. Update orchestration table
        try:
            update_orchestration_scan_id(orchestration_id, "inventory", inventory_scan_id)
        except Exception as e:
            logger.warning(f"Failed to update orchestration table: {e}")

        # 4. Preload ARN patterns
        _preload_arn_patterns(db_url)

        # 5. Run inventory scan
        providers = [provider] if provider else ["aws"]
        accounts = [account_id] if account_id else []

        orchestrator = ScanOrchestrator(
            tenant_id=tenant_id,
            db_url=db_url,
        )

        start = datetime.now(timezone.utc)
        result = orchestrator.run_scan_from_discovery(
            discovery_scan_id=discovery_scan_id,
            check_scan_id=check_scan_id,
            providers=providers,
            scan_run_id=inventory_scan_id,
        )
        duration = (datetime.now(timezone.utc) - start).total_seconds()

        # 6. Update status to completed
        _update_report_status(db_url, inventory_scan_id, "completed")
        logger.info(
            f"Inventory scan completed: {inventory_scan_id} — "
            f"{result.get('total_assets', 0)} assets, "
            f"{result.get('total_relationships', 0)} relationships in {duration:.1f}s"
        )

        # 7. Retention cleanup (keep last 5 scans per tenant)
        try:
            cleanup_old_scans("inventory", tenant_id, keep=5)
        except Exception as e:
            logger.warning(f"Retention cleanup failed: {e}")

    except Exception as e:
        logger.error(f"Inventory scan FAILED: {e}", exc_info=True)
        _update_report_status(db_url, inventory_scan_id, "failed", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
