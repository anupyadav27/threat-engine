"""
Inventory Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --scan-run-id X

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
from engine_common.orchestration import get_orchestration_metadata
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


def _update_report_status(db_url: str, scan_run_id: str, status: str, error: str = None):
    """Update inventory_report status in DB."""
    try:
        import psycopg2
        conn = psycopg2.connect(db_url)
        with conn.cursor() as cur:
            cur.execute(
                """UPDATE inventory_report
                   SET status = %s, completed_at = NOW()
                   WHERE scan_run_id = %s""",
                (status, scan_run_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to update report status: {e}")


def _create_report_row(db_url: str, scan_run_id: str, tenant_id: str,
                       provider: str, discovery_scan_id: str, metadata: dict):
    """Pre-create inventory_report row with status='running'."""
    try:
        import psycopg2
        conn = psycopg2.connect(db_url)
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO inventory_report
                   (scan_run_id, tenant_id, discovery_scan_id, status, started_at, scan_metadata)
                   VALUES (%s, %s, %s, 'running', NOW(), %s)
                   ON CONFLICT (scan_run_id) DO UPDATE SET status = 'running', discovery_scan_id = EXCLUDED.discovery_scan_id""",
                (scan_run_id, tenant_id, discovery_scan_id, json.dumps({
                    "scan_run_id": metadata.get("scan_run_id"),
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
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan run ID")
    args = parser.parse_args()

    scan_run_id = args.scan_run_id

    logger.info(f"Inventory scanner starting scan_run_id={scan_run_id}")

    db_url = _get_db_url()

    # SIGTERM handler — mark scan failed on preemption/timeout
    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking inventory scan {scan_run_id} as failed")
        _update_report_status(db_url, scan_run_id, "failed", "Terminated by SIGTERM (spot preemption or timeout)")
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        # 1. Get orchestration metadata
        logger.info("Resolving orchestration metadata...")
        metadata = get_orchestration_metadata(scan_run_id)
        if not metadata:
            raise ValueError(f"No orchestration metadata for {scan_run_id}")

        # All engines share the same scan_run_id
        discovery_scan_id = scan_run_id

        tenant_id = metadata.get("tenant_id", "default-tenant")
        provider = (metadata.get("provider") or metadata.get("provider_type", "aws")).lower()
        account_id = metadata.get("account_id") or metadata.get("account_id", "")
        check_scan_id = scan_run_id

        logger.info(
            f"Resolved: tenant={tenant_id} provider={provider} "
            f"discovery={discovery_scan_id} account={account_id} check={check_scan_id}"
        )

        # 2. Pre-create report row
        _create_report_row(db_url, scan_run_id, tenant_id, provider, discovery_scan_id, {
            "scan_run_id": scan_run_id,
        })

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
            scan_run_id=scan_run_id,
        )
        duration = (datetime.now(timezone.utc) - start).total_seconds()

        # 6. Update status to completed
        _update_report_status(db_url, scan_run_id, "completed")
        logger.info(
            f"Inventory scan completed: {scan_run_id} — "
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
        _update_report_status(db_url, scan_run_id, "failed", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
