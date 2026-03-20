"""
Check Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --orchestration-id X --check-scan-id Y

Reads discovery_findings from DB, evaluates compliance rules,
writes results to check_findings. No cloud credentials needed.
"""

import argparse
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

from common.database.database_manager import DatabaseManager
from common.database.rule_reader import RuleReader
from common.models.evaluator_interface import CheckEvaluationError
from common.orchestration.check_engine import CheckEngine
from providers.aws.evaluator.check_evaluator import AWSCheckEvaluator

logger = setup_logger(__name__, engine_name="check-scanner")

# Provider evaluators (no credentials needed)
PROVIDER_EVALUATORS = {
    "aws": AWSCheckEvaluator,
}


def _update_report_status(db_manager: DatabaseManager, check_scan_id: str, status: str, error: str = None):
    """Update check_report status in DB."""
    try:
        conn = db_manager._get_connection()
        with conn.cursor() as cur:
            if error:
                cur.execute(
                    "UPDATE check_report SET status = %s, error_details = %s WHERE check_scan_id = %s",
                    (status, error, check_scan_id),
                )
            else:
                cur.execute(
                    "UPDATE check_report SET status = %s WHERE check_scan_id = %s",
                    (status, check_scan_id),
                )
        conn.commit()
        db_manager._return_connection(conn)
    except Exception as e:
        logger.error(f"Failed to update report status: {e}")


def _create_report_row(db_manager: DatabaseManager, check_scan_id: str, tenant_id: str,
                       provider: str, discovery_scan_id: str, metadata: dict):
    """Pre-create check_report row with status='running'."""
    try:
        conn = db_manager._get_connection()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO check_report
                   (check_scan_id, tenant_id, provider, discovery_scan_id, status, scan_timestamp, metadata)
                   VALUES (%s, %s, %s, %s, 'running', NOW(), %s)
                   ON CONFLICT (check_scan_id) DO UPDATE SET status = 'running'""",
                (check_scan_id, tenant_id, provider, discovery_scan_id,
                 __import__('json').dumps(metadata)),
            )
        conn.commit()
        db_manager._return_connection(conn)
    except Exception as e:
        logger.warning(f"Failed to pre-create report row: {e}")


def main():
    parser = argparse.ArgumentParser(description="Check Engine Scanner")
    parser.add_argument("--orchestration-id", required=True, help="Pipeline orchestration ID")
    parser.add_argument("--check-scan-id", required=True, help="Pre-assigned check scan ID")
    args = parser.parse_args()

    orchestration_id = args.orchestration_id
    check_scan_id = args.check_scan_id

    logger.info(f"Check scanner starting orchestration_id={orchestration_id} scan_id={check_scan_id}")

    db_manager = DatabaseManager()

    # SIGTERM handler — mark scan failed on preemption/timeout
    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking check scan {check_scan_id} as failed")
        _update_report_status(db_manager, check_scan_id, "failed", "Terminated by SIGTERM (spot preemption or timeout)")
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
        customer_id = metadata.get("customer_id", "default")
        provider = metadata.get("provider") or metadata.get("provider_type", "aws")
        hierarchy_id = metadata.get("hierarchy_id") or metadata.get("account_id", "")
        hierarchy_type = metadata.get("hierarchy_type", "account")
        include_services = metadata.get("include_services")

        logger.info(f"Resolved: tenant={tenant_id} provider={provider} discovery={discovery_scan_id}")

        # 2. Pre-create report row
        _create_report_row(db_manager, check_scan_id, tenant_id, provider, discovery_scan_id, {
            "orchestration_id": orchestration_id,
            "mode": "job",
        })

        # 3. Update orchestration table
        try:
            update_orchestration_scan_id(orchestration_id, "check", check_scan_id)
        except Exception as e:
            logger.warning(f"Failed to update orchestration table: {e}")

        # 4. Run check scan
        provider_key = provider.lower()
        if provider_key not in PROVIDER_EVALUATORS:
            raise ValueError(f"Unsupported provider: {provider}")

        evaluator = PROVIDER_EVALUATORS[provider_key](provider=provider_key)
        engine = CheckEngine(evaluator=evaluator, db_manager=db_manager)

        services = include_services
        if not services:
            try:
                services = RuleReader().get_services_for_provider(provider_key)
            except Exception:
                services = []

        start = datetime.now(timezone.utc)
        results = engine.run_check_scan(
            discovery_scan_id=discovery_scan_id,
            check_scan_id=check_scan_id,
            customer_id=customer_id,
            tenant_id=tenant_id,
            provider=provider_key,
            hierarchy_id=hierarchy_id,
            hierarchy_type=hierarchy_type,
            services=services,
            check_source="default",
        )
        duration = (datetime.now(timezone.utc) - start).total_seconds()

        # 5. Update status to completed
        _update_report_status(db_manager, check_scan_id, "completed")
        logger.info(f"Check scan completed: {check_scan_id} — {results.get('total_checks', 0)} checks in {duration:.1f}s")

        # 6. Retention cleanup (keep last 3 scans per tenant)
        try:
            cleanup_old_scans("check", tenant_id, keep=3)
        except Exception as e:
            logger.warning(f"Retention cleanup failed: {e}")

    except Exception as e:
        logger.error(f"Check scan FAILED: {e}", exc_info=True)
        _update_report_status(db_manager, check_scan_id, "failed", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
