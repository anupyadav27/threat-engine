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
from engine_common.orchestration import get_orchestration_metadata

from common.database.database_manager import DatabaseManager
from common.database.rule_reader import RuleReader
from common.models.evaluator_interface import CheckEvaluationError
from common.orchestration.check_engine import CheckEngine
from providers.aws.evaluator.check_evaluator import AWSCheckEvaluator
from providers.gcp.evaluator.check_evaluator import GCPCheckEvaluator
from providers.azure.evaluator.check_evaluator import AzureCheckEvaluator
from providers.oci.evaluator.check_evaluator import OCICheckEvaluator
from providers.ibm.evaluator.check_evaluator import IBMCheckEvaluator
from providers.k8s.evaluator.check_evaluator import K8sCheckEvaluator
from providers.alicloud.evaluator.check_evaluator import AliCloudCheckEvaluator

logger = setup_logger(__name__, engine_name="check-scanner")

# Provider evaluators (no credentials needed — DB-only identifier parsing)
PROVIDER_EVALUATORS = {
    "aws":      AWSCheckEvaluator,
    "gcp":      GCPCheckEvaluator,
    "azure":    AzureCheckEvaluator,
    "oci":      OCICheckEvaluator,
    "ibm":      IBMCheckEvaluator,
    "k8s":      K8sCheckEvaluator,
    "alicloud": AliCloudCheckEvaluator,
}


def _update_report_status(db_manager: DatabaseManager, scan_run_id: str, status: str, error: str = None):
    """Update check_report status in DB."""
    try:
        conn = db_manager._get_connection()
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE check_report SET status = %s WHERE scan_run_id = %s",
                (status, scan_run_id),
            )
        conn.commit()
        db_manager._return_connection(conn)
        if error:
            logger.error(f"Check scan error: {error}")
    except Exception as e:
        logger.error(f"Failed to update report status: {e}")


def _create_report_row(db_manager: DatabaseManager, scan_run_id: str, customer_id: str,
                       tenant_id: str, provider: str, discovery_scan_id: str, metadata: dict):
    """Pre-create check_report row with status='running'."""
    try:
        conn = db_manager._get_connection()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO check_report
                   (scan_run_id, customer_id, tenant_id, provider, discovery_scan_id, status, first_seen_at, metadata)
                   VALUES (%s, %s, %s, %s, %s, 'running', NOW(), %s)
                   ON CONFLICT (scan_run_id) DO UPDATE SET status = 'running'""",
                (scan_run_id, customer_id, tenant_id, provider, discovery_scan_id,
                 __import__('json').dumps(metadata)),
            )
        conn.commit()
        db_manager._return_connection(conn)
    except Exception as e:
        logger.warning(f"Failed to pre-create report row: {e}")


def main():
    parser = argparse.ArgumentParser(description="Check Engine Scanner")
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan run ID")
    args = parser.parse_args()

    scan_run_id = args.scan_run_id

    logger.info(f"Check scanner starting scan_run_id={scan_run_id}")

    db_manager = DatabaseManager()

    # SIGTERM handler — mark scan failed on preemption/timeout
    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking check scan {scan_run_id} as failed")
        _update_report_status(db_manager, scan_run_id, "failed", "Terminated by SIGTERM (spot preemption or timeout)")
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

        tenant_id = metadata.get("tenant_id") or "default-tenant"
        customer_id = metadata.get("customer_id") or tenant_id  # fall back to tenant_id
        provider = metadata.get("provider") or metadata.get("provider_type", "aws")
        account_id = metadata.get("account_id") or ""
        hierarchy_type = metadata.get("hierarchy_type", "account")
        include_services = metadata.get("include_services")

        logger.info(f"Resolved: tenant={tenant_id} customer={customer_id} provider={provider} discovery={discovery_scan_id}")

        # 2. Pre-create report row
        _create_report_row(db_manager, scan_run_id, customer_id, tenant_id, provider, discovery_scan_id, {
            "scan_run_id": scan_run_id,
            "mode": "job",
        })

        # 3. Run check scan
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
            scan_run_id=scan_run_id,
            customer_id=customer_id,
            tenant_id=tenant_id,
            provider=provider_key,
            account_id=account_id,
            hierarchy_type=hierarchy_type,
            services=services,
            check_source="default",
        )
        duration = (datetime.now(timezone.utc) - start).total_seconds()

        # 5. Update status to completed
        _update_report_status(db_manager, scan_run_id, "completed")
        logger.info(f"Check scan completed: {scan_run_id} — {results.get('total_checks', 0)} checks in {duration:.1f}s")

        # Retention: archive old scans to S3, keep last 5 in DB
        try:
            from engine_common.retention import run_retention
            run_retention("check", scan_run_id)
        except Exception as _ret_err:
            logger.warning("Retention cleanup skipped: %s", _ret_err)


    except Exception as e:
        logger.error(f"Check scan FAILED: {e}", exc_info=True)
        _update_report_status(db_manager, scan_run_id, "failed", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
