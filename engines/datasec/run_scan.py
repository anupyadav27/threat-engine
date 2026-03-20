"""
DataSec Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --orchestration-id X --datasec-scan-id Y

Reads threat_findings from DB, enriches with data-security modules
(classification, lineage, residency, activity monitoring), writes
results to datasec_report / datasec_findings / datasec_data_stores.
No cloud credentials needed.
"""

import argparse
import json
import logging
import os
import signal
import sys
import uuid
from datetime import datetime, timezone

# Ensure /app is on PYTHONPATH
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from engine_common.logger import setup_logger
from engine_common.orchestration import get_orchestration_metadata, update_orchestration_scan_id
from engine_common.retention import cleanup_old_scans

logger = setup_logger(__name__, engine_name="datasec-scanner")


def _get_datasec_conn():
    """Get psycopg2 connection to the DataSec database."""
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("DATASEC_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DATASEC_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("DATASEC_DB_NAME", "threat_engine_datasec"),
        user=os.getenv("DATASEC_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("DATASEC_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


def _update_report_status(datasec_scan_id: str, status: str, error: str = None):
    """Update datasec_report status in DB."""
    try:
        conn = _get_datasec_conn()
        with conn.cursor() as cur:
            if error:
                cur.execute(
                    "UPDATE datasec_report SET status = %s, report_data = %s::jsonb WHERE datasec_scan_id = %s",
                    (status, json.dumps({"error": error}), datasec_scan_id),
                )
            else:
                cur.execute(
                    "UPDATE datasec_report SET status = %s WHERE datasec_scan_id = %s",
                    (status, datasec_scan_id),
                )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to update report status: {e}")


def _create_report_row(datasec_scan_id: str, tenant_id: str, provider: str,
                       threat_scan_id: str, metadata: dict):
    """Pre-create datasec_report row with status='running'."""
    try:
        conn = _get_datasec_conn()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO datasec_report
                   (datasec_scan_id, tenant_id, scan_run_id, provider, threat_scan_id, status, generated_at, report_data)
                   VALUES (%s, %s, %s, %s, %s, 'running', NOW(), '{}'::jsonb)
                   ON CONFLICT (datasec_scan_id) DO UPDATE SET status = 'running'""",
                (datasec_scan_id, tenant_id, datasec_scan_id, provider, threat_scan_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to pre-create report row: {e}")


def main():
    parser = argparse.ArgumentParser(description="DataSec Engine Scanner")
    parser.add_argument("--orchestration-id", required=True, help="Pipeline orchestration ID")
    parser.add_argument("--datasec-scan-id", required=True, help="Pre-assigned DataSec scan ID")
    args = parser.parse_args()

    orchestration_id = args.orchestration_id
    datasec_scan_id = args.datasec_scan_id

    logger.info(f"DataSec scanner starting orchestration_id={orchestration_id} scan_id={datasec_scan_id}")

    # SIGTERM handler — mark scan failed on preemption/timeout
    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking datasec scan {datasec_scan_id} as failed")
        _update_report_status(datasec_scan_id, "failed", "Terminated by SIGTERM (spot preemption or timeout)")
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        # 1. Get orchestration metadata
        logger.info("Resolving orchestration metadata...")
        metadata = get_orchestration_metadata(orchestration_id)
        if not metadata:
            raise ValueError(f"No orchestration metadata for {orchestration_id}")

        threat_scan_id = metadata.get("threat_scan_id")
        if not threat_scan_id:
            raise ValueError(f"Threat scan not completed for orchestration_id={orchestration_id}")

        tenant_id = metadata.get("tenant_id", "default-tenant")
        provider = (metadata.get("provider") or metadata.get("provider_type", "aws")).lower()

        logger.info(f"Resolved: tenant={tenant_id} provider={provider} threat_scan_id={threat_scan_id}")

        # 2. Pre-create report row
        _create_report_row(datasec_scan_id, tenant_id, provider, threat_scan_id, {
            "orchestration_id": orchestration_id,
            "mode": "job",
        })

        # 3. Update orchestration table
        try:
            update_orchestration_scan_id(orchestration_id, "datasec", datasec_scan_id)
        except Exception as e:
            logger.warning(f"Failed to update orchestration table: {e}")

        # 4. Run DataSec scan using modular architecture
        start = datetime.now(timezone.utc)

        from data_security_engine.rules.rule_loader import DataSecRuleLoader
        from data_security_engine.orchestrator.module_orchestrator import ModuleOrchestrator
        from data_security_engine.input.threat_db_reader import ThreatDBReader

        # 4a. Load threat findings (input data)
        logger.info(f"Loading threat findings: threat_scan_id={threat_scan_id}")
        threat_reader = ThreatDBReader()
        findings = threat_reader.get_misconfig_findings(
            tenant_id=tenant_id,
            scan_run_id=threat_scan_id,
        )
        data_stores = threat_reader.filter_data_stores(tenant_id=tenant_id, scan_run_id=threat_scan_id, csp=provider) if findings else []
        logger.info(f"Loaded {len(findings)} findings, {len(data_stores)} data stores")

        # 4b. Initialize rule loader + module orchestrator
        rule_loader = DataSecRuleLoader()
        orchestrator = ModuleOrchestrator(
            rule_loader=rule_loader,
            tenant_id=tenant_id,
            csp=provider,
        )
        orchestrator.initialize_modules()

        # 4c. Run all modules
        context = {
            "csp": provider,
            "tenant_id": tenant_id,
            "orchestration_id": orchestration_id,
            "datasec_scan_id": datasec_scan_id,
            "threat_scan_id": threat_scan_id,
        }
        module_results = orchestrator.run_scan(findings, data_stores, context)
        summary = orchestrator.get_summary(module_results)

        # 4d. Write findings to DB
        try:
            from data_security_engine.storage.datasec_db_writer import save_module_results_to_db
            save_module_results_to_db(
                datasec_scan_id=datasec_scan_id,
                tenant_id=tenant_id,
                provider=provider,
                module_results=module_results,
                summary=summary,
            )
            logger.info(f"DataSec findings saved to database")
        except Exception as e:
            logger.error(f"Error saving DataSec findings to database: {e}", exc_info=True)

        # 4e. Save report JSON to /output for S3 sync
        try:
            output_dir = os.getenv("OUTPUT_DIR", "/output")
            if output_dir and os.path.exists(output_dir):
                datasec_dir = os.path.join(output_dir, "datasec", "reports", tenant_id)
                os.makedirs(datasec_dir, exist_ok=True)
                report_data = {"summary": summary, "scan_id": datasec_scan_id}
                with open(os.path.join(datasec_dir, f"{datasec_scan_id}_report.json"), "w") as f:
                    json.dump(report_data, f, indent=2, default=str)
                logger.info(f"DataSec report saved to {datasec_dir}")
        except Exception as e:
            logger.error(f"Error saving DataSec report to output dir: {e}")

        duration = (datetime.now(timezone.utc) - start).total_seconds()

        # 5. Update status to completed
        _update_report_status(datasec_scan_id, "completed")

        total = summary.get("total_findings", 0)
        fails = summary.get("findings_by_status", {}).get("FAIL", 0)
        logger.info(f"DataSec scan completed: {datasec_scan_id} — {total} evaluations, {fails} failures in {duration:.1f}s")

        # 6. Retention cleanup (keep last 3 scans per tenant)
        try:
            cleanup_old_scans("datasec", tenant_id, keep=3)
        except Exception as e:
            logger.warning(f"Retention cleanup failed: {e}")

    except Exception as e:
        logger.error(f"DataSec scan FAILED: {e}", exc_info=True)
        _update_report_status(datasec_scan_id, "failed", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
