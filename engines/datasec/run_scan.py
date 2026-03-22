"""
DataSec Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --scan-run-id X

Pipeline:
  1. Read check_findings + rule_metadata.data_security mapping (primary source)
  2. Categorize findings into datasec modules (encryption, access, lifecycle, etc.)
  3. Write results to datasec_report / datasec_findings
  4. Fallback: if no check_findings, use legacy threat_findings + module evaluators
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
from engine_common.orchestration import get_orchestration_metadata
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


def _update_report_status(scan_run_id: str, status: str, error: str = None):
    """Update datasec_report status in DB."""
    try:
        conn = _get_datasec_conn()
        with conn.cursor() as cur:
            if error:
                cur.execute(
                    "UPDATE datasec_report SET status = %s, report_data = %s::jsonb WHERE scan_run_id = %s",
                    (status, json.dumps({"error": error}), scan_run_id),
                )
            else:
                cur.execute(
                    "UPDATE datasec_report SET status = %s WHERE scan_run_id = %s",
                    (status, scan_run_id),
                )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to update report status: {e}")


def _create_report_row(scan_run_id: str, tenant_id: str, provider: str,
                       threat_scan_id: str, metadata: dict):
    """Pre-create datasec_report row with status='running'."""
    try:
        conn = _get_datasec_conn()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO datasec_report
                   (scan_run_id, tenant_id, provider, threat_scan_id, status, generated_at, report_data)
                   VALUES (%s, %s, %s, %s, 'running', NOW(), '{}'::jsonb)
                   ON CONFLICT (scan_run_id) DO UPDATE SET status = 'running'""",
                (scan_run_id, tenant_id, provider, threat_scan_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to pre-create report row: {e}")


def main():
    parser = argparse.ArgumentParser(description="DataSec Engine Scanner")
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan run ID")
    args = parser.parse_args()

    scan_run_id = args.scan_run_id

    logger.info(f"DataSec scanner starting scan_run_id={scan_run_id}")

    # SIGTERM handler — mark scan failed on preemption/timeout
    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking datasec scan {scan_run_id} as failed")
        _update_report_status(scan_run_id, "failed", "Terminated by SIGTERM (spot preemption or timeout)")
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        # 1. Get orchestration metadata
        logger.info("Resolving orchestration metadata...")
        metadata = get_orchestration_metadata(scan_run_id)
        if not metadata:
            raise ValueError(f"No orchestration metadata for {scan_run_id}")

        # All engines share the same scan_run_id
        threat_scan_id = scan_run_id

        tenant_id = metadata.get("tenant_id", "default-tenant")
        provider = (metadata.get("provider") or metadata.get("provider_type", "aws")).lower()

        logger.info(f"Resolved: tenant={tenant_id} provider={provider} threat_scan_id={threat_scan_id}")

        # 2. Pre-create report row
        _create_report_row(scan_run_id, tenant_id, provider, threat_scan_id, {
            "scan_run_id": scan_run_id,
            "mode": "job",
        })

        # 3. Run DataSec scan — check_findings-based approach (primary)
        start = datetime.now(timezone.utc)

        # All engines share the same scan_run_id
        check_scan_id = scan_run_id
        module_results = {}
        summary = {}

        # 4a. PRIMARY: Read check_findings + rule_metadata.data_security mapping
        if check_scan_id:
            try:
                from data_security_engine.input.check_findings_reader import CheckFindingsReader
                from data_security_engine.orchestrator.module_orchestrator import ModuleOrchestrator

                logger.info(f"Loading check findings for datasec: check_scan_id={check_scan_id}")
                check_reader = CheckFindingsReader()
                check_reader.load_datasec_rule_mapping(provider=provider)
                check_findings = check_reader.load_check_findings(check_scan_id, tenant_id)

                if check_findings:
                    module_results = check_reader.to_module_results(check_findings)

                    # Build summary using the orchestrator's get_summary
                    orchestrator = ModuleOrchestrator.__new__(ModuleOrchestrator)
                    orchestrator.csp = provider
                    summary = orchestrator.get_summary(module_results)
                    logger.info(
                        f"Check-based datasec: {summary.get('total_findings', 0)} findings "
                        f"({summary.get('findings_by_status', {}).get('FAIL', 0)} FAIL) "
                        f"across {len(module_results)} modules"
                    )
                else:
                    logger.warning("No datasec-relevant check findings found")

                check_reader.close()
            except Exception as e:
                logger.error(f"Check-based datasec analysis failed: {e}", exc_info=True)

        # 4b. FALLBACK: Legacy threat_findings + module evaluator (if check approach produced nothing)
        if not module_results:
            logger.info("Falling back to legacy threat_findings-based approach")
            try:
                from data_security_engine.rules.rule_loader import DataSecRuleLoader
                from data_security_engine.orchestrator.module_orchestrator import ModuleOrchestrator
                from data_security_engine.input.threat_db_reader import ThreatDBReader

                threat_reader = ThreatDBReader()
                findings = threat_reader.get_misconfig_findings(
                    tenant_id=tenant_id, scan_run_id=threat_scan_id,
                )
                data_stores = threat_reader.filter_data_stores(
                    tenant_id=tenant_id, scan_run_id=threat_scan_id, csp=provider
                ) if findings else []
                logger.info(f"Fallback: loaded {len(findings)} findings, {len(data_stores)} data stores")

                rule_loader = DataSecRuleLoader()
                orchestrator = ModuleOrchestrator(
                    rule_loader=rule_loader, tenant_id=tenant_id, csp=provider,
                )
                orchestrator.initialize_modules()
                context = {
                    "csp": provider, "tenant_id": tenant_id,
                    "scan_run_id": scan_run_id,
                    "scan_run_id": scan_run_id,
                    "threat_scan_id": threat_scan_id,
                }
                module_results = orchestrator.run_scan(findings, data_stores, context)
                summary = orchestrator.get_summary(module_results)
            except Exception as e:
                logger.error(f"Fallback datasec analysis also failed: {e}", exc_info=True)
                summary = {"total_findings": 0, "findings_by_status": {}, "findings_by_module": {}, "findings_by_severity": {}}

        # 4c. Write findings to DB
        try:
            from data_security_engine.storage.datasec_db_writer import save_module_results_to_db
            save_module_results_to_db(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                provider=provider,
                module_results=module_results,
                summary=summary,
            )
            logger.info(f"DataSec findings saved to database")
        except Exception as e:
            logger.error(f"Error saving DataSec findings to database: {e}", exc_info=True)

        # 4d. Save report JSON to /output for S3 sync
        try:
            output_dir = os.getenv("OUTPUT_DIR", "/output")
            if output_dir and os.path.exists(output_dir):
                datasec_dir = os.path.join(output_dir, "datasec", "reports", tenant_id)
                os.makedirs(datasec_dir, exist_ok=True)
                report_data = {"summary": summary, "scan_id": scan_run_id}
                with open(os.path.join(datasec_dir, f"{scan_run_id}_report.json"), "w") as f:
                    json.dump(report_data, f, indent=2, default=str)
                logger.info(f"DataSec report saved to {datasec_dir}")
        except Exception as e:
            logger.error(f"Error saving DataSec report to output dir: {e}")

        duration = (datetime.now(timezone.utc) - start).total_seconds()

        # 5. Update status to completed
        _update_report_status(scan_run_id, "completed")

        total = summary.get("total_findings", 0)
        fails = summary.get("findings_by_status", {}).get("FAIL", 0)
        logger.info(f"DataSec scan completed: {scan_run_id} — {total} evaluations, {fails} failures in {duration:.1f}s")

        # 6. Retention cleanup (keep last 3 scans per tenant)
        try:
            cleanup_old_scans("datasec", tenant_id, keep=3)
        except Exception as e:
            logger.warning(f"Retention cleanup failed: {e}")

    except Exception as e:
        logger.error(f"DataSec scan FAILED: {e}", exc_info=True)
        _update_report_status(scan_run_id, "failed", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
