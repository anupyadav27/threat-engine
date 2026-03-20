"""
Compliance Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --orchestration-id X --compliance-scan-id Y

Reads check_findings from DB, generates compliance reports against 13+
frameworks, writes results to compliance_report / compliance_findings.
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

logger = setup_logger(__name__, engine_name="compliance-scanner")


def _get_compliance_conn():
    """Get psycopg2 connection to the compliance database."""
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("COMPLIANCE_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("COMPLIANCE_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("COMPLIANCE_DB_NAME", "threat_engine_compliance"),
        user=os.getenv("COMPLIANCE_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("COMPLIANCE_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


def _update_report_status(compliance_scan_id: str, status: str, error: str = None):
    """Update compliance_report status in DB."""
    try:
        conn = _get_compliance_conn()
        with conn.cursor() as cur:
            if error:
                cur.execute(
                    "UPDATE compliance_report SET status = %s, report_data = %s::jsonb WHERE compliance_scan_id = %s",
                    (status, __import__('json').dumps({"error": error}), compliance_scan_id),
                )
            else:
                cur.execute(
                    "UPDATE compliance_report SET status = %s WHERE compliance_scan_id = %s",
                    (status, compliance_scan_id),
                )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to update report status: {e}")


def _create_report_row(compliance_scan_id: str, tenant_id: str, provider: str,
                       check_scan_id: str, metadata: dict):
    """Pre-create compliance_report row with status='running'."""
    try:
        conn = _get_compliance_conn()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO compliance_report
                   (compliance_scan_id, tenant_id, scan_run_id, provider, check_scan_id, status, started_at)
                   VALUES (%s, %s, %s, %s, %s, 'running', NOW())
                   ON CONFLICT (compliance_scan_id) DO UPDATE SET status = 'running'""",
                (compliance_scan_id, tenant_id, compliance_scan_id, provider, check_scan_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to pre-create report row: {e}")


def main():
    parser = argparse.ArgumentParser(description="Compliance Engine Scanner")
    parser.add_argument("--orchestration-id", required=True, help="Pipeline orchestration ID")
    parser.add_argument("--compliance-scan-id", required=True, help="Pre-assigned compliance scan ID")
    args = parser.parse_args()

    orchestration_id = args.orchestration_id
    compliance_scan_id = args.compliance_scan_id

    logger.info(f"Compliance scanner starting orchestration_id={orchestration_id} scan_id={compliance_scan_id}")

    # SIGTERM handler — mark scan failed on preemption/timeout
    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking compliance scan {compliance_scan_id} as failed")
        _update_report_status(compliance_scan_id, "failed", "Terminated by SIGTERM (spot preemption or timeout)")
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        # 1. Get orchestration metadata
        logger.info("Resolving orchestration metadata...")
        metadata = get_orchestration_metadata(orchestration_id)
        if not metadata:
            raise ValueError(f"No orchestration metadata for {orchestration_id}")

        check_scan_id = metadata.get("check_scan_id")
        if not check_scan_id:
            raise ValueError(f"Check scan not completed for orchestration_id={orchestration_id}")

        tenant_id = metadata.get("tenant_id", "default-tenant")
        provider = (metadata.get("provider") or metadata.get("provider_type", "aws")).lower()

        logger.info(f"Resolved: tenant={tenant_id} provider={provider} check_scan_id={check_scan_id}")

        # 2. Pre-create report row
        _create_report_row(compliance_scan_id, tenant_id, provider, check_scan_id, {
            "orchestration_id": orchestration_id,
            "mode": "job",
        })

        # 3. Update orchestration table
        try:
            update_orchestration_scan_id(orchestration_id, "compliance", compliance_scan_id)
        except Exception as e:
            logger.warning(f"Failed to update orchestration table: {e}")

        # 4. Run compliance scan — enterprise report from check DB
        start = datetime.now(timezone.utc)

        from compliance_engine.loader.check_db_loader import CheckDBLoader
        from compliance_engine.mapper.rule_mapper import RuleMapper
        from compliance_engine.mapper.framework_loader import FrameworkLoader
        from compliance_engine.aggregator.result_aggregator import ResultAggregator
        from compliance_engine.aggregator.score_calculator import ScoreCalculator
        from compliance_engine.reporter.executive_dashboard import ExecutiveDashboard
        from compliance_engine.reporter.framework_report import FrameworkReport
        from compliance_engine.reporter.enterprise_reporter import EnterpriseReporter

        logger.info(f"Loading check findings from DB: check_scan_id={check_scan_id}")
        loader = CheckDBLoader()
        try:
            scan_results = loader.load_and_convert(
                scan_id=check_scan_id,
                tenant_id=tenant_id,
                csp=provider,
                status_filter=None,
            )
        finally:
            loader.close()

        if not scan_results or not scan_results.get("results"):
            raise ValueError(f"No check findings found for check_scan_id={check_scan_id}")

        # Generate enterprise report
        from compliance_engine.schemas.enterprise_report_schema import (
            ScanContext, TriggerType, Cloud, CollectionMode,
        )
        scan_context = ScanContext(
            scan_run_id=check_scan_id,
            trigger_type=TriggerType("api"),
            cloud=Cloud(provider),
            collection_mode=CollectionMode("full"),
            started_at=scan_results.get("scanned_at", datetime.now(timezone.utc).isoformat() + "Z"),
            completed_at=datetime.now(timezone.utc).isoformat() + "Z",
        )

        s3_bucket = os.getenv("S3_BUCKET", "cspm-lgtech")
        reporter = EnterpriseReporter(tenant_id=tenant_id, s3_bucket=s3_bucket)
        enterprise_report = reporter.generate_report(
            scan_results=scan_results,
            scan_context=scan_context,
            tenant_name=tenant_id,
        )

        # Export to database
        try:
            from compliance_engine.exporter.db_exporter import DatabaseExporter
            db_exporter = DatabaseExporter()
            db_exporter.create_schema()
            db_report_id = db_exporter.export_report(enterprise_report)
            logger.info(f"Compliance report exported to database: {db_report_id}")
        except Exception as e:
            logger.warning(f"Database export failed (non-fatal): {e}")

        # Save to compliance_report / compliance_findings via the writer
        try:
            from compliance_engine.storage.compliance_db_writer import save_compliance_report_to_db
            # Build a dict that save_compliance_report_to_db expects
            report_dict = {
                "report_id": compliance_scan_id,
                "scan_id": check_scan_id,
                "csp": provider,
                "tenant_id": tenant_id,
                "generated_at": datetime.now(timezone.utc).isoformat() + "Z",
                "source": "check_db",
            }
            if hasattr(enterprise_report, "posture_summary"):
                ps = enterprise_report.posture_summary
                report_dict["posture_summary"] = {
                    "total_controls": ps.total_controls,
                    "controls_passed": ps.controls_passed,
                    "controls_failed": ps.controls_failed,
                    "total_findings": ps.total_findings,
                    "findings_by_severity": ps.findings_by_severity,
                }
            if hasattr(enterprise_report, "frameworks"):
                report_dict["framework_ids"] = [f.framework_id for f in enterprise_report.frameworks]
            save_compliance_report_to_db(report_dict)
            logger.info("Compliance report saved to compliance DB tables")
        except Exception as e:
            logger.warning(f"Compliance DB writer failed (non-fatal): {e}")

        duration = (datetime.now(timezone.utc) - start).total_seconds()

        # 5. Update status to completed
        _update_report_status(compliance_scan_id, "completed")
        logger.info(f"Compliance scan completed: {compliance_scan_id} in {duration:.1f}s")

        # 6. Retention cleanup (keep last 3 scans per tenant)
        try:
            cleanup_old_scans("compliance", tenant_id, keep=3)
        except Exception as e:
            logger.warning(f"Retention cleanup failed: {e}")

    except Exception as e:
        logger.error(f"Compliance scan FAILED: {e}", exc_info=True)
        _update_report_status(compliance_scan_id, "failed", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
