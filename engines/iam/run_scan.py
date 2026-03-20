"""
IAM Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --orchestration-id X --iam-scan-id Y

Reads threat_findings from DB, filters IAM-relevant rules, enriches
findings, writes results to iam_report / iam_findings.
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

logger = setup_logger(__name__, engine_name="iam-scanner")


def _get_iam_conn():
    """Get psycopg2 connection to the IAM database."""
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("IAM_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("IAM_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("IAM_DB_NAME", "threat_engine_iam"),
        user=os.getenv("IAM_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("IAM_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


def _update_report_status(iam_scan_id: str, status: str, error: str = None):
    """Update iam_report status in DB."""
    try:
        conn = _get_iam_conn()
        with conn.cursor() as cur:
            if error:
                cur.execute(
                    "UPDATE iam_report SET status = %s, report_data = %s::jsonb WHERE iam_scan_id = %s",
                    (status, __import__('json').dumps({"error": error}), iam_scan_id),
                )
            else:
                cur.execute(
                    "UPDATE iam_report SET status = %s WHERE iam_scan_id = %s",
                    (status, iam_scan_id),
                )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to update report status: {e}")


def _create_report_row(iam_scan_id: str, tenant_id: str, provider: str,
                       threat_scan_id: str, metadata: dict):
    """Pre-create iam_report row with status='running'."""
    try:
        conn = _get_iam_conn()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO iam_report
                   (iam_scan_id, tenant_id, scan_run_id, provider, threat_scan_id, status, generated_at)
                   VALUES (%s, %s, %s, %s, %s, 'running', NOW())
                   ON CONFLICT (iam_scan_id) DO UPDATE SET status = 'running'""",
                (iam_scan_id, tenant_id, iam_scan_id, provider, threat_scan_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to pre-create report row: {e}")


def main():
    parser = argparse.ArgumentParser(description="IAM Engine Scanner")
    parser.add_argument("--orchestration-id", required=True, help="Pipeline orchestration ID")
    parser.add_argument("--iam-scan-id", required=True, help="Pre-assigned IAM scan ID")
    args = parser.parse_args()

    orchestration_id = args.orchestration_id
    iam_scan_id = args.iam_scan_id

    logger.info(f"IAM scanner starting orchestration_id={orchestration_id} scan_id={iam_scan_id}")

    # SIGTERM handler — mark scan failed on preemption/timeout
    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking IAM scan {iam_scan_id} as failed")
        _update_report_status(iam_scan_id, "failed", "Terminated by SIGTERM (spot preemption or timeout)")
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
        _create_report_row(iam_scan_id, tenant_id, provider, threat_scan_id, {
            "orchestration_id": orchestration_id,
            "mode": "job",
        })

        # 3. Update orchestration table
        try:
            update_orchestration_scan_id(orchestration_id, "iam", iam_scan_id)
        except Exception as e:
            logger.warning(f"Failed to update orchestration table: {e}")

        # 4. Run IAM scan
        start = datetime.now(timezone.utc)

        from iam_engine.input.threat_db_reader import ThreatDBReader
        from iam_engine.enricher.finding_enricher import FindingEnricher
        from iam_engine.reporter.iam_reporter import IAMReporter

        threat_db_reader = ThreatDBReader()
        finding_enricher = FindingEnricher()
        reporter = IAMReporter()

        logger.info(f"Generating IAM report: csp={provider} scan_id={threat_scan_id}")
        report = reporter.generate_report(
            csp=provider,
            scan_id=threat_scan_id,
            tenant_id=tenant_id,
        )

        # Add report_id
        if "report_id" not in report:
            report["report_id"] = iam_scan_id

        # Save to database
        try:
            from iam_engine.storage.iam_db_writer import save_iam_report_to_db
            saved_id = save_iam_report_to_db(report)
            logger.info(f"IAM report saved to database: {saved_id}")
        except Exception as e:
            logger.error(f"Error saving IAM report to database: {e}", exc_info=True)

        # Save to /output for S3 sync
        try:
            output_dir = os.getenv("OUTPUT_DIR", "/output")
            if output_dir and os.path.exists(output_dir):
                iam_dir = os.path.join(output_dir, "iam", tenant_id, threat_scan_id)
                os.makedirs(iam_dir, exist_ok=True)
                with open(os.path.join(iam_dir, "iam_report.json"), "w") as f:
                    json.dump(report, f, indent=2, default=str)
                logger.info(f"IAM report saved to {iam_dir}")
        except Exception as e:
            logger.error(f"Error saving IAM report to output dir: {e}")

        duration = (datetime.now(timezone.utc) - start).total_seconds()

        # 5. Update status to completed
        _update_report_status(iam_scan_id, "completed")

        findings_count = len(report.get("findings", []))
        logger.info(f"IAM scan completed: {iam_scan_id} — {findings_count} findings in {duration:.1f}s")

        # 6. Retention cleanup (keep last 3 scans per tenant)
        try:
            cleanup_old_scans("iam", tenant_id, keep=3)
        except Exception as e:
            logger.warning(f"Retention cleanup failed: {e}")

    except Exception as e:
        logger.error(f"IAM scan FAILED: {e}", exc_info=True)
        _update_report_status(iam_scan_id, "failed", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
