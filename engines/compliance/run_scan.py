"""
Compliance Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --scan-run-id X

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
from engine_common.orchestration import get_orchestration_metadata
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


def _update_report_status(scan_run_id: str, status: str, error: str = None):
    """Update compliance_report status in DB."""
    try:
        conn = _get_compliance_conn()
        with conn.cursor() as cur:
            if error:
                cur.execute(
                    "UPDATE compliance_report SET status = %s, report_data = %s::jsonb WHERE scan_run_id = %s",
                    (status, __import__('json').dumps({"error": error}), scan_run_id),
                )
            else:
                cur.execute(
                    "UPDATE compliance_report SET status = %s WHERE scan_run_id = %s",
                    (status, scan_run_id),
                )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to update report status: {e}")


def _create_report_row(scan_run_id: str, tenant_id: str, provider: str,
                       check_scan_id: str, metadata: dict):
    """Pre-create compliance_report row with status='running'."""
    try:
        conn = _get_compliance_conn()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO tenants (tenant_id, tenant_name)
                   VALUES (%s, %s) ON CONFLICT (tenant_id) DO NOTHING""",
                (tenant_id, tenant_id),
            )
            cur.execute(
                """INSERT INTO compliance_report
                   (scan_run_id, tenant_id, provider, check_scan_id,
                    trigger_type, collection_mode, cloud,
                    total_controls, controls_passed, controls_failed, total_findings,
                    report_data, status, started_at, completed_at)
                   VALUES (%s, %s, %s, %s,
                    'orchestrated', 'full', %s,
                    0, 0, 0, 0,
                    '{}'::jsonb, 'running', NOW(), NOW())
                   ON CONFLICT (scan_run_id) DO UPDATE SET status = 'running'""",
                (scan_run_id, tenant_id, provider, check_scan_id, provider),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to pre-create report row: {e}")


def main():
    parser = argparse.ArgumentParser(description="Compliance Engine Scanner")
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan run ID")
    args = parser.parse_args()

    scan_run_id = args.scan_run_id

    logger.info(f"Compliance scanner starting scan_run_id={scan_run_id}")

    # SIGTERM handler — mark scan failed on preemption/timeout
    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking compliance scan {scan_run_id} as failed")
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
        check_scan_id = scan_run_id

        tenant_id = metadata.get("tenant_id", "default-tenant")
        account_id = metadata.get("account_id", "")
        provider = (metadata.get("provider") or metadata.get("provider_type", "aws")).lower()

        logger.info(f"Resolved: tenant={tenant_id} account={account_id} provider={provider} check_scan_id={check_scan_id}")

        # 2. Pre-create report row
        _create_report_row(scan_run_id, tenant_id, provider, check_scan_id, {
            "scan_run_id": scan_run_id,
            "mode": "job",
        })

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

        # Merge CIEM findings into scan_results (log-based compliance evidence)
        try:
            from engine_common.ciem_reader import CIEMReader
            ciem_c = CIEMReader(tenant_id=tenant_id, account_id=account_id or "", days=30)
            ciem_compliance_findings = ciem_c.get_ciem_findings(engine_filter="compliance")
            if ciem_compliance_findings:
                results_list = scan_results.get("results", [])
                existing_ids = {r.get("finding_id") or r.get("rule_id") for r in results_list}
                added = 0
                for cf in ciem_compliance_findings:
                    fid = cf.get("finding_id", "")
                    if fid in existing_ids:
                        continue
                    results_list.append({
                        "finding_id": fid,
                        "rule_id": cf.get("rule_id", ""),
                        "severity": cf.get("severity", "medium"),
                        "status": "FAIL",
                        "title": cf.get("title", ""),
                        "resource_uid": cf.get("resource_uid", ""),
                        "resource_type": cf.get("resource_type", ""),
                        "account_id": cf.get("account_id", account_id or ""),
                        "region": cf.get("region", ""),
                        "provider": provider or "aws",
                        "source": "ciem",
                        "finding_data": {
                            "source": "ciem",
                            "title": cf.get("title", ""),
                            "description": cf.get("description", ""),
                            "remediation": cf.get("remediation", ""),
                            "compliance_frameworks": cf.get("compliance_frameworks", []),
                            "mitre_tactics": cf.get("mitre_tactics", []),
                            "mitre_techniques": cf.get("mitre_techniques", []),
                            "risk_score": cf.get("risk_score"),
                            "domain": cf.get("domain", ""),
                            "actor_principal": cf.get("actor_principal", ""),
                            "operation": cf.get("operation", ""),
                        },
                    })
                    existing_ids.add(fid)
                    added += 1
                scan_results["results"] = results_list
                logger.info(f"CIEM: merged {added} compliance findings into scan_results")
        except Exception as ciem_pre_err:
            logger.warning(f"CIEM compliance pre-merge failed (non-fatal): {ciem_pre_err}")

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
            db_report_id = db_exporter.export_report(enterprise_report, account_id=account_id)
            logger.info(f"Compliance report exported to database: {db_report_id}")
        except Exception as e:
            logger.warning(f"Database export failed (non-fatal): {e}")

        # 4c. CIEM audit evidence (logging completeness from log_events)
        try:
            from engine_common.ciem_reader import CIEMReader
            ciem = CIEMReader(tenant_id=tenant_id, account_id=account_id or "", days=30)
            audit_completeness = ciem.get_audit_completeness()
            if audit_completeness:
                logger.info(f"CIEM: audit logging evidence for {list(audit_completeness.keys())}")
        except Exception as ciem_exc:
            logger.warning(f"CIEM audit evidence failed (non-fatal): {ciem_exc}")

        duration = (datetime.now(timezone.utc) - start).total_seconds()

        # 5. Update status to completed
        _update_report_status(scan_run_id, "completed")
        logger.info(f"Compliance scan completed: {scan_run_id} in {duration:.1f}s")

        # 6. Retention cleanup (keep last 3 scans per tenant)
        try:
            cleanup_old_scans("compliance", tenant_id, keep=3)
        except Exception as e:
            logger.warning(f"Retention cleanup failed: {e}")

    except Exception as e:
        logger.error(f"Compliance scan FAILED: {e}", exc_info=True)
        _update_report_status(scan_run_id, "failed", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
