"""
Threat Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --orchestration-id X --threat-scan-id Y

Reads check_findings from Check DB, runs threat detection + analysis,
writes results to threat_report / threat_findings / threat_detections.
No cloud credentials needed.
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime, timezone

# Ensure /app is on PYTHONPATH
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from engine_common.logger import setup_logger, LogContext, log_duration, audit_log
from engine_common.orchestration import get_orchestration_metadata, update_orchestration_scan_id
from engine_common.retention import cleanup_old_scans

from threat_engine.schemas.threat_report_schema import (
    ThreatReport,
    Tenant,
    ScanContext,
    Cloud,
    TriggerType,
)
from threat_engine.schemas.misconfig_normalizer import normalize_db_check_results_to_findings
from threat_engine.database.metadata_enrichment import get_enriched_check_results
from threat_engine.detector.threat_detector import ThreatDetector
from threat_engine.detector.drift_detector import DriftDetector
from threat_engine.detector.check_drift_detector import CheckDriftDetector
from threat_engine.reporter.threat_reporter import ThreatReporter
from threat_engine.storage.threat_storage import ThreatStorage
from threat_engine.storage.threat_db_writer import save_analyses_to_db
from threat_engine.analyzer.threat_analyzer import ThreatAnalyzer

logger = setup_logger(__name__, engine_name="threat-scanner")


# ── DB helpers ───────────────────────────────────────────────────────────────

def _get_threat_conn():
    """Get a psycopg2 connection to the threat DB."""
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("THREAT_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("THREAT_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("THREAT_DB_NAME", "threat_engine_threat"),
        user=os.getenv("THREAT_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("THREAT_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        connect_timeout=5,
    )


def _ensure_tenant(conn, tenant_id: str):
    """Upsert tenant row (FK requirement)."""
    with conn.cursor() as cur:
        cur.execute(
            """INSERT INTO tenants (tenant_id, tenant_name)
               VALUES (%s, %s)
               ON CONFLICT (tenant_id) DO NOTHING""",
            (tenant_id, tenant_id),
        )
    conn.commit()


def _create_report_row(threat_scan_id: str, tenant_id: str, provider: str,
                        check_scan_id: str, scan_run_id: str, metadata: dict):
    """Pre-create threat_report row with status='running'."""
    try:
        conn = _get_threat_conn()
        _ensure_tenant(conn, tenant_id)
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO threat_report
                   (threat_scan_id, tenant_id, provider, check_scan_id,
                    scan_run_id, status, started_at, report_data)
                   VALUES (%s, %s, %s, %s, %s, 'running', NOW(), %s)
                   ON CONFLICT (threat_scan_id) DO UPDATE SET status = 'running'""",
                (threat_scan_id, tenant_id, provider, check_scan_id,
                 scan_run_id, json.dumps(metadata)),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to pre-create threat_report row: {e}")


def _update_report_status(threat_scan_id: str, status: str, error: str = None):
    """Update threat_report status in DB."""
    try:
        conn = _get_threat_conn()
        with conn.cursor() as cur:
            if error:
                cur.execute(
                    """UPDATE threat_report
                       SET status = %s, report_data = report_data || %s
                       WHERE threat_scan_id = %s""",
                    (status, json.dumps({"error_details": error}), threat_scan_id),
                )
            else:
                if status == "completed":
                    cur.execute(
                        "UPDATE threat_report SET status = %s, completed_at = NOW() WHERE threat_scan_id = %s",
                        (status, threat_scan_id),
                    )
                else:
                    cur.execute(
                        "UPDATE threat_report SET status = %s WHERE threat_scan_id = %s",
                        (status, threat_scan_id),
                    )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to update report status: {e}")


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Threat Engine Scanner")
    parser.add_argument("--orchestration-id", required=True, help="Pipeline orchestration ID")
    parser.add_argument("--threat-scan-id", required=True, help="Pre-assigned threat scan ID")
    args = parser.parse_args()

    orchestration_id = args.orchestration_id
    threat_scan_id = args.threat_scan_id

    logger.info(f"Threat scanner starting orchestration_id={orchestration_id} scan_id={threat_scan_id}")

    # SIGTERM handler — mark scan failed on preemption/timeout
    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking threat scan {threat_scan_id} as failed")
        _update_report_status(threat_scan_id, "failed", "Terminated by SIGTERM (spot preemption or timeout)")
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
        provider = metadata.get("provider") or metadata.get("provider_type", "aws")
        account_id = metadata.get("account_id", "")
        discovery_scan_id = metadata.get("discovery_scan_id")
        scan_run_id = orchestration_id  # orchestration_id == scan_run_id

        # Determine cloud enum
        provider_lower = provider.lower()
        cloud_map = {"aws": Cloud.AWS, "azure": Cloud.AZURE, "gcp": Cloud.GCP}
        cloud = cloud_map.get(provider_lower, Cloud.AWS)

        logger.info(f"Resolved: tenant={tenant_id} provider={provider} check={check_scan_id}")

        # 2. Pre-create report row with status='running'
        _create_report_row(threat_scan_id, tenant_id, provider, check_scan_id, scan_run_id, {
            "orchestration_id": orchestration_id,
            "mode": "job",
        })

        # 3. Update orchestration table
        try:
            update_orchestration_scan_id(orchestration_id, "threat", threat_scan_id)
        except Exception as e:
            logger.warning(f"Failed to update orchestration table: {e}")

        # 4. Load check results from DB
        start = time.time()
        logger.info(f"Loading check results for check_scan_id={check_scan_id}")

        check_results = get_enriched_check_results(
            scan_id=check_scan_id,
            schema="check_db",
            status_filter=["FAIL", "WARN"],
            tenant_id=tenant_id,
        )

        if not check_results:
            logger.warning(f"No failing check results for check_scan_id={check_scan_id} — generating empty report")
            # Still mark as completed with 0 findings
            _update_report_status(threat_scan_id, "completed")
            logger.info(f"Threat scan completed (empty): {threat_scan_id}")
            return

        logger.info(f"Loaded {len(check_results)} check results in {time.time() - start:.1f}s")

        # 5. Normalize findings
        findings = normalize_db_check_results_to_findings(
            check_results,
            cloud,
            include_metadata=True,
        )

        if not findings:
            logger.info("No findings after normalization — completing with empty report")
            _update_report_status(threat_scan_id, "completed")
            return

        # 6. Detect threats
        logger.info(f"Detecting threats from {len(findings)} findings...")
        detector = ThreatDetector()
        threats = detector.detect_threats(findings)

        # Drift detection (optional)
        if discovery_scan_id:
            try:
                from threat_engine.database.discovery_queries import DiscoveryDatabaseQueries
                from threat_engine.database.check_queries import CheckDatabaseQueries

                drift_detector = DriftDetector(discovery_queries=DiscoveryDatabaseQueries())
                check_drift_detector = CheckDriftDetector(check_queries=CheckDatabaseQueries())

                drift_threats = drift_detector.detect_configuration_drift(
                    tenant_id=tenant_id,
                    hierarchy_id=account_id,
                    service=None,
                    current_scan_id=discovery_scan_id,
                )
                check_drift_threats = check_drift_detector.detect_check_status_drift(
                    tenant_id=tenant_id,
                    hierarchy_id=account_id,
                    service=None,
                    current_scan_id=scan_run_id,
                )
                threats.extend(drift_threats)
                threats.extend(check_drift_threats)
            except Exception as e:
                logger.warning(f"Drift detection failed (continuing): {e}")

        logger.info(f"Detected {len(threats)} threats")

        # 7. Generate and save report
        tenant = Tenant(tenant_id=tenant_id, tenant_name=tenant_id)
        scan_context = ScanContext(
            scan_run_id=threat_scan_id,  # db_writer uses this directly as threat_scan_id
            trigger_type=TriggerType.SCHEDULED,
            cloud=cloud,
            accounts=[account_id] if account_id else [],
            regions=[],
            services=[],
            started_at=datetime.now(timezone.utc).isoformat(),
            completed_at=None,
            engine_version="2.0.0-job",
        )

        reporter = ThreatReporter()
        report = reporter.generate_report(
            tenant=tenant,
            scan_context=scan_context,
            threats=threats,
            misconfig_findings=findings,
        )

        # Save report to DB (writes threat_report + threat_findings + threat_detections)
        storage = ThreatStorage()
        storage.save_report(report)

        # 8. Run threat analysis (blast radius, risk scoring, attack chains)
        analysis_count = 0
        try:
            analyzer = ThreatAnalyzer()
            analyses = analyzer.analyze_scan(
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                orchestration_id=orchestration_id,
            )
            if analyses:
                analysis_count = save_analyses_to_db(analyses)
                logger.info(f"Threat analysis complete: {analysis_count} analyses saved")
        except Exception as e:
            logger.warning(f"Threat analysis failed (report still saved): {e}", exc_info=True)

        # 9. Build security graph (Neo4j)
        try:
            from threat_engine.graph.graph_builder import SecurityGraphBuilder
            graph_start = time.time()
            logger.info("Building security graph in Neo4j...")
            builder = SecurityGraphBuilder()
            graph_stats = builder.build_graph(tenant_id=tenant_id)
            logger.info(f"Graph build complete in {time.time() - graph_start:.1f}s: {graph_stats}")
        except Exception as e:
            logger.warning(f"Graph build failed (scan still successful): {e}", exc_info=True)

        # 10. Update status to completed
        duration = time.time() - start
        _update_report_status(threat_scan_id, "completed")
        logger.info(
            f"Threat scan completed: {threat_scan_id} — "
            f"{len(threats)} threats, {len(findings)} findings, "
            f"{analysis_count} analyses in {duration:.1f}s"
        )

        # 11. Retention cleanup (keep last 3 scans per tenant)
        try:
            cleanup_old_scans("threat", tenant_id, keep=3)
        except Exception as e:
            logger.warning(f"Retention cleanup failed: {e}")

    except Exception as e:
        logger.error(f"Threat scan FAILED: {e}", exc_info=True)
        _update_report_status(threat_scan_id, "failed", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
