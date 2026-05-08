"""
Risk Quantification Engine — K8s Job Entry Point

Pipeline position: Layer 4 (runs AFTER all other engines complete)
Receives scan_run_id, runs 3-stage FAIR pipeline:
  Stage 1: ETL — collect CRITICAL/HIGH findings from all 6+ engine DBs
  Stage 2: Evaluate — compute FAIR loss estimates per finding
  Stage 3: Report — aggregate into risk_report, risk_summary, risk_trends
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import time
from datetime import datetime, timezone
from uuid import uuid4

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared"))
# engine_common may be at /app/engine_common (Job pod) or shared/common (local)
_app_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _app_dir not in sys.path:
    sys.path.insert(0, _app_dir)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("risk_quantification.run_scan")

from engine_common.db_connections import get_risk_conn, get_onboarding_conn


def get_orchestration_metadata(scan_run_id: str) -> dict:
    """Read scan metadata from scan_runs table."""
    from psycopg2.extras import RealDictCursor
    conn = get_onboarding_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM scan_runs WHERE scan_run_id = %s", (scan_run_id,))
            row = cur.fetchone()
            return dict(row) if row else {}
    finally:
        conn.close()


def run_risk_scan(scan_run_id: str) -> dict:
    """Execute the full 3-stage FAIR risk quantification pipeline."""
    start_time = time.time()
    risk_scan_id = str(uuid4())

    logger.info("=== Risk Quantification START: scan_run_id=%s, risk_scan_id=%s ===",
                scan_run_id, risk_scan_id)

    # ── 1. Get orchestration metadata ─────────────────────────────────
    metadata = get_orchestration_metadata(scan_run_id)
    tenant_id = metadata.get("tenant_id", os.getenv("TENANT_ID", "default-tenant"))
    account_id = metadata.get("account_id", "")
    provider = (metadata.get("provider") or metadata.get("provider_type", "aws")).lower()

    logger.info("Tenant: %s, Account: %s, Provider: %s", tenant_id, account_id, provider)

    # Risk engine is CSP-agnostic (reads from all engine DBs by scan_run_id)
    # For non-AWS CSPs with 0 CRITICAL/HIGH findings, ETL returns 0 and creates empty report
    if provider not in {"aws", "azure", "gcp", "k8s", "alicloud", "oci", "ibm"}:
        logger.warning("Risk: unrecognized provider='%s' — proceeding anyway", provider)

    risk_conn = get_risk_conn()
    onboarding_conn = None
    try:
        onboarding_conn = get_onboarding_conn()
    except Exception:
        logger.warning("Onboarding DB not available — using defaults for tenant config")

    # Optional: external DB for EPSS
    external_conn = None
    try:
        import psycopg2
        external_conn = psycopg2.connect(
            host=os.getenv("EXTERNAL_DB_HOST", os.getenv("DB_HOST", "localhost")),
            port=int(os.getenv("EXTERNAL_DB_PORT", os.getenv("DB_PORT", "5432"))),
            dbname=os.getenv("EXTERNAL_DB_NAME", "vulnerability_db"),
            user=os.getenv("EXTERNAL_DB_USER", os.getenv("DB_USER", "postgres")),
            password=os.getenv("EXTERNAL_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
            sslmode=os.getenv("DB_SSLMODE", "prefer"),
            connect_timeout=5,
        )
    except Exception:
        logger.info("External/vulnerability DB not available — EPSS scores will use defaults")

    try:
        # ── 2. Ensure tenant exists ───────────────────────────────────
        with risk_conn.cursor() as cur:
            cur.execute(
                "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (tenant_id, tenant_id),
            )
        risk_conn.commit()

        # ── 3. Stage 1: ETL ──────────────────────────────────────────
        from engines.risk.etl.risk_etl import RiskETL

        etl = RiskETL(
            risk_conn=risk_conn,
            onboarding_conn=onboarding_conn,
            external_conn=external_conn,
        )
        transformed_count = etl.run(
            scan_id=risk_scan_id,
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            account_id=account_id,
            provider=provider,
        )
        logger.info("Stage 1 ETL: %d findings transformed", transformed_count)

        if transformed_count == 0:
            logger.info("No CRITICAL/HIGH findings — creating empty report")
            _create_empty_report(risk_conn, risk_scan_id, scan_run_id, tenant_id, provider)
            elapsed_ms = int((time.time() - start_time) * 1000)
            return {"status": "completed", "scenarios": 0, "risk_scan_id": risk_scan_id,
                    "duration_ms": elapsed_ms}

        # ── 4. Stage 2: FAIR Evaluation ──────────────────────────────
        from engines.risk.evaluator.risk_evaluator import RiskEvaluator

        evaluator = RiskEvaluator(risk_conn)
        scenario_count = evaluator.run(
            scan_id=risk_scan_id,
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            account_id=account_id,
            provider=provider,
        )
        logger.info("Stage 2 FAIR: %d scenarios evaluated", scenario_count)

        # ── 5. Stage 3: Report Aggregation ───────────────────────────
        from engines.risk.reporter.risk_reporter import RiskReporter

        reporter = RiskReporter(risk_conn)
        report = reporter.run(
            scan_id=risk_scan_id,
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            account_id=account_id,
            provider=provider,
        )
        logger.info("Stage 3 Report: total_exposure=$%s, %d scenarios",
                     report.get("total_exposure_likely", 0), report.get("total_scenarios", 0))

        elapsed_ms = int((time.time() - start_time) * 1000)

        logger.info("=== Risk Quantification COMPLETE: %d scenarios, $%s exposure in %dms ===",
                     scenario_count, report.get("total_exposure_likely", 0), elapsed_ms)

        # Retention: archive old scans to S3, keep last 5 in DB
        try:
            from engine_common.retention import run_retention
            run_retention("risk", scan_run_id)
        except Exception as _ret_err:
            logger.warning("Retention cleanup skipped: %s", _ret_err)

        return {
            "status": "completed",
            "risk_scan_id": risk_scan_id,
            "scan_run_id": scan_run_id,
            "scenarios": scenario_count,
            "total_exposure_likely": report.get("total_exposure_likely", 0),
            "critical_scenarios": report.get("critical_scenarios", 0),
            "high_scenarios": report.get("high_scenarios", 0),
            "duration_ms": elapsed_ms,
        }

    except Exception as e:
        logger.exception("Risk quantification scan FAILED: %s", e)
        return {"status": "failed", "error": str(e)}
    finally:
        risk_conn.close()
        if onboarding_conn:
            onboarding_conn.close()
        if external_conn:
            external_conn.close()


def _create_empty_report(conn, risk_scan_id, scan_run_id, tenant_id, provider):
    """Create an empty risk report when no findings to quantify."""
    from engines.risk.db.risk_db_writer import RiskDBWriter
    writer = RiskDBWriter(conn)
    writer.insert_report({
        "risk_scan_id": risk_scan_id,
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "provider": provider,
        "total_scenarios": 0,
        "critical_scenarios": 0,
        "high_scenarios": 0,
        "medium_scenarios": 0,
        "low_scenarios": 0,
        "total_exposure_min": 0,
        "total_exposure_likely": 0,
        "total_exposure_max": 0,
        "total_regulatory_exposure": 0,
        "engine_breakdown": {},
        "scenario_type_breakdown": {},
        "top_scenarios": [],
        "frameworks_at_risk": [],
        "status": "completed",
    })


def _write_failed_report(scan_run_id: str, error: str) -> None:
    """Best-effort: write a failed row to risk_report so polling doesn't hang forever."""
    try:
        from uuid import uuid4 as _uuid4
        conn = get_risk_conn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO risk_report (risk_scan_id, scan_run_id, status, error_message, created_at)
                VALUES (gen_random_uuid(), %s, 'failed', %s, NOW())
                ON CONFLICT DO NOTHING
            """, (scan_run_id, error[:500]))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning("Could not write failed risk_report row: %s", e)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Risk Quantification Engine Scanner (FAIR model)")
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan_run_id")
    args = parser.parse_args()

    try:
        result = run_risk_scan(args.scan_run_id)
        logger.info("Result: %s", result)
        if result.get("status") != "completed":
            _write_failed_report(args.scan_run_id, result.get("error", "Unknown error"))
            sys.exit(1)
    except Exception as exc:
        logger.exception("Unhandled error in risk scan: %s", exc)
        _write_failed_report(args.scan_run_id, str(exc))
        sys.exit(1)
