"""
Database Security Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --scan-run-id X

Pipeline:
  1. Read discovery_findings (RDS, DynamoDB, Redshift, ElastiCache, Neptune, etc.)
  2. Read check_findings (234 database security rules)
  3. Read datasec data (data classification for sensitive data cross-ref)
  4. Categorize findings by security domain (access, encryption, audit, backup, network, config)
  5. Build database inventory + posture scores + attack surface analysis
  6. Write results to database_security DB
"""

import argparse
import json
import logging
import os
import signal
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from engine_common.logger import setup_logger
from engine_common.orchestration import get_orchestration_metadata
from engine_common.retention import cleanup_old_scans

logger = setup_logger(__name__, engine_name="dbsec-scanner")


def _get_dbsec_conn():
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("DBSEC_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DBSEC_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("DBSEC_DB_NAME", "threat_engine_database_security"),
        user=os.getenv("DBSEC_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("DBSEC_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


def _update_report_status(scan_run_id: str, status: str, error: str = None):
    try:
        conn = _get_dbsec_conn()
        with conn.cursor() as cur:
            if error:
                cur.execute(
                    "UPDATE dbsec_report SET status = %s, error_message = %s WHERE scan_run_id = %s",
                    (status, error, scan_run_id),
                )
            else:
                cur.execute(
                    "UPDATE dbsec_report SET status = %s WHERE scan_run_id = %s",
                    (status, scan_run_id),
                )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to update report status: {e}")


def _create_report_row(scan_run_id: str, tenant_id: str, provider: str):
    try:
        conn = _get_dbsec_conn()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (tenant_id, tenant_id),
            )
            cur.execute(
                """INSERT INTO dbsec_report
                   (scan_run_id, tenant_id, provider, status, started_at, report_data)
                   VALUES (%s, %s, %s, 'running', NOW(), '{}'::jsonb)
                   ON CONFLICT (scan_run_id) DO UPDATE SET status = 'running', started_at = NOW()""",
                (scan_run_id, tenant_id, provider),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to pre-create report row: {e}")


def main():
    parser = argparse.ArgumentParser(description="Database Security Engine Scanner")
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan run ID")
    args = parser.parse_args()

    scan_run_id = args.scan_run_id
    logger.info(f"Database security scanner starting scan_run_id={scan_run_id}")

    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking dbsec scan {scan_run_id} as failed")
        _update_report_status(scan_run_id, "failed", "Terminated by SIGTERM (spot preemption or timeout)")
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        # 1. Get orchestration metadata
        metadata = get_orchestration_metadata(scan_run_id)
        if not metadata:
            raise ValueError(f"No orchestration metadata for {scan_run_id}")

        tenant_id = metadata.get("tenant_id", "default-tenant")
        provider = (metadata.get("provider") or metadata.get("provider_type", "aws")).lower()
        account_id = metadata.get("account_id", "")

        logger.info(f"Resolved: tenant={tenant_id} provider={provider} account={account_id}")

        _create_report_row(scan_run_id, tenant_id, provider)
        start = datetime.now(timezone.utc)

        # 2. Load data from source databases
        from database_security_engine.input.discovery_reader import DBDiscoveryReader
        from database_security_engine.input.check_reader import DBCheckReader
        from database_security_engine.input.datasec_reader import DBDataSecReader

        disc_reader = DBDiscoveryReader()
        check_reader = DBCheckReader()
        datasec_reader = DBDataSecReader()

        try:
            # Discovery: all database services
            discovery_resources = disc_reader.load_all_db_resources(
                scan_run_id, tenant_id, account_id or None
            )
            total_disc = sum(len(v) for v in discovery_resources.values())
            logger.info(f"Discovery: {total_disc} resources across {len(discovery_resources)} services")

            # Check findings
            check_findings = check_reader.load_db_check_findings(scan_run_id, tenant_id)
            rule_metadata = check_reader.load_rule_metadata()
            logger.info(f"Check: {len(check_findings)} findings, {len(rule_metadata)} rules")

            # DataSec classification
            datasec_data = datasec_reader.load_db_classification(scan_run_id, tenant_id)
            enhanced_data = datasec_reader.load_enhanced_db_data(scan_run_id, tenant_id)
            logger.info(f"DataSec: {len(datasec_data)} findings, {len(enhanced_data)} enhanced rows")

        finally:
            disc_reader.close()
            check_reader.close()
            datasec_reader.close()

        # 2c. CIEM findings (pre-evaluated log-based database detections)
        ciem_db_findings = []
        try:
            from engine_common.ciem_reader import CIEMReader
            ciem = CIEMReader(tenant_id=tenant_id, account_id=account_id or "", days=30)
            ciem_db_findings = ciem.get_ciem_findings(engine_filter="database")
            if ciem_db_findings:
                logger.info(f"CIEM: {len(ciem_db_findings)} database findings from ciem_findings")
        except Exception as ciem_f_err:
            logger.warning(f"CIEM findings load failed (non-fatal): {ciem_f_err}")

        # 3. Categorize findings by security domain
        from database_security_engine.analyzer.rule_categorizer import categorize_finding, get_service_from_rule
        from database_security_engine.analyzer.inventory_builder import build_db_inventory
        from database_security_engine.analyzer.posture_scorer import compute_posture_scores
        from database_security_engine.analyzer.attack_surface import analyze_attack_surface
        from database_security_engine.storage.dbsec_db_writer import (
            generate_finding_id, save_findings_to_db, save_db_inventory,
        )

        # Build categorized findings
        findings = []
        for cf in check_findings:
            rule_id = cf.get("rule_id", "")
            domain = categorize_finding(rule_id, cf)
            db_service = get_service_from_rule(rule_id)
            sev = cf.get("severity") or (rule_metadata.get(rule_id, {}).get("severity", "medium"))
            meta = rule_metadata.get(rule_id, {})

            finding_id = generate_finding_id(
                rule_id, cf.get("resource_uid", ""),
                cf.get("account_id", ""), cf.get("region", ""),
            )

            findings.append({
                "finding_id": finding_id,
                "resource_uid": cf.get("resource_uid", ""),
                "resource_type": cf.get("resource_type", ""),
                "account_id": cf.get("account_id", ""),
                "region": cf.get("region", ""),
                "credential_ref": metadata.get("credential_ref"),
                "credential_type": metadata.get("credential_type"),
                "db_engine": cf.get("finding_data", {}).get("Engine") if isinstance(cf.get("finding_data"), dict) else None,
                "db_service": db_service,
                "security_domain": domain,
                "severity": sev.upper() if sev else "MEDIUM",
                "status": cf.get("status", "FAIL"),
                "rule_id": rule_id,
                "title": meta.get("title", ""),
                "description": meta.get("description", ""),
                "remediation": meta.get("remediation", ""),
                "finding_data": cf.get("finding_data") or {},
            })

        # 3b. Merge CIEM findings (log-based database detections)
        for cf in ciem_db_findings:
            rule_id = cf.get("rule_id", "")
            finding_id = generate_finding_id(
                rule_id, cf.get("resource_uid", ""),
                cf.get("account_id", ""), cf.get("region", ""),
            )
            findings.append({
                "finding_id": finding_id,
                "resource_uid": cf.get("resource_uid", ""),
                "resource_type": cf.get("resource_type", ""),
                "account_id": cf.get("account_id", account_id or ""),
                "region": cf.get("region", ""),
                "credential_ref": metadata.get("credential_ref"),
                "credential_type": metadata.get("credential_type"),
                "db_engine": None,
                "db_service": get_service_from_rule(rule_id),
                "security_domain": categorize_finding(rule_id, cf),
                "severity": (cf.get("severity") or "medium").upper(),
                "status": "FAIL",
                "rule_id": rule_id,
                "title": cf.get("title", ""),
                "description": cf.get("description", ""),
                "remediation": cf.get("remediation", ""),
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
                    "actor": cf.get("actor_principal", ""),
                    "operation": cf.get("operation", ""),
                },
            })

        logger.info(f"Categorized {len(findings)} findings (incl. {len(ciem_db_findings)} from CIEM)")

        # 4. Build database inventory
        # Build datasec classification map
        datasec_classification = {}
        for ed in enhanced_data:
            uid = ed.get("resource_arn", "")
            if uid:
                datasec_classification[uid] = ed
        for df in datasec_data:
            uid = df.get("resource_uid", "")
            if uid and uid not in datasec_classification:
                datasec_classification[uid] = df

        db_inventory = build_db_inventory(
            discovery_resources, findings, datasec_classification
        )
        logger.info(f"Inventory: {len(db_inventory)} databases")

        # 5. Compute posture scores
        scores = compute_posture_scores(findings, db_inventory)
        logger.info(f"Posture: overall={scores.get('posture_score', 0)}")

        # 6. Attack surface analysis
        attack_surface = analyze_attack_surface(db_inventory, datasec_classification)
        logger.info(f"Attack surface: {len(attack_surface)} findings")

        # Add attack surface findings to main list
        for asf in attack_surface:
            asf_id = generate_finding_id(
                asf.get("attack_type", "attack_surface"),
                asf.get("resource_uid", ""),
                asf.get("account_id", ""),
                asf.get("region", ""),
            )
            findings.append({
                "finding_id": asf_id,
                "resource_uid": asf.get("resource_uid", ""),
                "resource_type": asf.get("resource_type", ""),
                "account_id": asf.get("account_id", ""),
                "region": asf.get("region", ""),
                "credential_ref": metadata.get("credential_ref"),
                "credential_type": metadata.get("credential_type"),
                "db_engine": asf.get("db_engine"),
                "db_service": asf.get("db_service"),
                "security_domain": asf.get("security_domain", "access_control"),
                "severity": asf.get("severity", "HIGH"),
                "status": "FAIL",
                "rule_id": None,
                "title": asf.get("title", ""),
                "description": asf.get("description", ""),
                "remediation": asf.get("remediation", ""),
                "finding_data": asf.get("finding_data", {}),
            })

        # 7. Build summary
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        domain_counts = {}
        service_counts = {}
        pass_count = 0
        fail_count = 0

        for f in findings:
            sev = f["severity"].lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            domain = f.get("security_domain", "unknown")
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
            svc = f.get("db_service", "unknown")
            service_counts[svc] = service_counts.get(svc, 0) + 1
            if f["status"] == "PASS":
                pass_count += 1
            else:
                fail_count += 1

        summary = {
            **scores,
            "total_databases": len(db_inventory),
            "total_findings": len(findings),
            "critical_findings": sev_counts["critical"],
            "high_findings": sev_counts["high"],
            "medium_findings": sev_counts["medium"],
            "low_findings": sev_counts["low"],
            "pass_count": pass_count,
            "fail_count": fail_count,
            "findings_by_service": service_counts,
            "findings_by_domain": domain_counts,
            "coverage_by_service": {svc: len(res) for svc, res in discovery_resources.items()},
            "attack_surface_count": len(attack_surface),
        }

        # 8. Write to database
        save_findings_to_db(scan_run_id, tenant_id, provider, findings, summary)
        save_db_inventory(scan_run_id, tenant_id, db_inventory)

        # 9. Save report JSON
        try:
            output_dir = os.getenv("OUTPUT_DIR", "/output")
            if output_dir and os.path.exists(output_dir):
                dbsec_dir = os.path.join(output_dir, "database-security", "reports", tenant_id)
                os.makedirs(dbsec_dir, exist_ok=True)
                with open(os.path.join(dbsec_dir, f"{scan_run_id}_report.json"), "w") as f:
                    json.dump(summary, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving report: {e}")

        duration = (datetime.now(timezone.utc) - start).total_seconds()
        _update_report_status(scan_run_id, "completed")

        logger.info(
            f"Database security scan completed: {scan_run_id} — "
            f"score={scores.get('posture_score', 0)}, {len(findings)} findings, "
            f"{len(db_inventory)} databases in {duration:.1f}s"
        )

        # 10. Retention cleanup
        try:
            cleanup_old_scans("database_security", tenant_id, keep=3)
        except Exception as e:
            logger.warning(f"Retention cleanup failed: {e}")

    except Exception as e:
        logger.error(f"Database security scan FAILED: {e}", exc_info=True)
        _update_report_status(scan_run_id, "failed", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
