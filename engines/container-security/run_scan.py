"""
Container Security Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --scan-run-id X

Pipeline:
  1. Read discovery_findings (EKS, ECS, ECR, Fargate, Lambda)
  2. Read check_findings (148 container rules)
  3. Read CIEM events (K8s audit, container CloudTrail)
  4. Categorize by domain (cluster, workload, image, network, rbac, runtime)
  5. Build inventory + posture scores + attack surface
  6. Write results to container_security DB
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

logger = setup_logger(__name__, engine_name="container-sec-scanner")


def _get_csec_conn():
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("CSEC_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("CSEC_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("CSEC_DB_NAME", "threat_engine_container_security"),
        user=os.getenv("CSEC_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("CSEC_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


def _update_report_status(scan_run_id: str, status: str, error: str = None):
    try:
        conn = _get_csec_conn()
        with conn.cursor() as cur:
            if error:
                cur.execute(
                    "UPDATE container_sec_report SET status = %s, error_message = %s WHERE scan_run_id = %s",
                    (status, error, scan_run_id),
                )
            else:
                cur.execute(
                    "UPDATE container_sec_report SET status = %s WHERE scan_run_id = %s",
                    (status, scan_run_id),
                )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to update report status: {e}")


def _create_report_row(scan_run_id: str, tenant_id: str, provider: str):
    try:
        conn = _get_csec_conn()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (tenant_id, tenant_id),
            )
            cur.execute(
                """INSERT INTO container_sec_report
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
    parser = argparse.ArgumentParser(description="Container Security Engine Scanner")
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan run ID")
    args = parser.parse_args()

    scan_run_id = args.scan_run_id
    logger.info(f"Container security scanner starting scan_run_id={scan_run_id}")

    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking container sec scan {scan_run_id} as failed")
        _update_report_status(scan_run_id, "failed", "Terminated by SIGTERM")
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        metadata = get_orchestration_metadata(scan_run_id)
        if not metadata:
            raise ValueError(f"No orchestration metadata for {scan_run_id}")

        tenant_id = metadata.get("tenant_id", "default-tenant")
        provider = (metadata.get("provider") or "aws").lower()
        account_id = metadata.get("account_id", "")

        logger.info(f"Resolved: tenant={tenant_id} provider={provider} account={account_id}")

        _create_report_row(scan_run_id, tenant_id, provider)
        start = datetime.now(timezone.utc)

        # 1. Load data
        from container_security_engine.input.discovery_reader import ContainerDiscoveryReader
        from container_security_engine.input.check_reader import ContainerCheckReader

        disc_reader = ContainerDiscoveryReader()
        check_reader = ContainerCheckReader()

        try:
            discovery_resources = disc_reader.load_all_container_resources(
                scan_run_id, tenant_id, account_id or None
            )
            total_disc = sum(len(v) for v in discovery_resources.values())
            logger.info(f"Discovery: {total_disc} resources across {len(discovery_resources)} services")

            check_findings = check_reader.load_container_check_findings(scan_run_id, tenant_id)
            rule_metadata = check_reader.load_rule_metadata()
            logger.info(f"Check: {len(check_findings)} findings, {len(rule_metadata)} rules")
        finally:
            disc_reader.close()
            check_reader.close()

        # 2. CIEM events (non-fatal)
        ciem_events = []
        try:
            from container_security_engine.input.ciem_reader import ContainerCIEMReader
            ciem_reader = ContainerCIEMReader()
            try:
                ciem_events = ciem_reader.load_container_events(tenant_id, account_id or None, days=30)
                logger.info(f"CIEM: {len(ciem_events)} container events")
            finally:
                ciem_reader.close()
        except Exception as ciem_err:
            logger.warning(f"CIEM reader failed (non-fatal): {ciem_err}")

        # 2b. CIEM findings (pre-evaluated log-based detections)
        ciem_check_findings = []
        try:
            from engine_common.ciem_reader import CIEMReader
            ciem = CIEMReader(tenant_id=tenant_id, account_id=account_id or "", days=30)
            ciem_check_findings = ciem.get_ciem_findings(engine_filter="container")
            if ciem_check_findings:
                logger.info(f"CIEM: {len(ciem_check_findings)} container findings from ciem_findings")
        except Exception as ciem_f_err:
            logger.warning(f"CIEM findings load failed (non-fatal): {ciem_f_err}")

        # 3. Categorize findings
        from container_security_engine.analyzer.rule_categorizer import categorize_finding, get_service_from_rule
        from container_security_engine.analyzer.inventory_builder import build_container_inventory
        from container_security_engine.analyzer.posture_scorer import compute_posture_scores
        from container_security_engine.analyzer.attack_surface import analyze_attack_surface
        from container_security_engine.storage.container_db_writer import (
            generate_finding_id, save_findings_to_db, save_container_inventory,
        )

        findings = []
        for cf in check_findings:
            rule_id = cf.get("rule_id", "")
            domain = categorize_finding(rule_id, cf)
            svc = get_service_from_rule(rule_id)
            sev = cf.get("severity") or rule_metadata.get(rule_id, {}).get("severity", "medium")
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
                "container_service": svc,
                "cluster_name": _extract_cluster_name(cf),
                "security_domain": domain,
                "severity": sev.upper() if sev else "MEDIUM",
                "status": cf.get("status", "FAIL"),
                "rule_id": rule_id,
                "title": meta.get("title", ""),
                "description": meta.get("description", ""),
                "remediation": meta.get("remediation", ""),
                "finding_data": cf.get("finding_data") or {},
            })

        # 3b. Merge CIEM findings (log-based detections)
        for cf in ciem_check_findings:
            rule_id = cf.get("rule_id", "")
            finding_id = generate_finding_id(
                rule_id, cf.get("resource_uid", ""),
                cf.get("account_id", account_id or ""), cf.get("region", ""),
            )
            findings.append({
                "finding_id": finding_id,
                "resource_uid": cf.get("resource_uid", ""),
                "resource_type": cf.get("resource_type", ""),
                "account_id": cf.get("account_id", account_id or ""),
                "region": cf.get("region", ""),
                "credential_ref": metadata.get("credential_ref"),
                "credential_type": metadata.get("credential_type"),
                "container_service": get_service_from_rule(rule_id),
                "cluster_name": "",
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

        logger.info(f"Categorized {len(findings)} findings (incl. {len(ciem_check_findings)} from CIEM)")

        # 4. Build inventory
        container_inventory = build_container_inventory(discovery_resources, findings)
        logger.info(f"Inventory: {len(container_inventory)} resources")

        # 5. Posture scores
        scores = compute_posture_scores(findings, container_inventory)
        logger.info(f"Posture: overall={scores.get('posture_score', 0)}")

        # 6. Attack surface
        attack_surface = analyze_attack_surface(container_inventory, ciem_events)
        logger.info(f"Attack surface: {len(attack_surface)} findings")

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
                "container_service": asf.get("container_service"),
                "cluster_name": asf.get("cluster_name"),
                "security_domain": asf.get("security_domain", "cluster_security"),
                "severity": asf.get("severity", "HIGH"),
                "status": "FAIL",
                "rule_id": None,
                "title": asf.get("title", ""),
                "description": asf.get("description", ""),
                "remediation": asf.get("remediation", ""),
                "finding_data": asf.get("finding_data", {}),
            })

        # 7. Summary
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        domain_counts = {}
        service_counts = {}
        pass_count = fail_count = 0

        for f in findings:
            sev_counts[f["severity"].lower()] = sev_counts.get(f["severity"].lower(), 0) + 1
            domain_counts[f.get("security_domain", "unknown")] = domain_counts.get(f.get("security_domain", "unknown"), 0) + 1
            service_counts[f.get("container_service", "unknown")] = service_counts.get(f.get("container_service", "unknown"), 0) + 1
            if f["status"] == "PASS":
                pass_count += 1
            else:
                fail_count += 1

        clusters = [i for i in container_inventory if i.get("resource_type") == "cluster"]
        images = [i for i in container_inventory if i.get("container_service") == "ecr"]

        summary = {
            **scores,
            "total_clusters": len(clusters),
            "total_workloads": len(container_inventory) - len(clusters) - len(images),
            "total_images": len(images),
            "total_findings": len(findings),
            "critical_findings": sev_counts["critical"],
            "high_findings": sev_counts["high"],
            "medium_findings": sev_counts["medium"],
            "low_findings": sev_counts["low"],
            "pass_count": pass_count,
            "fail_count": fail_count,
            "findings_by_service": service_counts,
            "findings_by_domain": domain_counts,
            "attack_surface_count": len(attack_surface),
        }

        # 8. Write
        save_findings_to_db(scan_run_id, tenant_id, provider, findings, summary)
        save_container_inventory(scan_run_id, tenant_id, container_inventory)

        # 9. Report JSON
        try:
            output_dir = os.getenv("OUTPUT_DIR", "/output")
            if output_dir and os.path.exists(output_dir):
                csec_dir = os.path.join(output_dir, "container-security", "reports", tenant_id)
                os.makedirs(csec_dir, exist_ok=True)
                with open(os.path.join(csec_dir, f"{scan_run_id}_report.json"), "w") as f:
                    json.dump(summary, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Error saving report: {e}")

        duration = (datetime.now(timezone.utc) - start).total_seconds()
        _update_report_status(scan_run_id, "completed")

        logger.info(
            f"Container security scan completed: {scan_run_id} — "
            f"score={scores.get('posture_score', 0)}, {len(findings)} findings, "
            f"{len(container_inventory)} resources in {duration:.1f}s"
        )

        try:
            cleanup_old_scans("container_security", tenant_id, keep=3)
        except Exception as e:
            logger.warning(f"Retention cleanup failed: {e}")

    except Exception as e:
        logger.error(f"Container security scan FAILED: {e}", exc_info=True)
        _update_report_status(scan_run_id, "failed", str(e))
        sys.exit(1)


def _extract_cluster_name(finding: dict) -> str:
    """Extract cluster name from finding data."""
    fd = finding.get("finding_data") or {}
    if isinstance(fd, dict):
        return fd.get("ClusterName") or fd.get("cluster_name") or ""
    uid = finding.get("resource_uid", "")
    # Parse from ARN: arn:aws:eks:region:account:cluster/name
    if ":cluster/" in uid:
        return uid.split(":cluster/")[-1]
    return ""


if __name__ == "__main__":
    main()
