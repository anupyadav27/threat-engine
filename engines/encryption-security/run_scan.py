"""
Encryption Security Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --scan-run-id X

Pipeline:
  1. Read discovery_findings (KMS, ACM, SecretsManager)
  2. Read check_findings (encryption rules)
  3. Read datasec data (encryption posture columns)
  4. Build coverage analysis, key/cert/secret inventories, posture score
  5. Write results to encryption DB
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

logger = setup_logger(__name__, engine_name="encryption-scanner")


def _get_encryption_conn():
    """Get psycopg2 connection to the Encryption database."""
    import psycopg2
    return psycopg2.connect(
        host=os.getenv("ENCRYPTION_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("ENCRYPTION_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("ENCRYPTION_DB_NAME", "threat_engine_encryption"),
        user=os.getenv("ENCRYPTION_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("ENCRYPTION_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


def _update_report_status(scan_run_id: str, status: str, error: str = None):
    """Update encryption_report status in DB."""
    try:
        conn = _get_encryption_conn()
        with conn.cursor() as cur:
            if error:
                cur.execute(
                    "UPDATE encryption_report SET status = %s, error_message = %s WHERE scan_run_id = %s",
                    (status, error, scan_run_id),
                )
            else:
                cur.execute(
                    "UPDATE encryption_report SET status = %s WHERE scan_run_id = %s",
                    (status, scan_run_id),
                )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to update report status: {e}")


def _create_report_row(scan_run_id: str, tenant_id: str, provider: str):
    """Pre-create encryption_report row with status='running'."""
    try:
        conn = _get_encryption_conn()
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO tenants (tenant_id, tenant_name) VALUES (%s, %s) ON CONFLICT DO NOTHING",
                (tenant_id, tenant_id),
            )
            cur.execute(
                """INSERT INTO encryption_report
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
    parser = argparse.ArgumentParser(description="Encryption Security Engine Scanner")
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan run ID")
    args = parser.parse_args()

    scan_run_id = args.scan_run_id
    logger.info(f"Encryption scanner starting scan_run_id={scan_run_id}")

    # SIGTERM handler — mark scan failed on preemption/timeout
    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking encryption scan {scan_run_id} as failed")
        _update_report_status(scan_run_id, "failed", "Terminated by SIGTERM (spot preemption or timeout)")
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        # 1. Get orchestration metadata
        logger.info("Resolving orchestration metadata...")
        metadata = get_orchestration_metadata(scan_run_id)
        if not metadata:
            raise ValueError(f"No orchestration metadata for {scan_run_id}")

        tenant_id = metadata.get("tenant_id", "default-tenant")
        provider = (metadata.get("provider") or metadata.get("provider_type", "aws")).lower()
        account_id = metadata.get("account_id", "")

        logger.info(f"Resolved: tenant={tenant_id} provider={provider} account={account_id}")

        # 2. Pre-create report row
        _create_report_row(scan_run_id, tenant_id, provider)

        start = datetime.now(timezone.utc)

        # 3. Load data from source databases
        from encryption_security_engine.input.discovery_reader import DiscoveryReader
        from encryption_security_engine.input.check_reader import CheckReader
        from encryption_security_engine.input.datasec_reader import DataSecReader
        from encryption_security_engine.input.inventory_reader import InventoryReader

        disc_reader = DiscoveryReader()
        check_reader = CheckReader()
        datasec_reader = DataSecReader()
        inv_reader = InventoryReader()

        try:
            # Discovery: KMS, ACM, ACM-PCA, SecretsManager
            discovery_resources = disc_reader.load_all_encryption_resources(scan_run_id, tenant_id, account_id or None)
            kms_resources = discovery_resources.get("kms", [])
            acm_resources = discovery_resources.get("acm", [])
            acm_pca_resources = discovery_resources.get("acm-pca", [])
            secrets_resources = discovery_resources.get("secretsmanager", [])
            logger.info(f"Discovery: {len(kms_resources)} KMS, {len(acm_resources)} ACM, {len(secrets_resources)} secrets")

            # Check findings
            check_findings = check_reader.load_encryption_check_findings(scan_run_id, tenant_id)
            cross_svc_findings = check_reader.load_encryption_rule_findings(scan_run_id, tenant_id)
            all_check_findings = check_findings + cross_svc_findings
            logger.info(f"Check: {len(all_check_findings)} encryption findings")

            # DataSec
            datasec_findings = datasec_reader.load_encryption_posture(scan_run_id, tenant_id)
            enhanced_data = datasec_reader.load_enhanced_encryption_data(scan_run_id, tenant_id)
            logger.info(f"DataSec: {len(datasec_findings)} findings, {len(enhanced_data)} enhanced rows")

            # Inventory relationships
            kms_relationships = inv_reader.load_kms_relationships(scan_run_id, tenant_id)
            logger.info(f"Inventory: {len(kms_relationships)} KMS relationships")

        finally:
            disc_reader.close()
            check_reader.close()
            datasec_reader.close()
            inv_reader.close()

        # 4. Run analyzers
        from encryption_security_engine.analyzer.coverage_analyzer import analyze_coverage
        from encryption_security_engine.analyzer.posture_scorer import compute_posture_score
        from encryption_security_engine.analyzer.key_inventory_builder import build_key_inventory
        from encryption_security_engine.analyzer.cert_inventory_builder import build_cert_inventory
        from encryption_security_engine.analyzer.secrets_inventory_builder import build_secrets_inventory

        # Coverage analysis
        coverage_data = analyze_coverage(
            discovery_resources=discovery_resources,
            check_findings=all_check_findings,
            datasec_findings=datasec_findings,
            enhanced_data=enhanced_data,
        )
        logger.info(f"Coverage: {coverage_data['totals']}")

        # Build inventories
        key_inventory = build_key_inventory(kms_resources, kms_relationships)
        cert_inventory = build_cert_inventory(acm_resources, acm_pca_resources)
        secrets_inventory = build_secrets_inventory(secrets_resources)

        # Posture score
        posture = compute_posture_score(coverage_data, key_inventory)

        # 5. Build findings from coverage per-resource data
        from encryption_security_engine.storage.encryption_db_writer import (
            generate_finding_id, save_findings_to_db,
            save_key_inventory, save_cert_inventory, save_secrets_inventory,
        )

        findings = []
        for uid, info in coverage_data.get("per_resource", {}).items():
            # Determine severity based on encryption status
            enc_at_rest = info.get("encrypted_at_rest")
            key_type = info.get("key_type")

            if enc_at_rest is False:
                severity = "HIGH"
                status = "FAIL"
                domain = "at_rest_coverage"
            elif key_type in (None, "none", "AWS") and enc_at_rest is True:
                severity = "MEDIUM"
                status = "WARNING"
                domain = "kms_key_management"
            elif info.get("rotation_compliant") is False:
                severity = "MEDIUM"
                status = "FAIL"
                domain = "kms_key_management"
            elif info.get("encrypted_in_transit") is False:
                severity = "MEDIUM"
                status = "FAIL"
                domain = "in_transit_enforcement"
            else:
                severity = "LOW"
                status = "PASS"
                domain = "at_rest_coverage"

            finding_id = generate_finding_id(
                domain, uid, info.get("account_id", ""), info.get("region", "")
            )

            findings.append({
                "finding_id": finding_id,
                "resource_uid": uid,
                "resource_type": info.get("resource_type", ""),
                "account_id": info.get("account_id", ""),
                "region": info.get("region", ""),
                "credential_ref": metadata.get("credential_ref"),
                "credential_type": metadata.get("credential_type"),
                "encryption_domain": domain,
                "encryption_status": _determine_enc_status(info),
                "key_type": key_type,
                "algorithm": info.get("algorithm"),
                "rotation_compliant": info.get("rotation_compliant"),
                "transit_enforced": info.get("encrypted_in_transit"),
                "severity": severity,
                "status": status,
                "rule_id": None,
                "finding_data": {
                    "encrypted_at_rest": enc_at_rest,
                    "encrypted_in_transit": info.get("encrypted_in_transit"),
                    "key_type": key_type,
                    "algorithm": info.get("algorithm"),
                    "service": info.get("service"),
                },
            })

        # 5b. Phase 2: Dependency graph, blast radius, cross-reference, remediation
        try:
            from encryption_security_engine.analyzer.dependency_graph import build_dependency_graph
            from encryption_security_engine.analyzer.blast_radius import calculate_all_blast_radii
            from encryption_security_engine.analyzer.sensitivity_cross_ref import cross_reference_sensitive_data
            from encryption_security_engine.analyzer.remediation_prioritizer import prioritize_findings, get_top_remediations

            # Dependency graph
            dep_graph = build_dependency_graph(
                kms_relationships=kms_relationships,
                enhanced_data=enhanced_data,
                discovery_resources=discovery_resources,
                key_inventory=key_inventory,
                datasec_findings=datasec_findings,
            )
            logger.info(f"Dependency graph: {dep_graph.total_edges} edges")

            # Update key inventory with dependency counts
            for k in key_inventory:
                k["dependent_resource_count"] = dep_graph.get_dependency_count(k.get("key_arn", ""))

            # Build datasec classification map for blast radius + prioritizer
            datasec_classification = {}
            for ed in enhanced_data:
                uid = ed.get("resource_arn", "")
                if uid:
                    datasec_classification[uid] = ed
            for uid, meta in dep_graph.resource_metadata.items():
                if uid not in datasec_classification:
                    datasec_classification[uid] = meta

            # Blast radius for all keys
            blast_radii = calculate_all_blast_radii(dep_graph, datasec_classification)
            logger.info(f"Blast radius: computed for {len(blast_radii)} keys")

            # Sensitive data cross-reference
            cross_ref_findings = cross_reference_sensitive_data(
                coverage_per_resource=coverage_data.get("per_resource", {}),
                datasec_findings=datasec_findings,
                enhanced_data=enhanced_data,
            )
            logger.info(f"Cross-ref: {len(cross_ref_findings)} sensitive data findings")

            # Add cross-ref findings to main findings list
            for xf in cross_ref_findings:
                xf_id = generate_finding_id(
                    xf.get("cross_ref_type", "xref"),
                    xf.get("resource_uid", ""),
                    xf.get("account_id", ""),
                    xf.get("region", ""),
                )
                findings.append({
                    "finding_id": xf_id,
                    "resource_uid": xf.get("resource_uid", ""),
                    "resource_type": xf.get("resource_type", ""),
                    "account_id": xf.get("account_id", ""),
                    "region": xf.get("region", ""),
                    "credential_ref": metadata.get("credential_ref"),
                    "credential_type": metadata.get("credential_type"),
                    "encryption_domain": "sensitive_data_exposure",
                    "encryption_status": xf.get("encryption_status"),
                    "key_type": xf.get("key_type"),
                    "algorithm": None,
                    "rotation_compliant": None,
                    "transit_enforced": None,
                    "severity": xf.get("severity", "HIGH"),
                    "status": "FAIL",
                    "rule_id": None,
                    "finding_data": {
                        "cross_ref_type": xf.get("cross_ref_type"),
                        "title": xf.get("title"),
                        "description": xf.get("description"),
                        "remediation": xf.get("remediation"),
                        "data_classification": xf.get("data_classification"),
                        "sensitivity_score": xf.get("sensitivity_score"),
                    },
                })

            # Remediation prioritization
            prioritized = prioritize_findings(findings, cross_ref_findings, datasec_classification)
            top_remediations = get_top_remediations(prioritized, top_n=10)
            logger.info(f"Remediations: top {len(top_remediations)} items")

        except Exception as phase2_err:
            logger.warning(f"Phase 2 analysis failed (non-fatal): {phase2_err}", exc_info=True)
            dep_graph = None
            blast_radii = []
            cross_ref_findings = []
            top_remediations = []

        # 5c. Phase 3: Cert chain, cross-account, drift, multi-cloud parity
        cert_chain_findings = []
        cross_account_findings = []
        drift_findings = []
        multi_cloud = {}

        try:
            from encryption_security_engine.analyzer.cert_chain_validator import validate_cert_chains
            from encryption_security_engine.analyzer.cross_account_keys import analyze_cross_account_keys
            from encryption_security_engine.analyzer.multi_cloud_parity import analyze_multi_cloud_parity

            # Cert chain validation
            cert_chain_findings = validate_cert_chains(cert_inventory, kms_relationships)
            logger.info(f"Cert validation: {len(cert_chain_findings)} findings")

            # Add cert findings to main list
            for cf in cert_chain_findings:
                cf_id = generate_finding_id(
                    cf.get("validation_type", "cert"),
                    cf.get("cert_arn", ""),
                    cf.get("account_id", ""),
                    cf.get("region", ""),
                )
                findings.append({
                    "finding_id": cf_id,
                    "resource_uid": cf.get("cert_arn", ""),
                    "resource_type": "acm::certificate",
                    "account_id": cf.get("account_id", ""),
                    "region": cf.get("region", ""),
                    "credential_ref": metadata.get("credential_ref"),
                    "credential_type": metadata.get("credential_type"),
                    "encryption_domain": "certificate_lifecycle",
                    "encryption_status": None,
                    "key_type": None,
                    "algorithm": cf.get("key_algorithm"),
                    "rotation_compliant": None,
                    "transit_enforced": None,
                    "severity": cf.get("severity", "MEDIUM"),
                    "status": "FAIL",
                    "rule_id": None,
                    "finding_data": {
                        "validation_type": cf.get("validation_type"),
                        "title": cf.get("title"),
                        "description": cf.get("description"),
                        "remediation": cf.get("remediation"),
                        "domain_name": cf.get("domain_name"),
                        "days_until_expiry": cf.get("days_until_expiry"),
                    },
                })

            # Cross-account key sharing
            own_accounts = {account_id} if account_id else None
            cross_account_findings = analyze_cross_account_keys(key_inventory, own_accounts)
            logger.info(f"Cross-account: {len(cross_account_findings)} findings")

            for ca in cross_account_findings:
                ca_id = generate_finding_id(
                    ca.get("sharing_type", "xacct"),
                    ca.get("key_arn", ""),
                    ca.get("account_id", ""),
                    ca.get("region", ""),
                )
                findings.append({
                    "finding_id": ca_id,
                    "resource_uid": ca.get("key_arn", ""),
                    "resource_type": "kms::key",
                    "account_id": ca.get("account_id", ""),
                    "region": ca.get("region", ""),
                    "credential_ref": metadata.get("credential_ref"),
                    "credential_type": metadata.get("credential_type"),
                    "encryption_domain": "cross_account_sharing",
                    "encryption_status": None,
                    "key_type": ca.get("key_manager"),
                    "algorithm": None,
                    "rotation_compliant": None,
                    "transit_enforced": None,
                    "severity": ca.get("severity", "HIGH"),
                    "status": "FAIL",
                    "rule_id": None,
                    "finding_data": {
                        "sharing_type": ca.get("sharing_type"),
                        "title": ca.get("title"),
                        "description": ca.get("description"),
                        "remediation": ca.get("remediation"),
                        "external_accounts": ca.get("external_accounts", []),
                        "grant_count": ca.get("grant_count"),
                    },
                })

            # Multi-cloud parity
            multi_cloud = analyze_multi_cloud_parity(
                coverage_data.get("by_service", {}),
                coverage_data.get("per_resource", {}),
                key_inventory,
            )
            logger.info(f"Multi-cloud parity: score={multi_cloud.get('parity_score', 'N/A')}")

        except Exception as phase3a_err:
            logger.warning(f"Phase 3a (cert/xacct/parity) failed (non-fatal): {phase3a_err}", exc_info=True)

        # Drift detection (CIEM-based, separate try block)
        try:
            from encryption_security_engine.input.ciem_reader import CIEMEncryptionReader
            from encryption_security_engine.analyzer.drift_detector import detect_drift_from_events

            ciem_reader = CIEMEncryptionReader()
            try:
                ciem_events = ciem_reader.load_kms_events(tenant_id, account_id or None, days=30)
                config_events = ciem_reader.load_encryption_config_changes(tenant_id, account_id or None, days=30)
                all_events = ciem_events + config_events

                if all_events:
                    drift_findings = detect_drift_from_events(all_events)
                    logger.info(f"Drift detection: {len(drift_findings)} findings from {len(all_events)} events")

                    for df in drift_findings:
                        df_id = generate_finding_id(
                            df.get("event_name", "drift"),
                            df.get("resource_arn", ""),
                            df.get("account_id", ""),
                            df.get("region", ""),
                        )
                        findings.append({
                            "finding_id": df_id,
                            "resource_uid": df.get("resource_arn", ""),
                            "resource_type": "kms::key",
                            "account_id": df.get("account_id", ""),
                            "region": df.get("region", ""),
                            "credential_ref": metadata.get("credential_ref"),
                            "credential_type": metadata.get("credential_type"),
                            "encryption_domain": "encryption_drift",
                            "encryption_status": None,
                            "key_type": None,
                            "algorithm": None,
                            "rotation_compliant": None,
                            "transit_enforced": None,
                            "severity": df.get("severity", "HIGH"),
                            "status": "FAIL",
                            "rule_id": None,
                            "finding_data": {
                                "drift_type": df.get("drift_type"),
                                "event_name": df.get("event_name"),
                                "title": df.get("title"),
                                "description": df.get("description"),
                                "remediation": df.get("remediation"),
                                "event_time": str(df.get("event_time", "")),
                                "caller": df.get("caller"),
                            },
                        })
            finally:
                ciem_reader.close()

        except Exception as ciem_err:
            logger.warning(f"CIEM drift detection failed (non-fatal): {ciem_err}")

        # CIEM findings (pre-evaluated log-based encryption detections)
        try:
            from engine_common.ciem_reader import CIEMReader
            ciem = CIEMReader(tenant_id=tenant_id, account_id=account_id or "", days=30)
            ciem_enc_findings = ciem.get_ciem_findings(engine_filter="encryption")
            if ciem_enc_findings:
                logger.info(f"CIEM: {len(ciem_enc_findings)} encryption findings from ciem_findings")
                for cf in ciem_enc_findings:
                    cf_id = generate_finding_id(
                        cf.get("rule_id", "ciem"),
                        cf.get("resource_uid", ""),
                        cf.get("account_id", ""),
                        cf.get("region", ""),
                    )
                    findings.append({
                        "finding_id": cf_id,
                        "resource_uid": cf.get("resource_uid", ""),
                        "resource_type": cf.get("resource_type", ""),
                        "account_id": cf.get("account_id", ""),
                        "region": cf.get("region", ""),
                        "credential_ref": metadata.get("credential_ref"),
                        "credential_type": metadata.get("credential_type"),
                        "encryption_domain": "ciem_detection",
                        "encryption_status": None,
                        "key_type": None,
                        "algorithm": None,
                        "rotation_compliant": None,
                        "transit_enforced": None,
                        "severity": (cf.get("severity") or "medium").upper(),
                        "status": "FAIL",
                        "rule_id": cf.get("rule_id"),
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
        except Exception as ciem_f_err:
            logger.warning(f"CIEM findings load failed (non-fatal): {ciem_f_err}")

        # Build summary
        sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f["severity"].lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        summary = {
            **posture,
            "total_resources": coverage_data["totals"]["total"],
            "encrypted_resources": coverage_data["totals"]["encrypted"],
            "unencrypted_resources": coverage_data["totals"]["unencrypted"],
            "total_keys": len(key_inventory),
            "total_certificates": len(cert_inventory),
            "total_secrets": len(secrets_inventory),
            "total_findings": len(findings),
            "critical_findings": sev_counts["critical"],
            "high_findings": sev_counts["high"],
            "medium_findings": sev_counts["medium"],
            "low_findings": sev_counts["low"],
            "coverage_by_service": coverage_data["by_service"],
            "severity_breakdown": sev_counts,
            "domain_breakdown": _count_by_domain(findings),
            "dependency_graph": dep_graph.to_dict() if dep_graph else {},
            "blast_radii": blast_radii,
            "cross_ref_findings_count": len(cross_ref_findings),
            "top_remediations": top_remediations,
            "cert_chain_findings_count": len(cert_chain_findings),
            "cross_account_findings_count": len(cross_account_findings),
            "drift_findings_count": len(drift_findings),
            "multi_cloud_parity": multi_cloud,
        }

        # 6. Write to database
        save_findings_to_db(scan_run_id, tenant_id, provider, findings, summary)
        save_key_inventory(scan_run_id, tenant_id, key_inventory)
        save_cert_inventory(scan_run_id, tenant_id, cert_inventory)
        save_secrets_inventory(scan_run_id, tenant_id, secrets_inventory)

        # 7. Save report JSON to /output for S3 sync
        try:
            output_dir = os.getenv("OUTPUT_DIR", "/output")
            if output_dir and os.path.exists(output_dir):
                enc_dir = os.path.join(output_dir, "encryption", "reports", tenant_id)
                os.makedirs(enc_dir, exist_ok=True)
                with open(os.path.join(enc_dir, f"{scan_run_id}_report.json"), "w") as f:
                    json.dump(summary, f, indent=2, default=str)
                logger.info(f"Report saved to {enc_dir}")
        except Exception as e:
            logger.error(f"Error saving report to output dir: {e}")

        duration = (datetime.now(timezone.utc) - start).total_seconds()
        _update_report_status(scan_run_id, "completed")

        logger.info(
            f"Encryption scan completed: {scan_run_id} — "
            f"score={posture['posture_score']}, {len(findings)} findings, "
            f"{len(key_inventory)} keys, {len(cert_inventory)} certs, "
            f"{len(secrets_inventory)} secrets in {duration:.1f}s"
        )

        # 8. Retention cleanup
        try:
            cleanup_old_scans("encryption", tenant_id, keep=3)
        except Exception as e:
            logger.warning(f"Retention cleanup failed: {e}")

    except Exception as e:
        logger.error(f"Encryption scan FAILED: {e}", exc_info=True)
        _update_report_status(scan_run_id, "failed", str(e))
        sys.exit(1)


def _determine_enc_status(info: dict) -> str:
    """Determine encryption_status string from resource info."""
    if info.get("encrypted_at_rest") is False:
        return "unencrypted"
    key_type = info.get("key_type")
    if key_type in ("CUSTOMER", "customer_managed"):
        return "encrypted_cmk"
    if info.get("encrypted_at_rest") is True:
        return "encrypted_managed"
    return "unknown"


def _count_by_domain(findings: list) -> dict:
    """Count findings by encryption_domain."""
    counts = {}
    for f in findings:
        d = f.get("encryption_domain", "unknown")
        counts[d] = counts.get(d, 0) + 1
    return counts


if __name__ == "__main__":
    main()
