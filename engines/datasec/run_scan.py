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
from engine_common.db_connections import get_datasec_conn

logger = setup_logger(__name__, engine_name="datasec-scanner")


def _update_report_status(scan_run_id: str, status: str, error: str = None):
    """Update datasec_report status in DB."""
    try:
        conn = get_datasec_conn()
        with conn.cursor() as cur:
            if error:
                cur.execute(
                    "UPDATE datasec_report SET status = %s, report_data = %s::jsonb WHERE scan_run_id = %s",
                    (status, json.dumps({"error": error}), scan_run_id),
                )
            elif status == "completed":
                cur.execute(
                    "UPDATE datasec_report SET status = %s, completed_at = NOW() WHERE scan_run_id = %s",
                    (status, scan_run_id),
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
    """Pre-create datasec_report row with status='running'.
    datasec_scan_id is the PK (set to scan_run_id); scan_run_id is a plain column.
    """
    try:
        conn = get_datasec_conn()
        with conn.cursor() as cur:
            # Upsert tenant first to satisfy the FK constraint
            cur.execute(
                "INSERT INTO tenants (tenant_id) VALUES (%s) ON CONFLICT (tenant_id) DO NOTHING",
                (tenant_id,),
            )
            cur.execute(
                """INSERT INTO datasec_report
                   (datasec_scan_id, scan_run_id, tenant_id, cloud, provider,
                    threat_scan_id, status, report_data, generated_at)
                   VALUES (%s, %s, %s, %s, %s, %s, 'running', '{}'::jsonb, NOW())
                   ON CONFLICT (datasec_scan_id) DO UPDATE SET status = 'running'""",
                (scan_run_id, scan_run_id, tenant_id, provider, provider, threat_scan_id),
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
        account_id = metadata.get("account_id", "")
        provider = (metadata.get("provider") or metadata.get("provider_type", "aws")).lower()
        credential_ref = metadata.get("credential_ref", "")
        credential_type = metadata.get("credential_type", "")

        from data_security_engine.providers import get_provider as get_datasec_provider
        ds_provider = get_datasec_provider(provider)

        logger.info(f"Resolved: tenant={tenant_id} account={account_id} provider={provider} threat_scan_id={threat_scan_id}")

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
        # Only runs for supported providers — the module orchestrator uses boto3-backed analyzers
        # (classification, lineage, activity) that require credentials.
        # Unsupported providers rely entirely on the check_findings primary path above.
        if not module_results and ds_provider.is_supported():
            logger.info("Falling back to legacy threat_findings-based approach (AWS only)")
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
                    "account_id": account_id,
                    "scan_run_id": scan_run_id,
                    "threat_scan_id": threat_scan_id,
                }
                module_results = orchestrator.run_scan(findings, data_stores, context)
                summary = orchestrator.get_summary(module_results)
            except Exception as e:
                logger.error(f"Fallback datasec analysis also failed: {e}", exc_info=True)
                summary = {"total_findings": 0, "findings_by_status": {}, "findings_by_module": {}, "findings_by_severity": {}}

        if not module_results and not ds_provider.is_supported():
            logger.info(f"No datasec findings for provider={provider} — check_findings path produced nothing (expected if check scan had no data-security rules)")
            summary = {"total_findings": 0, "findings_by_status": {}, "findings_by_module": {}, "findings_by_severity": {}}

        # 4b2. SECONDARY: provider.analyze() — discovery-based DSPM (additive)
        # Runs after check_findings path regardless. Produces structured per-module
        # findings with dspm_module, classification_labels, encryption_status, public_access.
        try:
            from engine_common.db_connections import get_discoveries_conn, get_check_conn
            from data_security_engine.storage.datasec_db_writer import save_dspm_findings

            discoveries_conn = get_discoveries_conn()
            check_conn = get_check_conn()
            try:
                dspm_findings = ds_provider.analyze(
                    scan_run_id=scan_run_id,
                    tenant_id=tenant_id,
                    account_id=account_id,
                    discoveries_conn=discoveries_conn,
                    check_conn=check_conn,
                )
                if dspm_findings:
                    written = save_dspm_findings(
                        dspm_findings,
                        credential_ref=credential_ref,
                        credential_type=credential_type,
                    )
                    logger.info(
                        f"DSPM analyze(): {len(dspm_findings)} findings produced, "
                        f"{written} written to DB for provider={provider}"
                    )
                else:
                    logger.info(f"DSPM analyze(): 0 findings for provider={provider} scan_run_id={scan_run_id}")
            finally:
                discoveries_conn.close()
                check_conn.close()
        except Exception as dspm_exc:
            logger.warning(f"DSPM analyze() secondary path failed (non-fatal): {dspm_exc}", exc_info=True)

        # 4c. Write findings to DB
        try:
            from data_security_engine.storage.datasec_db_writer import save_module_results_to_db
            save_module_results_to_db(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id,
                provider=provider,
                credential_ref=credential_ref,
                credential_type=credential_type,
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

        # 4e. Cross-engine enrichment: discovery/DI metadata → data catalog
        try:
            import os as _os
            if _os.getenv("DI_ENGINE_ENABLED", "false").lower() == "true":
                from data_security_engine.input.di_reader import DataStoreDIReader as DataStoreDiscoveryReader
            else:
                from data_security_engine.input.discovery_db_reader import DataStoreDiscoveryReader
            from data_security_engine.storage.datasec_db_writer import save_data_catalog

            ds_reader = DataStoreDiscoveryReader()
            ds_metadata = ds_reader.load_data_store_metadata(scan_run_id, tenant_id, account_id)
            if ds_metadata:
                save_data_catalog(scan_run_id, tenant_id, account_id, provider, ds_metadata)
                logger.info(f"Data catalog: enriched {len(ds_metadata)} data stores with discovery metadata")
        except Exception as e:
            logger.warning(f"Data catalog enrichment failed (non-fatal): {e}")

        # 4f. Cross-engine enrichment: inventory → data lineage
        try:
            from data_security_engine.input.inventory_reader import DataStoreInventoryReader
            from data_security_engine.storage.datasec_db_writer import save_lineage_records

            inv_reader = DataStoreInventoryReader()
            lineage = inv_reader.build_lineage_records(scan_run_id, tenant_id)
            if lineage:
                save_lineage_records(lineage)
                logger.info(f"Data lineage: {len(lineage)} flow relationships from inventory")
        except Exception as e:
            logger.warning(f"Data lineage enrichment failed (non-fatal): {e}")

        # 4g. Cross-engine enrichment: CIEM → access activity
        try:
            from engine_common.ciem_reader import CIEMReader
            from data_security_engine.storage.datasec_db_writer import save_access_activity

            ciem = CIEMReader(tenant_id=tenant_id, account_id=account_id, days=30)
            data_access = ciem.get_data_access_patterns()
            if data_access:
                save_access_activity(scan_run_id, tenant_id, account_id, data_access)
                logger.info(f"CIEM: {len(data_access)} data store access patterns saved")

            ciem_ds_findings = ciem.get_ciem_findings(engine_filter="datasec")
            if ciem_ds_findings:
                logger.info(f"CIEM: {len(ciem_ds_findings)} datasec findings from CIEM")
                # Merge CIEM findings as a "ciem_detection" module in module_results
                ciem_module_findings = []
                for cf in ciem_ds_findings:
                    ciem_module_findings.append({
                        "finding_id": cf.get("finding_id", ""),
                        "rule_id": cf.get("rule_id", ""),
                        "severity": cf.get("severity", "medium"),
                        "status": "FAIL",
                        "title": cf.get("title", ""),
                        "resource_uid": cf.get("resource_uid", ""),
                        "resource_type": cf.get("resource_type", ""),
                        "account_id": cf.get("account_id", account_id or ""),
                        "region": cf.get("region", ""),
                        "provider": provider or "aws",
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
                            "action_category": cf.get("action_category", ""),
                        },
                    })
                if ciem_module_findings:
                    if not isinstance(module_results, dict):
                        module_results = {}
                    module_results["ciem_detection"] = ciem_module_findings
                    # Update summary counts
                    sev_counts = summary.get("findings_by_severity", {})
                    mod_counts = summary.get("findings_by_module", {})
                    for cf in ciem_module_findings:
                        s = (cf.get("severity") or "medium").lower()
                        sev_counts[s] = sev_counts.get(s, 0) + 1
                    mod_counts["ciem_detection"] = len(ciem_module_findings)
                    summary["total_findings"] = summary.get("total_findings", 0) + len(ciem_module_findings)
                    summary["findings_by_severity"] = sev_counts
                    summary["findings_by_module"] = mod_counts
                    logger.info(f"Merged {len(ciem_module_findings)} CIEM findings into module_results")
        except Exception as ciem_exc:
            logger.warning(f"CIEM enrichment failed (non-fatal): {ciem_exc}")

        # 4h. Cross-engine enrichment: encryption engine → encryption status
        try:
            from data_security_engine.input.encryption_reader import EncryptionCrossRefReader
            from data_security_engine.storage.datasec_db_writer import update_catalog_encryption

            enc_reader = EncryptionCrossRefReader()
            enc_status = enc_reader.load_encryption_status(scan_run_id, tenant_id)
            if enc_status:
                update_catalog_encryption(scan_run_id, tenant_id, enc_status)
                logger.info(f"Encryption cross-ref: enriched {len(enc_status)} resources")
        except Exception as e:
            logger.warning(f"Encryption cross-ref failed (non-fatal): {e}")

        duration = (datetime.now(timezone.utc) - start).total_seconds()

        # 5. Update status to completed
        _update_report_status(scan_run_id, "completed")

        total = summary.get("total_findings", 0)
        fails = summary.get("findings_by_status", {}).get("FAIL", 0)
        logger.info(f"DataSec scan completed: {scan_run_id} — {total} evaluations, {fails} failures in {duration:.1f}s")

        # Retention: archive old scans to S3, keep last 5 in DB
        try:
            from engine_common.retention import run_retention
            run_retention("datasec", scan_run_id)
        except Exception as _ret_err:
            logger.warning("Retention cleanup skipped: %s", _ret_err)

        # Write datasec posture signals to resource_security_posture (non-fatal)
        try:
            from data_security_engine.posture_signals import write_datasec_posture_signals
            write_datasec_posture_signals(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id or "",
                provider=provider,
            )
        except Exception as _ps_err:
            logger.warning("DataSec posture signal write skipped: %s", _ps_err)

        # Write datasec FAIL findings to shared security_findings table (non-fatal)
        try:
            import hashlib
            from engine_common.security_findings_writer import upsert_findings
            from engine_common.db_connections import get_inventory_conn

            inv_conn = get_inventory_conn()
            datasec_conn = get_datasec_conn()
            rows: list = []
            raw_rows = []
            with datasec_conn.cursor(cursor_factory=__import__("psycopg2.extras", fromlist=["RealDictCursor"]).RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT finding_id, rule_id, resource_uid, resource_type,
                           account_id, provider, region, severity, status, finding_data
                    FROM datasec_findings
                    WHERE scan_run_id = %s AND tenant_id = %s AND status = 'FAIL'
                    LIMIT 2000
                    """,
                    (scan_run_id, tenant_id),
                )
                raw_rows = cur.fetchall()

            # Batch-lookup MITRE data from rule_metadata
            mitre_by_rule: dict = {}
            rule_ids = list({r["rule_id"] for r in raw_rows if r.get("rule_id")})
            if rule_ids:
                try:
                    from engine_common.db_connections import get_check_conn
                    check_conn = get_check_conn()
                    with check_conn.cursor(cursor_factory=__import__("psycopg2.extras", fromlist=["RealDictCursor"]).RealDictCursor) as mc:
                        mc.execute(
                            "SELECT rule_id, mitre_attack_id, mitre_tactic FROM rule_metadata WHERE rule_id = ANY(%s)",
                            (rule_ids,),
                        )
                        for rm in mc.fetchall():
                            mitre_by_rule[rm["rule_id"]] = (rm.get("mitre_attack_id"), rm.get("mitre_tactic"))
                    check_conn.close()
                except Exception:
                    pass

            for r in raw_rows:
                    fd = r["finding_data"] if isinstance(r["finding_data"], dict) else {}
                    src_id = hashlib.sha256(
                        f"datasec|{r['finding_id']}".encode()
                    ).hexdigest()[:64]
                    _rule_id = r.get("rule_id") or ""
                    _mitre_tech, _mitre_tac = mitre_by_rule.get(_rule_id, (None, None))
                    rows.append({
                        "source_finding_id": src_id,
                        "resource_uid": (r["resource_uid"] or "")[:512],
                        "account_id": r.get("account_id", "")[:128],
                        "provider": r.get("provider", ""),
                        "resource_type": r.get("resource_type", "")[:128],
                        "finding_type": "data_violation",
                        "severity": (r.get("severity") or "medium").lower(),
                        "rule_id": _rule_id[:128],
                        "title": fd.get("title", "")[:500],
                        "description": fd.get("description", ""),
                        "mitre_technique_id": _mitre_tech,
                        "mitre_tactic": _mitre_tac,
                        "detail": {
                            "datasec_modules": fd.get("datasec_modules"),
                            "data_classification": fd.get("data_classification"),
                            "evidence": fd.get("evidence"),
                        },
                        "status": "open",
                    })
            if rows:
                written = upsert_findings(
                    conn=inv_conn,
                    findings=rows,
                    source_engine="datasec",
                    tenant_id=tenant_id,
                    scan_run_id=scan_run_id,
                )
                logger.info("security_findings: wrote %d datasec rows", written)
            inv_conn.close()
            datasec_conn.close()
        except Exception as _sf_err:
            logger.warning("DataSec security_findings write skipped: %s", _sf_err)

    except Exception as e:
        logger.error(f"DataSec scan FAILED: {e}", exc_info=True)
        _update_report_status(scan_run_id, "failed", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
