"""
IAM Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --scan-run-id X

Pipeline:
  1. Load threat_findings → enrich → filter IAM-relevant (existing)
  2. Load IAM discovery data → parse policies → analyze trusts (NEW)
  3. Run policy-based detectors → merge findings (NEW)
  4. Save policy statements to iam_policy_statements table (NEW)
  5. Create Neo4j graph edges (HAS_POLICY, ASSUMES, CAN_ACCESS) (NEW)
  6. Write combined findings to iam_findings + iam_report
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


def _update_report_status(scan_run_id: str, status: str, error: str = None):
    """Update iam_report status in DB."""
    try:
        conn = _get_iam_conn()
        with conn.cursor() as cur:
            if error:
                cur.execute(
                    "UPDATE iam_report SET status = %s, report_data = %s::jsonb WHERE scan_run_id = %s",
                    (status, __import__('json').dumps({"error": error}), scan_run_id),
                )
            else:
                cur.execute(
                    "UPDATE iam_report SET status = %s WHERE scan_run_id = %s",
                    (status, scan_run_id),
                )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Failed to update report status: {e}")


def _create_report_row(scan_run_id: str, tenant_id: str, provider: str,
                       threat_scan_id: str, metadata: dict):
    """Pre-create iam_report row with status='running'."""
    try:
        conn = _get_iam_conn()
        with conn.cursor() as cur:
            cur.execute(
                """INSERT INTO iam_report
                   (scan_run_id, tenant_id, provider, threat_scan_id, status, generated_at)
                   VALUES (%s, %s, %s, %s, 'running', NOW())
                   ON CONFLICT (scan_run_id) DO UPDATE SET status = 'running'""",
                (scan_run_id, tenant_id, provider, threat_scan_id),
            )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Failed to pre-create report row: {e}")


def main():
    parser = argparse.ArgumentParser(description="IAM Engine Scanner")
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan run ID")
    args = parser.parse_args()

    scan_run_id = args.scan_run_id

    logger.info(f"IAM scanner starting scan_run_id={scan_run_id}")

    # SIGTERM handler — mark scan failed on preemption/timeout
    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking IAM scan {scan_run_id} as failed")
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

        # 3. Run IAM scan — existing threat-findings flow
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

        # 4.5 NEW: Policy analysis from discovery data
        discovery_scan_id = scan_run_id
        account_id = metadata.get("account_id", "")
        policy_findings = []
        managed_policies = []
        inline_policies = []
        trust_relationships = []
        discovery_roles = []
        discovery_users = []
        discovery_groups = []
        discovery_instance_profiles = []

        if discovery_scan_id:
            try:
                from iam_engine.parsers.policy_parser import (
                    extract_managed_policies, extract_inline_policies,
                    extract_trust_policies, policies_to_db_rows,
                )
                from iam_engine.parsers.trust_analyzer import TrustAnalyzer
                from iam_engine.detectors.policy_detector import run_all_detectors

                data_source = os.getenv("IAM_DATA_SOURCE", "discovery").lower()
                if data_source == "inventory":
                    from iam_engine.input.inventory_reader import IAMInventoryReader
                    logger.info(f"Loading IAM data from inventory_findings: scan={discovery_scan_id}")
                    reader = IAMInventoryReader()
                else:
                    from iam_engine.input.discovery_db_reader import IAMDiscoveryReader
                    logger.info(f"Loading IAM discovery data: scan={discovery_scan_id}")
                    reader = IAMDiscoveryReader()
                resources = reader.load_iam_resources(discovery_scan_id, tenant_id, account_id or None)
                reader.close()

                # Extract structured data
                discovery_roles = reader.get_roles(resources)
                discovery_users = reader.get_users(resources)
                discovery_groups = reader.get_groups(resources)
                discovery_instance_profiles = reader.get_instance_profiles(resources)
                discovery_policies = reader.get_policies(resources)

                # Parse policies
                managed_policies = extract_managed_policies(discovery_policies, account_id)
                logger.info(f"Parsed {len(managed_policies)} managed policies")

                for role in discovery_roles:
                    inline_policies.extend(extract_inline_policies(role, "role"))
                for user in discovery_users:
                    inline_policies.extend(extract_inline_policies(user, "user"))
                logger.info(f"Parsed {len(inline_policies)} inline policies")

                trust_policies = extract_trust_policies(discovery_roles)
                logger.info(f"Parsed {len(trust_policies)} trust policies")

                # Analyze trust relationships
                trust_analyzer = TrustAnalyzer()
                trust_relationships = trust_analyzer.analyze_trust_policies(discovery_roles, account_id)
                risky_trusts = trust_analyzer.find_risky_trusts(trust_relationships)
                logger.info(f"Found {len(risky_trusts)} risky trust relationships")

                # Save policy statements to DB
                all_parsed = managed_policies + inline_policies + trust_policies
                db_rows = policies_to_db_rows(all_parsed, scan_run_id, tenant_id, account_id)
                try:
                    from iam_engine.storage.iam_db_writer import save_policy_statements
                    stmt_count = save_policy_statements(scan_run_id, tenant_id, db_rows)
                    logger.info(f"Saved {stmt_count} policy statements to iam_policy_statements")
                except Exception as e:
                    logger.error(f"Error saving policy statements: {e}", exc_info=True)

                # Run policy-based detectors
                policy_findings = run_all_detectors(
                    managed_policies=managed_policies,
                    inline_policies=inline_policies,
                    trust_relationships=trust_relationships,
                    account_id=account_id,
                )
                logger.info(f"Policy detectors generated {len(policy_findings)} findings")

            except Exception as e:
                logger.error(f"Policy analysis failed (non-fatal): {e}", exc_info=True)
        else:
            logger.warning("No scan_run_id in orchestration — skipping policy analysis")

        # ── CIEM Enrichment: actual usage from CloudTrail logs ──
        try:
            from engine_common.ciem_reader import CIEMReader
            ciem = CIEMReader(tenant_id=tenant_id, account_id=account_id or "", days=30)

            # Get actual usage per identity
            identity_usage = ciem.get_identity_usage()
            logger.info(f"CIEM: loaded usage for {len(identity_usage)} identities")

            # Enrich roles with actual usage
            for role in discovery_roles:
                role_arn = role.get("_resource_uid", role.get("Arn", ""))
                # Also check assumed-role pattern
                for principal, usage in identity_usage.items():
                    if role_arn and (role_arn in principal or principal.endswith(role.get("RoleName", "---"))):
                        role["_ciem_usage"] = usage
                        role["_ciem_last_activity"] = usage.get("last_activity")
                        role["_ciem_total_calls"] = usage.get("total_api_calls", 0)
                        role["_ciem_unique_ops"] = usage.get("unique_operations", 0)
                        role["_ciem_is_active"] = True
                        break
                else:
                    role["_ciem_is_active"] = False
                    role["_ciem_usage"] = None

            active = sum(1 for r in discovery_roles if r.get("_ciem_is_active"))
            inactive = len(discovery_roles) - active
            logger.info(f"CIEM: {active} active roles, {inactive} inactive/stale roles")

            # Get cross-account access
            cross_account = ciem.get_cross_account_access()
            if cross_account:
                logger.info(f"CIEM: {len(cross_account)} cross-account access patterns")

            # Get CIEM findings for IAM and merge into policy_findings
            ciem_findings = ciem.get_ciem_findings(engine_filter="ciem")
            if ciem_findings:
                logger.info(f"CIEM: {len(ciem_findings)} IAM-relevant findings from CIEM")
                for cf in ciem_findings:
                    policy_findings.append({
                        "finding_id": cf.get("finding_id", ""),
                        "rule_id": cf.get("rule_id", ""),
                        "severity": cf.get("severity", "medium"),
                        "status": "FAIL",
                        "title": cf.get("title", ""),
                        "resource_uid": cf.get("resource_uid", ""),
                        "resource_type": cf.get("resource_type", ""),
                        "account_id": cf.get("account_id", account_id or ""),
                        "region": cf.get("region", "global"),
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
                            "event_time": str(cf.get("event_time", "")),
                        },
                    })

            ciem.close()

            # Add stale role findings
            for role in discovery_roles:
                if not role.get("_ciem_is_active") and role.get("RoleName"):
                    policy_findings.append({
                        "finding_id": f"iam_stale_role_{role.get('RoleName', '')}",
                        "rule_id": "iam.role.stale_inactive",
                        "severity": "medium",
                        "status": "FAIL",
                        "title": f"Stale IAM role: {role.get('RoleName')} — no API activity in 30 days",
                        "resource_uid": role.get("_resource_uid", role.get("Arn", "")),
                        "resource_type": "iam.role",
                        "account_id": account_id,
                        "provider": "aws",
                        "finding_data": {
                            "module": "ciem_usage_analysis",
                            "role_name": role.get("RoleName"),
                            "last_activity": None,
                            "remediation": "Consider deleting or deactivating this role",
                        },
                    })

        except Exception as ciem_exc:
            logger.warning(f"CIEM enrichment failed (non-fatal): {ciem_exc}")

        # Merge policy findings with threat-based findings
        if policy_findings:
            existing_ids = {f.get("misconfig_finding_id") or f.get("finding_id")
                           for f in report.get("findings", [])}
            for pf in policy_findings:
                if pf["finding_id"] not in existing_ids:
                    report.setdefault("findings", []).append(pf)
            # Update summary counts
            summary = report.get("summary", {})
            summary["total_findings"] = len(report.get("findings", []))
            summary["iam_relevant_findings"] = len(report.get("findings", []))
            report["summary"] = summary
            logger.info(f"Merged findings: {len(report.get('findings', []))} total")

        # Add report_id
        if "report_id" not in report:
            report["report_id"] = scan_run_id

        # Save to database
        try:
            from iam_engine.storage.iam_db_writer import save_iam_report_to_db
            saved_id = save_iam_report_to_db(report)
            logger.info(f"IAM report saved to database: {saved_id}")
        except Exception as e:
            logger.error(f"Error saving IAM report to database: {e}", exc_info=True)

        # 4.7 NEW: Create Neo4j graph edges
        if discovery_scan_id and (discovery_roles or discovery_users):
            try:
                from iam_engine.graph.neo4j_writer import IAMGraphWriter
                neo4j_password = os.getenv("NEO4J_PASSWORD", "")
                if neo4j_password:
                    graph_writer = IAMGraphWriter()
                    edge_counts = graph_writer.create_iam_edges(
                        tenant_id=tenant_id,
                        roles=discovery_roles,
                        users=discovery_users,
                        groups=discovery_groups,
                        managed_policies=managed_policies,
                        trust_relationships=trust_relationships,
                        instance_profiles=discovery_instance_profiles,
                    )
                    graph_writer.close()
                    logger.info(f"Neo4j IAM edges: {edge_counts}")
                else:
                    logger.warning("NEO4J_PASSWORD not set — skipping graph edges")
            except Exception as e:
                logger.error(f"Neo4j graph edge creation failed (non-fatal): {e}", exc_info=True)

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
        _update_report_status(scan_run_id, "completed")

        findings_count = len(report.get("findings", []))
        logger.info(f"IAM scan completed: {scan_run_id} — {findings_count} findings in {duration:.1f}s")

        # 6. Retention cleanup (keep last 3 scans per tenant)
        try:
            cleanup_old_scans("iam", tenant_id, keep=3)
        except Exception as e:
            logger.warning(f"Retention cleanup failed: {e}")

    except Exception as e:
        logger.error(f"IAM scan FAILED: {e}", exc_info=True)
        _update_report_status(scan_run_id, "failed", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
