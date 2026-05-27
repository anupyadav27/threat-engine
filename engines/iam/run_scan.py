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
from engine_common.db_connections import get_iam_conn

logger = setup_logger(__name__, engine_name="iam-scanner")


def _update_report_status(scan_run_id: str, status: str, error: str = None):
    """Update iam_report status in DB."""
    try:
        conn = get_iam_conn()
        with conn.cursor() as cur:
            if error:
                cur.execute(
                    "UPDATE iam_report SET status = %s, report_data = %s::jsonb WHERE scan_run_id = %s",
                    (status, __import__('json').dumps({"error": error}), scan_run_id),
                )
            elif status == "completed":
                cur.execute(
                    "UPDATE iam_report SET status = %s, generated_at = NOW() WHERE scan_run_id = %s",
                    (status, scan_run_id),
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
        conn = get_iam_conn()
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

        # 4.5: Provider-specific IAM analysis (policy parsing, trust analysis, detectors)
        account_id = metadata.get("account_id", "")

        from iam_engine.providers import get_provider as get_iam_provider
        logger.info(f"Running IAM provider analysis for provider={provider}")
        iam_provider = get_iam_provider(provider)
        iam_result = iam_provider.analyze(
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            account_id=account_id,
        )
        policy_findings = iam_result["policy_findings"]
        managed_policies = iam_result.get("managed_policies", [])
        inline_policies = iam_result.get("inline_policies", [])
        trust_relationships = iam_result.get("trust_relationships", [])
        discovery_roles = iam_result.get("roles", [])
        discovery_users = iam_result.get("users", [])
        discovery_groups = iam_result.get("groups", [])
        discovery_instance_profiles = iam_result.get("instance_profiles", [])

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

            # Map CIEM action_category → IAM module tabs so findings surface
            # in the correct section of the IAM page (roles / access_keys /
            # privilege_escalation) rather than landing in a catch-all list.
            _CIEM_MODULE_MAP = {
                "overprivilege":     ["least_privilege"],
                "least_privilege":   ["least_privilege"],
                "policy_management": ["role_management"],
                "identity_hygiene":  ["role_management"],
                "anomaly":           ["role_management"],
                "cross_account":     ["access_control"],
                "defense_evasion":   ["access_control"],
                "data_access":       ["access_control"],
                "compute_access":    ["access_control"],
                "credential":        ["access_control"],
                "log_correlation":   ["access_control"],
            }

            # Get CIEM findings for IAM and merge into policy_findings
            ciem_findings = ciem.get_ciem_findings(engine_filter="ciem")
            if ciem_findings:
                logger.info(f"CIEM: {len(ciem_findings)} IAM-relevant findings from CIEM")
                for cf in ciem_findings:
                    action_cat = cf.get("action_category", "")
                    iam_modules = _CIEM_MODULE_MAP.get(action_cat, ["role_management"])
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
                        "iam_security_modules": iam_modules,
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
                            "action_category": action_cat,
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
                        "provider": provider,
                        "iam_security_modules": ["role_management"],
                        "finding_data": {
                            "source": "ciem",
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
        if discovery_roles or discovery_users:
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

        # Retention: archive old scans to S3, keep last 5 in DB
        try:
            from engine_common.retention import run_retention
            run_retention("iam", scan_run_id)
        except Exception as _ret_err:
            logger.warning("Retention cleanup skipped: %s", _ret_err)

        # Write IAM posture signals to resource_security_posture (non-fatal)
        try:
            from iam_engine.posture_signals import write_iam_posture_signals
            write_iam_posture_signals(
                scan_run_id=scan_run_id,
                tenant_id=tenant_id,
                account_id=account_id or "",
                provider=provider,
            )
        except Exception as _ps_err:
            logger.warning("IAM posture signal write skipped: %s", _ps_err)

        # Write IAM violations to security_findings (non-fatal)
        try:
            from engine_common.security_findings_writer import upsert_findings
            from engine_common.db_connections import get_di_conn
            _inv_conn = get_di_conn()
            try:
                # Batch-lookup MITRE data from rule_metadata (fallback for non-CIEM findings)
                _mitre_by_rule: dict = {}
                _all_rule_ids = list({_f.get("rule_id") for _f in report.get("findings", []) if _f.get("rule_id")})
                if _all_rule_ids:
                    try:
                        from engine_common.db_connections import get_check_conn
                        import psycopg2.extras as _pge
                        _chk_conn = get_check_conn()
                        with _chk_conn.cursor(cursor_factory=_pge.RealDictCursor) as _mc:
                            _mc.execute(
                                "SELECT rule_id, mitre_attack_id, mitre_tactic FROM rule_metadata WHERE rule_id = ANY(%s)",
                                (_all_rule_ids,),
                            )
                            for _rm in _mc.fetchall():
                                _mitre_by_rule[_rm["rule_id"]] = (_rm.get("mitre_attack_id"), _rm.get("mitre_tactic"))
                        _chk_conn.close()
                    except Exception:
                        pass

                _iam_sf_rows = []
                for _f in report.get("findings", []):
                    _fdata = _f.get("finding_data") or {}
                    if isinstance(_fdata, str):
                        try:
                            import json as _json
                            _fdata = _json.loads(_fdata)
                        except Exception:
                            _fdata = {}
                    _mitre_techniques = _fdata.get("mitre_techniques", [])
                    _mitre_technique_id = (
                        _mitre_techniques[0] if _mitre_techniques
                        else _fdata.get("mitre_technique_id")
                    )
                    _mitre_tactics = _fdata.get("mitre_tactics", [])
                    _mitre_tactic = (
                        _mitre_tactics[0] if _mitre_tactics
                        else _fdata.get("mitre_tactic")
                    )
                    # Fallback to rule_metadata lookup for non-CIEM findings
                    if not _mitre_technique_id:
                        _rm_tech, _rm_tac = _mitre_by_rule.get(_f.get("rule_id", ""), (None, None))
                        _mitre_technique_id = _rm_tech
                        if not _mitre_tactic:
                            _mitre_tactic = _rm_tac
                    _iam_sf_rows.append({
                        "source_finding_id": (
                            _f.get("finding_id") or _f.get("misconfig_finding_id") or _f.get("resource_uid", "")
                        ),
                        "resource_uid": _f.get("resource_uid", ""),
                        "finding_type": "iam_violation",
                        "severity": (_f.get("severity") or "medium").lower(),
                        "title": _f.get("title") or _f.get("rule_id") or "IAM Violation",
                        "account_id": _f.get("account_id"),
                        "provider": _f.get("provider") or provider,
                        "resource_type": _f.get("resource_type"),
                        "rule_id": _f.get("rule_id"),
                        "description": _fdata.get("description"),
                        "mitre_technique_id": _mitre_technique_id,
                        "mitre_tactic": _mitre_tactic,
                        "detail": {
                            "resource_uid": _f.get("resource_uid"),
                            "account_id": _f.get("account_id"),
                            "region": _f.get("region", "global"),
                            "iam_modules": _f.get("iam_security_modules", []),
                            "remediation": _fdata.get("remediation"),
                        },
                        "in_kev": False,
                    })
                if _iam_sf_rows:
                    upsert_findings(
                        _inv_conn, _iam_sf_rows, source_engine="iam",
                        tenant_id=tenant_id, scan_run_id=scan_run_id,
                    )
                    logger.info("security_findings (iam): wrote %d findings", len(_iam_sf_rows))
            finally:
                _inv_conn.close()
        except Exception as _sf_err:
            logger.warning("security_findings write (iam) skipped: %s", _sf_err)

    except Exception as e:
        logger.error(f"IAM scan FAILED: {e}", exc_info=True)
        _update_report_status(scan_run_id, "failed", str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
