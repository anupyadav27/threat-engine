"""
AI Security Engine — Job entry point.

Runs as a K8s Job on spot nodes. Called by the API pod via:
    python -m run_scan --scan-run-id X

Pipeline:
  1. Read data from 6 engine databases (discoveries, check, CIEM, IAM, datasec, encryption)
  2. Build AI resource inventory (classify resources, extract security posture)
  3. Detect shadow AI (CIEM vs inventory cross-reference)
  4. Evaluate 30 AI security rules against inventory
  5. Categorize cross-engine findings by module
  6. Compute posture scores
  7. Write results to threat_engine_ai_security
  8. Export JSON report to /output
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

logger = setup_logger(__name__, engine_name="ai-security-scanner")


def main():
    parser = argparse.ArgumentParser(description="AI Security Engine Scanner")
    parser.add_argument("--scan-run-id", required=True, help="Pipeline scan run ID")
    args = parser.parse_args()

    scan_run_id = args.scan_run_id
    logger.info(f"AI security scanner starting scan_run_id={scan_run_id}")

    # Late import — db_writer needed for SIGTERM handler
    from ai_security_engine.storage.ai_security_db_writer import AISecurityDBWriter
    db_writer = AISecurityDBWriter()

    # SIGTERM handler — mark scan failed on spot preemption/timeout
    def _handle_sigterm(*_):
        logger.warning(f"SIGTERM received — marking AI security scan {scan_run_id} as failed")
        db_writer.mark_failed(scan_run_id, "Terminated by SIGTERM (spot preemption or timeout)")
        sys.exit(1)

    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        # ── Phase 0: Orchestration metadata ──────────────────────────────
        logger.info("[Phase 0] Resolving orchestration metadata...")
        metadata = get_orchestration_metadata(scan_run_id)
        if not metadata:
            raise ValueError(f"No orchestration metadata for {scan_run_id}")

        tenant_id = metadata.get("tenant_id", "default-tenant")
        provider = (metadata.get("provider") or metadata.get("provider_type", "aws")).lower()
        account_id = metadata.get("account_id", "")

        logger.info(f"Resolved: tenant={tenant_id} provider={provider} account={account_id}")

        # Pre-create report row
        db_writer.ensure_tenant(tenant_id)
        db_writer.create_report(scan_run_id, tenant_id, account_id, provider)
        start = datetime.now(timezone.utc)

        # ── Phase 1: Load input data from 6 engines ─────────────────────
        logger.info("[Phase 1] Loading input data from engine databases...")

        from ai_security_engine.input.discovery_reader import AIDiscoveryReader
        from ai_security_engine.input.check_reader import AICheckReader

        disc_reader = AIDiscoveryReader()
        check_reader = AICheckReader()

        try:
            # 1a. Discovery resources — AI/ML services (REQUIRED)
            discovery_resources = disc_reader.load_ai_resources(scan_run_id, tenant_id, account_id or None)
            logger.info(f"  [1a] Discovered {len(discovery_resources)} AI/ML resources")

            # 1b. Check findings — AI rules (REQUIRED)
            check_findings = check_reader.load_ai_check_findings(scan_run_id, tenant_id)
            rule_metadata = check_reader.load_ai_rule_metadata()
            logger.info(f"  [1b] Loaded {len(check_findings)} AI check findings, {len(rule_metadata)} rules")
        finally:
            disc_reader.close()
            check_reader.close()

        # 1c. AI security rules (from own DB)
        from ai_security_engine.evaluator.rule_loader import AIRuleLoader
        rule_loader = AIRuleLoader()
        ai_rules = rule_loader.load_rules(csp=provider)
        logger.info(f"  [1c] Loaded {len(ai_rules)} AI security rules")

        # 1d-1e. CIEM data (NON-FATAL)
        ciem_patterns = []
        ciem_shadow_calls = []
        try:
            from ai_security_engine.input.ciem_reader import AICIEMReader
            ciem_reader = AICIEMReader()
            try:
                ciem_patterns = ciem_reader.get_ai_invocation_patterns(tenant_id, account_id)
                ciem_shadow_calls = ciem_reader.get_shadow_ai_calls(tenant_id, account_id)
                logger.info(
                    f"  [1d-e] CIEM: {len(ciem_patterns)} invocation patterns, "
                    f"{len(ciem_shadow_calls)} shadow calls"
                )
            finally:
                ciem_reader.close()
        except Exception as e:
            logger.warning(f"  [1d-e] CIEM data unavailable (non-fatal): {e}")

        # 1d2. CIEM findings (pre-evaluated log-based detections for AI)
        ciem_ai_findings = []
        try:
            from engine_common.ciem_reader import CIEMReader
            ciem = CIEMReader(tenant_id=tenant_id, account_id=account_id or "", days=30)
            ciem_ai_findings = ciem.get_ciem_findings(engine_filter="ai_security")
            if ciem_ai_findings:
                logger.info(f"  [1d2] CIEM: {len(ciem_ai_findings)} AI findings from ciem_findings")
        except Exception as ciem_f_err:
            logger.warning(f"  [1d2] CIEM findings load failed (non-fatal): {ciem_f_err}")

        # 1f-1g. IAM data (NON-FATAL)
        iam_findings = []
        iam_policies = []
        try:
            from ai_security_engine.input.iam_reader import AIIAMReader
            iam_reader = AIIAMReader()
            try:
                iam_findings = iam_reader.get_ml_role_findings(scan_run_id, tenant_id)
                iam_policies = iam_reader.get_ml_policy_statements(scan_run_id, tenant_id)
                logger.info(f"  [1f-g] IAM: {len(iam_findings)} findings, {len(iam_policies)} policy statements")
            finally:
                iam_reader.close()
        except Exception as e:
            logger.warning(f"  [1f-g] IAM data unavailable (non-fatal): {e}")

        # 1h. DataSec data (NON-FATAL)
        datasec_findings = []
        try:
            from ai_security_engine.input.datasec_reader import AIDataSecReader
            datasec_reader = AIDataSecReader()
            try:
                datasec_findings = datasec_reader.get_ml_data_findings(scan_run_id, tenant_id)
                logger.info(f"  [1h] DataSec: {len(datasec_findings)} findings")
            finally:
                datasec_reader.close()
        except Exception as e:
            logger.warning(f"  [1h] DataSec data unavailable (non-fatal): {e}")

        # 1i. Encryption data (NON-FATAL)
        encryption_findings = []
        try:
            from ai_security_engine.input.encryption_reader import AIEncryptionReader
            encryption_reader = AIEncryptionReader()
            try:
                encryption_findings = encryption_reader.get_ml_encryption_findings(scan_run_id, tenant_id)
                logger.info(f"  [1i] Encryption: {len(encryption_findings)} findings")
            finally:
                encryption_reader.close()
        except Exception as e:
            logger.warning(f"  [1i] Encryption data unavailable (non-fatal): {e}")

        # ── Phase 2: Build AI inventory ──────────────────────────────────
        logger.info("[Phase 2] Building AI resource inventory...")
        from ai_security_engine.analyzer.ai_inventory_builder import AIInventoryBuilder

        inventory_builder = AIInventoryBuilder()
        inventory = inventory_builder.build_inventory(
            discovery_resources=discovery_resources,
            check_findings=check_findings,
            ciem_patterns=ciem_patterns,
        )
        logger.info(f"  [2a] Built inventory: {len(inventory)} AI/ML resources")

        # ── Phase 2b: Detect shadow AI ───────────────────────────────────
        shadow_findings = []
        try:
            from ai_security_engine.analyzer.shadow_ai_detector import ShadowAIDetector
            shadow_detector = ShadowAIDetector()
            shadow_findings = shadow_detector.detect_shadow_ai(
                ciem_invocations=ciem_shadow_calls,
                discovery_resources=discovery_resources,
            )
            logger.info(f"  [2b] Shadow AI: {len(shadow_findings)} findings")
        except Exception as e:
            logger.warning(f"  [2b] Shadow AI detection failed (non-fatal): {e}")

        # ── Phase 2c: Evaluate AI-specific rules against inventory ───────
        logger.info("[Phase 2c] Evaluating AI security rules...")
        from ai_security_engine.evaluator.rule_evaluator import AIRuleEvaluator
        from ai_security_engine.storage.ai_security_db_writer import generate_finding_id

        rule_evaluator = AIRuleEvaluator()
        rule_findings = []

        for resource in inventory:
            for rule in ai_rules:
                status, evidence = rule_evaluator.evaluate_rule(rule, resource)
                finding_id = generate_finding_id(
                    rule["rule_id"],
                    resource.get("resource_uid", resource.get("resource_arn", resource.get("resource_id", ""))),
                    resource.get("account_id", ""),
                    resource.get("region", ""),
                )
                rule_findings.append({
                    "finding_id": finding_id,
                    "tenant_id": tenant_id,
                    "rule_id": rule["rule_id"],
                    "resource_id": resource.get("resource_id"),
                    "resource_type": resource.get("resource_type"),
                    "resource_uid": resource.get("resource_uid") or resource.get("resource_arn"),
                    "ml_service": resource.get("ml_service"),
                    "model_type": resource.get("model_type"),
                    "severity": rule.get("severity", "medium").upper(),
                    "status": status,
                    "category": rule.get("category"),
                    "title": rule.get("title"),
                    "detail": json.dumps(evidence) if evidence else None,
                    "remediation": rule.get("remediation"),
                    "frameworks": rule.get("frameworks", []),
                    "mitre_techniques": rule.get("mitre_techniques", []),
                    "account_id": resource.get("account_id", account_id),
                    "region": resource.get("region"),
                    "provider": provider,
                })

        logger.info(f"  [2c] Evaluated {len(rule_findings)} rule-resource combinations")

        # ── Phase 3: Cross-engine enrichment (NON-FATAL) ─────────────────
        logger.info("[Phase 3] Cross-engine enrichment...")

        # 3a. Cross-reference IAM findings → access_control module
        iam_cross_findings = []
        try:
            if iam_findings:
                iam_resource_uids = {f.get("resource_uid") for f in iam_findings}
                for inv in inventory:
                    arn = inv.get("resource_uid") or inv.get("resource_arn", "")
                    role_arn = inv.get("iam_role_arn", "")
                    if arn in iam_resource_uids or role_arn in iam_resource_uids:
                        for iamf in iam_findings:
                            if iamf.get("resource_uid") in (arn, role_arn):
                                fid = generate_finding_id(
                                    f"iam_xref_{iamf.get('rule_id', 'iam')}",
                                    arn, inv.get("account_id", ""), inv.get("region", ""),
                                )
                                iam_cross_findings.append({
                                    "finding_id": fid,
                                    "tenant_id": tenant_id,
                                    "rule_id": iamf.get("rule_id", "IAM-XREF"),
                                    "resource_id": inv.get("resource_id"),
                                    "resource_type": inv.get("resource_type"),
                                    "resource_uid": arn,
                                    "ml_service": inv.get("ml_service"),
                                    "model_type": inv.get("model_type"),
                                    "severity": iamf.get("severity", "MEDIUM"),
                                    "status": "FAIL",
                                    "category": "access_control",
                                    "title": f"IAM cross-ref: {iamf.get('title', 'IAM finding')}",
                                    "detail": json.dumps(iamf.get("finding_data", {})),
                                    "remediation": iamf.get("remediation"),
                                    "frameworks": [],
                                    "mitre_techniques": [],
                                    "account_id": inv.get("account_id", account_id),
                                    "region": inv.get("region"),
                                    "provider": provider,
                                })
                logger.info(f"  [3a] IAM cross-ref: {len(iam_cross_findings)} findings")
        except Exception as e:
            logger.warning(f"  [3a] IAM cross-ref failed (non-fatal): {e}")

        # 3b. Cross-reference DataSec findings → data_pipeline module
        datasec_cross_findings = []
        try:
            if datasec_findings:
                datasec_uids = {f.get("resource_uid") for f in datasec_findings}
                for inv in inventory:
                    arn = inv.get("resource_uid") or inv.get("resource_arn", "")
                    bucket = inv.get("artifact_bucket", "")
                    if arn in datasec_uids or bucket in datasec_uids:
                        for dsf in datasec_findings:
                            if dsf.get("resource_uid") in (arn, bucket):
                                fid = generate_finding_id(
                                    f"datasec_xref_{dsf.get('rule_id', 'ds')}",
                                    arn, inv.get("account_id", ""), inv.get("region", ""),
                                )
                                datasec_cross_findings.append({
                                    "finding_id": fid,
                                    "tenant_id": tenant_id,
                                    "rule_id": dsf.get("rule_id", "DS-XREF"),
                                    "resource_id": inv.get("resource_id"),
                                    "resource_type": inv.get("resource_type"),
                                    "resource_uid": arn,
                                    "ml_service": inv.get("ml_service"),
                                    "model_type": inv.get("model_type"),
                                    "severity": dsf.get("severity", "MEDIUM"),
                                    "status": "FAIL",
                                    "category": "data_pipeline",
                                    "title": f"DataSec cross-ref: {dsf.get('title', 'Data finding')}",
                                    "detail": json.dumps(dsf.get("finding_data", {})),
                                    "remediation": dsf.get("remediation"),
                                    "frameworks": [],
                                    "mitre_techniques": [],
                                    "account_id": inv.get("account_id", account_id),
                                    "region": inv.get("region"),
                                    "provider": provider,
                                })
                logger.info(f"  [3b] DataSec cross-ref: {len(datasec_cross_findings)} findings")
        except Exception as e:
            logger.warning(f"  [3b] DataSec cross-ref failed (non-fatal): {e}")

        # 3c. Cross-reference Encryption findings → model_security module
        encryption_cross_findings = []
        try:
            if encryption_findings:
                enc_uids = {f.get("resource_uid") for f in encryption_findings}
                for inv in inventory:
                    arn = inv.get("resource_uid") or inv.get("resource_arn", "")
                    bucket = inv.get("artifact_bucket", "")
                    if arn in enc_uids or bucket in enc_uids:
                        for ef in encryption_findings:
                            if ef.get("resource_uid") in (arn, bucket):
                                fid = generate_finding_id(
                                    f"enc_xref_{ef.get('rule_id', 'enc')}",
                                    arn, inv.get("account_id", ""), inv.get("region", ""),
                                )
                                encryption_cross_findings.append({
                                    "finding_id": fid,
                                    "tenant_id": tenant_id,
                                    "rule_id": ef.get("rule_id", "ENC-XREF"),
                                    "resource_id": inv.get("resource_id"),
                                    "resource_type": inv.get("resource_type"),
                                    "resource_uid": arn,
                                    "ml_service": inv.get("ml_service"),
                                    "model_type": inv.get("model_type"),
                                    "severity": ef.get("severity", "MEDIUM"),
                                    "status": "FAIL",
                                    "category": "model_security",
                                    "title": f"Encryption cross-ref: {ef.get('title', 'Encryption finding')}",
                                    "detail": json.dumps(ef.get("finding_data", {})),
                                    "remediation": ef.get("remediation"),
                                    "frameworks": [],
                                    "mitre_techniques": [],
                                    "account_id": inv.get("account_id", account_id),
                                    "region": inv.get("region"),
                                    "provider": provider,
                                })
                logger.info(f"  [3c] Encryption cross-ref: {len(encryption_cross_findings)} findings")
        except Exception as e:
            logger.warning(f"  [3c] Encryption cross-ref failed (non-fatal): {e}")

        # ── Phase 4: Merge, deduplicate, score ───────────────────────────
        logger.info("[Phase 4] Merging findings and computing scores...")

        # Convert CIEM findings to AI security finding format
        ciem_converted = []
        for cf in ciem_ai_findings:
            fid = generate_finding_id(
                cf.get("rule_id", "ciem"),
                cf.get("resource_uid", ""),
                cf.get("account_id", ""),
                cf.get("region", ""),
            )
            ciem_converted.append({
                "finding_id": fid,
                "tenant_id": tenant_id,
                "rule_id": cf.get("rule_id", ""),
                "resource_id": None,
                "resource_type": cf.get("resource_type", ""),
                "resource_uid": cf.get("resource_uid", ""),
                "ml_service": None,
                "model_type": None,
                "severity": (cf.get("severity") or "medium").upper(),
                "status": "FAIL",
                "category": cf.get("action_category", "ai_governance"),
                "title": cf.get("title", ""),
                "detail": json.dumps({
                    "source": "ciem",
                    "actor": cf.get("actor_principal", ""),
                    "operation": cf.get("operation", ""),
                    "description": cf.get("description", ""),
                    "domain": cf.get("domain", ""),
                }),
                "remediation": cf.get("remediation", ""),
                "frameworks": cf.get("compliance_frameworks", []),
                "mitre_techniques": cf.get("mitre_techniques", []),
                "account_id": cf.get("account_id", account_id),
                "region": cf.get("region"),
                "provider": provider,
            })

        # Merge all findings
        all_findings = rule_findings + shadow_findings + iam_cross_findings + datasec_cross_findings + encryption_cross_findings + ciem_converted

        # Deduplicate by finding_id (keep first occurrence)
        seen_ids = set()
        findings = []
        for f in all_findings:
            fid = f.get("finding_id")
            if fid and fid not in seen_ids:
                seen_ids.add(fid)
                findings.append(f)
            elif not fid:
                findings.append(f)

        logger.info(f"  [4a] Merged: {len(findings)} unique findings (from {len(all_findings)} total)")

        # Compute posture scores
        scores = _compute_posture_scores(inventory, findings)
        duration_ms = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
        scores["scan_duration_ms"] = duration_ms

        logger.info(f"  [4b] Posture score: {scores.get('risk_score', 0)}/100")

        # ── Phase 5: Write results ───────────────────────────────────────
        logger.info("[Phase 5] Writing results to database...")

        saved_findings = db_writer.save_findings(scan_run_id, findings)
        logger.info(f"  [5a] Saved {saved_findings} findings")

        saved_inventory = db_writer.save_inventory(scan_run_id, inventory, tenant_id=tenant_id)
        logger.info(f"  [5b] Saved {saved_inventory} inventory records")

        db_writer.update_report(scan_run_id, scores, inventory, findings, status="completed")
        logger.info("  [5c] Report updated")

        # 5d. Export JSON report
        try:
            output_dir = os.getenv("OUTPUT_DIR", "/output")
            if output_dir and os.path.exists(output_dir):
                ai_dir = os.path.join(output_dir, "ai-security", "reports", tenant_id)
                os.makedirs(ai_dir, exist_ok=True)
                report_data = {
                    "scan_run_id": scan_run_id,
                    "tenant_id": tenant_id,
                    "account_id": account_id,
                    "provider": provider,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "summary": scores,
                    "inventory_count": len(inventory),
                    "findings_count": len(findings),
                }
                with open(os.path.join(ai_dir, f"{scan_run_id}_report.json"), "w") as f:
                    json.dump(report_data, f, indent=2, default=str)
                logger.info(f"  [5d] Report exported to {ai_dir}")
        except Exception as e:
            logger.warning(f"  [5d] Report export failed (non-fatal): {e}")

        # ── Phase 6: Retention cleanup ───────────────────────────────────
        try:
            cleaned = db_writer.cleanup_old_scans(tenant_id, keep_latest=3)
            if cleaned > 0:
                logger.info(f"[Phase 6] Cleaned up {cleaned} old scans")
        except Exception as e:
            logger.warning(f"Retention cleanup failed: {e}")

        duration = (datetime.now(timezone.utc) - start).total_seconds()
        logger.info(
            f"AI security scan completed: {scan_run_id} — "
            f"score={scores.get('risk_score', 0)}, {len(findings)} findings, "
            f"{len(inventory)} resources in {duration:.1f}s"
        )

    except Exception as e:
        logger.error(f"AI security scan FAILED: {e}", exc_info=True)
        db_writer.mark_failed(scan_run_id, str(e))
        sys.exit(1)


def _compute_posture_scores(
    inventory: list,
    findings: list,
) -> dict:
    """Compute AI security posture scores from inventory and findings.

    Returns dict with coverage percentages, risk_score, and framework_compliance.
    """
    total = len(inventory) if inventory else 1  # Avoid div-by-zero

    # Coverage metrics
    vpc_isolated = sum(1 for r in inventory if r.get("is_vpc_isolated"))
    enc_rest = sum(1 for r in inventory if r.get("encryption_at_rest"))
    enc_transit = sum(1 for r in inventory if r.get("encryption_in_transit"))
    model_card = sum(1 for r in inventory if r.get("has_model_card"))
    monitoring = sum(1 for r in inventory if r.get("has_monitoring"))
    guardrails = sum(1 for r in inventory if r.get("has_guardrails"))

    # Severity-weighted risk score (0=worst, 100=best)
    severity_weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}
    total_weight = 0
    for f in findings:
        if (f.get("status") or "").upper() == "FAIL":
            sev = (f.get("severity") or "medium").lower()
            total_weight += severity_weights.get(sev, 1)

    # Max theoretical weight: 10 * total_resources * rules_per_resource
    max_weight = max(total * 30, 1)
    risk_score = max(0, min(100, 100 - int((total_weight / max_weight) * 100)))

    # Framework compliance
    framework_compliance = {}
    for f in findings:
        for fw in (f.get("frameworks") or []):
            if fw not in framework_compliance:
                framework_compliance[fw] = {"total": 0, "pass": 0, "fail": 0}
            framework_compliance[fw]["total"] += 1
            st = (f.get("status") or "").upper()
            if st == "PASS":
                framework_compliance[fw]["pass"] += 1
            elif st == "FAIL":
                framework_compliance[fw]["fail"] += 1

    return {
        "vpc_isolation_pct": round(vpc_isolated / total * 100, 2),
        "encryption_rest_pct": round(enc_rest / total * 100, 2),
        "encryption_transit_pct": round(enc_transit / total * 100, 2),
        "model_card_pct": round(model_card / total * 100, 2),
        "monitoring_pct": round(monitoring / total * 100, 2),
        "guardrails_pct": round(guardrails / total * 100, 2),
        "risk_score": risk_score,
        "framework_compliance": framework_compliance,
    }


if __name__ == "__main__":
    main()
