"""
AI Security Module Orchestrator — coordinates the full AI security analysis pipeline.

Pipeline:
1. Build AI inventory from discovery + check + CIEM data
2. Detect shadow AI from CIEM vs inventory
3. Categorize check findings into 6 modules
4. Evaluate AI-specific rules against inventory
5. Cross-reference IAM + DataSec + Encryption findings
6. Merge all findings, deduplicate
7. Compute posture scores
8. Build report summary
"""
import hashlib
import logging
from typing import Any, Dict, List, Optional

from .rule_loader import AIRuleLoader
from .rule_evaluator import AIRuleEvaluator

logger = logging.getLogger(__name__)


class AIModuleOrchestrator:
    """Orchestrates the AI security analysis pipeline."""

    MODULES = [
        "model_security",
        "endpoint_security",
        "prompt_security",
        "data_pipeline",
        "ai_governance",
        "access_control",
    ]

    def __init__(self) -> None:
        self.rule_loader = AIRuleLoader()
        self.rule_evaluator = AIRuleEvaluator()

    # ------------------------------------------------------------------ main

    def run_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Run the complete AI security analysis pipeline.

        Args:
            data: Input payload containing:
                - scan_run_id: str
                - tenant_id: str
                - account_id: str
                - provider: str (default 'aws')
                - discovery_resources: list of discovered cloud resources
                - check_findings: list of check-engine findings
                - ciem_patterns: list of CIEM usage patterns
                - ciem_shadow_calls: list of unregistered API calls
                - iam_findings: list of IAM findings
                - iam_policies: list of IAM policy docs
                - datasec_findings: list of datasec findings
                - encryption_findings: list of encryption-related findings
                - ai_rules: list (optional pre-loaded rules, skips DB load)

        Returns:
            Dict with inventory, findings, shadow_ai, scores, report.
        """
        scan_run_id = data.get("scan_run_id", "")
        tenant_id = data.get("tenant_id", "")
        account_id = data.get("account_id", "")
        provider = data.get("provider", "aws")

        logger.info(
            "Starting AI security analysis scan_run_id=%s tenant=%s account=%s",
            scan_run_id, tenant_id, account_id,
        )

        # Step 1: Load rules
        ai_rules = data.get("ai_rules") or []
        if not ai_rules:
            rules_by_cat = self.rule_loader.get_rules_by_category(csp=provider, tenant_id=tenant_id)
            for cat_rules in rules_by_cat.values():
                ai_rules.extend(cat_rules)
        logger.info("Loaded %d AI security rules", len(ai_rules))

        rules_by_category = self._group_by_category(ai_rules)

        # Step 2: Build AI inventory from discovery resources
        discovery_resources = data.get("discovery_resources", [])
        inventory = self._build_inventory(discovery_resources, provider)
        logger.info("Built AI inventory: %d resources", len(inventory))

        # Step 3: Detect shadow AI
        ciem_shadow_calls = data.get("ciem_shadow_calls", [])
        shadow_ai = self._detect_shadow_ai(inventory, ciem_shadow_calls)
        logger.info("Shadow AI detections: %d", len(shadow_ai))

        # Step 4: Evaluate rules against each inventory resource
        rule_findings = self._evaluate_all_rules(
            rules_by_category, inventory, scan_run_id, tenant_id, account_id, provider,
        )
        logger.info("Rule evaluation findings: %d", len(rule_findings))

        # Step 5: Cross-reference IAM + DataSec + Encryption findings
        cross_ref_findings = self._cross_reference_findings(
            data.get("iam_findings", []),
            data.get("datasec_findings", []),
            data.get("encryption_findings", []),
            inventory,
            scan_run_id, tenant_id, account_id, provider,
        )
        logger.info("Cross-reference findings: %d", len(cross_ref_findings))

        # Step 6: Merge and deduplicate
        all_findings = self._merge_findings(rule_findings, cross_ref_findings, shadow_ai)
        logger.info("Total deduplicated findings: %d", len(all_findings))

        # Step 7: Compute posture scores
        scores = self._compute_scores(all_findings, inventory)

        # Step 8: Build report summary
        report = self._build_report(all_findings, inventory, scores, scan_run_id, tenant_id, account_id, provider)

        logger.info(
            "AI security analysis complete: %d findings, risk_score=%d",
            len(all_findings), scores.get("overall_risk_score", 0),
        )

        return {
            "inventory": inventory,
            "findings": all_findings,
            "shadow_ai": shadow_ai,
            "scores": scores,
            "report": report,
        }

    # ------------------------------------------------------------ pipeline steps

    def _build_inventory(self, discovery_resources: List[Dict], provider: str) -> List[Dict[str, Any]]:
        """Filter discovery resources to AI/ML-related services.

        Args:
            discovery_resources: Raw discovery resources.
            provider: Cloud provider.

        Returns:
            List of AI/ML resource dicts.
        """
        ml_service_keywords = {
            "sagemaker", "bedrock", "rekognition", "comprehend", "textract",
            "polly", "transcribe", "translate", "kendra", "personalize",
            "forecast", "fraud-detector", "lookout", "lex", "ai-platform",
            "ml-engine", "vertex", "openai", "azure-ml", "cognitive-services",
        }

        ml_resource_types = {
            "sagemaker_endpoint", "sagemaker_model", "sagemaker_notebook",
            "sagemaker_training_job", "sagemaker_processing_job",
            "bedrock_model", "bedrock_endpoint", "bedrock_guardrail",
            "lambda_ml", "s3_ml_artifact",
        }

        inventory: List[Dict[str, Any]] = []
        for resource in discovery_resources:
            resource_type = (resource.get("resource_type") or "").lower()
            service = (resource.get("service") or resource.get("ml_service") or "").lower()

            is_ml = (
                resource_type in ml_resource_types
                or any(kw in service for kw in ml_service_keywords)
                or any(kw in resource_type for kw in ml_service_keywords)
            )
            if is_ml:
                inventory.append(resource)

        return inventory

    def _detect_shadow_ai(
        self,
        inventory: List[Dict],
        ciem_shadow_calls: List[Dict],
    ) -> List[Dict[str, Any]]:
        """Detect shadow AI usage by comparing CIEM calls against known inventory.

        Args:
            inventory: Known AI/ML resources.
            ciem_shadow_calls: API calls from CIEM that hit ML services.

        Returns:
            List of shadow AI detection dicts.
        """
        known_arns = {r.get("resource_uid") or r.get("resource_arn") for r in inventory}
        shadow: List[Dict[str, Any]] = []

        for call in ciem_shadow_calls:
            target_arn = call.get("resource_uid") or call.get("resource_arn") or call.get("target_resource")
            if target_arn and target_arn not in known_arns:
                shadow.append({
                    "resource_uid": target_arn,
                    "service": call.get("service"),
                    "action": call.get("action"),
                    "caller": call.get("caller_arn") or call.get("principal"),
                    "detection_source": "ciem_shadow",
                    "severity": "high",
                })

        return shadow

    def _evaluate_all_rules(
        self,
        rules_by_category: Dict[str, List[Dict]],
        inventory: List[Dict],
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        provider: str,
    ) -> List[Dict[str, Any]]:
        """Evaluate all rules against every inventory resource.

        Args:
            rules_by_category: Rules grouped by category.
            inventory: AI/ML resources to evaluate.
            scan_run_id: Current scan identifier.
            tenant_id: Tenant identifier.
            account_id: Cloud account identifier.
            provider: Cloud provider.

        Returns:
            List of finding dicts.
        """
        findings: List[Dict[str, Any]] = []

        for category, rules in rules_by_category.items():
            for resource in inventory:
                for rule in rules:
                    status, evidence = self.rule_evaluator.evaluate_rule(rule, resource)

                    if status in ("ERROR", "SKIP"):
                        continue

                    finding_id = self._generate_finding_id(
                        rule.get("rule_id", ""),
                        resource.get("resource_uid") or resource.get("resource_arn") or "",
                        account_id,
                        resource.get("region", ""),
                    )

                    findings.append({
                        "finding_id": finding_id,
                        "scan_run_id": scan_run_id,
                        "tenant_id": tenant_id,
                        "account_id": account_id,
                        "provider": provider,
                        "rule_id": rule.get("rule_id"),
                        "title": rule.get("title"),
                        "description": rule.get("description"),
                        "severity": rule.get("severity", "medium"),
                        "status": status,
                        "category": category,
                        "resource_uid": resource.get("resource_uid") or resource.get("resource_arn"),
                        "resource_type": resource.get("resource_type"),
                        "resource_name": resource.get("resource_name"),
                        "ml_service": resource.get("ml_service") or resource.get("service"),
                        "model_type": resource.get("model_type"),
                        "region": resource.get("region"),
                        "evidence": evidence,
                        "remediation": rule.get("remediation"),
                        "frameworks": rule.get("frameworks", []),
                        "mitre_techniques": rule.get("mitre_techniques", []),
                    })

        return findings

    def _cross_reference_findings(
        self,
        iam_findings: List[Dict],
        datasec_findings: List[Dict],
        encryption_findings: List[Dict],
        inventory: List[Dict],
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        provider: str,
    ) -> List[Dict[str, Any]]:
        """Enrich AI findings with related IAM, DataSec, and Encryption issues.

        Matches external findings to AI inventory by resource_arn/resource_uid.

        Args:
            iam_findings: IAM engine findings.
            datasec_findings: DataSec engine findings.
            encryption_findings: Encryption-related findings.
            inventory: Known AI/ML resources.
            scan_run_id: Current scan identifier.
            tenant_id: Tenant identifier.
            account_id: Cloud account identifier.
            provider: Cloud provider.

        Returns:
            List of cross-referenced finding dicts.
        """
        ml_arns = {r.get("resource_uid") or r.get("resource_arn") for r in inventory}
        cross_ref: List[Dict[str, Any]] = []

        all_external = []
        for f in iam_findings:
            f["_source_engine"] = "iam"
            all_external.append(f)
        for f in datasec_findings:
            f["_source_engine"] = "datasec"
            all_external.append(f)
        for f in encryption_findings:
            f["_source_engine"] = "encryption"
            all_external.append(f)

        for finding in all_external:
            resource_uid = finding.get("resource_uid") or finding.get("resource_arn") or ""
            if resource_uid in ml_arns:
                finding_id = self._generate_finding_id(
                    finding.get("rule_id", finding.get("_source_engine", "")),
                    resource_uid,
                    account_id,
                    finding.get("region", ""),
                )
                cross_ref.append({
                    "finding_id": finding_id,
                    "scan_run_id": scan_run_id,
                    "tenant_id": tenant_id,
                    "account_id": account_id,
                    "provider": provider,
                    "rule_id": finding.get("rule_id"),
                    "title": finding.get("title", "Cross-referenced finding"),
                    "severity": finding.get("severity", "medium"),
                    "status": finding.get("status", "FAIL"),
                    "category": f"cross_ref_{finding['_source_engine']}",
                    "resource_uid": resource_uid,
                    "resource_type": finding.get("resource_type"),
                    "region": finding.get("region"),
                    "source_engine": finding["_source_engine"],
                    "evidence": {"cross_reference": True, "original_finding_id": finding.get("finding_id")},
                })

        return cross_ref

    def _merge_findings(
        self,
        rule_findings: List[Dict],
        cross_ref_findings: List[Dict],
        shadow_ai: List[Dict],
    ) -> List[Dict[str, Any]]:
        """Merge all finding sources and deduplicate by finding_id.

        Args:
            rule_findings: Findings from rule evaluation.
            cross_ref_findings: Cross-referenced findings.
            shadow_ai: Shadow AI detections.

        Returns:
            Deduplicated list of findings.
        """
        seen: Dict[str, Dict[str, Any]] = {}

        for f in rule_findings:
            fid = f.get("finding_id", "")
            if fid not in seen:
                seen[fid] = f

        for f in cross_ref_findings:
            fid = f.get("finding_id", "")
            if fid not in seen:
                seen[fid] = f

        # Shadow AI entries become findings
        for idx, s in enumerate(shadow_ai):
            fid = self._generate_finding_id(
                "AI-GOV-002",
                s.get("resource_uid", ""),
                s.get("caller", ""),
                str(idx),
            )
            if fid not in seen:
                seen[fid] = {
                    "finding_id": fid,
                    "rule_id": "AI-GOV-002",
                    "title": "Shadow AI detected - unregistered ML endpoint",
                    "severity": "high",
                    "status": "FAIL",
                    "category": "ai_governance",
                    "resource_uid": s.get("resource_uid"),
                    "evidence": s,
                }

        return list(seen.values())

    def _compute_scores(self, findings: List[Dict], inventory: List[Dict]) -> Dict[str, Any]:
        """Compute posture scores from findings.

        Args:
            findings: All deduplicated findings.
            inventory: AI/ML resource inventory.

        Returns:
            Dict with overall_risk_score, category_scores, severity_breakdown.
        """
        severity_weights = {"critical": 10, "high": 5, "medium": 2, "low": 1}

        total_resources = max(len(inventory), 1)
        fail_findings = [f for f in findings if f.get("status") == "FAIL"]

        # Weighted penalty
        penalty = sum(severity_weights.get(f.get("severity", "medium"), 2) for f in fail_findings)
        max_possible = total_resources * 10  # worst case: all critical
        raw_score = min(100, int((penalty / max(max_possible, 1)) * 100))

        # Category breakdown
        category_scores: Dict[str, Dict[str, int]] = {}
        for module in self.MODULES:
            cat_findings = [f for f in findings if f.get("category") == module]
            cat_fail = sum(1 for f in cat_findings if f.get("status") == "FAIL")
            cat_pass = sum(1 for f in cat_findings if f.get("status") == "PASS")
            category_scores[module] = {
                "total": len(cat_findings),
                "pass": cat_pass,
                "fail": cat_fail,
            }

        # Severity breakdown
        severity_breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in fail_findings:
            sev = f.get("severity", "medium")
            severity_breakdown[sev] = severity_breakdown.get(sev, 0) + 1

        return {
            "overall_risk_score": raw_score,
            "total_resources": total_resources,
            "total_findings": len(findings),
            "total_failures": len(fail_findings),
            "category_scores": category_scores,
            "severity_breakdown": severity_breakdown,
        }

    def _build_report(
        self,
        findings: List[Dict],
        inventory: List[Dict],
        scores: Dict[str, Any],
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        provider: str,
    ) -> Dict[str, Any]:
        """Build the final report summary.

        Args:
            findings: All findings.
            inventory: AI/ML inventory.
            scores: Computed scores.
            scan_run_id: Scan identifier.
            tenant_id: Tenant identifier.
            account_id: Account identifier.
            provider: Cloud provider.

        Returns:
            Report dict matching ai_security_report schema.
        """
        fail_findings = [f for f in findings if f.get("status") == "FAIL"]
        sev = scores.get("severity_breakdown", {})

        # Coverage metrics from inventory
        total_inv = max(len(inventory), 1)
        vpc_count = sum(1 for r in inventory if r.get("is_vpc_isolated"))
        enc_rest = sum(1 for r in inventory if r.get("encryption_at_rest"))
        enc_transit = sum(1 for r in inventory if r.get("encryption_in_transit"))
        model_card = sum(1 for r in inventory if r.get("has_model_card"))
        monitoring = sum(1 for r in inventory if r.get("has_monitoring"))
        guardrails = sum(1 for r in inventory if r.get("has_guardrails"))

        # Top failing rules
        rule_fail_count: Dict[str, int] = {}
        for f in fail_findings:
            rid = f.get("rule_id", "unknown")
            rule_fail_count[rid] = rule_fail_count.get(rid, 0) + 1
        top_failing = sorted(rule_fail_count.items(), key=lambda x: x[1], reverse=True)[:10]

        # Service breakdown
        service_counts: Dict[str, int] = {}
        for r in inventory:
            svc = r.get("ml_service") or r.get("service") or "unknown"
            service_counts[svc] = service_counts.get(svc, 0) + 1

        return {
            "scan_run_id": scan_run_id,
            "tenant_id": tenant_id,
            "account_id": account_id,
            "provider": provider,
            "total_ml_resources": len(inventory),
            "total_findings": len(findings),
            "critical_findings": sev.get("critical", 0),
            "high_findings": sev.get("high", 0),
            "medium_findings": sev.get("medium", 0),
            "low_findings": sev.get("low", 0),
            "pass_count": sum(1 for f in findings if f.get("status") == "PASS"),
            "fail_count": len(fail_findings),
            "vpc_isolation_pct": round(vpc_count / total_inv * 100, 2),
            "encryption_rest_pct": round(enc_rest / total_inv * 100, 2),
            "encryption_transit_pct": round(enc_transit / total_inv * 100, 2),
            "model_card_pct": round(model_card / total_inv * 100, 2),
            "monitoring_pct": round(monitoring / total_inv * 100, 2),
            "guardrails_pct": round(guardrails / total_inv * 100, 2),
            "category_breakdown": scores.get("category_scores", {}),
            "service_breakdown": service_counts,
            "top_failing_rules": [{"rule_id": r, "count": c} for r, c in top_failing],
            "risk_score": scores.get("overall_risk_score", 0),
        }

    # ------------------------------------------------------------ helpers

    @staticmethod
    def _group_by_category(rules: List[Dict]) -> Dict[str, List[Dict]]:
        """Group a flat list of rules by category.

        Args:
            rules: Flat list of rule dicts.

        Returns:
            Dict mapping category to list of rules.
        """
        grouped: Dict[str, List[Dict]] = {}
        for rule in rules:
            cat = rule.get("category", "unknown")
            grouped.setdefault(cat, []).append(rule)
        return grouped

    @staticmethod
    def _generate_finding_id(rule_id: str, resource_uid: str, account_id: str, region: str) -> str:
        """Generate a deterministic finding_id using SHA-256.

        Args:
            rule_id: Rule identifier.
            resource_uid: Resource ARN or unique identifier.
            account_id: Cloud account identifier.
            region: Resource region.

        Returns:
            16-character hex digest.
        """
        raw = f"{rule_id}|{resource_uid}|{account_id}|{region}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
