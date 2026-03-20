"""Data protection and encryption evaluation module.

Evaluates encryption at rest, encryption in transit, KMS usage,
and key rotation policies for cloud data stores.
"""

from typing import Any, Dict, List

from .base_module import BaseDataSecModule, ModuleResult
from ..rules.rule_evaluator import DataSecRuleEvaluator


class EncryptionModule(BaseDataSecModule):
    """Evaluates encryption posture for data stores and resources."""

    CATEGORY = "data_protection_encryption"

    # Fields in finding_data that indicate encryption configuration
    ENCRYPTION_FIELDS = [
        "encryption_enabled",
        "encryption_at_rest",
        "encryption_in_transit",
        "kms_key_id",
        "kms_key_arn",
        "server_side_encryption",
        "sse_algorithm",
        "key_rotation_enabled",
        "key_rotation_interval_days",
        "ssl_enforcement",
        "tls_version",
    ]

    def evaluate(
        self,
        findings: List[Dict],
        data_stores: List[Dict],
        context: Dict,
    ) -> List[ModuleResult]:
        """Evaluate encryption rules against discovered findings.

        Args:
            findings: Discovery findings with finding_data containing
                encryption-related fields.
            data_stores: Enriched data store records (unused for now).
            context: Must contain 'csp' key (e.g. 'aws').

        Returns:
            List of ModuleResult for each rule/finding pair.
        """
        results: List[ModuleResult] = []
        csp = context.get("csp", "aws")
        evaluator = DataSecRuleEvaluator()

        for rule in self.get_applicable_rules(csp):
            service = rule.get("service")
            for finding in findings:
                if finding.get("resource_type", "").lower() != service:
                    continue

                resource_data = (
                    finding.get("finding_data")
                    or finding.get("evidence")
                    or {}
                )

                status, evidence = evaluator.evaluate_rule(rule, resource_data)

                # Enrich evidence with encryption-specific context
                for ef in self.ENCRYPTION_FIELDS:
                    if ef in resource_data and ef not in evidence:
                        evidence[ef] = resource_data[ef]

                results.append(
                    ModuleResult(
                        rule_id=rule["rule_id"],
                        resource_uid=finding.get("resource_uid", ""),
                        resource_id=finding.get("resource_id", ""),
                        resource_type=finding.get("resource_type", ""),
                        status=status,
                        severity=rule.get("severity", "high"),
                        category=self.CATEGORY,
                        title=rule.get("title", ""),
                        description=rule.get("description", ""),
                        remediation=rule.get("remediation", ""),
                        compliance_frameworks=rule.get("compliance_frameworks", []),
                        sensitive_data_types=rule.get("sensitive_data_types", []),
                        evidence=evidence,
                    )
                )

        return results
