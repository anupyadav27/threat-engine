"""Data access governance evaluation module.

Evaluates public access settings, IAM policies, RBAC configurations,
and cross-account access controls for cloud data stores.
"""

from typing import Any, Dict, List

from .base_module import BaseDataSecModule, ModuleResult
from ..rules.rule_evaluator import DataSecRuleEvaluator


class AccessModule(BaseDataSecModule):
    """Evaluates access governance posture for data stores."""

    CATEGORY = "data_access_governance"

    # Fields in finding_data that indicate access configuration
    ACCESS_FIELDS = [
        "public_access",
        "public_access_block",
        "acl",
        "bucket_policy",
        "resource_policy",
        "iam_policy",
        "cross_account_access",
        "rbac_enabled",
        "network_access_rules",
        "ip_restrictions",
        "vpc_endpoint",
    ]

    def evaluate(
        self,
        findings: List[Dict],
        data_stores: List[Dict],
        context: Dict,
    ) -> List[ModuleResult]:
        """Evaluate access governance rules against discovered findings.

        Args:
            findings: Discovery findings with finding_data containing
                access-related fields (public_access, acl, bucket_policy).
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

                # Enrich evidence with access-specific context
                for af in self.ACCESS_FIELDS:
                    if af in resource_data and af not in evidence:
                        evidence[af] = resource_data[af]

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
