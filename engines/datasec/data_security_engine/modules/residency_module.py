"""Data residency evaluation module.

Checks whether resources reside in approved regions according to
organizational data residency policies.
"""

from typing import Any, Dict, List

from .base_module import BaseDataSecModule, ModuleResult
from ..rules.rule_evaluator import DataSecRuleEvaluator


class ResidencyModule(BaseDataSecModule):
    """Evaluates data residency compliance for resources."""

    CATEGORY = "data_residency"

    def evaluate(
        self,
        findings: List[Dict],
        data_stores: List[Dict],
        context: Dict,
    ) -> List[ModuleResult]:
        """Evaluate residency rules against discovered findings.

        For each finding, compares its region against the allowed
        regions specified in the rule or context.

        Args:
            findings: Discovery findings with region information.
            data_stores: Enriched data store records (unused for now).
            context: Must contain 'csp'; should contain 'allowed_regions'
                list defining permitted deployment regions.

        Returns:
            List of ModuleResult for each rule/finding pair.
        """
        results: List[ModuleResult] = []
        csp = context.get("csp", "aws")
        global_allowed_regions = context.get("allowed_regions", [])
        evaluator = DataSecRuleEvaluator()

        for rule in self.get_applicable_rules(csp):
            service = rule.get("service")
            # Rule-level allowed regions override global context
            rule_allowed_regions = (
                rule.get("allowed_regions") or global_allowed_regions
            )

            for finding in findings:
                if finding.get("resource_type", "").lower() != service:
                    continue

                resource_data = (
                    finding.get("finding_data")
                    or finding.get("evidence")
                    or {}
                )

                resource_region = (
                    finding.get("region")
                    or resource_data.get("region")
                    or ""
                )

                if rule_allowed_regions:
                    # Residency check: region must be in allowed list
                    in_allowed = resource_region in rule_allowed_regions
                    status = "PASS" if in_allowed else "FAIL"
                    evidence = {
                        "resource_region": resource_region,
                        "allowed_regions": rule_allowed_regions,
                        "in_allowed_region": in_allowed,
                    }
                else:
                    # Fall back to rule evaluator if no regions configured
                    status, evidence = evaluator.evaluate_rule(rule, resource_data)
                    evidence["resource_region"] = resource_region

                results.append(
                    ModuleResult(
                        rule_id=rule["rule_id"],
                        resource_uid=finding.get("resource_uid", ""),
                        resource_id=finding.get("resource_id", ""),
                        resource_type=finding.get("resource_type", ""),
                        status=status,
                        severity=rule.get("severity", "medium"),
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
