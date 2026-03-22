"""Data activity monitoring evaluation module.

Evaluates whether logging, audit trails, and access monitoring
are properly configured for cloud data stores.
"""

from typing import Any, Dict, List

from .base_module import BaseDataSecModule, ModuleResult
from ..rules.rule_evaluator import DataSecRuleEvaluator


class ActivityModule(BaseDataSecModule):
    """Evaluates data activity monitoring posture."""

    CATEGORY = "data_activity_monitoring"

    # Fields in finding_data that indicate monitoring configuration
    ACTIVITY_FIELDS = [
        "logging_enabled",
        "access_logging",
        "audit_trail",
        "audit_logging_enabled",
        "data_access_logging",
        "cloudtrail_logging",
        "flow_logs_enabled",
        "monitoring_enabled",
        "metric_alarms",
        "event_notifications",
    ]

    def evaluate(
        self,
        findings: List[Dict],
        data_stores: List[Dict],
        context: Dict,
    ) -> List[ModuleResult]:
        """Evaluate activity monitoring rules against discovered findings.

        Args:
            findings: Discovery findings with finding_data containing
                monitoring-related fields (logging_enabled, access_logging,
                audit_trail).
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

                # Enrich evidence with activity-specific context
                for af in self.ACTIVITY_FIELDS:
                    if af in resource_data and af not in evidence:
                        evidence[af] = resource_data[af]

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
