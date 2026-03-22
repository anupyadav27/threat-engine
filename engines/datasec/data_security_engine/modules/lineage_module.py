"""Data lineage evaluation module.

Evaluates replication configuration, cross-region data transfer,
and data flow metadata for cloud data stores.
"""

from typing import Any, Dict, List

from .base_module import BaseDataSecModule, ModuleResult
from ..rules.rule_evaluator import DataSecRuleEvaluator


class LineageModule(BaseDataSecModule):
    """Evaluates data lineage and replication posture."""

    CATEGORY = "data_lineage"

    # Fields in finding_data that indicate lineage/replication configuration
    LINEAGE_FIELDS = [
        "replication_enabled",
        "replication_configuration",
        "cross_region",
        "cross_region_replication",
        "transfer_encryption",
        "data_flow_logging",
        "destination_regions",
        "source_region",
        "replication_status",
    ]

    def evaluate(
        self,
        findings: List[Dict],
        data_stores: List[Dict],
        context: Dict,
    ) -> List[ModuleResult]:
        """Evaluate lineage rules against discovered findings.

        Args:
            findings: Discovery findings with finding_data containing
                replication-related fields (replication_enabled,
                cross_region).
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

                # Enrich evidence with lineage-specific context
                for lf in self.LINEAGE_FIELDS:
                    if lf in resource_data and lf not in evidence:
                        evidence[lf] = resource_data[lf]

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
