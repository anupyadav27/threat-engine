"""Data classification evaluation module.

Detects PII, PCI, PHI and other sensitive data types using regex pattern
matching and field-level classification tag checks.
"""

import re
from typing import Any, Dict, List, Optional

from .base_module import BaseDataSecModule, ModuleResult
from ..rules.rule_evaluator import DataSecRuleEvaluator


class ClassificationModule(BaseDataSecModule):
    """Detects and evaluates sensitive data classification posture.

    Supports two evaluation modes driven by rule type:
      - regex_match: applies detection_pattern from sensitive_data_types
        against finding content to detect PII/PCI/PHI.
      - field_check: verifies that the resource has proper classification
        tags applied.
    """

    CATEGORY = "data_classification"

    def __init__(
        self,
        rules: List[Dict[str, Any]],
        tenant_id: str = "default",
        sensitive_patterns: Optional[Dict[str, str]] = None,
    ):
        """Initialize with optional sensitive data patterns.

        Args:
            rules: DataSec rules filtered for this category.
            tenant_id: Tenant identifier.
            sensitive_patterns: Mapping of pattern_name -> regex loaded
                from the datasec_sensitive_data_types table. Merged with
                any patterns defined inline in the rules.
        """
        super().__init__(rules, tenant_id)
        self.sensitive_patterns: Dict[str, re.Pattern] = {}
        if sensitive_patterns:
            for name, pattern in sensitive_patterns.items():
                try:
                    self.sensitive_patterns[name] = re.compile(pattern)
                except re.error:
                    continue

    def _detect_sensitive_types(
        self, resource_data: Dict[str, Any]
    ) -> List[str]:
        """Scan resource data values for sensitive data type matches."""
        detected: List[str] = []
        text_blob = " ".join(
            str(v) for v in resource_data.values() if isinstance(v, (str, int, float))
        )
        for name, pattern in self.sensitive_patterns.items():
            if pattern.search(text_blob):
                detected.append(name)
        return detected

    def evaluate(
        self,
        findings: List[Dict],
        data_stores: List[Dict],
        context: Dict,
    ) -> List[ModuleResult]:
        """Evaluate classification rules against discovered findings.

        Args:
            findings: Discovery findings with finding_data.
            data_stores: Enriched data store records (unused for now).
            context: Must contain 'csp'; may contain 'required_tags'.

        Returns:
            List of ModuleResult for each rule/finding pair.
        """
        results: List[ModuleResult] = []
        csp = context.get("csp", "aws")
        evaluator = DataSecRuleEvaluator()

        for rule in self.get_applicable_rules(csp):
            service = rule.get("service")
            rule_type = rule.get("evaluation_type", "field_check")

            for finding in findings:
                if finding.get("resource_type", "").lower() != service:
                    continue

                resource_data = (
                    finding.get("finding_data")
                    or finding.get("evidence")
                    or {}
                )

                if rule_type == "regex_match":
                    # Use sensitive pattern detection
                    detected = self._detect_sensitive_types(resource_data)
                    has_classification_tags = bool(
                        resource_data.get("classification_tags")
                        or resource_data.get("data_classification")
                    )
                    if detected and not has_classification_tags:
                        status = "FAIL"
                    elif detected and has_classification_tags:
                        status = "PASS"
                    else:
                        status = "PASS"
                    evidence = {
                        "detected_types": detected,
                        "has_classification": has_classification_tags,
                    }
                else:
                    # Standard field_check via rule evaluator
                    status, evidence = evaluator.evaluate_rule(rule, resource_data)

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
