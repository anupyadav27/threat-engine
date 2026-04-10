"""
Rule evaluator for AI Security engine.
Evaluates resources against AI security rules using JSONB conditions.

Condition types (from seed SQL):
- field_check:   {"field": "encryption_at_rest", "op": "eq", "value": false}
- threshold:     {"field": "error_rate_pct", "op": "gt", "value": 5}
- composite:     {"all": [...]} or {"any": [...]}
- pattern_match: {"field": "iam_role", "pattern": ".*\\*.*"}
"""
import re
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class AIRuleEvaluator:
    """Evaluates AI security rules against resource data."""

    # ------------------------------------------------------------------ public

    def evaluate_rule(self, rule: Dict[str, Any], resource_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Evaluate a single rule against resource data.

        Args:
            rule: Rule dict containing 'condition' (JSONB) and 'condition_type'.
            resource_data: Flat or nested dict of resource attributes.

        Returns:
            Tuple of (status, evidence) where status is one of
            PASS, FAIL, SKIP, ERROR and evidence contains evaluation details.
        """
        condition = rule.get("condition", {})
        condition_type = rule.get("condition_type", "field_check")

        # Handle composite shorthand: top-level "all" or "any" key
        if "all" in condition:
            condition_type = "composite"
        elif "any" in condition:
            condition_type = "composite"

        try:
            if condition_type == "field_check":
                return self._evaluate_field_check(condition, resource_data)
            elif condition_type == "threshold":
                return self._evaluate_threshold(condition, resource_data)
            elif condition_type == "composite":
                return self._evaluate_composite(condition, resource_data)
            elif condition_type == "pattern_match":
                return self._evaluate_pattern_match(condition, resource_data)
            else:
                logger.warning("Unknown condition_type: %s", condition_type)
                return "ERROR", {"error": f"Unknown condition_type: {condition_type}"}
        except Exception as e:
            logger.warning("Rule evaluation error for %s: %s", rule.get("rule_id"), e)
            return "ERROR", {"error": str(e)}

    def evaluate_rules(
        self,
        rules: List[Dict[str, Any]],
        resource_data: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Evaluate multiple rules against a single resource.

        Args:
            rules: List of rule dicts.
            resource_data: Resource attributes to evaluate against.

        Returns:
            List of result dicts with rule_id, status, and evidence.
        """
        results: List[Dict[str, Any]] = []
        for rule in rules:
            status, evidence = self.evaluate_rule(rule, resource_data)
            results.append({
                "rule_id": rule.get("rule_id"),
                "status": status,
                "evidence": evidence,
            })
        return results

    # ------------------------------------------------------------ evaluators

    def _evaluate_field_check(self, condition: Dict[str, Any], resource_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Evaluate a field_check condition.

        Supports operators: eq, ne, in, not_in, contains, not_contains,
        missing_keys, exists, not_exists.

        Args:
            condition: Dict with field, op, value keys.
            resource_data: Resource attributes.

        Returns:
            Tuple of (status, evidence).
        """
        field_path = condition.get("field", "")
        operator = condition.get("op", condition.get("operator", "eq"))
        expected = condition.get("value", condition.get("expected"))

        actual = self._extract_field(resource_data, field_path)
        passed = self._compare(actual, operator, expected)

        return ("FAIL" if passed else "PASS"), {
            "field": field_path,
            "operator": operator,
            "expected": expected,
            "actual": actual,
        }

    def _evaluate_threshold(self, condition: Dict[str, Any], resource_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Evaluate a threshold condition.

        Supports operators: gt, gte, lt, lte, eq, ne.

        Args:
            condition: Dict with field, op, value keys.
            resource_data: Resource attributes.

        Returns:
            Tuple of (status, evidence).
        """
        field_path = condition.get("field", "")
        operator = condition.get("op", condition.get("operator", "gt"))
        threshold = condition.get("value", condition.get("expected", 0))

        actual = self._extract_field(resource_data, field_path)

        # Coerce to numeric for comparison
        try:
            actual_num = float(actual) if actual is not None else 0.0
            threshold_num = float(threshold)
        except (TypeError, ValueError):
            return "ERROR", {
                "field": field_path,
                "error": f"Non-numeric value: actual={actual}, threshold={threshold}",
            }

        passed = self._compare_numeric(actual_num, operator, threshold_num)

        return ("FAIL" if passed else "PASS"), {
            "field": field_path,
            "operator": operator,
            "expected": threshold,
            "actual": actual,
        }

    def _evaluate_composite(self, condition: Dict[str, Any], resource_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Evaluate a composite (and/or) condition.

        Handles:
        - {"all": [sub1, sub2, ...]} — all must trigger (FAIL) for composite FAIL
        - {"any": [sub1, sub2, ...]} — any trigger means composite FAIL
        - {"operator": "and", "conditions": [...]} — alternate format

        Args:
            condition: Dict with 'all', 'any', or 'conditions' key.
            resource_data: Resource attributes.

        Returns:
            Tuple of (status, evidence).
        """
        if "all" in condition:
            sub_conditions = condition["all"]
            require_all = True
        elif "any" in condition:
            sub_conditions = condition["any"]
            require_all = False
        else:
            # Alternate format with explicit operator
            sub_conditions = condition.get("conditions", [])
            op = condition.get("operator", "and")
            require_all = op.lower() == "and"

        sub_results: List[Dict[str, Any]] = []
        for sub in sub_conditions:
            sub_type = sub.get("type", sub.get("condition_type", "field_check"))
            if sub_type == "threshold":
                status, evidence = self._evaluate_threshold(sub, resource_data)
            elif sub_type == "pattern_match":
                status, evidence = self._evaluate_pattern_match(sub, resource_data)
            else:
                status, evidence = self._evaluate_field_check(sub, resource_data)
            sub_results.append({"status": status, **evidence})

        if require_all:
            # All sub-conditions must FAIL for the composite to FAIL
            overall_fail = all(r["status"] == "FAIL" for r in sub_results)
        else:
            # Any sub-condition FAIL triggers composite FAIL
            overall_fail = any(r["status"] == "FAIL" for r in sub_results)

        return ("FAIL" if overall_fail else "PASS"), {"sub_results": sub_results}

    def _evaluate_pattern_match(self, condition: Dict[str, Any], resource_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """Evaluate a regex pattern match condition.

        Args:
            condition: Dict with field and pattern keys.
            resource_data: Resource attributes.

        Returns:
            Tuple of (status, evidence).
        """
        field_path = condition.get("field", "")
        pattern = condition.get("pattern", "")

        actual = self._extract_field(resource_data, field_path)
        if actual is None or not isinstance(actual, str):
            return "SKIP", {
                "field": field_path,
                "pattern": pattern,
                "matched": False,
                "reason": "field_missing_or_non_string",
            }

        try:
            match = re.search(pattern, actual, re.IGNORECASE)
            if match:
                return "FAIL", {
                    "field": field_path,
                    "pattern": pattern,
                    "matched": True,
                    "match_value": match.group(),
                }
            return "PASS", {
                "field": field_path,
                "pattern": pattern,
                "matched": False,
            }
        except re.error as e:
            return "ERROR", {"error": f"Invalid regex: {e}", "pattern": pattern}

    # ------------------------------------------------------------ helpers

    def _extract_field(self, resource_data: Dict[str, Any], field_path: str) -> Any:
        """Extract a field value using dotted notation.

        Supports paths like 'config.encryption.enabled' by walking nested dicts.

        Args:
            resource_data: Source dict.
            field_path: Dot-separated path to the desired field.

        Returns:
            The field value, or None if the path does not exist.
        """
        if not field_path:
            return None

        current: Any = resource_data
        for part in field_path.split("."):
            if isinstance(current, dict):
                current = current.get(part)
            else:
                return None
        return current

    def _compare(self, actual: Any, operator: str, expected: Any) -> bool:
        """Compare actual vs expected using the given operator.

        Returns True when the condition *triggers* (i.e. the finding should FAIL).

        Args:
            actual: Actual resource value.
            operator: Comparison operator string.
            expected: Expected/threshold value.

        Returns:
            True if condition triggers (resource violates rule).
        """
        if operator in ("eq", "equals"):
            return actual == expected
        elif operator in ("ne", "not_equals"):
            return actual != expected
        elif operator in ("in",):
            if isinstance(expected, list):
                return actual in expected
            return False
        elif operator in ("not_in",):
            if isinstance(expected, list):
                return actual not in expected
            return False
        elif operator in ("contains",):
            if isinstance(actual, str) and isinstance(expected, str):
                return expected in actual
            return False
        elif operator in ("not_contains",):
            if isinstance(actual, str) and isinstance(expected, str):
                return expected not in actual
            return False
        elif operator in ("missing_keys",):
            if isinstance(actual, dict) and isinstance(expected, list):
                return any(k not in actual for k in expected)
            # If tags are None/missing, all keys are missing
            return True
        elif operator in ("exists",):
            return actual is not None
        elif operator in ("not_exists",):
            return actual is None
        else:
            # Fall through to numeric comparison
            return self._compare_numeric_safe(actual, operator, expected)

    def _compare_numeric(self, actual: float, operator: str, expected: float) -> bool:
        """Numeric comparison. Returns True when condition triggers.

        Args:
            actual: Actual numeric value.
            operator: One of gt, gte, lt, lte, eq, ne.
            expected: Threshold value.

        Returns:
            True if condition triggers.
        """
        if operator in ("gt", "greater_than"):
            return actual > expected
        elif operator in ("gte", "greater_than_or_equal"):
            return actual >= expected
        elif operator in ("lt", "less_than"):
            return actual < expected
        elif operator in ("lte", "less_than_or_equal"):
            return actual <= expected
        elif operator in ("eq", "equals"):
            return actual == expected
        elif operator in ("ne", "not_equals"):
            return actual != expected
        return False

    def _compare_numeric_safe(self, actual: Any, operator: str, expected: Any) -> bool:
        """Attempt numeric comparison with type coercion.

        Args:
            actual: Value from resource.
            operator: Comparison operator.
            expected: Threshold value.

        Returns:
            True if condition triggers, False if values are non-numeric.
        """
        try:
            return self._compare_numeric(float(actual), operator, float(expected))
        except (TypeError, ValueError):
            return False
