"""
Rule evaluator for DataSec engine.
Wraps shared/common/condition_evaluator.py for datasec rule conditions.
"""
import re
import logging
from typing import Dict, Any, Tuple, List

logger = logging.getLogger(__name__)

# Import shared condition evaluator
try:
    from engine_common.condition_evaluator import extract_value, evaluate_condition, resolve_template
except ImportError:
    # Fallback: direct import from shared path
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "shared", "common"))
    from condition_evaluator import extract_value, evaluate_condition, resolve_template


class DataSecRuleEvaluator:
    """Evaluates datasec rules against resource/finding data."""

    def evaluate_rule(self, rule: Dict[str, Any], resource_data: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        """
        Evaluate a single rule against resource data.
        Returns: (status: "PASS"|"FAIL"|"ERROR", evidence: {...})
        """
        condition = rule.get("condition", {})
        condition_type = condition.get("type", rule.get("condition_type", "field_check"))

        try:
            if condition_type == "field_check":
                return self._eval_field_check(condition, resource_data)
            elif condition_type == "regex_match":
                return self._eval_regex_match(condition, resource_data)
            elif condition_type in ("all_of", "composite"):
                return self._eval_composite(condition, resource_data, require_all=True)
            elif condition_type == "any_of":
                return self._eval_composite(condition, resource_data, require_all=False)
            elif condition_type == "resource_property":
                return self._eval_field_check(condition, resource_data)  # same logic
            else:
                logger.warning(f"Unknown condition_type: {condition_type}")
                return "ERROR", {"error": f"Unknown condition_type: {condition_type}"}
        except Exception as e:
            logger.warning(f"Rule evaluation error: {e}")
            return "ERROR", {"error": str(e)}

    def _eval_field_check(self, condition: Dict, data: Dict) -> Tuple[str, Dict]:
        field_path = condition.get("field", "")
        operator = condition.get("operator", "equals")
        expected = condition.get("expected")

        actual = extract_value(data, field_path)
        passed = evaluate_condition(actual, operator, expected)

        return ("PASS" if passed else "FAIL"), {
            "field": field_path,
            "operator": operator,
            "expected": expected,
            "actual": actual,
        }

    def _eval_regex_match(self, condition: Dict, data: Dict) -> Tuple[str, Dict]:
        field_path = condition.get("field", "")
        pattern = condition.get("pattern", "")
        data_type = condition.get("data_type", "unknown")

        content = extract_value(data, field_path)
        if not content or not isinstance(content, str):
            return "PASS", {"field": field_path, "matched": False, "data_type": data_type}

        try:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return "FAIL", {
                    "field": field_path,
                    "matched": True,
                    "data_type": data_type,
                    "match_count": len(matches),
                    "pattern": pattern,
                }
            return "PASS", {"field": field_path, "matched": False, "data_type": data_type}
        except re.error as e:
            return "ERROR", {"error": f"Invalid regex: {e}", "pattern": pattern}

    def _eval_composite(self, condition: Dict, data: Dict, require_all: bool) -> Tuple[str, Dict]:
        sub_conditions = condition.get("conditions", [])
        sub_results = []

        for sub in sub_conditions:
            sub_type = sub.get("type", "field_check")
            if sub_type == "field_check":
                status, evidence = self._eval_field_check(sub, data)
            elif sub_type == "regex_match":
                status, evidence = self._eval_regex_match(sub, data)
            else:
                status, evidence = self._eval_field_check(sub, data)
            sub_results.append({"status": status, **evidence})

        if require_all:
            passed = all(r["status"] == "PASS" for r in sub_results)
        else:
            passed = any(r["status"] == "PASS" for r in sub_results)

        return ("PASS" if passed else "FAIL"), {"sub_results": sub_results}
