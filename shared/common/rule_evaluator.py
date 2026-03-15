"""
Shared Rule Evaluator — Task 0.5.1 [Seq 44 | BD]

Generic rule evaluation engine used by all 5 new engines (container, network,
supplychain, api, risk). Supports 4 condition types defined in JSONB:

  1. field_check   — compare asset field against expected value
  2. threshold     — compare metric against baseline × multiplier (anomaly)
  3. set_membership — check if field value is in a pre-loaded set
  4. composite     — AND/OR of multiple sub-conditions (recursive)

Usage:
    from shared.common.rule_evaluator import RuleEvaluator, RuleResult

    evaluator = RuleEvaluator()
    result = evaluator.evaluate(asset_dict, rule_dict)
    # result.result  → 'PASS' | 'FAIL' | 'SKIP' | 'ERROR'
    # result.evidence → dict with actual/expected values
    # result.severity → from rule definition

Consumed by: Tasks 1.4, 2.4, 3.5, 4.4, 5.5 (all engine evaluators)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Union

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass
class RuleResult:
    """Evaluation result for a single rule against a single asset."""

    result: str          # PASS | FAIL | SKIP | ERROR
    evidence: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result": self.result,
            "evidence": self.evidence,
            "severity": self.severity,
        }


# ---------------------------------------------------------------------------
# Operator implementations
# ---------------------------------------------------------------------------

def _compare(actual: Any, operator: str, expected: Any) -> bool:
    """
    Compare *actual* against *expected* using *operator*.

    Supported operators (superset of check_engine's VALID_OPERATORS that are
    relevant to the new engines):

        eq / equals         — strict equality
        ne / not_equals     — strict inequality
        gt / greater_than   — numeric >
        lt / less_than      — numeric <
        gte                 — numeric >=
        lte                 — numeric <=
        contains            — substring or list-element membership
        not_contains        — negation of contains
        starts_with         — string prefix
        ends_with           — string suffix
        in                  — actual is in expected (list)
        not_in              — actual is NOT in expected (list)
        is_null             — actual is None (expected ignored)
        is_not_null         — actual is not None
        is_empty            — actual is empty (str/list/dict)
        is_not_empty        — actual is not empty
        regex               — re.search(expected, actual)
        not_regex           — negation of regex
        exists              — field was resolved (not _MISSING)
        not_exists          — field was NOT resolved
        contains_all        — actual (list) contains ALL items in expected
        contains_any        — actual (list) contains ANY item in expected
        length_equals       — len(actual) == expected
        length_greater_than — len(actual) > expected
        length_less_than    — len(actual) < expected
    """
    try:
        op = operator.lower().strip()

        # --- equality ---
        if op in ("eq", "equals"):
            return actual == expected
        if op in ("ne", "not_equals"):
            return actual != expected

        # --- numeric ---
        if op in ("gt", "greater_than"):
            return float(actual) > float(expected)
        if op in ("lt", "less_than"):
            return float(actual) < float(expected)
        if op == "gte":
            return float(actual) >= float(expected)
        if op == "lte":
            return float(actual) <= float(expected)

        # --- string / collection ---
        if op == "contains":
            if isinstance(actual, (list, tuple, set)):
                return expected in actual
            return str(expected) in str(actual)
        if op == "not_contains":
            return not _compare(actual, "contains", expected)

        if op == "starts_with":
            return str(actual).startswith(str(expected))
        if op == "ends_with":
            return str(actual).endswith(str(expected))

        # --- membership ---
        if op == "in":
            if isinstance(expected, (list, tuple, set)):
                return actual in expected
            return actual == expected
        if op == "not_in":
            if isinstance(expected, (list, tuple, set)):
                return actual not in expected
            return actual != expected

        # --- null / empty ---
        if op == "is_null":
            return actual is None
        if op == "is_not_null":
            return actual is not None
        if op == "is_empty":
            if actual is None:
                return True
            return len(actual) == 0 if hasattr(actual, "__len__") else False
        if op == "is_not_empty":
            return not _compare(actual, "is_empty", expected)

        # --- regex ---
        if op == "regex":
            return bool(re.search(str(expected), str(actual)))
        if op == "not_regex":
            return not bool(re.search(str(expected), str(actual)))

        # --- existence (used with _get_nested sentinel) ---
        if op == "exists":
            return actual is not _MISSING
        if op == "not_exists":
            return actual is _MISSING

        # --- list-level operators ---
        if op == "contains_all":
            if not isinstance(actual, (list, tuple, set)):
                return False
            return all(item in actual for item in (expected or []))
        if op == "contains_any":
            if not isinstance(actual, (list, tuple, set)):
                return False
            return any(item in actual for item in (expected or []))

        # --- length operators ---
        if op == "length_equals":
            return len(actual) == int(expected)
        if op == "length_greater_than":
            return len(actual) > int(expected)
        if op == "length_less_than":
            return len(actual) < int(expected)

        logger.warning("Unknown operator '%s', treating as FAIL", operator)
        return False

    except (TypeError, ValueError, AttributeError) as exc:
        logger.debug("Comparison error: op=%s, actual=%r, expected=%r — %s",
                      operator, actual, expected, exc)
        return False


# ---------------------------------------------------------------------------
# Nested field access
# ---------------------------------------------------------------------------

class _MissingSentinel:
    """Sentinel returned when a field path cannot be resolved."""

    def __repr__(self) -> str:
        return "<MISSING>"

_MISSING = _MissingSentinel()


def _get_nested(data: Any, field_path: str) -> Any:
    """
    Resolve a dotted/bracket field path against a nested dict/list.

    Supports:
        "encryption_enabled"             → data["encryption_enabled"]
        "config.logging.enabled"         → data["config"]["logging"]["enabled"]
        "inbound_rules[*].cidr"          → [r["cidr"] for r in data["inbound_rules"]]
        "tags[0].key"                    → data["tags"][0]["key"]
        "response.BucketName"            → data["response"]["BucketName"]

    Returns _MISSING if any segment cannot be resolved.
    """
    if not field_path:
        return _MISSING

    parts = _split_field_path(field_path)
    return _resolve_parts(data, parts)


def _split_field_path(path: str) -> List[Union[str, int, str]]:
    """
    Split 'a.b[*].c[0].d' into ['a', 'b', '*', 'c', 0, 'd'].
    """
    tokens: List[Union[str, int, str]] = []
    for segment in path.split("."):
        # Handle bracket notation within a segment: 'items[*]' or 'items[0]'
        bracket_match = re.match(r'^(\w+)\[(.+?)\]$', segment)
        if bracket_match:
            key, idx = bracket_match.group(1), bracket_match.group(2)
            tokens.append(key)
            if idx == "*":
                tokens.append("*")
            else:
                try:
                    tokens.append(int(idx))
                except ValueError:
                    tokens.append(idx)
        else:
            tokens.append(segment)
    return tokens


def _resolve_parts(data: Any, parts: List[Union[str, int]]) -> Any:
    """Recursively resolve field path parts."""
    if not parts:
        return data

    head, *tail = parts

    # Wildcard: fan-out across list elements
    if head == "*":
        if not isinstance(data, (list, tuple)):
            return _MISSING
        results = []
        for item in data:
            val = _resolve_parts(item, tail)
            if val is not _MISSING:
                results.append(val)
        return results if results else _MISSING

    # Integer index
    if isinstance(head, int):
        if isinstance(data, (list, tuple)) and 0 <= head < len(data):
            return _resolve_parts(data[head], tail)
        return _MISSING

    # Dict key
    if isinstance(data, dict):
        if head in data:
            return _resolve_parts(data[head], tail)
        return _MISSING

    return _MISSING


# ---------------------------------------------------------------------------
# Core evaluator
# ---------------------------------------------------------------------------

class RuleEvaluator:
    """
    Stateless rule evaluation engine.

    Evaluate a single rule (dict from {engine}_rules row) against a single
    asset (dict from {engine}_input_transformed row).

    The rule dict must contain at minimum:
        condition_type : str   — 'field_check', 'threshold', 'set_membership', 'composite'
        condition      : dict  — JSONB condition body
        severity       : str   — 'critical', 'high', 'medium', 'low', 'info'

    For set_membership rules, the caller (rule_loader) must pre-load the set
    and inject it as rule["_set_values"]: Set[str].
    """

    def evaluate(self, asset: Dict[str, Any], rule: Dict[str, Any]) -> RuleResult:
        """
        Evaluate a rule against an asset.

        Args:
            asset: Flattened resource dict from {engine}_input_transformed.
            rule:  Rule dict from {engine}_rules (must contain condition_type,
                   condition, severity).

        Returns:
            RuleResult with result, evidence, and severity.
        """
        severity = rule.get("severity", "info")

        try:
            ctype = rule.get("condition_type", "")
            condition = rule.get("condition", {})

            if ctype == "field_check":
                return self._eval_field_check(asset, condition, severity)

            elif ctype == "threshold":
                return self._eval_threshold(asset, condition, severity)

            elif ctype == "set_membership":
                return self._eval_set_membership(asset, rule, condition, severity)

            elif ctype == "composite":
                return self._eval_composite(asset, rule, condition, severity)

            else:
                return RuleResult(
                    result="ERROR",
                    evidence={"reason": f"unknown condition_type '{ctype}'"},
                    severity=severity,
                )

        except KeyError as exc:
            logger.debug("Missing field for rule %s: %s", rule.get("rule_id"), exc)
            return RuleResult(
                result="SKIP",
                evidence={"reason": f"missing field: {exc}"},
                severity=severity,
            )
        except Exception as exc:
            logger.warning("Rule evaluation error for %s: %s",
                           rule.get("rule_id"), exc, exc_info=True)
            return RuleResult(
                result="ERROR",
                evidence={"reason": str(exc)},
                severity=severity,
            )

    # ------------------------------------------------------------------
    # Condition type handlers
    # ------------------------------------------------------------------

    def _eval_field_check(
        self,
        asset: Dict[str, Any],
        condition: Dict[str, Any],
        severity: str,
    ) -> RuleResult:
        """
        Type 1 — field_check.

        Condition shape:
            {"field": "encryption_enabled", "operator": "eq", "value": false}
        """
        field_path = condition["field"]
        operator = condition["operator"]
        expected = condition.get("value")

        actual = _get_nested(asset, field_path)

        # For exists/not_exists operators, pass the raw actual (may be _MISSING)
        if operator in ("exists", "not_exists"):
            passed = _compare(actual, operator, expected)
        else:
            # If field is missing and operator isn't about existence → SKIP
            if actual is _MISSING:
                return RuleResult(
                    result="SKIP",
                    evidence={
                        "field": field_path,
                        "reason": "field not found in asset",
                    },
                    severity=severity,
                )
            passed = _compare(actual, operator, expected)

        evidence = {
            "field": field_path,
            "operator": operator,
            "actual": actual if actual is not _MISSING else None,
            "expected": expected,
        }

        return RuleResult(
            result="PASS" if passed else "FAIL",
            evidence=evidence,
            severity=severity,
        )

    def _eval_threshold(
        self,
        asset: Dict[str, Any],
        condition: Dict[str, Any],
        severity: str,
    ) -> RuleResult:
        """
        Type 2 — threshold (anomaly detection).

        Condition shape:
            {
                "metric": "outbound_bytes",
                "operator": "gt",
                "baseline_field": "baseline_bytes",
                "multiplier": 3.0
            }

        FAIL when metric exceeds baseline × multiplier.
        """
        metric_field = condition["metric"]
        baseline_field = condition["baseline_field"]
        multiplier = float(condition.get("multiplier", 1.0))
        operator = condition.get("operator", "gt")

        metric_val = asset.get(metric_field, 0)
        baseline_val = asset.get(baseline_field, 0)

        if metric_val is None:
            metric_val = 0
        if baseline_val is None:
            baseline_val = 0

        threshold = float(baseline_val) * multiplier

        # "passed" means the metric does NOT breach the threshold
        breached = _compare(float(metric_val), operator, threshold)

        evidence = {
            "metric": metric_field,
            "actual": metric_val,
            "baseline": baseline_val,
            "multiplier": multiplier,
            "threshold": threshold,
            "operator": operator,
        }

        return RuleResult(
            result="FAIL" if breached else "PASS",
            evidence=evidence,
            severity=severity,
        )

    def _eval_set_membership(
        self,
        asset: Dict[str, Any],
        rule: Dict[str, Any],
        condition: Dict[str, Any],
        severity: str,
    ) -> RuleResult:
        """
        Type 3 — set_membership (CVE/package/IP blacklists).

        Condition shape:
            {
                "field": "cve_id",
                "operator": "in_set",
                "set_table": "cve_kev_list",
                "set_column": "cve_id"
            }

        Caller (rule_loader) must pre-load the set and inject as rule["_set_values"].
        FAIL when the asset's field value IS in the set (i.e., it's on the blacklist).
        """
        field_path = condition["field"]
        actual = _get_nested(asset, field_path)

        if actual is _MISSING:
            return RuleResult(
                result="SKIP",
                evidence={
                    "field": field_path,
                    "reason": "field not found in asset",
                },
                severity=severity,
            )

        set_values: Set[str] = rule.get("_set_values", set())
        in_set = actual in set_values

        evidence = {
            "field": field_path,
            "actual": actual,
            "in_set": in_set,
            "set_table": condition.get("set_table"),
            "set_size": len(set_values),
        }

        # Being in the blacklist = FAIL
        return RuleResult(
            result="FAIL" if in_set else "PASS",
            evidence=evidence,
            severity=severity,
        )

    def _eval_composite(
        self,
        asset: Dict[str, Any],
        rule: Dict[str, Any],
        condition: Dict[str, Any],
        severity: str,
    ) -> RuleResult:
        """
        Type 4 — composite (AND / OR of sub-conditions).

        Condition shape:
            {
                "operator": "and",   # or "or"
                "conditions": [
                    {"condition_type": "field_check", "condition": {...}},
                    {"condition_type": "threshold",   "condition": {...}}
                ]
            }

        For AND: FAIL if any sub-condition FAILs.
        For OR:  FAIL only if ALL sub-conditions FAIL.
        """
        logic_op = condition.get("operator", "and").lower()
        sub_conditions = condition.get("conditions", [])

        if not sub_conditions:
            return RuleResult(
                result="SKIP",
                evidence={"reason": "composite rule has no sub-conditions"},
                severity=severity,
            )

        sub_results: List[Dict[str, Any]] = []
        for i, sub in enumerate(sub_conditions):
            sub_rule = {
                "rule_id": f"{rule.get('rule_id', 'unknown')}_sub_{i}",
                "condition_type": sub.get("condition_type", "field_check"),
                "condition": sub.get("condition", sub),
                "severity": severity,
                "_set_values": rule.get("_set_values", set()),
            }
            sub_result = self.evaluate(asset, sub_rule)
            sub_results.append(sub_result.to_dict())

        results_list = [sr["result"] for sr in sub_results]

        if logic_op == "and":
            # PASS only if ALL sub-conditions PASS
            if "ERROR" in results_list:
                final = "ERROR"
            elif "FAIL" in results_list:
                final = "FAIL"
            elif "SKIP" in results_list and "PASS" not in results_list:
                final = "SKIP"
            else:
                final = "PASS" if all(r in ("PASS", "SKIP") for r in results_list) else "FAIL"
        elif logic_op == "or":
            # PASS if ANY sub-condition PASSes
            if "PASS" in results_list:
                final = "PASS"
            elif "ERROR" in results_list:
                final = "ERROR"
            elif "SKIP" in results_list:
                final = "SKIP"
            else:
                final = "FAIL"
        else:
            return RuleResult(
                result="ERROR",
                evidence={"reason": f"unknown composite operator '{logic_op}'"},
                severity=severity,
            )

        return RuleResult(
            result=final,
            evidence={
                "composite_operator": logic_op,
                "sub_results": sub_results,
            },
            severity=severity,
        )
