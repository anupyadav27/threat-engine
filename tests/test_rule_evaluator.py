"""
Unit tests for shared/common/rule_evaluator.py — Task 0.5.1

15+ tests covering all 4 condition types + edge cases.
"""

import pytest
from shared.common.rule_evaluator import RuleEvaluator, RuleResult, _get_nested, _compare, _MISSING


@pytest.fixture
def evaluator():
    return RuleEvaluator()


# ============================================================================
# _get_nested — field path resolution
# ============================================================================

class TestGetNested:
    def test_simple_key(self):
        assert _get_nested({"name": "bucket-1"}, "name") == "bucket-1"

    def test_dotted_path(self):
        data = {"config": {"logging": {"enabled": True}}}
        assert _get_nested(data, "config.logging.enabled") is True

    def test_wildcard(self):
        data = {"rules": [{"cidr": "10.0.0.0/8"}, {"cidr": "0.0.0.0/0"}]}
        assert _get_nested(data, "rules[*].cidr") == ["10.0.0.0/8", "0.0.0.0/0"]

    def test_index(self):
        data = {"tags": [{"key": "env"}, {"key": "team"}]}
        assert _get_nested(data, "tags[0].key") == "env"

    def test_missing_key(self):
        assert _get_nested({"a": 1}, "b") is _MISSING

    def test_missing_nested(self):
        assert _get_nested({"a": {"b": 1}}, "a.c.d") is _MISSING

    def test_empty_path(self):
        assert _get_nested({"a": 1}, "") is _MISSING

    def test_wildcard_on_non_list(self):
        assert _get_nested({"a": "string"}, "a[*].b") is _MISSING


# ============================================================================
# _compare — operator tests
# ============================================================================

class TestCompare:
    def test_eq(self):
        assert _compare(True, "eq", True) is True
        assert _compare("hello", "eq", "hello") is True
        assert _compare(42, "eq", 42) is True
        assert _compare(42, "eq", 43) is False

    def test_ne(self):
        assert _compare(True, "ne", False) is True

    def test_gt_lt(self):
        assert _compare(10, "gt", 5) is True
        assert _compare(5, "lt", 10) is True
        assert _compare(5, "gte", 5) is True
        assert _compare(5, "lte", 5) is True

    def test_contains_string(self):
        assert _compare("hello world", "contains", "world") is True

    def test_contains_list(self):
        assert _compare(["a", "b", "c"], "contains", "b") is True

    def test_in_list(self):
        assert _compare("b", "in", ["a", "b", "c"]) is True
        assert _compare("d", "not_in", ["a", "b", "c"]) is True

    def test_is_null(self):
        assert _compare(None, "is_null", None) is True
        assert _compare("val", "is_null", None) is False
        assert _compare("val", "is_not_null", None) is True

    def test_is_empty(self):
        assert _compare("", "is_empty", None) is True
        assert _compare([], "is_empty", None) is True
        assert _compare("x", "is_not_empty", None) is True

    def test_regex(self):
        assert _compare("CVE-2024-1234", "regex", r"CVE-\d{4}-\d+") is True
        assert _compare("not-a-cve", "not_regex", r"CVE-\d{4}-\d+") is True

    def test_exists(self):
        assert _compare("value", "exists", None) is True
        assert _compare(_MISSING, "exists", None) is False
        assert _compare(_MISSING, "not_exists", None) is True

    def test_contains_all(self):
        assert _compare(["a", "b", "c"], "contains_all", ["a", "c"]) is True
        assert _compare(["a", "b"], "contains_all", ["a", "c"]) is False

    def test_contains_any(self):
        assert _compare(["a", "b"], "contains_any", ["b", "c"]) is True
        assert _compare(["a", "b"], "contains_any", ["c", "d"]) is False

    def test_length_operators(self):
        assert _compare([1, 2, 3], "length_equals", 3) is True
        assert _compare([1, 2, 3], "length_greater_than", 2) is True
        assert _compare([1], "length_less_than", 2) is True

    def test_unknown_operator(self):
        assert _compare(1, "unknown_op", 1) is False

    def test_type_error_returns_false(self):
        assert _compare("not_a_number", "gt", 5) is False


# ============================================================================
# field_check condition type
# ============================================================================

class TestFieldCheck:
    def test_pass(self, evaluator):
        asset = {"encryption_enabled": True}
        rule = {
            "rule_id": "test-1",
            "condition_type": "field_check",
            "condition": {"field": "encryption_enabled", "operator": "eq", "value": True},
            "severity": "high",
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "PASS"
        assert result.severity == "high"
        assert result.evidence["actual"] is True

    def test_fail(self, evaluator):
        asset = {"encryption_enabled": False}
        rule = {
            "rule_id": "test-2",
            "condition_type": "field_check",
            "condition": {"field": "encryption_enabled", "operator": "eq", "value": True},
            "severity": "critical",
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "FAIL"

    def test_nested_field(self, evaluator):
        asset = {"config": {"public_access": True}}
        rule = {
            "rule_id": "test-3",
            "condition_type": "field_check",
            "condition": {"field": "config.public_access", "operator": "eq", "value": False},
            "severity": "high",
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "FAIL"

    def test_missing_field_skip(self, evaluator):
        asset = {"name": "bucket-1"}
        rule = {
            "rule_id": "test-4",
            "condition_type": "field_check",
            "condition": {"field": "encryption_enabled", "operator": "eq", "value": True},
            "severity": "medium",
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "SKIP"

    def test_exists_operator(self, evaluator):
        asset = {"tags": {"env": "prod"}}
        rule = {
            "rule_id": "test-5",
            "condition_type": "field_check",
            "condition": {"field": "tags", "operator": "exists", "value": True},
            "severity": "low",
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "PASS"

    def test_wildcard_contains(self, evaluator):
        asset = {"inbound_rules": [{"cidr": "10.0.0.0/8"}, {"cidr": "0.0.0.0/0"}]}
        rule = {
            "rule_id": "test-6",
            "condition_type": "field_check",
            "condition": {"field": "inbound_rules[*].cidr", "operator": "contains", "value": "0.0.0.0/0"},
            "severity": "critical",
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "FAIL"


# ============================================================================
# threshold condition type
# ============================================================================

class TestThreshold:
    def test_pass_under_threshold(self, evaluator):
        asset = {"outbound_bytes": 100, "baseline_bytes": 50}
        rule = {
            "rule_id": "threshold-1",
            "condition_type": "threshold",
            "condition": {
                "metric": "outbound_bytes",
                "operator": "gt",
                "baseline_field": "baseline_bytes",
                "multiplier": 3.0,
            },
            "severity": "high",
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "PASS"
        assert result.evidence["threshold"] == 150.0

    def test_fail_over_threshold(self, evaluator):
        asset = {"outbound_bytes": 200, "baseline_bytes": 50}
        rule = {
            "rule_id": "threshold-2",
            "condition_type": "threshold",
            "condition": {
                "metric": "outbound_bytes",
                "operator": "gt",
                "baseline_field": "baseline_bytes",
                "multiplier": 3.0,
            },
            "severity": "critical",
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "FAIL"

    def test_null_metric_treated_as_zero(self, evaluator):
        asset = {"outbound_bytes": None, "baseline_bytes": 50}
        rule = {
            "rule_id": "threshold-3",
            "condition_type": "threshold",
            "condition": {
                "metric": "outbound_bytes",
                "operator": "gt",
                "baseline_field": "baseline_bytes",
                "multiplier": 3.0,
            },
            "severity": "medium",
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "PASS"


# ============================================================================
# set_membership condition type
# ============================================================================

class TestSetMembership:
    def test_fail_in_blacklist(self, evaluator):
        asset = {"cve_id": "CVE-2024-1234"}
        rule = {
            "rule_id": "set-1",
            "condition_type": "set_membership",
            "condition": {"field": "cve_id", "operator": "in_set", "set_table": "cve_kev_list", "set_column": "cve_id"},
            "severity": "critical",
            "_set_values": {"CVE-2024-1234", "CVE-2024-5678"},
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "FAIL"
        assert result.evidence["in_set"] is True

    def test_pass_not_in_blacklist(self, evaluator):
        asset = {"cve_id": "CVE-2024-9999"}
        rule = {
            "rule_id": "set-2",
            "condition_type": "set_membership",
            "condition": {"field": "cve_id", "operator": "in_set"},
            "severity": "high",
            "_set_values": {"CVE-2024-1234"},
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "PASS"

    def test_missing_field_skip(self, evaluator):
        asset = {"name": "pkg-1"}
        rule = {
            "rule_id": "set-3",
            "condition_type": "set_membership",
            "condition": {"field": "cve_id", "operator": "in_set"},
            "severity": "medium",
            "_set_values": set(),
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "SKIP"


# ============================================================================
# composite condition type
# ============================================================================

class TestComposite:
    def test_and_all_pass(self, evaluator):
        asset = {"encryption_enabled": True, "public_access": False}
        rule = {
            "rule_id": "composite-1",
            "condition_type": "composite",
            "condition": {
                "operator": "and",
                "conditions": [
                    {"condition_type": "field_check", "condition": {"field": "encryption_enabled", "operator": "eq", "value": True}},
                    {"condition_type": "field_check", "condition": {"field": "public_access", "operator": "eq", "value": False}},
                ],
            },
            "severity": "high",
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "PASS"

    def test_and_one_fails(self, evaluator):
        asset = {"encryption_enabled": True, "public_access": True}
        rule = {
            "rule_id": "composite-2",
            "condition_type": "composite",
            "condition": {
                "operator": "and",
                "conditions": [
                    {"condition_type": "field_check", "condition": {"field": "encryption_enabled", "operator": "eq", "value": True}},
                    {"condition_type": "field_check", "condition": {"field": "public_access", "operator": "eq", "value": False}},
                ],
            },
            "severity": "high",
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "FAIL"

    def test_or_one_passes(self, evaluator):
        asset = {"encryption_enabled": False, "public_access": False}
        rule = {
            "rule_id": "composite-3",
            "condition_type": "composite",
            "condition": {
                "operator": "or",
                "conditions": [
                    {"condition_type": "field_check", "condition": {"field": "encryption_enabled", "operator": "eq", "value": True}},
                    {"condition_type": "field_check", "condition": {"field": "public_access", "operator": "eq", "value": False}},
                ],
            },
            "severity": "medium",
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "PASS"

    def test_empty_conditions_skip(self, evaluator):
        rule = {
            "rule_id": "composite-4",
            "condition_type": "composite",
            "condition": {"operator": "and", "conditions": []},
            "severity": "low",
        }
        result = evaluator.evaluate({}, rule)
        assert result.result == "SKIP"


# ============================================================================
# Edge cases
# ============================================================================

class TestEdgeCases:
    def test_unknown_condition_type(self, evaluator):
        rule = {
            "rule_id": "edge-1",
            "condition_type": "unknown_type",
            "condition": {},
            "severity": "info",
        }
        result = evaluator.evaluate({}, rule)
        assert result.result == "ERROR"

    def test_rule_result_to_dict(self):
        r = RuleResult(result="FAIL", evidence={"field": "x"}, severity="high")
        d = r.to_dict()
        assert d["result"] == "FAIL"
        assert d["evidence"]["field"] == "x"
        assert d["severity"] == "high"

    def test_missing_severity_defaults_info(self, evaluator):
        asset = {"x": 1}
        rule = {
            "rule_id": "edge-2",
            "condition_type": "field_check",
            "condition": {"field": "x", "operator": "eq", "value": 1},
        }
        result = evaluator.evaluate(asset, rule)
        assert result.result == "PASS"
        assert result.severity == "info"
