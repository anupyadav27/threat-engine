"""
Unit tests for shared/common/rule_loader.py — Task 0.5.2
"""

import pytest
import time
from unittest.mock import MagicMock, AsyncMock, patch
from shared.common.rule_loader import RuleLoader, Rule, _is_safe_identifier


# ============================================================================
# Rule model tests
# ============================================================================

class TestRuleModel:
    def test_defaults(self):
        r = Rule(rule_id="test-1", title="Test Rule")
        assert r.severity == "medium"
        assert r.condition_type == "field_check"
        assert r.csp == ["all"]
        assert r.is_active is True
        assert r._set_values == set()

    def test_to_eval_dict(self):
        r = Rule(
            rule_id="test-2",
            title="Encryption Check",
            severity="high",
            condition_type="field_check",
            condition={"field": "encryption", "operator": "eq", "value": True},
        )
        d = r.to_eval_dict()
        assert d["rule_id"] == "test-2"
        assert d["severity"] == "high"
        assert d["condition_type"] == "field_check"
        assert d["condition"]["field"] == "encryption"
        assert d["_set_values"] == set()

    def test_to_eval_dict_with_set(self):
        r = Rule(rule_id="test-3", title="KEV Check")
        r._set_values = {"CVE-2024-1234"}
        d = r.to_eval_dict()
        assert "CVE-2024-1234" in d["_set_values"]


# ============================================================================
# Safe identifier check
# ============================================================================

class TestSafeIdentifier:
    def test_valid(self):
        assert _is_safe_identifier("container_rules") is True
        assert _is_safe_identifier("cve_kev_list") is True
        assert _is_safe_identifier("a") is True

    def test_invalid(self):
        assert _is_safe_identifier("") is False
        assert _is_safe_identifier("DROP TABLE") is False
        assert _is_safe_identifier("table; --") is False
        assert _is_safe_identifier("CamelCase") is False
        assert _is_safe_identifier("123start") is False


# ============================================================================
# Sync rule loading
# ============================================================================

class TestRuleLoaderSync:
    def _make_mock_conn(self, rows, columns):
        """Create a mock psycopg2 connection."""
        cursor = MagicMock()
        cursor.description = [(col,) for col in columns]
        cursor.fetchall.return_value = rows
        conn = MagicMock()
        conn.cursor.return_value = cursor
        return conn

    def test_load_rules_basic(self):
        columns = [
            "rule_id", "title", "description", "category", "severity",
            "condition_type", "condition", "evidence_fields", "frameworks",
            "remediation", "references", "csp", "is_active",
        ]
        rows = [
            (
                "container-001", "Image CVE Check", "Check for known CVEs", "vulnerability",
                "critical", "set_membership",
                {"field": "cve_id", "operator": "in_set", "set_table": "vuln_cache", "set_column": "cve_id"},
                ["cve_id", "severity"], ["CIS"], "Update image",
                ["https://cve.org"], ["all"], True,
            ),
        ]
        conn = self._make_mock_conn(rows, columns)

        loader = RuleLoader(cache_ttl=0)  # No cache for test
        rules = loader.load_rules_sync(conn, "container", filter_csp="aws")

        assert len(rules) == 1
        assert rules[0].rule_id == "container-001"
        assert rules[0].condition_type == "set_membership"
        assert rules[0].severity == "critical"

    def test_load_rules_empty_table(self):
        conn = self._make_mock_conn([], [])
        # Simulate table not found
        cursor = MagicMock()
        cursor.execute.side_effect = Exception("relation container_rules does not exist")
        conn.cursor.return_value = cursor

        loader = RuleLoader(cache_ttl=0)
        rules = loader.load_rules_sync(conn, "container")
        assert rules == []

    def test_cache_hit(self):
        columns = [
            "rule_id", "title", "description", "category", "severity",
            "condition_type", "condition", "evidence_fields", "frameworks",
            "remediation", "references", "csp", "is_active",
        ]
        rows = [(
            "r1", "Rule 1", "", "", "high", "field_check",
            {"field": "x", "operator": "eq", "value": True},
            [], [], "", [], ["all"], True,
        )]
        conn = self._make_mock_conn(rows, columns)

        loader = RuleLoader(cache_ttl=60)

        # First call — DB hit
        rules1 = loader.load_rules_sync(conn, "network", filter_csp="all")
        assert len(rules1) == 1

        # Second call — cache hit (cursor shouldn't be called again)
        conn.cursor.reset_mock()
        rules2 = loader.load_rules_sync(conn, "network", filter_csp="all")
        assert len(rules2) == 1
        conn.cursor.assert_not_called()

    def test_cache_miss_after_ttl(self):
        columns = [
            "rule_id", "title", "description", "category", "severity",
            "condition_type", "condition", "evidence_fields", "frameworks",
            "remediation", "references", "csp", "is_active",
        ]
        rows = [(
            "r1", "Rule 1", "", "", "high", "field_check",
            {"field": "x", "operator": "eq", "value": True},
            [], [], "", [], ["all"], True,
        )]
        conn = self._make_mock_conn(rows, columns)

        loader = RuleLoader(cache_ttl=1)  # 1 second TTL

        rules1 = loader.load_rules_sync(conn, "api", filter_csp="all")
        assert len(rules1) == 1

        # Wait for cache to expire
        time.sleep(1.1)

        rules2 = loader.load_rules_sync(conn, "api", filter_csp="all")
        assert len(rules2) == 1
        # cursor should have been called twice (once per load)
        assert conn.cursor.call_count == 2

    def test_clear_cache(self):
        loader = RuleLoader(cache_ttl=60)
        # Manually populate cache
        loader._cache["test:all"] = MagicMock(rules=[], loaded_at=time.time())
        assert len(loader._cache) == 1

        loader.clear_cache()
        assert len(loader._cache) == 0

    def test_json_string_condition(self):
        """Condition stored as JSON string (not dict) should be parsed."""
        import json
        columns = [
            "rule_id", "title", "description", "category", "severity",
            "condition_type", "condition", "evidence_fields", "frameworks",
            "remediation", "references", "csp", "is_active",
        ]
        condition = json.dumps({"field": "x", "operator": "eq", "value": 1})
        rows = [(
            "r1", "Rule 1", "", "", "medium", "field_check",
            condition, [], [], "", [], ["all"], True,
        )]
        conn = self._make_mock_conn(rows, columns)

        loader = RuleLoader(cache_ttl=0)
        rules = loader.load_rules_sync(conn, "risk")
        assert isinstance(rules[0].condition, dict)
        assert rules[0].condition["field"] == "x"


# ============================================================================
# Async rule loading (mocked)
# ============================================================================

class TestRuleLoaderAsync:
    @pytest.mark.asyncio
    async def test_load_rules_async(self):
        columns = [
            "rule_id", "title", "description", "category", "severity",
            "condition_type", "condition", "evidence_fields", "frameworks",
            "remediation", "references", "csp", "is_active",
        ]
        mock_row = {col: val for col, val in zip(columns, [
            "async-001", "Async Rule", "Desc", "cat", "high", "field_check",
            {"field": "x", "operator": "eq", "value": True},
            [], [], "", [], ["all"], True,
        ])}

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[mock_row])

        mock_pool = AsyncMock()
        mock_pool.acquire.return_value.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_pool.acquire.return_value.__aexit__ = AsyncMock(return_value=False)

        loader = RuleLoader(cache_ttl=0)
        rules = await loader.load_rules(mock_pool, "container", filter_csp="aws")

        assert len(rules) == 1
        assert rules[0].rule_id == "async-001"
