"""
Unit tests for shared/common/finding_writer.py — Task 0.5.3
"""

import pytest
import uuid
from unittest.mock import MagicMock, AsyncMock, call
from shared.common.finding_writer import FindingWriter, Finding, result_to_finding


# ============================================================================
# Finding model tests
# ============================================================================

class TestFindingModel:
    def test_defaults(self):
        f = Finding()
        assert f.result == "SKIP"
        assert f.severity == "info"
        assert f.csp == "aws"
        assert f.is_active is True
        assert f.evidence == {}
        # finding_id should be auto-generated UUID
        uuid.UUID(f.finding_id)  # validates format

    def test_validate_all_required(self):
        f = Finding(
            scan_id="s1",
            tenant_id="t1",
            orchestration_id="o1",
            rule_id="r1",
            result="PASS",
        )
        assert f.validate() == []

    def test_validate_missing_fields(self):
        f = Finding()  # All required fields empty
        missing = f.validate()
        assert "scan_id" in missing
        assert "tenant_id" in missing
        assert "orchestration_id" in missing
        assert "rule_id" in missing
        # result defaults to "SKIP" which is truthy, so not missing

    def test_to_tuple_length(self):
        f = Finding(
            scan_id="s1",
            tenant_id="t1",
            orchestration_id="o1",
            rule_id="r1",
            result="FAIL",
        )
        t = f.to_tuple()
        assert len(t) == 18  # 18 columns

    def test_to_tuple_evidence_serialized(self):
        f = Finding(
            scan_id="s1",
            tenant_id="t1",
            orchestration_id="o1",
            rule_id="r1",
            result="FAIL",
            evidence={"field": "x", "actual": 42},
        )
        t = f.to_tuple()
        # evidence should be JSON string
        assert '"field": "x"' in t[12]


# ============================================================================
# FindingWriter validation
# ============================================================================

class TestFindingWriterValidation:
    def test_validate_raises_on_missing(self):
        writer = FindingWriter()
        findings = [Finding()]  # Missing required fields

        with pytest.raises(ValueError, match="Validation failed"):
            writer._validate_all(findings)

    def test_validate_passes_valid(self):
        writer = FindingWriter()
        findings = [
            Finding(scan_id="s1", tenant_id="t1", orchestration_id="o1",
                    rule_id="r1", result="PASS"),
        ]
        writer._validate_all(findings)  # Should not raise

    def test_validate_multiple_errors(self):
        writer = FindingWriter()
        findings = [Finding(), Finding(), Finding()]

        with pytest.raises(ValueError, match="3 findings"):
            writer._validate_all(findings)


# ============================================================================
# Sync write_findings
# ============================================================================

class TestFindingWriterSync:
    def _make_findings(self, count: int) -> list:
        return [
            Finding(
                scan_id=f"scan-{i}",
                tenant_id="tenant-1",
                orchestration_id="orch-1",
                rule_id=f"rule-{i}",
                result="FAIL" if i % 2 == 0 else "PASS",
                severity="high",
                resource_id=f"resource-{i}",
            )
            for i in range(count)
        ]

    def test_write_empty_list(self):
        writer = FindingWriter()
        conn = MagicMock()
        count = writer.write_findings_sync(conn, "container", [])
        assert count == 0
        conn.cursor.assert_not_called()

    def test_write_single_finding(self):
        writer = FindingWriter()
        cursor = MagicMock()
        conn = MagicMock()
        conn.cursor.return_value = cursor

        findings = self._make_findings(1)
        count = writer.write_findings_sync(conn, "container", findings)

        assert count == 1
        cursor.executemany.assert_called_once()
        conn.commit.assert_called_once()

    def test_write_batching(self):
        writer = FindingWriter(batch_size=3)
        cursor = MagicMock()
        conn = MagicMock()
        conn.cursor.return_value = cursor

        findings = self._make_findings(7)
        count = writer.write_findings_sync(conn, "network", findings)

        assert count == 7
        # 7 findings / batch_size=3 → 3 batches (3+3+1)
        assert cursor.executemany.call_count == 3
        assert conn.commit.call_count == 3

    def test_write_rollback_on_error(self):
        writer = FindingWriter()
        cursor = MagicMock()
        cursor.executemany.side_effect = Exception("DB error")
        conn = MagicMock()
        conn.cursor.return_value = cursor

        findings = self._make_findings(2)

        with pytest.raises(Exception, match="DB error"):
            writer.write_findings_sync(conn, "api", findings)

        conn.rollback.assert_called_once()

    def test_table_name_uses_engine(self):
        writer = FindingWriter()
        cursor = MagicMock()
        conn = MagicMock()
        conn.cursor.return_value = cursor

        findings = self._make_findings(1)
        writer.write_findings_sync(conn, "supplychain", findings)

        # Check the SQL contains the correct table name and scan_id column
        sql = cursor.executemany.call_args[0][0]
        assert "supplychain_findings" in sql
        assert "supplychain_scan_id" in sql


# ============================================================================
# result_to_finding helper
# ============================================================================

class TestResultToFinding:
    def test_basic(self):
        rule_result = {"result": "FAIL", "evidence": {"field": "x", "actual": 42}, "severity": "high"}
        rule = {"rule_id": "r1", "title": "Test Rule", "remediation": "Fix it", "description": "Desc"}
        asset = {"resource_id": "i-123", "resource_type": "ec2_instance", "resource_arn": "arn:aws:ec2:us-east-1:123:instance/i-123"}

        f = result_to_finding(
            rule_result, rule, asset,
            scan_id="scan-1", tenant_id="t-1", orchestration_id="o-1",
            account_id="123456", region="us-east-1", csp="aws",
        )

        assert f.result == "FAIL"
        assert f.severity == "high"
        assert f.rule_id == "r1"
        assert f.resource_id == "i-123"
        assert f.resource_arn == "arn:aws:ec2:us-east-1:123:instance/i-123"
        assert f.evidence["actual"] == 42
        assert f.account_id == "123456"
        assert f.validate() == []  # Should be valid

    def test_missing_asset_fields(self):
        """Asset without resource_arn should still produce valid finding."""
        rule_result = {"result": "PASS", "evidence": {}, "severity": "low"}
        rule = {"rule_id": "r2", "title": "Check"}
        asset = {"resource_id": "pkg-1"}

        f = result_to_finding(
            rule_result, rule, asset,
            scan_id="s", tenant_id="t", orchestration_id="o",
        )

        assert f.resource_arn is None
        assert f.result == "PASS"
