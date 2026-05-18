"""DB writer tests — conflict deduplication, evidence JSONB handling."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../engines/api-security"))

from unittest.mock import MagicMock, patch

import psycopg2.extras
import pytest


def _finding(**kwargs):
    base = {
        "rule_id": "aws.apigateway.stage.no_waf",
        "resource_uid": "arn:aws:apigateway:us-east-1::/restapis/abc/stages/prod",
        "resource_type": "aws.apigateway.stage",
        "severity": "high",
        "title": "No WAF",
        "description": "Missing WAF",
        "remediation": "Add WAF",
        "owasp_api_category": "API8",
        "finding_source": "config",
        "has_waf": False,
        "has_rate_limit": False,
        "is_publicly_accessible": True,
        "auth_type": "none",
        "api_gateway_id": "abc",
        "evidence": {"test": "data"},
    }
    base.update(kwargs)
    return base


def test_write_calls_commit():
    from api_security_engine.storage.db_writer import APISecWriter
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur

    with patch("api_security_engine.storage.db_writer.psycopg2.extras.execute_batch"):
        writer = APISecWriter(mock_conn)
        result = writer.write([_finding()], "scan-1", "tenant-1")

    assert result == 1
    mock_conn.commit.assert_called_once()


def test_write_empty_findings_skips_db():
    from api_security_engine.storage.db_writer import APISecWriter
    mock_conn = MagicMock()
    writer = APISecWriter(mock_conn)
    result = writer.write([], "scan-1", "tenant-1")
    assert result == 0
    mock_conn.cursor.assert_not_called()


def test_normalize_wraps_evidence_in_json():
    from api_security_engine.storage.db_writer import APISecWriter
    row = APISecWriter._normalize(_finding(evidence={"key": "val"}), "scan-1", "tenant-1")
    assert isinstance(row["evidence"], psycopg2.extras.Json)


def test_normalize_handles_string_evidence():
    from api_security_engine.storage.db_writer import APISecWriter
    row = APISecWriter._normalize(_finding(evidence='{"raw":"string"}'), "scan-1", "tenant-1")
    assert isinstance(row["evidence"], psycopg2.extras.Json)


def test_normalize_handles_none_evidence():
    from api_security_engine.storage.db_writer import APISecWriter
    row = APISecWriter._normalize(_finding(evidence=None), "scan-1", "tenant-1")
    assert isinstance(row["evidence"], psycopg2.extras.Json)


def test_normalize_tenant_id_comes_from_param_not_finding():
    from api_security_engine.storage.db_writer import APISecWriter
    f = _finding()
    f["tenant_id"] = "wrong-tenant"  # if it existed in the finding, should be ignored
    row = APISecWriter._normalize(f, "scan-1", "correct-tenant")
    assert row["tenant_id"] == "correct-tenant"


def test_normalize_severity_defaults_to_low():
    from api_security_engine.storage.db_writer import APISecWriter
    f = _finding()
    del f["severity"]
    row = APISecWriter._normalize(f, "scan-1", "t1")
    assert row["severity"] == "low"
