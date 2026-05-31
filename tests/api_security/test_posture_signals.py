"""Unit tests for posture signal aggregation."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../engines/api-security"))

from unittest.mock import MagicMock

import pytest


def _finding(severity="high", resource_uid="arn:aws:res1", **kwargs):
    base = {
        "resource_uid": resource_uid,
        "severity": severity,
        "has_waf": False,
        "has_rate_limit": False,
        "is_publicly_accessible": True,
        "is_deprecated_version": False,
        "auth_type": "none",
        "owasp_api_category": "API8",
        "rule_id": "aws.apigateway.stage.no_waf",
        "api_name": "my-api",
    }
    base.update(kwargs)
    return base


def test_score_two_high_findings():
    from api_security_engine.storage.posture_signals import _build_row
    findings = [_finding("high"), _finding("high")]
    row = _build_row("arn:aws:res1", findings, "scan-1", "t1")
    assert row["api_security_score"] == 50  # 100 - 25 - 25


def test_score_floors_at_zero():
    from api_security_engine.storage.posture_signals import _build_row
    findings = [_finding("critical")] * 5  # 5 × 40 = 200 penalty
    row = _build_row("arn:aws:res1", findings, "scan-1", "t1")
    assert row["api_security_score"] == 0


def test_public_flag_aggregated():
    from api_security_engine.storage.posture_signals import _build_row
    findings = [_finding("low", is_publicly_accessible=True)]
    row = _build_row("arn:aws:res1", findings, "scan-1", "t1")
    assert row["api_publicly_accessible"] is True


def test_empty_findings_skips_db():
    from api_security_engine.storage.posture_signals import write_api_posture_signals
    mock_conn = MagicMock()
    write_api_posture_signals(mock_conn, [], "scan-1", "t1")
    mock_conn.cursor.assert_not_called()


def test_write_calls_commit():
    from unittest.mock import patch
    from api_security_engine.storage.posture_signals import write_api_posture_signals
    mock_conn = MagicMock()
    mock_cur = MagicMock()
    mock_conn.cursor.return_value.__enter__.return_value = mock_cur

    with patch("api_security_engine.storage.posture_signals.psycopg2.extras.execute_batch"):
        write_api_posture_signals(mock_conn, [_finding()], "scan-1", "t1")
    mock_conn.commit.assert_called_once()
