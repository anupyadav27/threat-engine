"""
Unit tests for the Risk Evaluator (Stage 2).
"""

import pytest
from unittest.mock import MagicMock, patch
from engines.risk.evaluator.risk_evaluator import RiskEvaluator


# ======================================================================
# Fixtures
# ======================================================================

@pytest.fixture
def mock_risk_conn():
    conn = MagicMock()
    cursor = MagicMock()
    conn.cursor.return_value = cursor
    cursor.fetchone.return_value = None
    cursor.fetchall.return_value = []
    return conn


@pytest.fixture
def mock_discovery_conn():
    conn = MagicMock()
    return conn


@pytest.fixture
def evaluator(mock_risk_conn, mock_discovery_conn):
    return RiskEvaluator(mock_risk_conn, mock_discovery_conn)


# ======================================================================
# _load_model_config
# ======================================================================

class TestLoadModelConfig:
    def test_returns_defaults_when_no_data(self, evaluator):
        config = evaluator._load_model_config("tenant-1")
        assert config["per_record_cost"] == 4.45
        assert config["estimated_annual_revenue"] == 100_000_000
        assert config["default_record_count"] == 1000

    def test_loads_from_db(self, evaluator, mock_risk_conn):
        cursor = mock_risk_conn.cursor.return_value
        cursor.fetchone.return_value = (
            10.93,     # per_record_cost
            500000000, # estimated_annual_revenue
            ["HIPAA", "GDPR"],  # applicable_regs (as list)
            25000.0,   # downtime_cost_hr
            {"restricted": 3.0, "confidential": 2.0, "internal": 1.0, "public": 0.1},
            5000,      # default_record_count
            "healthcare",  # industry
        )
        config = evaluator._load_model_config("tenant-1")
        assert config["per_record_cost"] == 10.93
        assert config["industry"] == "healthcare"
        assert config["default_record_count"] == 5000

    def test_handles_json_string_fields(self, evaluator, mock_risk_conn):
        cursor = mock_risk_conn.cursor.return_value
        cursor.fetchone.return_value = (
            4.45, 100000000,
            '["GDPR"]',  # JSON string
            10000.0,
            '{"restricted": 3.0}',  # JSON string
            1000,
            "default",
        )
        config = evaluator._load_model_config("tenant-1")
        assert config["applicable_regs"] == ["GDPR"]
        assert config["sensitivity_multipliers"]["restricted"] == 3.0

    def test_handles_db_error(self, evaluator, mock_risk_conn):
        cursor = mock_risk_conn.cursor.return_value
        cursor.execute.side_effect = Exception("DB error")
        config = evaluator._load_model_config("tenant-1")
        # Should return defaults
        assert config["per_record_cost"] == 4.45


# ======================================================================
# _load_transformed_findings
# ======================================================================

class TestLoadTransformedFindings:
    def test_loads_findings(self, evaluator, mock_risk_conn):
        cursor = mock_risk_conn.cursor.return_value
        cursor.fetchall.return_value = [
            ("f-001", "datasec", "scan-1", "RULE-1", "critical", "Title",
             "data_breach", "arn:aws:s3:::b", "s3_bucket", "arn:aws:s3:::b",
             "critical", True, "restricted", ["PII"], 5000,
             "healthcare", 500000000, ["HIPAA"], 0.5, "CVE-2024-1",
             1.0, "123456", "us-east-1", "aws"),
        ]
        findings = evaluator._load_transformed_findings("scan-1")
        assert len(findings) == 1
        assert findings[0]["source_finding_id"] == "f-001"
        assert findings[0]["epss_score"] == 0.5
        assert findings[0]["is_public"] is True

    def test_empty_findings(self, evaluator, mock_risk_conn):
        cursor = mock_risk_conn.cursor.return_value
        cursor.fetchall.return_value = []
        findings = evaluator._load_transformed_findings("scan-1")
        assert findings == []

    def test_handles_null_fields(self, evaluator, mock_risk_conn):
        cursor = mock_risk_conn.cursor.return_value
        cursor.fetchall.return_value = [
            ("f-002", "check", None, "RULE-2", "high", "Title2",
             None, "arn:x", None, "arn:x",
             "medium", False, None, None, None,
             None, None, None, None, None,
             None, None, None, None),
        ]
        findings = evaluator._load_transformed_findings("scan-1")
        assert findings[0]["epss_score"] == 0.05
        assert findings[0]["data_types"] == []
        assert findings[0]["estimated_record_count"] == 0


# ======================================================================
# run
# ======================================================================

class TestEvaluatorRun:
    @patch("engines.risk.evaluator.risk_evaluator.RiskEvaluator._load_transformed_findings")
    @patch("engines.risk.evaluator.risk_evaluator.RiskEvaluator._load_model_config")
    def test_run_no_findings(self, mock_config, mock_findings, evaluator):
        mock_config.return_value = {"per_record_cost": 4.45, "default_record_count": 1000}
        mock_findings.return_value = []
        count = evaluator.run("scan-1", "orch-1", "tenant-1", "acct-1")
        assert count == 0

    @patch("engines.risk.db.risk_db_writer.RiskDBWriter.batch_insert_scenarios", return_value=3)
    @patch("engines.risk.models.fair_model.compute_scenario")
    @patch("engines.risk.evaluator.risk_evaluator.RiskEvaluator._load_transformed_findings")
    @patch("engines.risk.evaluator.risk_evaluator.RiskEvaluator._load_model_config")
    def test_run_processes_findings(self, mock_config, mock_findings,
                                     mock_compute, mock_insert, evaluator):
        mock_config.return_value = {"per_record_cost": 4.45}
        mock_findings.return_value = [
            {"source_finding_id": "f-1", "source_engine": "check"},
            {"source_finding_id": "f-2", "source_engine": "datasec"},
            {"source_finding_id": "f-3", "source_engine": "threat"},
        ]
        mock_compute.return_value = {
            "source_finding_id": "f-1",
            "total_exposure_likely": 100000,
            "risk_tier": "medium",
        }
        count = evaluator.run("scan-1", "orch-1", "tenant-1", "acct-1")
        assert count == 3
        assert mock_compute.call_count == 3
