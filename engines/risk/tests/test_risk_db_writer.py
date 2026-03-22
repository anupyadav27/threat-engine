"""
Unit tests for the Risk DB Writer.
"""

import json
import pytest
from unittest.mock import MagicMock, call
from engines.risk.db.risk_db_writer import RiskDBWriter, BATCH_SIZE


# ======================================================================
# Fixtures
# ======================================================================

@pytest.fixture
def mock_conn():
    conn = MagicMock()
    cursor = MagicMock()
    conn.cursor.return_value = cursor
    return conn


@pytest.fixture
def writer(mock_conn):
    return RiskDBWriter(mock_conn)


# ======================================================================
# _prepare_transformed_row
# ======================================================================

class TestPrepareTransformedRow:
    def test_extracts_all_fields(self, writer):
        row = {
            "risk_scan_id": "scan-1",
            "tenant_id": "t-1",
            "scan_run_id": "orch-1",
            "source_finding_id": "f-001",
            "source_engine": "datasec",
            "severity": "critical",
            "asset_arn": "arn:aws:s3:::b",
            "is_public": True,
            "data_sensitivity": "restricted",
        }
        prepared = writer._prepare_transformed_row(row)
        assert prepared["risk_scan_id"] == "scan-1"
        assert prepared["source_engine"] == "datasec"
        assert prepared["is_public"] is True

    def test_applies_defaults(self, writer):
        prepared = writer._prepare_transformed_row({})
        assert prepared["asset_criticality"] == "medium"
        assert prepared["is_public"] is False
        assert prepared["data_sensitivity"] == "internal"
        assert prepared["epss_score"] == 0.05
        assert prepared["exposure_factor"] == 1.0
        assert prepared["csp"] == "aws"

    def test_preserves_empty_lists(self, writer):
        prepared = writer._prepare_transformed_row({
            "data_types": [],
            "applicable_regulations": [],
        })
        assert prepared["data_types"] == []
        assert prepared["applicable_regulations"] == []


# ======================================================================
# batch_insert_transformed
# ======================================================================

class TestBatchInsertTransformed:
    def test_inserts_rows(self, writer, mock_conn):
        rows = [{"risk_scan_id": "s-1", "source_engine": "check"}] * 3
        count = writer.batch_insert_transformed(rows)
        assert count == 3

    def test_empty_rows(self, writer):
        count = writer.batch_insert_transformed([])
        assert count == 0

    def test_batches_large_inputs(self, writer, mock_conn):
        rows = [{"risk_scan_id": "s-1"}] * (BATCH_SIZE + 10)
        count = writer.batch_insert_transformed(rows)
        assert count == BATCH_SIZE + 10


# ======================================================================
# _prepare_scenario_row
# ======================================================================

class TestPrepareScenarioRow:
    def test_generates_uuid(self, writer):
        row = {"source_finding_id": "f-1", "total_exposure_likely": 100000}
        prepared = writer._prepare_scenario_row(row, "scan-1", "t-1", "orch-1")
        assert prepared["scenario_id"] is not None
        assert len(prepared["scenario_id"]) == 36  # UUID format

    def test_serializes_calculation_model(self, writer):
        row = {
            "calculation_model": {"epss_score": 0.5, "lef": 0.15},
        }
        prepared = writer._prepare_scenario_row(row, "scan-1", "t-1", "orch-1")
        parsed = json.loads(prepared["calculation_model"])
        assert parsed["epss_score"] == 0.5

    def test_handles_string_calculation_model(self, writer):
        row = {
            "calculation_model": '{"key": "value"}',
        }
        prepared = writer._prepare_scenario_row(row, "scan-1", "t-1", "orch-1")
        assert prepared["calculation_model"] == '{"key": "value"}'

    def test_defaults_for_missing_fields(self, writer):
        prepared = writer._prepare_scenario_row({}, "scan-1", "t-1", "orch-1")
        assert prepared["risk_tier"] == "low"
        assert prepared["data_sensitivity"] == "internal"
        assert prepared["csp"] == "aws"


# ======================================================================
# batch_insert_scenarios
# ======================================================================

class TestBatchInsertScenarios:
    def test_inserts_scenarios(self, writer, mock_conn):
        rows = [
            {"source_finding_id": "f-1", "total_exposure_likely": 100000},
            {"source_finding_id": "f-2", "total_exposure_likely": 500000},
        ]
        count = writer.batch_insert_scenarios(rows, "scan-1", "t-1", "orch-1")
        assert count == 2

    def test_empty_rows(self, writer):
        count = writer.batch_insert_scenarios([], "scan-1", "t-1", "orch-1")
        assert count == 0


# ======================================================================
# insert_report
# ======================================================================

class TestInsertReport:
    def test_inserts_report(self, writer, mock_conn):
        report = {
            "risk_scan_id": "scan-1",
            "scan_run_id": "orch-1",
            "tenant_id": "t-1",
            "total_scenarios": 10,
            "total_exposure_likely": 5000000,
            "engine_breakdown": {"datasec": 3000000, "threat": 2000000},
            "top_scenarios": [{"scenario_id": "s-1"}],
            "status": "completed",
        }
        writer.insert_report(report)
        cursor = mock_conn.cursor.return_value
        assert cursor.execute.called
        assert mock_conn.commit.called

    def test_handles_none_jsonb_fields(self, writer, mock_conn):
        report = {
            "risk_scan_id": "scan-1",
            "scan_run_id": "orch-1",
            "tenant_id": "t-1",
            "engine_breakdown": None,
            "top_scenarios": None,
        }
        writer.insert_report(report)
        assert mock_conn.commit.called

    def test_rollback_on_error(self, writer, mock_conn):
        cursor = mock_conn.cursor.return_value
        cursor.execute.side_effect = Exception("DB error")
        with pytest.raises(Exception):
            writer.insert_report({"risk_scan_id": "scan-1"})
        assert mock_conn.rollback.called


# ======================================================================
# batch_insert_summaries
# ======================================================================

class TestBatchInsertSummaries:
    def test_inserts_summaries(self, writer, mock_conn):
        summaries = [
            {
                "risk_scan_id": "scan-1",
                "tenant_id": "t-1",
                "scan_run_id": "orch-1",
                "source_engine": "datasec",
                "scenario_count": 5,
                "critical_count": 2,
                "high_count": 3,
                "total_exposure_likely": 5000000,
                "total_regulatory_exposure": 1000000,
                "top_finding_types": [{"type": "data_breach", "count": 5}],
            }
        ]
        count = writer.batch_insert_summaries(summaries)
        assert count == 1

    def test_empty_summaries(self, writer):
        count = writer.batch_insert_summaries([])
        assert count == 0


# ======================================================================
# insert_trend
# ======================================================================

class TestInsertTrend:
    def test_inserts_trend(self, writer, mock_conn):
        writer.insert_trend({
            "tenant_id": "t-1",
            "risk_scan_id": "scan-1",
            "total_exposure_likely": 5000000,
            "critical_scenarios": 2,
            "high_scenarios": 5,
            "top_risk_type": "data_breach",
            "top_risk_engine": "datasec",
        })
        assert mock_conn.commit.called

    def test_rollback_on_error(self, writer, mock_conn):
        cursor = mock_conn.cursor.return_value
        cursor.execute.side_effect = Exception("DB error")
        with pytest.raises(Exception):
            writer.insert_trend({"tenant_id": "t-1", "risk_scan_id": "scan-1"})
        assert mock_conn.rollback.called


# ======================================================================
# update_orchestration
# ======================================================================

class TestUpdateOrchestration:
    def test_updates_orchestration(self, writer, mock_conn):
        writer.update_orchestration("orch-1", "scan-1")
        cursor = mock_conn.cursor.return_value
        assert cursor.execute.called
        assert mock_conn.commit.called

    def test_uses_alternate_conn(self, writer, mock_conn):
        alt_conn = MagicMock()
        alt_cursor = MagicMock()
        alt_conn.cursor.return_value = alt_cursor
        writer.update_orchestration("orch-1", "scan-1", conn=alt_conn)
        assert alt_cursor.execute.called
        assert alt_conn.commit.called

    def test_rollback_on_error(self, writer, mock_conn):
        cursor = mock_conn.cursor.return_value
        cursor.execute.side_effect = Exception("DB error")
        with pytest.raises(Exception):
            writer.update_orchestration("orch-1", "scan-1")
        assert mock_conn.rollback.called


# ======================================================================
# _batch_execute
# ======================================================================

class TestBatchExecute:
    def test_executes_batch(self, writer, mock_conn):
        params = [{"key": "val1"}, {"key": "val2"}]
        count = writer._batch_execute("INSERT ...", params)
        assert count == 2
        assert mock_conn.commit.called

    def test_empty_params(self, writer):
        count = writer._batch_execute("INSERT ...", [])
        assert count == 0

    def test_rollback_on_error(self, writer, mock_conn):
        cursor = mock_conn.cursor.return_value
        cursor.execute.side_effect = Exception("Insert failed")
        with pytest.raises(Exception):
            writer._batch_execute("INSERT ...", [{"key": "val"}])
        assert mock_conn.rollback.called
