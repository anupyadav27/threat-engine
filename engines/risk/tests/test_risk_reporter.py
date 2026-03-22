"""
Unit tests for the Risk Reporter (Stage 3).
"""

import pytest
from unittest.mock import MagicMock, patch
from engines.risk.reporter.risk_reporter import RiskReporter


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
def reporter(mock_risk_conn):
    return RiskReporter(mock_risk_conn)


@pytest.fixture
def sample_scenarios():
    return [
        {
            "scenario_id": "s-001",
            "source_finding_id": "f-001",
            "source_engine": "datasec",
            "asset_arn": "arn:aws:s3:::bucket-1",
            "scenario_type": "data_breach",
            "total_exposure_min": 10000,
            "total_exposure_max": 500000,
            "total_exposure_likely": 100000,
            "regulatory_fine_max": 50000,
            "risk_tier": "medium",
            "applicable_regulations": ["HIPAA", "GDPR"],
        },
        {
            "scenario_id": "s-002",
            "source_finding_id": "f-002",
            "source_engine": "threat",
            "asset_arn": "arn:aws:ec2::i-123",
            "scenario_type": "account_takeover",
            "total_exposure_min": 500000,
            "total_exposure_max": 25000000,
            "total_exposure_likely": 5000000,
            "regulatory_fine_max": 1000000,
            "risk_tier": "high",
            "applicable_regulations": ["GDPR"],
        },
        {
            "scenario_id": "s-003",
            "source_finding_id": "f-003",
            "source_engine": "datasec",
            "asset_arn": "arn:aws:rds::db-1",
            "scenario_type": "data_breach",
            "total_exposure_min": 1000000,
            "total_exposure_max": 50000000,
            "total_exposure_likely": 12000000,
            "regulatory_fine_max": 4000000,
            "risk_tier": "critical",
            "applicable_regulations": ["HIPAA"],
        },
    ]


# ======================================================================
# _count_by_tier
# ======================================================================

class TestCountByTier:
    def test_counts_tiers(self, reporter, sample_scenarios):
        counts = reporter._count_by_tier(sample_scenarios)
        assert counts["medium"] == 1
        assert counts["high"] == 1
        assert counts["critical"] == 1

    def test_empty_scenarios(self, reporter):
        assert reporter._count_by_tier([]) == {}

    def test_all_same_tier(self, reporter):
        scenarios = [{"risk_tier": "high"}] * 5
        counts = reporter._count_by_tier(scenarios)
        assert counts["high"] == 5


# ======================================================================
# _sum_exposure
# ======================================================================

class TestSumExposure:
    def test_sums_exposure(self, reporter, sample_scenarios):
        totals = reporter._sum_exposure(sample_scenarios)
        assert totals["likely"] == 17_100_000  # 100K + 5M + 12M
        assert totals["min"] == 1_510_000
        assert totals["max"] == 75_500_000

    def test_empty_scenarios(self, reporter):
        totals = reporter._sum_exposure([])
        assert totals["likely"] == 0


# ======================================================================
# _sum_regulatory_exposure
# ======================================================================

class TestSumRegulatoryExposure:
    def test_sums_regulatory(self, reporter, sample_scenarios):
        total = reporter._sum_regulatory_exposure(sample_scenarios)
        assert total == 5_050_000  # 50K + 1M + 4M


# ======================================================================
# _engine_breakdown
# ======================================================================

class TestEngineBreakdown:
    def test_groups_by_engine(self, reporter, sample_scenarios):
        breakdown = reporter._engine_breakdown(sample_scenarios)
        assert breakdown["datasec"] == 12_100_000  # 100K + 12M
        assert breakdown["threat"] == 5_000_000

    def test_empty(self, reporter):
        assert reporter._engine_breakdown([]) == {}


# ======================================================================
# _scenario_type_breakdown
# ======================================================================

class TestScenarioTypeBreakdown:
    def test_groups_by_type(self, reporter, sample_scenarios):
        breakdown = reporter._scenario_type_breakdown(sample_scenarios)
        assert breakdown["data_breach"] == 12_100_000
        assert breakdown["account_takeover"] == 5_000_000


# ======================================================================
# _top_scenarios
# ======================================================================

class TestTopScenarios:
    def test_returns_top_n(self, reporter, sample_scenarios):
        top = reporter._top_scenarios(sample_scenarios, 2)
        assert len(top) == 2
        assert top[0]["total_exposure_likely"] == 12_000_000
        assert top[1]["total_exposure_likely"] == 5_000_000

    def test_returns_all_when_fewer_than_limit(self, reporter, sample_scenarios):
        top = reporter._top_scenarios(sample_scenarios, 10)
        assert len(top) == 3


# ======================================================================
# _collect_frameworks
# ======================================================================

class TestCollectFrameworks:
    def test_unique_frameworks(self, reporter, sample_scenarios):
        frameworks = reporter._collect_frameworks(sample_scenarios)
        assert "GDPR" in frameworks
        assert "HIPAA" in frameworks
        assert len(frameworks) == 2

    def test_empty(self, reporter):
        assert reporter._collect_frameworks([]) == []


# ======================================================================
# _build_engine_summaries
# ======================================================================

class TestBuildEngineSummaries:
    def test_builds_summaries(self, reporter, sample_scenarios):
        summaries = reporter._build_engine_summaries(
            sample_scenarios, "scan-1", "orch-1", "tenant-1"
        )
        assert len(summaries) == 2  # datasec and threat

        datasec_summary = next(s for s in summaries if s["source_engine"] == "datasec")
        assert datasec_summary["scenario_count"] == 2
        assert datasec_summary["critical_count"] == 1
        assert datasec_summary["total_exposure_likely"] == 12_100_000

        threat_summary = next(s for s in summaries if s["source_engine"] == "threat")
        assert threat_summary["scenario_count"] == 1
        assert threat_summary["high_count"] == 1


# ======================================================================
# _load_previous_report (trending)
# ======================================================================

class TestLoadPreviousReport:
    def test_returns_none_when_no_previous(self, reporter):
        result = reporter._load_previous_report("tenant-1", "scan-1")
        assert result is None

    def test_returns_previous_report(self, reporter, mock_risk_conn):
        cursor = mock_risk_conn.cursor.return_value
        cursor.fetchone.return_value = (
            5_000_000, 500_000, 25_000_000, 100, 5, 20
        )
        result = reporter._load_previous_report("tenant-1", "scan-2")
        assert result["total_exposure_likely"] == 5_000_000
        assert result["critical_scenarios"] == 5


# ======================================================================
# run (integration-style)
# ======================================================================

class TestReporterRun:
    @patch("engines.risk.db.risk_db_writer.RiskDBWriter.insert_trend")
    @patch("engines.risk.db.risk_db_writer.RiskDBWriter.batch_insert_summaries", return_value=2)
    @patch("engines.risk.db.risk_db_writer.RiskDBWriter.insert_report")
    @patch("engines.risk.reporter.risk_reporter.RiskReporter._load_previous_report", return_value=None)
    @patch("engines.risk.reporter.risk_reporter.RiskReporter._load_scenarios")
    def test_run_returns_report(self, mock_scenarios, mock_prev,
                                 mock_insert_report, mock_insert_summaries,
                                 mock_insert_trend, reporter, sample_scenarios):
        mock_scenarios.return_value = sample_scenarios
        report = reporter.run("scan-1", "orch-1", "tenant-1", "acct-1")
        assert report["total_scenarios"] == 3
        assert report["critical_scenarios"] == 1
        assert report["high_scenarios"] == 1
        assert report["medium_scenarios"] == 1
        assert report["total_exposure_likely"] == 17_100_000
        assert report["status"] == "completed"
        assert mock_insert_report.called
        assert mock_insert_summaries.called
        assert mock_insert_trend.called

    @patch("engines.risk.db.risk_db_writer.RiskDBWriter.insert_trend")
    @patch("engines.risk.db.risk_db_writer.RiskDBWriter.batch_insert_summaries", return_value=0)
    @patch("engines.risk.db.risk_db_writer.RiskDBWriter.insert_report")
    @patch("engines.risk.reporter.risk_reporter.RiskReporter._load_previous_report")
    @patch("engines.risk.reporter.risk_reporter.RiskReporter._load_scenarios")
    def test_trending_comparison(self, mock_scenarios, mock_prev,
                                  mock_insert_report, mock_summaries,
                                  mock_trend, reporter, sample_scenarios):
        mock_scenarios.return_value = sample_scenarios
        mock_prev.return_value = {
            "total_exposure_likely": 10_000_000,
        }
        report = reporter.run("scan-1", "orch-1", "tenant-1", "acct-1")
        # Current: $17.1M, Previous: $10M → delta = $7.1M, +71%
        assert report["vs_previous_likely"] == 7_100_000
        assert report["vs_previous_pct"] == 71.0
