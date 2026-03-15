"""
Unit tests for the Risk ETL (Stage 1).
"""

import pytest
from unittest.mock import MagicMock, patch, call
from engines.risk.etl.risk_etl import RiskETL, ENGINE_FINDING_TABLES


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
    cursor = MagicMock()
    conn.cursor.return_value = cursor
    cursor.fetchall.return_value = []
    return conn


@pytest.fixture
def mock_onboarding_conn():
    conn = MagicMock()
    cursor = MagicMock()
    conn.cursor.return_value = cursor
    cursor.fetchone.return_value = None
    return conn


@pytest.fixture
def mock_external_conn():
    conn = MagicMock()
    cursor = MagicMock()
    conn.cursor.return_value = cursor
    cursor.fetchall.return_value = []
    return conn


@pytest.fixture
def etl(mock_risk_conn, mock_discovery_conn, mock_onboarding_conn, mock_external_conn):
    return RiskETL(mock_risk_conn, mock_discovery_conn, mock_onboarding_conn, mock_external_conn)


# ======================================================================
# ENGINE_FINDING_TABLES
# ======================================================================

class TestEngineFindingTables:
    def test_eight_engine_tables(self):
        assert len(ENGINE_FINDING_TABLES) == 8

    def test_all_engines_present(self):
        engines = [t[2] for t in ENGINE_FINDING_TABLES]
        expected = ["threat", "iam", "datasec", "container", "network",
                    "supplychain", "api", "check"]
        assert sorted(engines) == sorted(expected)

    def test_table_tuple_format(self):
        for table_name, scan_id_col, engine_name in ENGINE_FINDING_TABLES:
            assert table_name.endswith("_findings")
            assert scan_id_col.endswith("_scan_id")
            assert len(engine_name) > 0


# ======================================================================
# _collect_findings
# ======================================================================

class TestCollectFindings:
    def test_returns_findings_from_tables(self, etl, mock_discovery_conn):
        cursor = mock_discovery_conn.cursor.return_value
        # Return one finding per engine call
        cursor.fetchall.return_value = [
            ("f-001", "threat", "scan-1", "RULE-1", "critical",
             "Test finding", "arn:aws:ec2::i-123", "123456", "us-east-1", "aws")
        ]
        findings = etl._collect_findings("orch-1")
        # 8 tables, each returning 1 finding
        assert len(findings) == 8
        assert findings[0]["source_finding_id"] == "f-001"
        assert findings[0]["severity"] == "critical"

    def test_empty_tables(self, etl, mock_discovery_conn):
        cursor = mock_discovery_conn.cursor.return_value
        cursor.fetchall.return_value = []
        findings = etl._collect_findings("orch-1")
        assert len(findings) == 0

    def test_handles_query_failure_gracefully(self, etl, mock_discovery_conn):
        cursor = mock_discovery_conn.cursor.return_value
        cursor.execute.side_effect = Exception("Table not found")
        findings = etl._collect_findings("orch-1")
        assert len(findings) == 0  # All failed gracefully


# ======================================================================
# _load_tenant_config
# ======================================================================

class TestLoadTenantConfig:
    def test_returns_defaults_when_no_data(self, etl, mock_onboarding_conn, mock_risk_conn):
        config = etl._load_tenant_config("tenant-1")
        assert config["industry"] == "default"
        assert config["estimated_revenue"] == 100_000_000

    def test_loads_from_cloud_accounts(self, etl, mock_onboarding_conn, mock_risk_conn):
        ob_cursor = mock_onboarding_conn.cursor.return_value
        ob_cursor.fetchone.return_value = ("healthcare", "large", ["HIPAA", "GDPR"])
        config = etl._load_tenant_config("tenant-1")
        assert config["industry"] == "healthcare"
        assert config["applicable_regulations"] == ["HIPAA", "GDPR"]

    def test_loads_risk_model_config(self, etl, mock_onboarding_conn, mock_risk_conn):
        ob_cursor = mock_onboarding_conn.cursor.return_value
        ob_cursor.fetchone.return_value = None

        risk_cursor = mock_risk_conn.cursor.return_value
        risk_cursor.fetchone.return_value = (
            10.93,     # per_record_cost
            500000000, # estimated_annual_revenue
            '["HIPAA"]',  # applicable_regs
            25000.0,   # downtime_cost_hr
            '{"restricted": 3.0}',  # sensitivity_multipliers
            5000,      # default_record_count
        )
        config = etl._load_tenant_config("tenant-1")
        assert config["per_record_cost"] == 10.93
        assert config["default_record_count"] == 5000


# ======================================================================
# _load_epss_cache
# ======================================================================

class TestLoadEpssCache:
    def test_loads_epss_scores(self, etl, mock_external_conn):
        cursor = mock_external_conn.cursor.return_value
        cursor.fetchall.return_value = [
            ("CVE-2024-1234", 0.85),
            ("CVE-2024-5678", 0.12),
        ]
        cache = etl._load_epss_cache()
        assert cache["CVE-2024-1234"] == 0.85
        assert cache["CVE-2024-5678"] == 0.12

    def test_returns_empty_without_external_conn(self, mock_risk_conn, mock_discovery_conn, mock_onboarding_conn):
        etl = RiskETL(mock_risk_conn, mock_discovery_conn, mock_onboarding_conn, None)
        cache = etl._load_epss_cache()
        assert cache == {}


# ======================================================================
# _load_asset_metadata
# ======================================================================

class TestLoadAssetMetadata:
    def test_loads_assets(self, etl, mock_discovery_conn):
        cursor = mock_discovery_conn.cursor.return_value
        cursor.fetchall.return_value = [
            ("arn:aws:s3:::bucket-1", "s3_bucket", True, "critical"),
            ("arn:aws:ec2::i-123", "ec2_instance", False, "medium"),
        ]
        assets = etl._load_asset_metadata("orch-1")
        assert len(assets) == 2
        assert assets["arn:aws:s3:::bucket-1"]["is_public"] is True
        assert assets["arn:aws:ec2::i-123"]["asset_criticality"] == "medium"


# ======================================================================
# _load_datasec_metadata
# ======================================================================

class TestLoadDatasecMetadata:
    def test_loads_datasec(self, etl, mock_discovery_conn):
        cursor = mock_discovery_conn.cursor.return_value
        cursor.fetchall.return_value = [
            ("arn:aws:s3:::bucket-1", "restricted", ["PII", "PHI"], 50000),
        ]
        datasec = etl._load_datasec_metadata("orch-1")
        assert datasec["arn:aws:s3:::bucket-1"]["data_sensitivity"] == "restricted"
        assert datasec["arn:aws:s3:::bucket-1"]["estimated_record_count"] == 50000


# ======================================================================
# _enrich_finding
# ======================================================================

class TestEnrichFinding:
    def test_enriches_with_asset_data(self, etl):
        finding = {
            "source_finding_id": "f-001",
            "source_engine": "datasec",
            "severity": "critical",
            "asset_arn": "arn:aws:s3:::bucket-1",
            "account_id": "123456",
            "region": "us-east-1",
            "csp": "aws",
        }
        asset_metadata = {
            "arn:aws:s3:::bucket-1": {
                "asset_type": "s3_bucket",
                "is_public": True,
                "asset_criticality": "critical",
            }
        }
        datasec_metadata = {
            "arn:aws:s3:::bucket-1": {
                "data_sensitivity": "restricted",
                "data_types": ["PII"],
                "estimated_record_count": 5000,
            }
        }
        tenant_config = {
            "industry": "healthcare",
            "estimated_annual_revenue": 500_000_000,
            "applicable_regulations": ["HIPAA"],
            "default_record_count": 1000,
        }
        epss_cache = {}

        row = etl._enrich_finding(
            finding, tenant_config, epss_cache,
            asset_metadata, datasec_metadata,
            "scan-1", "orch-1", "tenant-1",
        )

        assert row["asset_criticality"] == "critical"
        assert row["is_public"] is True
        assert row["data_sensitivity"] == "restricted"
        assert row["estimated_record_count"] == 5000
        assert row["exposure_factor"] == 1.0  # public
        assert row["industry"] == "healthcare"

    def test_defaults_for_unknown_asset(self, etl):
        finding = {
            "source_finding_id": "f-002",
            "source_engine": "check",
            "asset_arn": "arn:aws:unknown::x",
        }
        row = etl._enrich_finding(
            finding, {"default_record_count": 1000}, {},
            {}, {},
            "scan-1", "orch-1", "tenant-1",
        )
        assert row["asset_criticality"] == "medium"
        assert row["is_public"] is False
        assert row["data_sensitivity"] == "internal"
        assert row["exposure_factor"] == 0.3

    def test_epss_lookup_with_cve(self, etl):
        finding = {
            "source_finding_id": "f-003",
            "source_engine": "vulnerability",
            "asset_arn": "arn:aws:ec2::i-1",
            "cve_id": "CVE-2024-9999",
        }
        epss_cache = {"CVE-2024-9999": 0.92}
        row = etl._enrich_finding(
            finding, {}, epss_cache, {}, {},
            "scan-1", "orch-1", "tenant-1",
        )
        assert row["epss_score"] == 0.92

    def test_epss_default_without_cve(self, etl):
        finding = {
            "source_finding_id": "f-004",
            "source_engine": "check",
            "asset_arn": "",
        }
        row = etl._enrich_finding(
            finding, {}, {}, {}, {},
            "scan-1", "orch-1", "tenant-1",
        )
        assert row["epss_score"] == 0.05


# ======================================================================
# run (integration-style)
# ======================================================================

class TestETLRun:
    @patch("engines.risk.etl.risk_etl.RiskETL._write_transformed", return_value=5)
    @patch("engines.risk.etl.risk_etl.RiskETL._collect_findings")
    @patch("engines.risk.etl.risk_etl.RiskETL._load_datasec_metadata", return_value={})
    @patch("engines.risk.etl.risk_etl.RiskETL._load_asset_metadata", return_value={})
    @patch("engines.risk.etl.risk_etl.RiskETL._load_epss_cache", return_value={})
    @patch("engines.risk.etl.risk_etl.RiskETL._load_tenant_config")
    def test_run_returns_count(self, mock_tenant, mock_epss, mock_asset,
                                mock_datasec, mock_collect, mock_write, etl):
        mock_tenant.return_value = {"industry": "default", "default_record_count": 1000}
        mock_collect.return_value = [
            {"source_finding_id": "f-1", "source_engine": "check", "asset_arn": ""},
        ] * 5

        count = etl.run("scan-1", "orch-1", "tenant-1", "acct-1")
        assert count == 5
        assert mock_write.called
