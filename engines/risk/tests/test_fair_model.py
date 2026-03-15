"""
Unit tests for the FAIR model and regulatory calculator.
"""

import pytest
from engines.risk.models.fair_model import (
    compute_scenario,
    classify_risk_tier,
    PER_RECORD_COST,
    SENSITIVITY_MULTIPLIER,
    ENGINE_TO_SCENARIO_TYPE,
)
from engines.risk.models.regulatory_calculator import (
    compute_regulatory_fines,
    _gdpr_fine,
    _hipaa_fine,
    _pci_dss_fine,
    _ccpa_fine,
    _sox_fine,
)


# ======================================================================
# classify_risk_tier
# ======================================================================

class TestClassifyRiskTier:
    def test_critical_tier(self):
        assert classify_risk_tier(10_000_001) == "critical"
        assert classify_risk_tier(50_000_000) == "critical"

    def test_critical_boundary(self):
        assert classify_risk_tier(10_000_000) == "critical"

    def test_high_tier(self):
        assert classify_risk_tier(1_000_001) == "high"
        assert classify_risk_tier(5_000_000) == "high"

    def test_high_boundary(self):
        assert classify_risk_tier(1_000_000) == "high"

    def test_medium_tier(self):
        assert classify_risk_tier(100_001) == "medium"
        assert classify_risk_tier(500_000) == "medium"

    def test_medium_boundary(self):
        assert classify_risk_tier(100_000) == "medium"

    def test_low_tier(self):
        assert classify_risk_tier(99_999) == "low"
        assert classify_risk_tier(0) == "low"
        assert classify_risk_tier(-100) == "low"


# ======================================================================
# compute_scenario — FAIR model
# ======================================================================

class TestComputeScenario:
    @pytest.fixture
    def base_finding(self):
        return {
            "source_finding_id": "f-001",
            "source_engine": "datasec",
            "asset_id": "arn:aws:s3:::bucket-1",
            "asset_type": "s3_bucket",
            "asset_arn": "arn:aws:s3:::bucket-1",
            "severity": "critical",
            "is_public": True,
            "epss_score": 0.5,
            "exposure_factor": 1.0,
            "data_sensitivity": "restricted",
            "data_types": ["PII", "PHI"],
            "estimated_record_count": 10000,
            "industry": "healthcare",
            "estimated_revenue": 500_000_000,
            "applicable_regulations": ["HIPAA", "GDPR"],
            "cve_id": "CVE-2024-1234",
            "account_id": "123456789012",
            "region": "us-east-1",
            "csp": "aws",
        }

    @pytest.fixture
    def model_config(self):
        return {
            "per_record_cost": 10.93,
            "estimated_annual_revenue": 500_000_000,
            "applicable_regs": ["HIPAA", "GDPR"],
            "downtime_cost_hr": 25000.0,
            "sensitivity_multipliers": SENSITIVITY_MULTIPLIER,
            "default_record_count": 5000,
        }

    def test_lef_calculation(self, base_finding, model_config):
        result = compute_scenario(base_finding, model_config)
        # LEF = EPSS × exposure_factor = 0.5 × 1.0 = 0.5
        assert result["loss_event_frequency"] == 0.5

    def test_primary_loss(self, base_finding, model_config):
        result = compute_scenario(base_finding, model_config)
        # primary_loss = records × per_record × sensitivity_mult
        # = 10000 × 10.93 × 3.0 = 327,900
        assert result["primary_loss_likely"] == 327900.0

    def test_scenario_type_from_engine(self, base_finding, model_config):
        result = compute_scenario(base_finding, model_config)
        assert result["scenario_type"] == "data_breach"  # datasec → data_breach

    def test_risk_tier_assigned(self, base_finding, model_config):
        result = compute_scenario(base_finding, model_config)
        assert result["risk_tier"] in ("critical", "high", "medium", "low")

    def test_total_exposure_calculated(self, base_finding, model_config):
        result = compute_scenario(base_finding, model_config)
        assert result["total_exposure_likely"] > 0
        assert result["total_exposure_min"] < result["total_exposure_likely"]
        assert result["total_exposure_max"] > result["total_exposure_likely"]

    def test_calculation_model_audit_trail(self, base_finding, model_config):
        result = compute_scenario(base_finding, model_config)
        calc = result["calculation_model"]
        assert calc["epss_score"] == 0.5
        assert calc["exposure_factor"] == 1.0
        assert calc["per_record_cost"] == 10.93
        assert calc["records"] == 10000
        assert calc["sensitivity_multiplier"] == 3.0

    def test_internal_exposure_lower(self, base_finding, model_config):
        """Internal (non-public) assets should have lower exposure."""
        base_finding["is_public"] = False
        base_finding["exposure_factor"] = 0.3
        result = compute_scenario(base_finding, model_config)
        assert result["loss_event_frequency"] == round(0.5 * 0.3, 5)

    def test_public_sensitivity_very_low(self, base_finding, model_config):
        base_finding["data_sensitivity"] = "public"
        result = compute_scenario(base_finding, model_config)
        assert result["primary_loss_likely"] < 11000  # 10000 × 10.93 × 0.1

    def test_missing_epss_defaults_to_005(self, base_finding, model_config):
        base_finding["epss_score"] = None
        result = compute_scenario(base_finding, model_config)
        assert result["calculation_model"]["epss_score"] == 0.05

    def test_threat_engine_scenario_type(self, base_finding, model_config):
        base_finding["source_engine"] = "threat"
        result = compute_scenario(base_finding, model_config)
        assert result["scenario_type"] == "account_takeover"

    def test_check_engine_scenario_type(self, base_finding, model_config):
        base_finding["source_engine"] = "check"
        result = compute_scenario(base_finding, model_config)
        assert result["scenario_type"] == "compliance_fine"

    def test_container_engine_scenario_type(self, base_finding, model_config):
        base_finding["source_engine"] = "container"
        result = compute_scenario(base_finding, model_config)
        assert result["scenario_type"] == "service_disruption"


# ======================================================================
# ENGINE_TO_SCENARIO_TYPE mapping
# ======================================================================

class TestEngineToScenarioType:
    def test_all_engines_mapped(self):
        expected_engines = [
            "threat", "iam", "datasec", "container",
            "network", "supplychain", "api", "check", "vulnerability",
        ]
        for engine in expected_engines:
            assert engine in ENGINE_TO_SCENARIO_TYPE


# ======================================================================
# Regulatory Fine Calculator
# ======================================================================

class TestGDPRFine:
    def test_four_percent_cap(self):
        result = _gdpr_fine(100_000_000, 5000)
        # 4% of $100M = $4M; €20M×1.1 = $22M; min = $4M
        assert result["max"] == 4_000_000

    def test_twenty_million_euro_cap(self):
        result = _gdpr_fine(1_000_000_000, 5000)
        # 4% of $1B = $40M; €20M×1.1 = $22M; min = $22M
        assert result["max"] == 22_000_000

    def test_small_revenue(self):
        result = _gdpr_fine(1_000_000, 100)
        assert result["max"] == 40_000  # 4% of $1M


class TestHIPAAFine:
    def test_per_violation_capped(self):
        result = _hipaa_fine(0, 100)
        # 100 × $50,000 = $5M, capped at $1.9M
        assert result["max"] == 1_900_000

    def test_small_violation_count(self):
        result = _hipaa_fine(0, 10)
        assert result["max"] == 500_000  # 10 × $50,000
        assert result["min"] == 1_000    # 10 × $100

    def test_single_violation(self):
        result = _hipaa_fine(0, 1)
        assert result["min"] == 100
        assert result["max"] == 50_000


class TestPCIDSSFine:
    def test_monthly_plus_per_card(self):
        result = _pci_dss_fine(0, 1000)
        # max: $100K×6 + 1000×$50 = $650,000
        assert result["max"] == 650_000
        # min: $5K×6 + 1000×$5 = $35,000
        assert result["min"] == 35_000

    def test_zero_records(self):
        result = _pci_dss_fine(0, 0)
        assert result["max"] == 600_000  # $100K×6 + 0
        assert result["min"] == 30_000   # $5K×6 + 0


class TestCCPAFine:
    def test_per_consumer(self):
        result = _ccpa_fine(0, 5000)
        assert result["max"] == 3_750_000  # 5000 × $750
        assert result["min"] == 500_000    # 5000 × $100

    def test_cap_at_75m(self):
        result = _ccpa_fine(0, 100_000)
        assert result["max"] == 7_500_000  # capped

    def test_small_incident(self):
        result = _ccpa_fine(0, 10)
        assert result["max"] == 7_500
        assert result["min"] == 1_000


class TestSOXFine:
    def test_fixed_range(self):
        result = _sox_fine(0, 0)
        assert result["min"] == 5_000_000
        assert result["max"] == 25_000_000


class TestComputeRegulatoryFines:
    def test_multiple_frameworks(self):
        result = compute_regulatory_fines(
            ["GDPR", "HIPAA"], 100_000_000, 1000
        )
        assert result["max_fine"] > 0
        assert result["min_fine"] > 0
        assert "GDPR" in result["breakdown"]
        assert "HIPAA" in result["breakdown"]

    def test_empty_frameworks(self):
        result = compute_regulatory_fines([], 100_000_000, 1000)
        assert result["max_fine"] == 0
        assert result["min_fine"] == 0

    def test_unknown_framework_ignored(self):
        result = compute_regulatory_fines(["UNKNOWN_REG"], 100_000_000, 1000)
        assert result["max_fine"] == 0

    def test_pci_dss_hyphen_normalized(self):
        result = compute_regulatory_fines(["PCI-DSS"], 100_000_000, 1000)
        assert "PCI_DSS" in result["breakdown"]

    def test_max_fine_is_highest_across_frameworks(self):
        result = compute_regulatory_fines(
            ["GDPR", "SOX"], 100_000_000, 1000
        )
        # SOX max is $25M, GDPR max is $4M (4% of $100M) → max = $25M
        assert result["max_fine"] == 25_000_000
