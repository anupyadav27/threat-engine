"""
FAIR Model — Financial Risk Quantification

Implements the Factor Analysis of Information Risk (FAIR) model:
  Risk = Loss Event Frequency (LEF) × Loss Magnitude (LM)

Per-record cost benchmarks from IBM Cost of Data Breach 2024.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

# Per-record cost by industry (USD, IBM 2024)
PER_RECORD_COST = {
    "healthcare": 10.93,
    "finance": 6.08,
    "technology": 4.88,
    "retail": 3.28,
    "default": 4.45,
}

# Sensitivity multipliers
SENSITIVITY_MULTIPLIER = {
    "restricted": 3.0,
    "confidential": 2.0,
    "internal": 1.0,
    "public": 0.1,
}

# Scenario type classification by finding source
ENGINE_TO_SCENARIO_TYPE = {
    "threat": "account_takeover",
    "iam": "account_takeover",
    "datasec": "data_breach",
    "container": "service_disruption",
    "network": "service_disruption",
    "supplychain": "data_breach",
    "api": "data_breach",
    "check": "compliance_fine",
    "compliance": "compliance_fine",
    "vulnerability": "data_breach",
    "encryption": "data_breach",
    "database": "data_breach",
    "ai_security": "data_breach",
    "ciem": "account_takeover",
}


def compute_scenario(
    finding: Dict[str, Any],
    model_config: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compute a FAIR risk scenario for one CRITICAL/HIGH finding.

    Args:
        finding: Transformed finding row from risk_input_transformed.
        model_config: Tenant/industry FAIR parameters from risk_model_config.

    Returns:
        Dict with all FAIR model outputs for risk_scenarios table.
    """
    # ---- Loss Event Frequency (LEF) ----
    epss = float(finding.get("epss_score") or 0.05)
    is_public = finding.get("is_public", False)
    exposure_factor = float(finding.get("exposure_factor") or (1.0 if is_public else 0.3))
    lef = epss * exposure_factor

    # ---- Loss Magnitude (LM) ----
    industry = (finding.get("industry") or "default").lower()
    per_record = model_config.get("per_record_cost") or PER_RECORD_COST.get(industry, PER_RECORD_COST["default"])
    per_record = float(per_record)

    records = int(finding.get("estimated_record_count") or model_config.get("default_record_count", 1000))
    sensitivity = (finding.get("data_sensitivity") or "internal").lower()

    # Allow config override of sensitivity multipliers
    sens_mults = model_config.get("sensitivity_multipliers", SENSITIVITY_MULTIPLIER)
    if isinstance(sens_mults, str):
        import json
        sens_mults = json.loads(sens_mults)
    sens_mult = float(sens_mults.get(sensitivity, SENSITIVITY_MULTIPLIER.get(sensitivity, 1.0)))

    primary_loss = records * per_record * sens_mult

    # ---- Regulatory Fine ----
    from engines.risk.models.regulatory_calculator import compute_regulatory_fines
    applicable_regs = finding.get("applicable_regulations") or []
    revenue = float(finding.get("estimated_revenue") or model_config.get("estimated_annual_revenue") or 100_000_000)
    reg_result = compute_regulatory_fines(applicable_regs, revenue, records)

    regulatory_fine_max = reg_result.get("max_fine", 0)
    regulatory_fine_min = reg_result.get("min_fine", 0)

    # ---- Total Exposure ----
    total_likely = (primary_loss + regulatory_fine_max) * lef
    total_min = total_likely * 0.1
    total_max = total_likely * 5.0

    # ---- Scenario Type ----
    source_engine = finding.get("source_engine", "check")
    scenario_type = ENGINE_TO_SCENARIO_TYPE.get(source_engine, "data_breach")

    # ---- Risk Tier ----
    risk_tier = classify_risk_tier(total_likely)

    return {
        "source_finding_id": finding.get("source_finding_id"),
        "source_engine": source_engine,
        "asset_id": finding.get("asset_id"),
        "asset_type": finding.get("asset_type"),
        "asset_arn": finding.get("asset_arn"),
        "scenario_type": scenario_type,
        "data_records_at_risk": records,
        "data_sensitivity": sensitivity,
        "data_types": finding.get("data_types", []),
        "loss_event_frequency": round(lef, 5),
        "primary_loss_min": round(primary_loss * 0.5, 2),
        "primary_loss_max": round(primary_loss * 2.0, 2),
        "primary_loss_likely": round(primary_loss, 2),
        "regulatory_fine_min": round(regulatory_fine_min, 2),
        "regulatory_fine_max": round(regulatory_fine_max, 2),
        "applicable_regulations": applicable_regs,
        "total_exposure_min": round(total_min, 2),
        "total_exposure_max": round(total_max, 2),
        "total_exposure_likely": round(total_likely, 2),
        "risk_tier": risk_tier,
        "calculation_model": {
            "epss_score": epss,
            "exposure_factor": exposure_factor,
            "lef": round(lef, 5),
            "per_record_cost": per_record,
            "records": records,
            "sensitivity_multiplier": sens_mult,
            "primary_loss": round(primary_loss, 2),
            "regulatory_fine": round(regulatory_fine_max, 2),
            "industry": industry,
        },
        "account_id": finding.get("account_id"),
        "region": finding.get("region"),
        "csp": finding.get("csp", "aws"),
    }


def classify_risk_tier(exposure: float) -> str:
    """Classify dollar exposure into risk tier."""
    if exposure >= 10_000_000:
        return "critical"   # >$10M
    if exposure >= 1_000_000:
        return "high"       # >$1M
    if exposure >= 100_000:
        return "medium"     # >$100K
    return "low"
