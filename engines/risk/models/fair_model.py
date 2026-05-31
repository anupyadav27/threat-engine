"""
FAIR Model — Financial Risk Quantification (ENG-13)

Implements the Factor Analysis of Information Risk (FAIR) model:
  Risk Score = Loss Event Frequency (LEF) × Loss Magnitude (LM)
  LEF  = Threat Event Frequency (TEF) × Vulnerability (V)
  LM   = Primary Loss (PL) × Secondary Loss (SL)

Regulatory multipliers applied to LM (AC-S5: hardcoded constants, not from env/DB):
  GDPR:    × 1.5  (4% global annual turnover cap)
  HIPAA:   × 1.3  ($1.9M/violation)
  PCI-DSS: × 1.2  ($5-100k/month)
  CCPA:    × 1.1  ($7,500/intentional)
  SOX:     × 1.4  (criminal penalties)

Per-record cost benchmarks from IBM Cost of Data Breach 2024.
"""

from __future__ import annotations

import hashlib
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

# Regulatory LM multipliers — AC-S5: hardcoded constants, never read from env or DB.
# Apply the highest applicable multiplier (not additive) to avoid double-counting.
# Source: IBM X-Force Threat Intelligence Index 2024 + regulatory fine data.
REGULATORY_MULTIPLIERS: Dict[str, float] = {
    "GDPR": 1.5,     # 4% global annual turnover cap
    "HIPAA": 1.3,    # $1.9M/violation
    "PCI": 1.2,
    "PCI-DSS": 1.2,  # $5-100k/month
    "PCI_DSS": 1.2,
    "CCPA": 1.1,     # $7,500/intentional violation
    "SOX": 1.4,      # criminal penalties
}

# High-value resource types by CSP — 10x LM multiplier (AC from ENG-13 spec)
# These asset types have outsized breach / data-loss impact on compromise.
HIGH_VALUE_RESOURCE_TYPES: Dict[str, set] = {
    "aws": {
        "RDS::DBInstance", "RDS::DBCluster", "Secret", "S3::Bucket",
        "EKS::Cluster", "ElasticSearch::Domain", "Redshift::Cluster",
        "SecretsManager::Secret",
    },
    "azure": {
        "SQL::Database", "KeyVault::Vault", "ContainerService::ManagedCluster",
        "Storage::BlobContainer", "CosmosDB::Account",
    },
    "gcp": {
        "CloudSQL::Instance", "SecretManager::Secret", "Container::Cluster",
        "BigQuery::Dataset", "Storage::Bucket",
    },
    "oci": {
        "Database::AutonomousDatabase", "Vault::Secret", "ContainerEngine::Cluster",
    },
    "alicloud": {
        "RDS::DBInstance", "KMS::Key", "ACK::Cluster", "OSS::Bucket",
    },
    "k8s": {
        "Secret", "Pod",
    },
}

HIGH_VALUE_MULTIPLIER = 10.0

# Crown jewel asset multipliers — driven by crown_jewel_type from attack-path classifier.
# Applied as max(asset_mult, crown_jewel_mult) so they never stack on top of HIGH_VALUE_MULTIPLIER.
# Ordered highest→lowest: encryption_control and identity have the widest blast radius.
CROWN_JEWEL_MULTIPLIER: Dict[str, float] = {
    "encryption_control":      20.0,  # KMS/Key Vault: every secret encrypted with it is at risk
    "k8s_secrets":             18.0,  # K8s Secret/ConfigMap with credentials
    "identity":                18.0,  # Admin IAM role: full account takeover
    "infra_control":           15.0,  # EKS/AKS/GKE cluster: all workloads under it
    "k8s_cluster_admin":       15.0,  # Overpermissive K8s ServiceAccount
    "data":                    12.0,  # RDS/S3/DynamoDB with PII/financial data
    "data_warehouse":          12.0,  # Redshift/BigQuery/Synapse
    "k8s_privileged_workload": 12.0,  # Privileged container
    "ai_model":                10.0,  # SageMaker/Bedrock: IP theft, data exfil
    "code":                    10.0,  # Container registry: supply chain vector
}

# ── Canonical 4 scenario types (AC-F8) ────────────────────────────────────────
VALID_SCENARIO_TYPES = frozenset({
    "data_exfiltration",
    "lateral_movement",
    "privilege_escalation",
    "denial_of_service",
})

# Scenario MITRE ATT&CK technique mapping — canonical 4 types only (ENG-13)
SCENARIO_MITRE_MAP: Dict[str, List[str]] = {
    "data_exfiltration":   ["T1530", "T1020", "T1119"],    # T1530: Data from Cloud Storage
    "lateral_movement":    ["T1210", "T1021", "T1078"],    # T1210: Remote Services
    "privilege_escalation": ["T1611", "T1068", "T1078.004"],
    "denial_of_service":   ["T1499", "T1486"],             # T1486: Data Encrypted for Impact
}

# Mapping from source engine to canonical scenario type
# Uses only the 4 types from VALID_SCENARIO_TYPES (AC-F8)
ENGINE_TO_SCENARIO_TYPE: Dict[str, str] = {
    # IAM/CIEM misuse → privilege escalation or lateral movement
    "iam":        "privilege_escalation",
    "ciem":       "privilege_escalation",
    # Threat findings span access / lateral movement
    "threat":     "lateral_movement",
    # Data-touching engines → data exfiltration
    "datasec":    "data_exfiltration",
    "database":   "data_exfiltration",
    "encryption": "data_exfiltration",
    "ai_security": "data_exfiltration",
    # Config/posture → data exfiltration (most common consequence)
    "check":      "data_exfiltration",
    "compliance": "data_exfiltration",
    "vulnerability": "data_exfiltration",
    # Availability-impacting engines → denial_of_service
    "container":  "denial_of_service",
    "network":    "denial_of_service",
    "supplychain": "denial_of_service",
    "api":        "data_exfiltration",
}

# EU regions that trigger GDPR regulatory flag (AC-F7)
EU_REGIONS = frozenset({
    # AWS EU regions
    "eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-central-2",
    "eu-north-1", "eu-south-1", "eu-south-2",
    # Azure EU regions
    "westeurope", "northeurope", "uksouth", "ukwest",
    "francecentral", "francesouth", "germanywestcentral", "germanynorth",
    "switzerlandnorth", "switzerlandwest", "norwayeast", "norwaywest",
    "swedencentral", "polandcentral", "italynorth",
    # GCP EU regions
    "europe-west1", "europe-west2", "europe-west3", "europe-west4",
    "europe-west6", "europe-west8", "europe-west9", "europe-west10",
    "europe-west12", "europe-north1", "europe-central2", "europe-southwest1",
    # OCI EU regions
    "eu-frankfurt-1", "eu-amsterdam-1", "eu-madrid-1", "eu-milan-1",
    "eu-paris-1", "eu-stockholm-1", "eu-marseille-1",
    # AliCloud EU regions
    "eu-central-1", "eu-west-1",
})


def compute_finding_id(
    scenario_type: str, resource_uid: str, account_id: str, region: str
) -> str:
    """Compute deterministic finding_id per AC-S4.

    sha256(f"{scenario_type}|{resource_uid}|{account_id}|{region}")[:16]
    Unique per scenario/resource combination; stable across re-scans.

    Args:
        scenario_type: One of the 4 canonical scenario types.
        resource_uid: Cloud resource unique identifier (ARN / resource ID).
        account_id: Cloud account / subscription / project ID.
        region: Cloud region or zone identifier.

    Returns:
        16-character lowercase hexadecimal string.
    """
    raw = f"{scenario_type}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def get_regulatory_flags_for_region(
    region: str, applicable_regs: List[str]
) -> List[str]:
    """Return the list of regulatory flags that apply to a given region.

    GDPR is added automatically for any resource in an EU region (AC-F7).
    All other applicable_regs are always returned as-is.

    Args:
        region: Cloud region identifier (e.g. 'eu-west-1').
        applicable_regs: Regulations already on the finding/tenant config.

    Returns:
        Deduplicated sorted list of regulation flags.
    """
    flags = set(applicable_regs or [])
    region_lower = (region or "").lower()
    if region_lower in EU_REGIONS:
        flags.add("GDPR")
    return sorted(flags)


def get_crown_jewel_multiplier(is_crown_jewel: bool, crown_jewel_type: Optional[str]) -> float:
    """Return the crown jewel LM multiplier for a classified crown jewel asset.

    Returns the type-specific multiplier, or 8.0 for unknown types (still elevated
    above the default 1.0). Returns 1.0 when is_crown_jewel is False.

    Args:
        is_crown_jewel: Whether this resource is classified as a crown jewel.
        crown_jewel_type: Crown jewel category from CrownJewelClassifier.

    Returns:
        Multiplier float — always >= 1.0.
    """
    if not is_crown_jewel:
        return 1.0
    return CROWN_JEWEL_MULTIPLIER.get(crown_jewel_type or "", 8.0)


def get_asset_multiplier(resource_type: str, csp: str) -> float:
    """Return 10x multiplier for high-value resource types, 1.0 otherwise.

    Args:
        resource_type: Cloud resource type string (e.g. 'RDS::DBInstance').
        csp: Cloud service provider identifier (aws/azure/gcp/oci/alicloud/k8s).

    Returns:
        HIGH_VALUE_MULTIPLIER (10.0) if resource is in the high-value set,
        1.0 otherwise.
    """
    hv = HIGH_VALUE_RESOURCE_TYPES.get(csp.lower() if csp else "aws", set())
    return HIGH_VALUE_MULTIPLIER if resource_type in hv else 1.0


def get_regulatory_multiplier(applicable_regs: List[str]) -> float:
    """Return the highest applicable regulatory LM multiplier.

    AC-S5: multiplier constants are hardcoded — never read from env or DB.
    Applies the single highest multiplier (not additive) to avoid
    double-counting across overlapping frameworks.

    Args:
        applicable_regs: List of regulation codes (e.g., ['GDPR', 'HIPAA']).

    Returns:
        Highest matching multiplier, minimum 1.0.
    """
    reg_mult = 1.0
    for reg in (applicable_regs or []):
        reg_key = reg.upper().replace("-", "_")
        # Check both original and normalized forms
        mult = REGULATORY_MULTIPLIERS.get(reg.upper(), REGULATORY_MULTIPLIERS.get(reg_key, 1.0))
        reg_mult = max(reg_mult, mult)
    return reg_mult


def compute_scenario(
    finding: Dict[str, Any],
    model_config: Dict[str, Any],
) -> Dict[str, Any]:
    """Compute a FAIR risk scenario for one CRITICAL/HIGH finding.

    FAIR formula (ENG-13):
        LEF  = TEF × V  (simplified: EPSS × exposure_factor)
        LM   = PL × SL  (simplified: records × per_record × sens_mult × asset_mult × reg_mult)
        Risk = LEF × LM

    Also produces:
      - fair_lef: Loss Event Frequency
      - fair_lm: Loss Magnitude (adjusted)
      - fair_risk_score: LEF × LM (canonical FAIR score)
      - regulatory_flags: regs applicable to this resource's region
      - finding_id: sha256(scenario_type|resource_uid|account_id|region)[:16]
      - attack_path: populated by evaluator from Neo4j blast radius sample_targets

    Args:
        finding: Transformed finding row from risk_input_transformed.
        model_config: Tenant/industry FAIR parameters from risk_model_config.

    Returns:
        Dict with all FAIR model outputs for risk_scenarios table.
    """
    # ── Loss Event Frequency (LEF = TEF × V) ─────────────────────────────────
    # TEF proxy: EPSS score (probability of exploitation within 30 days)
    # V proxy: exposure_factor (is_public = full exposure; private = 0.3)
    epss = float(finding.get("epss_score") or 0.05)
    is_public = finding.get("is_public", False)
    exposure_factor = float(finding.get("exposure_factor") or (1.0 if is_public else 0.3))
    fair_lef = round(epss * exposure_factor, 5)

    # ── Loss Magnitude (LM = PL × SL) ────────────────────────────────────────
    industry = (finding.get("industry") or "default").lower()
    per_record = model_config.get("per_record_cost") or PER_RECORD_COST.get(
        industry, PER_RECORD_COST["default"]
    )
    per_record = float(per_record)

    records = int(
        finding.get("estimated_record_count")
        or model_config.get("default_record_count", 1000)
    )
    sensitivity = (finding.get("data_sensitivity") or "internal").lower()

    # Allow config override of sensitivity multipliers
    sens_mults = model_config.get("sensitivity_multipliers", SENSITIVITY_MULTIPLIER)
    if isinstance(sens_mults, str):
        import json
        sens_mults = json.loads(sens_mults)
    sens_mult = float(
        sens_mults.get(sensitivity, SENSITIVITY_MULTIPLIER.get(sensitivity, 1.0))
    )

    # Asset multiplier: crown jewel classification takes precedence over static type list.
    # Crown jewel signals are written by CrownJewelClassifier (attack-path engine, Stage 6)
    # and read by RiskEvaluator from resource_security_posture before calling compute_scenario().
    resource_type = finding.get("asset_type") or ""
    csp = finding.get("csp") or "aws"
    is_crown_jewel: bool = bool(finding.get("is_crown_jewel", False))
    crown_jewel_type: Optional[str] = finding.get("crown_jewel_type")

    static_mult = get_asset_multiplier(resource_type, csp)
    cj_mult = get_crown_jewel_multiplier(is_crown_jewel, crown_jewel_type)
    # Take the higher of the two — crown jewel never stacks on top of high-value list.
    asset_mult = max(static_mult, cj_mult)

    # Base primary loss before regulatory adjustment
    primary_loss_base = records * per_record * sens_mult

    # ── Regulatory Fine ───────────────────────────────────────────────────────
    from engines.risk.models.regulatory_calculator import compute_regulatory_fines

    region = (finding.get("region") or "").lower()
    base_regs: List[str] = list(finding.get("applicable_regulations") or [])
    # Promote GDPR for EU regions (AC-F7)
    regulatory_flags = get_regulatory_flags_for_region(region, base_regs)

    revenue = float(
        finding.get("estimated_revenue")
        or model_config.get("estimated_annual_revenue")
        or 100_000_000
    )
    reg_result = compute_regulatory_fines(regulatory_flags, revenue, records)
    regulatory_fine_max = reg_result.get("max_fine", 0)
    regulatory_fine_min = reg_result.get("min_fine", 0)

    # ── Regulatory LM Multiplier ──────────────────────────────────────────────
    # AC-S5: constants hardcoded in REGULATORY_MULTIPLIERS dict above.
    # Apply highest multiplier only (not additive across frameworks).
    reg_mult = get_regulatory_multiplier(regulatory_flags)

    # Adjusted primary loss: base × high-value asset factor × regulatory multiplier
    primary_loss = primary_loss_base * asset_mult * reg_mult
    fair_lm = round(primary_loss, 2)

    # ── FAIR Risk Score (ENG-13 canonical: LEF × LM) ─────────────────────────
    fair_risk_score = round(fair_lef * fair_lm, 2)

    # ── Legacy total_exposure (includes regulatory fine for backward compat) ──
    total_likely = (primary_loss + regulatory_fine_max) * fair_lef
    total_min = total_likely * 0.1
    total_max = total_likely * 5.0

    # ── Scenario Type (canonical 4 — AC-F8) ──────────────────────────────────
    source_engine = finding.get("source_engine", "check")
    scenario_type = ENGINE_TO_SCENARIO_TYPE.get(source_engine, "data_exfiltration")
    # Guard: ensure only valid scenario types reach the DB
    if scenario_type not in VALID_SCENARIO_TYPES:
        scenario_type = "data_exfiltration"

    # ── MITRE ATT&CK Techniques ───────────────────────────────────────────────
    mitre_techniques = SCENARIO_MITRE_MAP.get(scenario_type, [])

    # ── Deterministic finding_id (AC-S4) ─────────────────────────────────────
    resource_uid = finding.get("asset_arn") or finding.get("asset_id") or ""
    account_id = finding.get("account_id") or ""
    finding_id = compute_finding_id(scenario_type, resource_uid, account_id, region)

    # ── Risk Tier ─────────────────────────────────────────────────────────────
    risk_tier = classify_risk_tier(total_likely)

    return {
        # Standard FAIR output fields (ENG-13)
        "finding_id": finding_id,
        "fair_lef": fair_lef,
        "fair_lm": fair_lm,
        "fair_risk_score": fair_risk_score,
        "regulatory_flags": regulatory_flags,
        # Source linkage
        "source_finding_id": finding.get("source_finding_id"),
        "source_engine": source_engine,
        # Asset fields
        "asset_id": finding.get("asset_id"),
        "asset_type": resource_type,
        "asset_arn": resource_uid,
        # Scenario classification
        "scenario_type": scenario_type,
        # Loss fields
        "data_records_at_risk": records,
        "data_sensitivity": sensitivity,
        "data_types": finding.get("data_types", []),
        "loss_event_frequency": fair_lef,
        "primary_loss_min": round(primary_loss * 0.5, 2),
        "primary_loss_max": round(primary_loss * 2.0, 2),
        "primary_loss_likely": fair_lm,
        "regulatory_fine_min": round(regulatory_fine_min, 2),
        "regulatory_fine_max": round(regulatory_fine_max, 2),
        "applicable_regulations": regulatory_flags,
        "total_exposure_min": round(total_min, 2),
        "total_exposure_max": round(total_max, 2),
        "total_exposure_likely": round(total_likely, 2),
        "risk_tier": risk_tier,
        "regulatory_multiplier": reg_mult,
        "mitre_techniques": mitre_techniques,
        # attack_path: evaluator populates this from Neo4j blast radius sample_targets
        "attack_path": [],
        "calculation_model": {
            "model": "FAIR",
            "epss_score": epss,
            "exposure_factor": exposure_factor,
            "fair_lef": fair_lef,
            "per_record_cost": per_record,
            "records": records,
            "sensitivity_multiplier": sens_mult,
            "static_asset_multiplier": static_mult,
            "crown_jewel_multiplier": cj_mult,
            "asset_multiplier": asset_mult,
            "is_crown_jewel": is_crown_jewel,
            "crown_jewel_type": crown_jewel_type,
            "regulatory_multiplier": reg_mult,
            "primary_loss_base": round(primary_loss_base, 2),
            "primary_loss_adjusted": fair_lm,
            "fair_lm": fair_lm,
            "fair_risk_score": fair_risk_score,
            "regulatory_fine": round(regulatory_fine_max, 2),
            "industry": industry,
        },
        "account_id": account_id,
        "region": region,
        "csp": csp,
    }


def classify_risk_tier(exposure: float) -> str:
    """Classify dollar exposure into risk tier.

    Args:
        exposure: Total exposure in USD.

    Returns:
        Risk tier string: 'critical', 'high', 'medium', or 'low'.
    """
    if exposure >= 10_000_000:
        return "critical"   # >$10M
    if exposure >= 1_000_000:
        return "high"       # >$1M
    if exposure >= 100_000:
        return "medium"     # >$100K
    return "low"
