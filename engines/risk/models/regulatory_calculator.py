"""
Regulatory Fine Calculator

Models for estimating regulatory fines by framework:
  GDPR:    min(4% annual revenue, €20M)
  HIPAA:   $100–$50,000 per violation, up to $1.9M/category/year
  PCI-DSS: $5,000–$100,000/month until compliant
  CCPA:    $100–$750 per consumer per incident
  SOX:     $5M–$25M fine + criminal penalties (simplified)
"""

from __future__ import annotations

from typing import Any, Dict, List


def compute_regulatory_fines(
    applicable_regs: List[str],
    annual_revenue: float,
    record_count: int,
) -> Dict[str, Any]:
    """
    Compute estimated regulatory fines across all applicable frameworks.

    Args:
        applicable_regs: List of regulation codes (e.g., ['GDPR', 'HIPAA']).
        annual_revenue: Estimated annual revenue in USD.
        record_count: Number of affected records.

    Returns:
        Dict with max_fine, min_fine, and per-framework breakdown.
    """
    fines: Dict[str, Dict[str, float]] = {}

    for reg in applicable_regs:
        reg_upper = reg.upper().replace("-", "_")
        if reg_upper in _FINE_MODELS:
            result = _FINE_MODELS[reg_upper](annual_revenue, record_count)
            fines[reg_upper] = result

    if not fines:
        return {"max_fine": 0, "min_fine": 0, "breakdown": {}}

    max_fine = max(f["max"] for f in fines.values())
    min_fine = min(f["min"] for f in fines.values())

    return {
        "max_fine": max_fine,
        "min_fine": min_fine,
        "breakdown": fines,
    }


# ------------------------------------------------------------------
# Framework-specific fine models
# ------------------------------------------------------------------

def _gdpr_fine(revenue: float, records: int) -> Dict[str, float]:
    """GDPR: max(4% annual revenue, €20M) — converted to USD at ~1.1."""
    eur_to_usd = 1.1
    max_fine = min(0.04 * revenue, 20_000_000 * eur_to_usd)
    min_fine = min(0.02 * revenue, 10_000_000 * eur_to_usd)
    return {"min": round(min_fine, 2), "max": round(max_fine, 2)}


def _hipaa_fine(revenue: float, records: int) -> Dict[str, float]:
    """HIPAA: $100-$50,000 per violation, up to $1.9M per category per year."""
    per_violation_min = 100
    per_violation_max = 50_000
    max_fine = min(records * per_violation_max, 1_900_000)
    min_fine = min(records * per_violation_min, 1_900_000)
    return {"min": round(min_fine, 2), "max": round(max_fine, 2)}


def _pci_dss_fine(revenue: float, records: int) -> Dict[str, float]:
    """PCI-DSS: $5,000-$100,000/month until compliant + $5-50/compromised card."""
    monthly_min = 5_000
    monthly_max = 100_000
    # Assume 6-month remediation window
    max_fine = monthly_max * 6 + records * 50
    min_fine = monthly_min * 6 + records * 5
    return {"min": round(min_fine, 2), "max": round(max_fine, 2)}


def _ccpa_fine(revenue: float, records: int) -> Dict[str, float]:
    """CCPA: $100-$750 per consumer per incident, cap at $7.5M."""
    max_fine = min(records * 750, 7_500_000)
    min_fine = min(records * 100, 7_500_000)
    return {"min": round(min_fine, 2), "max": round(max_fine, 2)}


def _sox_fine(revenue: float, records: int) -> Dict[str, float]:
    """SOX: $5M-$25M corporate fine (simplified)."""
    return {"min": 5_000_000, "max": 25_000_000}


# Registry of fine models
_FINE_MODELS = {
    "GDPR": _gdpr_fine,
    "HIPAA": _hipaa_fine,
    "PCI_DSS": _pci_dss_fine,
    "CCPA": _ccpa_fine,
    "SOX": _sox_fine,
}
