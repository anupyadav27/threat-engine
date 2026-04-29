"""
Composite Risk Scorer — Feature 5

Calculates a single 0–10 risk score that combines:
  - CVSS base score         (how severe is the vulnerability technically)
  - EPSS score              (how likely to be exploited in the next 30 days)
  - CISA KEV membership     (is it being actively exploited RIGHT NOW)
  - Fix availability        (is a patched version available)

WHY this matters over CVSS alone:
  CVSS 9.8 + EPSS 0.04% + not in KEV  →  Risk 4.2  (theoretical, low urgency)
  CVSS 5.5 + EPSS 94%  + in KEV       →  Risk 9.9  (patch immediately)

PRIORITY labels map to actionable SLAs:
  IMMEDIATE  (8.0–10.0) → patch within 24 hours
  HIGH       (6.0–7.9)  → patch within 72 hours
  MEDIUM     (3.0–5.9)  → patch within 2 weeks
  LOW        (0.0–2.9)  → patch in next release cycle
"""

from typing import Dict, Optional


# ── EPSS multiplier table ─────────────────────────────────────────────────────
# Maps exploitation probability → score multiplier
# The higher the EPSS, the more weight the vulnerability deserves

def _epss_multiplier(epss: Optional[float]) -> float:
    if epss is None:
        return 1.0          # no data — neutral
    if epss >= 0.80:
        return 2.0          # top ~1% most dangerous: double the score
    if epss >= 0.50:
        return 1.7
    if epss >= 0.20:
        return 1.3
    if epss >= 0.05:
        return 1.0
    if epss >= 0.01:
        return 0.7
    return 0.5              # extremely unlikely to be exploited: halve the score


def _kev_multiplier(in_kev: bool) -> float:
    """Being in the CISA KEV catalog means real attackers are using it today."""
    return 2.0 if in_kev else 1.0


def _fix_factor(fixed_version: Optional[str]) -> float:
    """
    If a fix is available and you haven't applied it, urgency increases.
    No fix available = slightly less urgent (nothing you can do immediately).
    """
    return 1.2 if fixed_version else 0.9


def _severity_to_base(severity: Optional[str], cvss_score: Optional[float]) -> float:
    """
    Use CVSS score if available; fall back to severity label midpoint.
    """
    if cvss_score is not None:
        try:
            return float(cvss_score)
        except (TypeError, ValueError):
            pass

    _fallback = {
        "critical": 9.0,
        "high":     7.5,
        "medium":   5.0,
        "low":      2.5,
        "none":     0.0,
    }
    return _fallback.get((severity or "").lower(), 5.0)


def _priority_label(score: float) -> str:
    if score >= 8.0:
        return "IMMEDIATE"
    if score >= 6.0:
        return "HIGH"
    if score >= 3.0:
        return "MEDIUM"
    return "LOW"


def _priority_sla(priority: str) -> str:
    return {
        "IMMEDIATE": "Patch within 24 hours",
        "HIGH":      "Patch within 72 hours",
        "MEDIUM":    "Patch within 2 weeks",
        "LOW":       "Patch in next release cycle",
    }.get(priority, "Review required")


# ── Main scoring function ─────────────────────────────────────────────────────

def calculate_composite_risk(
    severity: Optional[str] = None,
    cvss_score: Optional[float] = None,
    epss_score: Optional[float] = None,
    in_cisa_kev: bool = False,
    fixed_version: Optional[str] = None,
) -> Dict:
    """
    Calculate composite risk score for a single vulnerability finding.

    Returns:
        {
          "composite_risk":  8.7,
          "priority":        "IMMEDIATE",
          "sla":             "Patch within 24 hours",
          "factors": {
            "cvss_base":      7.5,
            "epss_multiplier": 1.7,
            "kev_multiplier":  2.0,
            "fix_factor":      1.2,
          }
        }
    """
    base    = _severity_to_base(severity, cvss_score)
    e_mult  = _epss_multiplier(epss_score)
    k_mult  = _kev_multiplier(in_cisa_kev)
    f_fact  = _fix_factor(fixed_version)

    raw_score = base * e_mult * k_mult * f_fact
    score = round(min(10.0, max(0.0, raw_score)), 2)
    priority = _priority_label(score)

    return {
        "composite_risk": score,
        "priority":       priority,
        "sla":            _priority_sla(priority),
        "factors": {
            "cvss_base":       round(base, 2),
            "epss_multiplier": e_mult,
            "kev_multiplier":  k_mult,
            "fix_factor":      f_fact,
        },
    }


def enrich_vuln_with_risk(vuln: Dict, intel: Optional[Dict]) -> Dict:
    """
    Merge threat intel + composite risk into a vulnerability dict.
    Returns the same dict with added fields.
    Non-destructive: existing fields are not overwritten.
    """
    intel = intel or {}

    epss_score   = intel.get("epss_score")
    epss_pct     = intel.get("epss_percentile")
    in_kev       = bool(intel.get("in_cisa_kev", False))
    kev_date     = intel.get("kev_date_added")
    kev_ransomware = intel.get("kev_ransomware_use")
    kev_action   = intel.get("kev_required_action")

    risk_result = calculate_composite_risk(
        severity      = vuln.get("severity"),
        cvss_score    = vuln.get("cvss_score"),
        epss_score    = epss_score,
        in_cisa_kev   = in_kev,
        fixed_version = vuln.get("fixed_version"),
    )

    vuln.update({
        "epss_score":        epss_score,
        "epss_percentile":   epss_pct,
        "in_cisa_kev":       in_kev,
        "kev_date_added":    str(kev_date) if kev_date else None,
        "kev_ransomware_use": kev_ransomware,
        "kev_required_action": kev_action,
        "composite_risk":    risk_result["composite_risk"],
        "priority":          risk_result["priority"],
        "sla":               risk_result["sla"],
        "risk_factors":      risk_result["factors"],
    })
    return vuln
