"""
CNAPP posture score aggregator.

Computes a unified CNAPP risk score (0-100, higher = better posture) as a
weighted average across all pillars that returned data.

Pillar weights reflect industry CNAPP risk priority:
  CSPM       20% — cloud configuration is the widest attack surface
  CIEM       20% — identity/entitlement misconfig is #1 breach vector
  CWPP       20% — workload runtime security
  DSPM       15% — data exposure risk
  Network    15% — network posture / lateral movement paths
  Threat      5% — threat intelligence (read-only signal)
  AppSec      5% — application code security
"""

from __future__ import annotations

from typing import Dict, List, Optional

PILLAR_WEIGHTS: Dict[str, float] = {
    "cspm":    0.20,
    "cdr":     0.20,
    "cwpp":    0.20,
    "dspm":    0.15,
    "network": 0.15,
    "threat":  0.05,
    "appsec":  0.05,
}


def compute_cnapp_score(pillar_results: List[Dict]) -> Optional[float]:
    """
    Weighted average of pillar posture_scores, skipping unavailable pillars.

    Args:
        pillar_results: list of pillar dicts, each with keys:
            pillar (str), status (str), posture_score (float|None)

    Returns:
        Rounded score 0-100, or None if no pillar has data.
    """
    total_weight = 0.0
    weighted_sum = 0.0

    for p in pillar_results:
        name = p.get("pillar")
        score = p.get("posture_score")
        if score is None or p.get("status") == "unavailable":
            continue
        weight = PILLAR_WEIGHTS.get(name, 0.0)
        weighted_sum += score * weight
        total_weight += weight

    if total_weight == 0:
        return None

    # Re-normalise: if some pillars are unavailable their weight is dropped,
    # so divide by actual accumulated weight (not 1.0) to stay in 0-100 range.
    return round(weighted_sum / total_weight, 1)


def risk_band(score: Optional[float]) -> str:
    """Map score to a human-readable risk band."""
    if score is None:
        return "unknown"
    if score >= 80:
        return "low"
    if score >= 60:
        return "medium"
    if score >= 40:
        return "high"
    return "critical"
