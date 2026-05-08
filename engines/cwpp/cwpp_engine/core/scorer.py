"""
CWPP posture score computation.

Overall CWPP score = weighted average of workload-type scores.

Workload weights:
  containers  30% — K8s / EKS / ECS / AKS / GKE are the primary attack surface
  images      25% — image CVEs are the #1 supply-chain risk vector
  hosts       25% — OS/middleware CVEs (agent-scanned VMs)
  serverless  10% — Lambda / Azure Functions / GCF
  runtime     10% — runtime threat signals (privileged containers, etc.)
"""

from __future__ import annotations

from typing import Dict, List, Optional

WORKLOAD_WEIGHTS: Dict[str, float] = {
    "containers": 0.30,
    "images":     0.25,
    "hosts":      0.25,
    "serverless": 0.10,
    "runtime":    0.10,
}


def compute_cwpp_score(workload_results: List[Dict]) -> Optional[float]:
    """
    Weighted average of workload-type posture scores, skipping unavailable types.

    Args:
        workload_results: list of workload dicts, each with:
            workload_type (str), status (str), posture_score (float|None)

    Returns:
        Rounded score 0-100, or None if no workload has data.
    """
    total_weight = 0.0
    weighted_sum = 0.0

    for w in workload_results:
        wtype = w.get("workload_type")
        score = w.get("posture_score")
        if score is None or w.get("status") == "unavailable":
            continue
        weight = WORKLOAD_WEIGHTS.get(wtype, 0.0)
        weighted_sum += score * weight
        total_weight += weight

    if total_weight == 0:
        return None

    return round(weighted_sum / total_weight, 1)


def risk_band(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 80:
        return "low"
    if score >= 60:
        return "medium"
    if score >= 40:
        return "high"
    return "critical"


def severity_to_score_penalty(critical: int, high: int, medium: int, total: int) -> float:
    """
    Convert finding severity counts to a posture score (0-100, higher = safer).
    Used when an engine does not return a pre-computed posture score.
    """
    if total == 0:
        return 100.0
    penalty = min(critical * 8 + high * 3 + medium * 1, 80)
    return round(max(100 - penalty, 20), 1)
