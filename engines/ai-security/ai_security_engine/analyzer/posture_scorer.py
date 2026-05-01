"""
AI Posture Scorer.

Computes weighted posture scores across 6 AI security modules:
  - model_security    (20%)
  - endpoint_security (25%)
  - prompt_security   (20%)
  - data_pipeline     (10%)
  - ai_governance     (10%)
  - access_control    (15%)

Rule → module lookup delegates to finding_categorizer (which queries rule_metadata).
MODULE_WEIGHTS and _SEVERITY_PENALTY are scoring formula constants, not data — kept in code.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

MODULE_WEIGHTS: Dict[str, float] = {
    "model_security":    0.20,
    "endpoint_security": 0.25,
    "prompt_security":   0.20,
    "data_pipeline":     0.10,
    "ai_governance":     0.10,
    "access_control":    0.15,
}

_SEVERITY_PENALTY: Dict[str, int] = {
    "CRITICAL": 20,
    "HIGH":     10,
    "MEDIUM":    3,
    "LOW":       1,
}


def _rule_to_module(rule_id: str) -> str:
    """Map a rule_id to its AI security module via rule_metadata (check DB)."""
    from .finding_categorizer import _map_check_rule_to_module
    return _map_check_rule_to_module(rule_id) or "model_security"


class AIPostureScorer:
    """Computes weighted posture scores for AI security modules."""

    def compute_scores(
        self,
        findings: List[Dict[str, Any]],
        inventory: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Compute per-module and overall posture scores.

        Per-module score = max(0, 100 - (critical*20 + high*10 + medium*3 + low*1))
        Overall score    = weighted average of module scores
        """
        module_severity_counts: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        )

        for f in (findings or []):
            if (f.get("status") or "").upper() != "FAIL":
                continue
            severity = (f.get("severity") or "MEDIUM").upper()
            module = _rule_to_module(f.get("rule_id", ""))
            if severity in module_severity_counts[module]:
                module_severity_counts[module][severity] += 1

        module_scores: Dict[str, float] = {}
        for module in MODULE_WEIGHTS:
            counts = module_severity_counts.get(module, {})
            penalty = sum(counts.get(sev, 0) * w for sev, w in _SEVERITY_PENALTY.items())
            module_scores[module] = max(0.0, 100.0 - penalty)

        overall_score = round(min(sum(
            module_scores.get(m, 100.0) * w for m, w in MODULE_WEIGHTS.items()
        ), 100.0), 1)

        coverage = _compute_coverage_metrics(inventory or [])
        risk_score = round(max(0.0, 100.0 - overall_score), 1)

        result = {
            "overall_score": overall_score,
            "module_scores": {k: round(v, 1) for k, v in module_scores.items()},
            "coverage_metrics": coverage,
            "risk_score": risk_score,
            "details": {
                "total_findings": len(findings or []),
                "fail_findings": sum(1 for f in (findings or []) if (f.get("status") or "").upper() == "FAIL"),
                "pass_findings": sum(1 for f in (findings or []) if (f.get("status") or "").upper() == "PASS"),
                "total_ml_resources": len(inventory or []),
                "severity_breakdown": {m: dict(c) for m, c in module_severity_counts.items()},
            },
        }

        logger.info("AI posture score: %.1f (risk=%.1f) across %d modules, %d resources",
                    overall_score, risk_score, len(module_scores), len(inventory or []))
        return result


def _compute_coverage_metrics(inventory: List[Dict[str, Any]]) -> Dict[str, float]:
    total = len(inventory)
    if total == 0:
        return {k: 0.0 for k in (
            "vpc_isolation_pct", "encryption_rest_pct", "encryption_transit_pct",
            "model_card_pct", "monitoring_pct", "guardrails_pct",
        )}

    def _pct(count: int, denom: int) -> float:
        return round((count / denom) * 100, 2) if denom > 0 else 0.0

    llm_resources = [r for r in inventory if (r.get("model_type") or "").lower() in ("llm", "generative")]

    return {
        "vpc_isolation_pct":      _pct(sum(1 for r in inventory if r.get("is_vpc_isolated")), total),
        "encryption_rest_pct":    _pct(sum(1 for r in inventory if r.get("encryption_at_rest")), total),
        "encryption_transit_pct": _pct(sum(1 for r in inventory if r.get("encryption_in_transit")), total),
        "model_card_pct":         _pct(sum(1 for r in inventory if r.get("has_model_card")), total),
        "monitoring_pct":         _pct(sum(1 for r in inventory if r.get("has_monitoring")), total),
        "guardrails_pct":         _pct(sum(1 for r in llm_resources if r.get("has_guardrails")), len(llm_resources)),
    }
