"""
AI Posture Scorer.

Computes weighted posture scores across 6 AI security modules:
  - model_security    (20%)
  - endpoint_security (25%)
  - prompt_security   (20%)
  - data_pipeline     (10%)
  - ai_governance     (10%)
  - access_control    (15%)
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Module weights (must sum to 1.0)
MODULE_WEIGHTS: Dict[str, float] = {
    "model_security": 0.20,
    "endpoint_security": 0.25,
    "prompt_security": 0.20,
    "data_pipeline": 0.10,
    "ai_governance": 0.10,
    "access_control": 0.15,
}

# Rule ID prefix -> module mapping
RULE_TO_MODULE: Dict[str, str] = {
    "AI-MOD": "model_security",
    "AI-EP": "endpoint_security",
    "AI-PS": "prompt_security",
    "AI-DP": "data_pipeline",
    "AI-GOV": "ai_governance",
    "AI-AC": "access_control",
}

# Severity penalty weights for per-module scoring
_SEVERITY_PENALTY: Dict[str, int] = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 3,
    "LOW": 1,
}


def _rule_to_module(rule_id: str) -> str:
    """Map a rule_id to its AI security module."""
    for prefix, module in RULE_TO_MODULE.items():
        if rule_id.startswith(prefix):
            return module
    return "model_security"


class AIPostureScorer:
    """Computes weighted posture scores for AI security modules."""

    def compute_scores(
        self,
        findings: List[Dict[str, Any]],
        inventory: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Compute per-module and overall posture scores.

        Per-module score = max(0, 100 - (critical*20 + high*10 + medium*3 + low*1))
        Overall score = weighted average of module scores

        Args:
            findings: AI security findings with rule_id, severity, status.
            inventory: AI inventory entries with security posture fields.

        Returns:
            Dict with overall_score, module_scores, coverage_metrics, risk_score.
        """
        # Count FAIL findings per module per severity
        module_severity_counts: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        )

        for f in (findings or []):
            status = (f.get("status") or "").upper()
            if status != "FAIL":
                continue
            rule_id = f.get("rule_id", "")
            severity = (f.get("severity") or "MEDIUM").upper()
            module = _rule_to_module(rule_id)
            if severity in module_severity_counts[module]:
                module_severity_counts[module][severity] += 1

        # Compute per-module scores
        module_scores: Dict[str, float] = {}
        for module in MODULE_WEIGHTS:
            counts = module_severity_counts.get(module, {})
            penalty = sum(
                counts.get(sev, 0) * weight
                for sev, weight in _SEVERITY_PENALTY.items()
            )
            module_scores[module] = max(0.0, 100.0 - penalty)

        # Weighted overall score
        overall_score = sum(
            module_scores.get(module, 100.0) * weight
            for module, weight in MODULE_WEIGHTS.items()
        )
        overall_score = round(min(overall_score, 100.0), 1)

        # Coverage metrics from inventory
        coverage = _compute_coverage_metrics(inventory or [])

        # Risk score is inverse of posture (0 = no risk, 100 = maximum risk)
        risk_score = round(max(0.0, 100.0 - overall_score), 1)

        result = {
            "overall_score": overall_score,
            "module_scores": {k: round(v, 1) for k, v in module_scores.items()},
            "coverage_metrics": coverage,
            "risk_score": risk_score,
            "details": {
                "total_findings": len(findings or []),
                "fail_findings": sum(
                    1 for f in (findings or [])
                    if (f.get("status") or "").upper() == "FAIL"
                ),
                "pass_findings": sum(
                    1 for f in (findings or [])
                    if (f.get("status") or "").upper() == "PASS"
                ),
                "total_ml_resources": len(inventory or []),
                "severity_breakdown": {
                    module: dict(counts)
                    for module, counts in module_severity_counts.items()
                },
            },
        }

        logger.info(
            "AI posture score: %.1f (risk=%.1f) across %d modules, %d resources",
            overall_score,
            risk_score,
            len(module_scores),
            len(inventory or []),
        )
        return result


def _compute_coverage_metrics(
    inventory: List[Dict[str, Any]],
) -> Dict[str, float]:
    """Compute security coverage percentages across AI inventory.

    Metrics:
        - vpc_isolation_pct: % ML resources with VPC isolation
        - encryption_rest_pct: % with encryption at rest
        - encryption_transit_pct: % with encryption in transit
        - model_card_pct: % models with model cards
        - monitoring_pct: % with monitoring enabled
        - guardrails_pct: % LLM endpoints with guardrails

    Args:
        inventory: AI inventory entries.

    Returns:
        Dict of coverage percentages (0.0-100.0).
    """
    total = len(inventory)
    if total == 0:
        return {
            "vpc_isolation_pct": 0.0,
            "encryption_rest_pct": 0.0,
            "encryption_transit_pct": 0.0,
            "model_card_pct": 0.0,
            "monitoring_pct": 0.0,
            "guardrails_pct": 0.0,
        }

    vpc_count = sum(1 for r in inventory if r.get("is_vpc_isolated"))
    enc_rest_count = sum(1 for r in inventory if r.get("encryption_at_rest"))
    enc_transit_count = sum(1 for r in inventory if r.get("encryption_in_transit"))
    model_card_count = sum(1 for r in inventory if r.get("has_model_card"))
    monitoring_count = sum(1 for r in inventory if r.get("has_monitoring"))

    # Guardrails only applies to LLM/generative models
    llm_resources = [
        r for r in inventory
        if (r.get("model_type") or "").lower() in ("llm", "generative")
    ]
    llm_total = len(llm_resources)
    guardrails_count = sum(1 for r in llm_resources if r.get("has_guardrails"))

    def _pct(count: int, denominator: int) -> float:
        return round((count / denominator) * 100, 2) if denominator > 0 else 0.0

    return {
        "vpc_isolation_pct": _pct(vpc_count, total),
        "encryption_rest_pct": _pct(enc_rest_count, total),
        "encryption_transit_pct": _pct(enc_transit_count, total),
        "model_card_pct": _pct(model_card_count, total),
        "monitoring_pct": _pct(monitoring_count, total),
        "guardrails_pct": _pct(guardrails_count, llm_total),
    }
