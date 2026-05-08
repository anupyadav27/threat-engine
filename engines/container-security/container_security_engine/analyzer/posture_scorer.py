"""
Posture Scorer — Compute per-cluster and overall container security posture scores.

Scoring model:
  - Per-resource, per-domain: PASS / (PASS + FAIL) ratio scaled to 0-100
  - Domain weights (sum = 100%):
      cluster_security   25%
      workload_security  20%
      image_security     20%
      network_exposure   15%
      rbac_access        15%
      runtime_audit       5%
  - Overall posture = weighted average of domain scores
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional

from .rule_categorizer import categorize_finding, get_service_from_rule, is_container_rule

logger = logging.getLogger(__name__)

# ── Domain weights (must sum to 1.0) ────────────────────────────────────────
DOMAIN_WEIGHTS: Dict[str, float] = {
    "cluster_security": 0.25,
    "workload_security": 0.20,
    "image_security": 0.20,
    "network_exposure": 0.15,
    "rbac_access": 0.15,
    "runtime_audit": 0.05,
}

ALL_DOMAINS = list(DOMAIN_WEIGHTS.keys())


def _score_from_counts(pass_count: int, fail_count: int) -> float:
    """Compute a 0-100 score from pass/fail counts.

    Args:
        pass_count: Number of passing checks.
        fail_count: Number of failing checks.

    Returns:
        Score between 0.0 and 100.0.  Returns 100.0 when there are no
        findings at all (no checks evaluated = no issues found).
    """
    total = pass_count + fail_count
    if total == 0:
        return 100.0
    return round((pass_count / total) * 100.0, 1)


def _compute_domain_scores(
    domain_counts: Dict[str, Dict[str, int]],
) -> Dict[str, Dict[str, Any]]:
    """Turn per-domain pass/fail counts into scored domain entries.

    Args:
        domain_counts: ``{domain: {"pass": N, "fail": N}}``

    Returns:
        ``{domain: {"score": float, "pass_count": int, "fail_count": int, "total": int}}``
    """
    result: Dict[str, Dict[str, Any]] = {}
    for domain in ALL_DOMAINS:
        counts = domain_counts.get(domain, {"pass": 0, "fail": 0})
        pc = counts.get("pass", 0)
        fc = counts.get("fail", 0)
        result[domain] = {
            "score": _score_from_counts(pc, fc),
            "pass_count": pc,
            "fail_count": fc,
            "total": pc + fc,
        }
    return result


def _weighted_overall(domain_scores: Dict[str, Dict[str, Any]]) -> float:
    """Compute the weighted overall posture score.

    Args:
        domain_scores: Output of ``_compute_domain_scores``.

    Returns:
        Weighted score 0-100, rounded to one decimal.
    """
    total_weight = 0.0
    weighted_sum = 0.0
    for domain, weight in DOMAIN_WEIGHTS.items():
        entry = domain_scores.get(domain)
        if entry and entry["total"] > 0:
            weighted_sum += entry["score"] * weight
            total_weight += weight

    if total_weight == 0.0:
        return 100.0
    return round(weighted_sum / total_weight * 1.0, 1)


def compute_posture_scores(
    findings: List[Dict[str, Any]],
    container_inventory: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Compute per-cluster and overall posture scores from check findings.

    Args:
        findings: List of check finding dicts.  Each must contain at least
                  ``rule_id``, ``resource_uid``, and ``status`` ('PASS'/'FAIL').
        container_inventory: Optional list of inventory entries. When provided,
                             every resource_uid in the inventory will appear in
                             the output even if it has zero findings.

    Returns:
        Dict with structure::

            {
                "overall_score": float,
                "domain_scores": {domain: {score, pass_count, fail_count, total}},
                "per_cluster": {
                    resource_uid: {
                        "container_service": str,
                        "overall_score": float,
                        "domain_scores": {...},
                        "finding_count": int,
                        "fail_count": int,
                    }
                },
                "summary": {
                    "total_containers": int,
                    "total_findings": int,
                    "total_pass": int,
                    "total_fail": int,
                    "containers_at_risk": int,
                },
            }
    """
    # ── Accumulate counts per resource per domain ────────────────────────
    # {resource_uid: {domain: {"pass": N, "fail": N}}}
    per_cluster: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: {"pass": 0, "fail": 0})
    )
    # {resource_uid: service}
    cluster_services: Dict[str, str] = {}

    # Global domain counts
    global_counts: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"pass": 0, "fail": 0}
    )

    total_pass = 0
    total_fail = 0
    container_findings_included = 0

    for f in findings:
        rule_id = f.get("rule_id", "")
        if not is_container_rule(rule_id):
            continue

        resource_uid = f.get("resource_uid", "unknown")
        status = (f.get("status") or "").upper()
        domain = categorize_finding(rule_id, f)
        service = get_service_from_rule(rule_id)

        if service:
            cluster_services[resource_uid] = service

        container_findings_included += 1

        if status == "PASS":
            per_cluster[resource_uid][domain]["pass"] += 1
            global_counts[domain]["pass"] += 1
            total_pass += 1
        else:
            per_cluster[resource_uid][domain]["fail"] += 1
            global_counts[domain]["fail"] += 1
            total_fail += 1

    # Ensure inventory resources appear even with zero findings
    if container_inventory:
        for inv in container_inventory:
            uid = inv.get("resource_uid", "")
            if uid and uid not in per_cluster:
                per_cluster[uid]  # creates defaultdict entry
            svc = inv.get("container_service")
            if uid and svc:
                cluster_services.setdefault(uid, svc)

    # ── Per-cluster scores ───────────────────────────────────────────────
    per_cluster_output: Dict[str, Dict[str, Any]] = {}
    containers_at_risk = 0

    for resource_uid, domain_map in per_cluster.items():
        d_scores = _compute_domain_scores(dict(domain_map))
        overall = _weighted_overall(d_scores)

        cl_fail = sum(d["fail_count"] for d in d_scores.values())
        cl_total = sum(d["total"] for d in d_scores.values())

        if cl_fail > 0:
            containers_at_risk += 1

        per_cluster_output[resource_uid] = {
            "container_service": cluster_services.get(resource_uid, "unknown"),
            "overall_score": overall,
            "domain_scores": d_scores,
            "finding_count": cl_total,
            "fail_count": cl_fail,
        }

    # ── Global scores ────────────────────────────────────────────────────
    global_domain_scores = _compute_domain_scores(dict(global_counts))
    overall_score = _weighted_overall(global_domain_scores)

    return {
        "overall_score": overall_score,
        "domain_scores": global_domain_scores,
        "per_cluster": per_cluster_output,
        "summary": {
            "total_containers": len(per_cluster),
            "total_findings": container_findings_included,
            "total_pass": total_pass,
            "total_fail": total_fail,
            "containers_at_risk": containers_at_risk,
        },
    }
