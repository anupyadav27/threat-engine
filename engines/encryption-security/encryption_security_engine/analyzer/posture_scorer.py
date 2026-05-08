"""
Encryption Posture Scorer.

Computes a weighted 0-100 posture score across four dimensions:
  - Coverage (40%): % of resources encrypted at rest
  - Rotation (20%): % of KMS keys with rotation enabled
  - Algorithm strength (20%): weighted average of algorithm scores
  - Transit (20%): % of resources with in-transit encryption
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Algorithm strength scores (0-100)
ALGORITHM_SCORES = {
    # Symmetric
    "AES-256": 100, "AES_256": 100, "aws:kms": 95,
    "SYMMETRIC_DEFAULT": 95,
    "AES-128": 70, "AES_128": 70,
    # Asymmetric RSA
    "RSA_4096": 100, "RSA-4096": 100,
    "RSA_3072": 90, "RSA-3072": 90,
    "RSA_2048": 80, "RSA-2048": 80,
    "RSA_1024": 30, "RSA-1024": 30,
    # Elliptic Curve
    "EC_secp384r1": 100, "ECC_NIST_P384": 100,
    "EC_prime256v1": 95, "ECC_NIST_P256": 95,
    "ECC_SECG_P256K1": 90,
    # Deprecated / weak
    "DES": 0, "3DES": 10, "RC4": 0, "MD5": 0,
}

DEFAULT_ALGORITHM_SCORE = 50  # Unknown algorithms


def compute_posture_score(
    coverage_data: Dict[str, Any],
    key_inventory: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute the overall encryption posture score.

    Args:
        coverage_data: Output from coverage_analyzer.analyze_coverage().
        key_inventory: List of key inventory dicts from key_inventory_builder.

    Returns:
        {
            "posture_score": int (0-100),
            "coverage_score": int,
            "rotation_score": int,
            "algorithm_score": int,
            "transit_score": int,
            "details": {...breakdown...},
        }
    """
    totals = coverage_data.get("totals", {})
    per_resource = coverage_data.get("per_resource", {})

    # 1. Coverage score: % resources encrypted at rest
    total = totals.get("total", 0)
    encrypted = totals.get("encrypted", 0)
    coverage_score = round((encrypted / total) * 100) if total > 0 else 0

    # 2. Rotation score: % KMS customer keys with rotation enabled
    customer_keys = [k for k in key_inventory if k.get("key_manager") in ("CUSTOMER", "customer_managed")]
    rotated_keys = [k for k in customer_keys if k.get("rotation_enabled")]
    rotation_score = round((len(rotated_keys) / len(customer_keys)) * 100) if customer_keys else 100

    # 3. Algorithm strength score: weighted average across all resources
    algo_scores = []
    for uid, info in per_resource.items():
        algo = info.get("algorithm")
        if algo:
            score = _get_algorithm_score(algo)
            algo_scores.append(score)
    algorithm_score = round(sum(algo_scores) / len(algo_scores)) if algo_scores else DEFAULT_ALGORITHM_SCORE

    # 4. Transit score: % resources with in-transit encryption
    transit_total = sum(1 for r in per_resource.values() if r.get("encrypted_in_transit") is not None)
    transit_encrypted = totals.get("transit", 0)
    transit_score = round((transit_encrypted / transit_total) * 100) if transit_total > 0 else 0

    # Weighted composite (40-20-20-20)
    posture_score = round(
        coverage_score * 0.40
        + rotation_score * 0.20
        + algorithm_score * 0.20
        + transit_score * 0.20
    )

    result = {
        "posture_score": min(posture_score, 100),
        "coverage_score": coverage_score,
        "rotation_score": rotation_score,
        "algorithm_score": algorithm_score,
        "transit_score": transit_score,
        "details": {
            "total_resources": total,
            "encrypted_resources": encrypted,
            "unencrypted_resources": totals.get("unencrypted", 0),
            "cmk_resources": totals.get("cmk", 0),
            "transit_resources": transit_encrypted,
            "customer_keys_total": len(customer_keys),
            "customer_keys_rotated": len(rotated_keys),
            "algorithms_evaluated": len(algo_scores),
        },
    }

    logger.info(
        f"Posture score: {posture_score} "
        f"(coverage={coverage_score}, rotation={rotation_score}, "
        f"algorithm={algorithm_score}, transit={transit_score})"
    )
    return result


def _get_algorithm_score(algorithm: str) -> int:
    """Look up algorithm strength score."""
    if not algorithm:
        return DEFAULT_ALGORITHM_SCORE
    # Try exact match first, then case-insensitive
    score = ALGORITHM_SCORES.get(algorithm)
    if score is not None:
        return score
    for key, val in ALGORITHM_SCORES.items():
        if key.lower() == algorithm.lower():
            return val
    return DEFAULT_ALGORITHM_SCORE
