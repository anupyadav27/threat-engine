"""
Blast Radius Calculator.

Given a KMS key, computes the impact of key deletion/disabling:
- Lists all dependent resources
- Classifies severity based on data classification and exposure
- Computes aggregate blast radius score
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# Severity weights for blast radius scoring
DATA_CLASSIFICATION_WEIGHTS = {
    "restricted": 4,
    "confidential": 3,
    "internal": 2,
    "public": 1,
}

EXPOSURE_WEIGHTS = {
    "public_access": 4,
    "cross_account": 3,
    "vpc_only": 2,
    "private": 1,
}


def calculate_blast_radius(
    key_arn: str,
    dependency_graph,
    datasec_classification: Optional[Dict[str, Dict]] = None,
) -> Dict[str, Any]:
    """Calculate blast radius for a KMS key.

    Args:
        key_arn: The KMS key ARN to analyze.
        dependency_graph: DependencyGraph instance.
        datasec_classification: Optional {resource_uid: {data_classification, is_public, ...}}.

    Returns:
        {
            "key_arn": str,
            "key_metadata": {...},
            "total_affected": int,
            "blast_radius_score": int (0-100),
            "severity": str (CRITICAL/HIGH/MEDIUM/LOW),
            "affected_resources": [
                {
                    "resource_uid": str,
                    "resource_type": str,
                    "data_classification": str,
                    "impact_severity": str,
                    "impact_score": int,
                    ...
                }
            ],
            "by_severity": {CRITICAL: N, HIGH: N, ...},
            "by_type": {resource_type: N, ...},
        }
    """
    datasec_classification = datasec_classification or {}

    # Get dependent resources
    dependent_uids = dependency_graph.get_resources_for_key(key_arn)
    key_meta = dependency_graph.key_metadata.get(key_arn, {})

    if not dependent_uids:
        return {
            "key_arn": key_arn,
            "key_metadata": key_meta,
            "total_affected": 0,
            "blast_radius_score": 0,
            "severity": "LOW",
            "affected_resources": [],
            "by_severity": {},
            "by_type": {},
        }

    affected_resources = []
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_type = {}
    total_impact_score = 0

    for uid in dependent_uids:
        resource_meta = dependency_graph.resource_metadata.get(uid, {})
        datasec_info = datasec_classification.get(uid, {})

        # Determine data classification
        data_class = (
            datasec_info.get("data_classification")
            or resource_meta.get("data_classification")
            or "internal"
        )
        if isinstance(data_class, list):
            # Take the most sensitive classification
            data_class = _most_sensitive_classification(data_class)

        # Determine exposure level
        is_public = datasec_info.get("is_public") or resource_meta.get("is_public", False)
        is_cross_account = datasec_info.get("cross_account_access") or resource_meta.get("cross_account_access", False)

        if is_public:
            exposure = "public_access"
        elif is_cross_account:
            exposure = "cross_account"
        else:
            exposure = "private"

        # Compute impact score for this resource
        class_weight = DATA_CLASSIFICATION_WEIGHTS.get(data_class, 2)
        exposure_weight = EXPOSURE_WEIGHTS.get(exposure, 1)
        impact_score = class_weight * exposure_weight

        # Map score to severity
        if impact_score >= 12:
            impact_severity = "CRITICAL"
        elif impact_score >= 6:
            impact_severity = "HIGH"
        elif impact_score >= 3:
            impact_severity = "MEDIUM"
        else:
            impact_severity = "LOW"

        resource_type = resource_meta.get("resource_type", "unknown")

        affected_resources.append({
            "resource_uid": uid,
            "resource_type": resource_type,
            "service": resource_meta.get("service") or resource_meta.get("data_store_service"),
            "account_id": resource_meta.get("account_id"),
            "region": resource_meta.get("region"),
            "data_classification": data_class,
            "exposure": exposure,
            "impact_severity": impact_severity,
            "impact_score": impact_score,
        })

        by_severity[impact_severity] = by_severity.get(impact_severity, 0) + 1
        by_type[resource_type] = by_type.get(resource_type, 0) + 1
        total_impact_score += impact_score

    # Aggregate blast radius score (0-100)
    # Scale: max score is 16 per resource (restricted + public_access)
    max_possible = len(dependent_uids) * 16
    blast_radius_score = min(100, round((total_impact_score / max_possible) * 100)) if max_possible > 0 else 0

    # Boost score if many resources are affected
    count_factor = min(1.0, len(dependent_uids) / 10.0)  # cap at 10+ resources
    blast_radius_score = min(100, round(blast_radius_score * (0.5 + 0.5 * count_factor) + count_factor * 20))

    # Overall severity
    if by_severity.get("CRITICAL", 0) > 0 or blast_radius_score >= 80:
        overall_severity = "CRITICAL"
    elif by_severity.get("HIGH", 0) > 0 or blast_radius_score >= 50:
        overall_severity = "HIGH"
    elif blast_radius_score >= 25:
        overall_severity = "MEDIUM"
    else:
        overall_severity = "LOW"

    # Sort affected resources by impact score descending
    affected_resources.sort(key=lambda r: r["impact_score"], reverse=True)

    result = {
        "key_arn": key_arn,
        "key_metadata": {
            "key_id": key_meta.get("key_id"),
            "key_alias": key_meta.get("key_alias"),
            "key_state": key_meta.get("key_state"),
            "key_manager": key_meta.get("key_manager"),
            "region": key_meta.get("region"),
            "account_id": key_meta.get("account_id"),
        },
        "total_affected": len(dependent_uids),
        "blast_radius_score": blast_radius_score,
        "severity": overall_severity,
        "affected_resources": affected_resources,
        "by_severity": {k: v for k, v in by_severity.items() if v > 0},
        "by_type": by_type,
    }

    logger.info(
        f"Blast radius for {key_arn}: {len(dependent_uids)} resources, "
        f"score={blast_radius_score}, severity={overall_severity}"
    )
    return result


def calculate_all_blast_radii(
    dependency_graph,
    datasec_classification: Optional[Dict[str, Dict]] = None,
) -> List[Dict[str, Any]]:
    """Calculate blast radius for all KMS keys in the graph.

    Returns list sorted by blast_radius_score descending.
    """
    results = []
    for key_arn in dependency_graph.key_to_resources:
        result = calculate_blast_radius(key_arn, dependency_graph, datasec_classification)
        if result["total_affected"] > 0:
            results.append(result)

    results.sort(key=lambda r: r["blast_radius_score"], reverse=True)
    logger.info(f"Computed blast radius for {len(results)} keys with dependencies")
    return results


def _most_sensitive_classification(classifications: list) -> str:
    """Return the most sensitive classification from a list."""
    priority = {"restricted": 0, "confidential": 1, "internal": 2, "public": 3}
    best = "internal"
    best_rank = 99
    for c in classifications:
        rank = priority.get(str(c).lower(), 99)
        if rank < best_rank:
            best_rank = rank
            best = str(c).lower()
    return best
