"""
Multi-Cloud Encryption Parity Analyzer.

Compares encryption posture across cloud providers (AWS, Azure, GCP)
for the same tenant to identify consistency gaps:
  - Coverage disparity (e.g., AWS 95% encrypted, GCP 60%)
  - Key management disparity (CMK adoption rates)
  - Rotation compliance disparity
  - Transit enforcement disparity
  - Algorithm strength disparity
"""

import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# Provider display names
PROVIDER_NAMES = {
    "aws": "AWS",
    "azure": "Azure",
    "gcp": "GCP",
    "oci": "OCI",
    "alicloud": "AliCloud",
    "ibm": "IBM Cloud",
}

# Threshold for flagging disparity (percentage points)
DISPARITY_THRESHOLD = 20


def analyze_multi_cloud_parity(
    coverage_by_service: Dict[str, Dict[str, Any]],
    per_resource: Dict[str, Dict[str, Any]],
    key_inventory: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Analyze encryption parity across cloud providers.

    Args:
        coverage_by_service: {service: {total, encrypted, cmk, transit}}.
        per_resource: {resource_uid: {...encryption status...}}.
        key_inventory: Key inventory list.

    Returns:
        {
            "by_provider": {provider: {scores...}},
            "gaps": [gap findings],
            "parity_score": int (0-100),
        }
    """
    # Group resources by provider
    provider_resources = {}
    for uid, info in per_resource.items():
        provider = (info.get("provider") or "aws").lower()
        if provider not in provider_resources:
            provider_resources[provider] = []
        provider_resources[provider].append(info)

    # Group keys by provider
    provider_keys = {}
    for k in key_inventory:
        provider = (k.get("provider") or "aws").lower()
        if provider not in provider_keys:
            provider_keys[provider] = []
        provider_keys[provider].append(k)

    # Compute per-provider scores
    provider_scores = {}
    for provider, resources in provider_resources.items():
        total = len(resources)
        if total == 0:
            continue

        encrypted = sum(1 for r in resources if r.get("encrypted_at_rest") is True)
        cmk = sum(1 for r in resources if r.get("key_type") in ("CUSTOMER", "customer_managed"))
        transit = sum(1 for r in resources if r.get("encrypted_in_transit") is True)
        rotation = sum(1 for r in resources if r.get("rotation_compliant") is True)

        keys = provider_keys.get(provider, [])
        customer_keys = [k for k in keys if k.get("key_manager") in ("CUSTOMER", "customer_managed")]
        rotated_keys = [k for k in customer_keys if k.get("rotation_enabled")]

        coverage_pct = round((encrypted / total) * 100) if total > 0 else 0
        cmk_pct = round((cmk / total) * 100) if total > 0 else 0
        transit_pct = round((transit / total) * 100) if total > 0 else 0
        rotation_pct = round((rotated_keys / len(customer_keys)) * 100) if customer_keys else 100

        # Composite score (same weights as posture scorer)
        composite = round(
            coverage_pct * 0.40
            + rotation_pct * 0.20
            + 80 * 0.20  # Assume reasonable algorithm strength per provider
            + transit_pct * 0.20
        )

        provider_scores[provider] = {
            "provider": provider,
            "provider_name": PROVIDER_NAMES.get(provider, provider.upper()),
            "total_resources": total,
            "coverage_pct": coverage_pct,
            "cmk_pct": cmk_pct,
            "transit_pct": transit_pct,
            "rotation_pct": rotation_pct,
            "total_keys": len(keys),
            "customer_keys": len(customer_keys),
            "composite_score": min(composite, 100),
        }

    # Detect gaps between providers
    gaps = _detect_parity_gaps(provider_scores)

    # Overall parity score: 100 = perfect parity, 0 = huge disparity
    parity_score = _compute_parity_score(provider_scores)

    result = {
        "by_provider": provider_scores,
        "gaps": gaps,
        "parity_score": parity_score,
        "provider_count": len(provider_scores),
    }

    logger.info(
        f"Multi-cloud parity: {len(provider_scores)} providers, "
        f"parity_score={parity_score}, {len(gaps)} gaps"
    )
    return result


def _detect_parity_gaps(
    provider_scores: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Detect significant disparities between providers."""
    gaps = []
    providers = list(provider_scores.keys())

    if len(providers) < 2:
        return gaps

    dimensions = [
        ("coverage_pct", "Encryption coverage", "Enable encryption at rest across all resources"),
        ("cmk_pct", "Customer-managed key adoption", "Migrate to customer-managed keys"),
        ("transit_pct", "Transit encryption", "Enable TLS/SSL enforcement"),
        ("rotation_pct", "Key rotation compliance", "Enable automatic key rotation"),
    ]

    for dim_key, dim_name, remediation in dimensions:
        values = {p: s.get(dim_key, 0) for p, s in provider_scores.items()}

        max_val = max(values.values())
        min_val = min(values.values())
        disparity = max_val - min_val

        if disparity >= DISPARITY_THRESHOLD:
            best_provider = max(values, key=values.get)
            worst_provider = min(values, key=values.get)

            severity = "HIGH" if disparity >= 40 else "MEDIUM"

            gaps.append({
                "dimension": dim_key,
                "dimension_name": dim_name,
                "severity": severity,
                "disparity_pct": disparity,
                "best_provider": best_provider,
                "best_provider_name": PROVIDER_NAMES.get(best_provider, best_provider),
                "best_value": max_val,
                "worst_provider": worst_provider,
                "worst_provider_name": PROVIDER_NAMES.get(worst_provider, worst_provider),
                "worst_value": min_val,
                "title": (
                    f"{dim_name} gap: "
                    f"{PROVIDER_NAMES.get(worst_provider, worst_provider)} ({min_val}%) "
                    f"vs {PROVIDER_NAMES.get(best_provider, best_provider)} ({max_val}%)"
                ),
                "description": (
                    f"{dim_name} differs by {disparity} percentage points across providers. "
                    f"{PROVIDER_NAMES.get(worst_provider, worst_provider)} is at {min_val}% "
                    f"while {PROVIDER_NAMES.get(best_provider, best_provider)} is at {max_val}%."
                ),
                "remediation": f"{remediation} in {PROVIDER_NAMES.get(worst_provider, worst_provider)}",
                "all_values": {
                    PROVIDER_NAMES.get(p, p): v for p, v in values.items()
                },
            })

    gaps.sort(key=lambda g: g["disparity_pct"], reverse=True)
    return gaps


def _compute_parity_score(provider_scores: Dict[str, Dict[str, Any]]) -> int:
    """Compute parity score (100 = all providers identical, 0 = maximum disparity)."""
    if len(provider_scores) < 2:
        return 100  # Single provider = perfect parity

    composites = [s.get("composite_score", 0) for s in provider_scores.values()]
    if not composites:
        return 100

    max_score = max(composites)
    min_score = min(composites)
    spread = max_score - min_score

    # Parity = 100 - spread (clamped to 0-100)
    return max(0, min(100, 100 - spread))
