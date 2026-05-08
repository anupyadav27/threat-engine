"""
Remediation Prioritizer.

Scores and ranks encryption findings by composite priority:
  priority = severity_weight × sensitivity_weight × exposure_weight

Higher scores should be remediated first.
"""

import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Severity weights
SEVERITY_WEIGHTS = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}

# Data classification sensitivity weights
SENSITIVITY_WEIGHTS = {
    "restricted": 4,
    "confidential": 3,
    "internal": 2,
    "public": 1,
}

# Exposure weights
EXPOSURE_WEIGHTS = {
    "public_access": 4,
    "cross_account": 3,
    "vpc_only": 2,
    "private": 1,
}


def prioritize_findings(
    findings: List[Dict[str, Any]],
    cross_ref_findings: List[Dict[str, Any]],
    datasec_classification: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Compute composite priority scores and rank findings.

    Args:
        findings: Encryption findings from coverage analysis.
        cross_ref_findings: Cross-reference findings from sensitivity_cross_ref.
        datasec_classification: {resource_uid: {data_classification, is_public, ...}}.

    Returns:
        Merged, deduplicated, priority-scored findings sorted by priority descending.
    """
    # Merge findings, dedup by resource_uid + domain
    seen = set()
    all_findings = []

    # Cross-ref findings get priority (they have sensitivity context)
    for f in cross_ref_findings:
        key = f"{f.get('resource_uid')}|{f.get('cross_ref_type', '')}"
        if key not in seen:
            seen.add(key)
            all_findings.append(f)

    # Add regular findings not already covered
    for f in findings:
        key = f"{f.get('resource_uid')}|{f.get('encryption_domain', '')}"
        if key not in seen:
            seen.add(key)
            all_findings.append(f)

    # Score each finding
    scored = []
    for f in all_findings:
        resource_uid = f.get("resource_uid", "")
        severity = f.get("severity", "MEDIUM").upper()
        classification_info = datasec_classification.get(resource_uid, {})

        # Severity weight
        sev_weight = SEVERITY_WEIGHTS.get(severity, 2)

        # Sensitivity weight
        data_class = (
            f.get("data_classification")
            or classification_info.get("data_classification")
            or "internal"
        )
        if isinstance(data_class, list):
            data_class = data_class[0] if data_class else "internal"
        sens_weight = SENSITIVITY_WEIGHTS.get(str(data_class).lower(), 2)

        # Exposure weight
        is_public = classification_info.get("is_public") or f.get("is_public", False)
        is_cross_account = classification_info.get("cross_account_access", False)

        if is_public:
            exposure = "public_access"
        elif is_cross_account:
            exposure = "cross_account"
        else:
            exposure = "private"
        exp_weight = EXPOSURE_WEIGHTS.get(exposure, 1)

        # Composite priority score (max = 4 * 4 * 4 = 64)
        priority_score = sev_weight * sens_weight * exp_weight

        # Normalize to 0-100
        normalized_score = min(100, round((priority_score / 64) * 100))

        scored.append({
            **f,
            "priority_score": normalized_score,
            "priority_raw": priority_score,
            "severity_weight": sev_weight,
            "sensitivity_weight": sens_weight,
            "exposure_weight": exp_weight,
            "exposure": exposure,
            "priority_label": _priority_label(normalized_score),
        })

    # Sort by priority score descending
    scored.sort(key=lambda x: x["priority_score"], reverse=True)

    logger.info(
        f"Prioritized {len(scored)} findings — "
        f"top score: {scored[0]['priority_score'] if scored else 0}"
    )
    return scored


def get_top_remediations(
    prioritized: List[Dict[str, Any]],
    top_n: int = 10,
) -> List[Dict[str, Any]]:
    """Get the top N highest-priority remediation items.

    Returns concise remediation cards for the UI.
    """
    results = []
    for f in prioritized[:top_n]:
        results.append({
            "resource_uid": f.get("resource_uid"),
            "resource_type": f.get("resource_type"),
            "service": f.get("service"),
            "account_id": f.get("account_id"),
            "region": f.get("region"),
            "severity": f.get("severity"),
            "priority_score": f.get("priority_score"),
            "priority_label": f.get("priority_label"),
            "title": f.get("title", _default_title(f)),
            "description": f.get("description", ""),
            "remediation": f.get("remediation", ""),
            "data_classification": f.get("data_classification"),
            "encryption_status": f.get("encryption_status"),
            "exposure": f.get("exposure"),
        })
    return results


def _priority_label(score: int) -> str:
    """Map score to priority label."""
    if score >= 75:
        return "P1-URGENT"
    elif score >= 50:
        return "P2-HIGH"
    elif score >= 25:
        return "P3-MEDIUM"
    return "P4-LOW"


def _default_title(finding: Dict) -> str:
    """Generate a default title for a finding without one."""
    domain = finding.get("encryption_domain", "encryption")
    status = finding.get("encryption_status", "unknown")
    rtype = finding.get("resource_type", "resource")
    return f"{domain.replace('_', ' ').title()} issue on {rtype} ({status})"
