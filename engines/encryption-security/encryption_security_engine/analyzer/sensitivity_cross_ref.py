"""
Sensitive Data Cross-Reference.

Joins DataSec classification data with encryption coverage to flag:
- Sensitive data (PII/PHI/PCI) on unencrypted resources → CRITICAL
- Sensitive data with AWS-managed keys (not CMK) → HIGH
- Public resources with sensitive data lacking transit encryption → CRITICAL
"""

import logging
from typing import Dict, Any, List, Optional

from .coverage_analyzer import analyze_coverage

logger = logging.getLogger(__name__)

# Sensitivity weights by data type
SENSITIVITY_WEIGHTS = {
    "PII": 4, "PHI": 4, "PCI": 4,
    "SSN": 4, "CREDIT_CARD": 4,
    "EMAIL": 3, "PHONE": 3,
    "FINANCIAL": 3,
    "INTERNAL": 2,
    "PUBLIC": 1,
}


def cross_reference_sensitive_data(
    coverage_per_resource: Dict[str, Dict[str, Any]],
    datasec_findings: List[Dict[str, Any]],
    enhanced_data: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Cross-reference sensitive data classification with encryption coverage.

    Args:
        coverage_per_resource: {resource_uid: {encrypted_at_rest, key_type, ...}}
            from coverage_analyzer.
        datasec_findings: DataSec findings with data_classification and sensitivity_score.
        enhanced_data: DataSec enhanced rows with structured classification columns.

    Returns:
        List of cross-reference findings, each with elevated severity.
    """
    # Build classification map from datasec sources
    classification_map = {}  # resource_uid -> {classification, sensitivity, data_types, is_public}

    # From enhanced data (structured columns)
    for ed in enhanced_data:
        uid = ed.get("resource_arn", "")
        if not uid:
            continue
        classification_map[uid] = {
            "data_classification": ed.get("data_classification", "internal"),
            "detected_pii_types": ed.get("detected_pii_types") or [],
            "detected_phi_types": ed.get("detected_phi_types") or [],
            "detected_pci_types": ed.get("detected_pci_types") or [],
            "is_public": ed.get("is_public", False),
            "cross_account_access": ed.get("cross_account_access", False),
            "sensitivity_score": ed.get("classification_confidence", 0),
        }

    # From datasec findings (JSONB finding_data)
    for df in datasec_findings:
        uid = df.get("resource_uid", "")
        if not uid or uid in classification_map:
            continue
        data_class = df.get("data_classification") or []
        sensitivity = df.get("sensitivity_score") or 0
        fd = df.get("finding_data") or {}
        if not isinstance(fd, dict):
            fd = {}

        if data_class or sensitivity > 0:
            classification_map[uid] = {
                "data_classification": data_class[0] if data_class else "internal",
                "detected_pii_types": [c for c in data_class if c.upper() in SENSITIVITY_WEIGHTS],
                "detected_phi_types": [],
                "detected_pci_types": [],
                "is_public": fd.get("is_public", False),
                "cross_account_access": fd.get("cross_account_access", False),
                "sensitivity_score": sensitivity,
            }

    # Cross-reference: find sensitive resources with encryption gaps
    cross_ref_findings = []

    for uid, class_info in classification_map.items():
        enc_info = coverage_per_resource.get(uid)
        if not enc_info:
            continue  # No encryption data for this resource

        data_class = class_info.get("data_classification", "internal")
        if isinstance(data_class, list):
            data_class = data_class[0] if data_class else "internal"
        is_sensitive = data_class.lower() in ("restricted", "confidential")
        has_pii = bool(class_info.get("detected_pii_types"))
        has_phi = bool(class_info.get("detected_phi_types"))
        has_pci = bool(class_info.get("detected_pci_types"))
        is_public = class_info.get("is_public", False)

        # Skip non-sensitive resources
        if not (is_sensitive or has_pii or has_phi or has_pci):
            continue

        encrypted_at_rest = enc_info.get("encrypted_at_rest")
        encrypted_in_transit = enc_info.get("encrypted_in_transit")
        key_type = enc_info.get("key_type")

        findings_for_resource = []

        # Case 1: Sensitive + unencrypted at rest → CRITICAL
        if encrypted_at_rest is False:
            findings_for_resource.append({
                "cross_ref_type": "sensitive_unencrypted",
                "severity": "CRITICAL",
                "title": "Sensitive data on unencrypted resource",
                "description": (
                    f"Resource contains {_describe_data_types(class_info)} "
                    f"but encryption at rest is not enabled"
                ),
                "remediation": "Enable encryption at rest with a customer-managed KMS key",
            })

        # Case 2: Sensitive + AWS-managed key (not CMK) → HIGH
        elif key_type in (None, "none", "AWS", "aws_managed"):
            findings_for_resource.append({
                "cross_ref_type": "sensitive_no_cmk",
                "severity": "HIGH",
                "title": "Sensitive data encrypted with AWS-managed key",
                "description": (
                    f"Resource contains {_describe_data_types(class_info)} "
                    f"but uses AWS-managed encryption instead of customer-managed key"
                ),
                "remediation": "Migrate to customer-managed KMS key for granular access control",
            })

        # Case 3: Sensitive + public + no transit encryption → CRITICAL
        if is_public and encrypted_in_transit is not True:
            findings_for_resource.append({
                "cross_ref_type": "sensitive_public_no_transit",
                "severity": "CRITICAL",
                "title": "Publicly accessible sensitive data without transit encryption",
                "description": (
                    f"Resource is publicly accessible, contains {_describe_data_types(class_info)}, "
                    f"and does not enforce encryption in transit"
                ),
                "remediation": "Enable TLS enforcement and restrict public access",
            })

        # Case 4: Sensitive + no rotation → HIGH
        if enc_info.get("rotation_compliant") is False and is_sensitive:
            findings_for_resource.append({
                "cross_ref_type": "sensitive_no_rotation",
                "severity": "HIGH",
                "title": "Sensitive data encrypted with non-rotating key",
                "description": (
                    f"Resource contains {_describe_data_types(class_info)} "
                    f"but the encryption key does not have automatic rotation enabled"
                ),
                "remediation": "Enable automatic key rotation on the KMS key",
            })

        # Add all findings for this resource
        for finding in findings_for_resource:
            cross_ref_findings.append({
                "resource_uid": uid,
                "resource_type": enc_info.get("resource_type", ""),
                "service": enc_info.get("service", ""),
                "account_id": enc_info.get("account_id", ""),
                "region": enc_info.get("region", ""),
                "data_classification": data_class,
                "sensitivity_score": class_info.get("sensitivity_score", 0),
                "encryption_status": _enc_status(enc_info),
                "key_type": key_type,
                **finding,
            })

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    cross_ref_findings.sort(key=lambda f: severity_order.get(f["severity"], 9))

    logger.info(
        f"Sensitive data cross-ref: {len(cross_ref_findings)} findings "
        f"from {len(classification_map)} classified resources"
    )
    return cross_ref_findings


def _describe_data_types(class_info: Dict) -> str:
    """Build human-readable description of detected data types."""
    types = []
    if class_info.get("detected_pii_types"):
        types.append(f"PII ({', '.join(class_info['detected_pii_types'][:3])})")
    if class_info.get("detected_phi_types"):
        types.append(f"PHI ({', '.join(class_info['detected_phi_types'][:3])})")
    if class_info.get("detected_pci_types"):
        types.append(f"PCI ({', '.join(class_info['detected_pci_types'][:3])})")
    if not types:
        dc = class_info.get("data_classification", "sensitive")
        types.append(f"{dc} data")
    return ", ".join(types)


def _enc_status(info: Dict) -> str:
    """Determine encryption status string."""
    if info.get("encrypted_at_rest") is False:
        return "unencrypted"
    kt = info.get("key_type")
    if kt in ("CUSTOMER", "customer_managed"):
        return "encrypted_cmk"
    if info.get("encrypted_at_rest") is True:
        return "encrypted_managed"
    return "unknown"
