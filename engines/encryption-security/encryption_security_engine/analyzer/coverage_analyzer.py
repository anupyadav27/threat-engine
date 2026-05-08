"""
Encryption Coverage Analyzer.

Cross-references discovery, check, and datasec data to compute
per-resource encryption status and per-service coverage percentages.
"""

import logging
from typing import Dict, Any, List, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


def analyze_coverage(
    discovery_resources: Dict[str, List[Dict]],
    check_findings: List[Dict[str, Any]],
    datasec_findings: List[Dict[str, Any]],
    enhanced_data: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute encryption coverage across all resources.

    Args:
        discovery_resources: {service: [resources]} from DiscoveryReader.
        check_findings: Encryption check findings from CheckReader.
        datasec_findings: DataSec findings from DataSecReader.
        enhanced_data: Enhanced datasec_input_transformed rows.

    Returns:
        {
            "per_resource": {resource_uid: {...encryption status...}},
            "by_service": {service: {total, encrypted, cmk, transit}},
            "totals": {total, encrypted, unencrypted, cmk, transit},
        }
    """
    resource_map = {}  # resource_uid -> encryption status

    # 1. Seed from discovery resources (all resources are "known")
    for service, resources in discovery_resources.items():
        for r in resources:
            uid = r.get("resource_uid", "")
            if not uid:
                continue
            resource_map[uid] = {
                "resource_uid": uid,
                "resource_type": r.get("resource_type", ""),
                "service": service,
                "region": r.get("region", ""),
                "account_id": r.get("account_id", ""),
                "provider": r.get("provider", "aws"),
                "encrypted_at_rest": None,
                "encrypted_in_transit": None,
                "key_type": None,
                "algorithm": None,
                "rotation_compliant": None,
            }
            # Extract encryption fields from emitted_fields
            emitted = r.get("emitted_fields") or {}
            if isinstance(emitted, dict):
                _enrich_from_emitted(resource_map[uid], emitted, service)

    # 2. Enrich from check findings (PASS/FAIL per rule)
    for cf in check_findings:
        uid = cf.get("resource_uid", "")
        if not uid:
            continue
        if uid not in resource_map:
            resource_map[uid] = _default_resource(cf)
        _enrich_from_check(resource_map[uid], cf)

    # 3. Enrich from datasec enhanced data (structured columns)
    for ed in enhanced_data:
        uid = ed.get("resource_arn", "")
        if not uid:
            continue
        if uid not in resource_map:
            resource_map[uid] = _default_resource_from_enhanced(ed)
        entry = resource_map[uid]
        if ed.get("encryption_at_rest") is not None:
            entry["encrypted_at_rest"] = ed["encryption_at_rest"]
        if ed.get("encryption_in_transit") is not None:
            entry["encrypted_in_transit"] = ed["encryption_in_transit"]
        if ed.get("kms_key_type"):
            entry["key_type"] = ed["kms_key_type"]
        if ed.get("encryption_algorithm"):
            entry["algorithm"] = ed["encryption_algorithm"]
        if ed.get("kms_key_rotation") is not None:
            entry["rotation_compliant"] = ed["kms_key_rotation"]

    # 4. Enrich from datasec findings (JSONB finding_data)
    for df in datasec_findings:
        uid = df.get("resource_uid", "")
        if not uid:
            continue
        if uid not in resource_map:
            resource_map[uid] = _default_resource(df)
        fd = df.get("finding_data") or {}
        if isinstance(fd, dict):
            entry = resource_map[uid]
            if fd.get("encryption_at_rest") is not None:
                entry["encrypted_at_rest"] = fd["encryption_at_rest"]
            if fd.get("encryption_in_transit") is not None:
                entry["encrypted_in_transit"] = fd["encryption_in_transit"]
            if fd.get("kms_key_id") or fd.get("kms_key_arn"):
                entry["key_type"] = entry.get("key_type") or "customer_managed"
            if fd.get("sse_algorithm"):
                entry["algorithm"] = fd["sse_algorithm"]

    # 5. Aggregate by service
    by_service = defaultdict(lambda: {"total": 0, "encrypted": 0, "cmk": 0, "transit": 0})
    totals = {"total": 0, "encrypted": 0, "unencrypted": 0, "cmk": 0, "transit": 0}

    for uid, info in resource_map.items():
        svc = info.get("service", "unknown")
        by_service[svc]["total"] += 1
        totals["total"] += 1

        is_encrypted = info.get("encrypted_at_rest") is True
        is_cmk = info.get("key_type") in ("customer_managed", "CUSTOMER")
        is_transit = info.get("encrypted_in_transit") is True

        if is_encrypted:
            by_service[svc]["encrypted"] += 1
            totals["encrypted"] += 1
        else:
            totals["unencrypted"] += 1

        if is_cmk:
            by_service[svc]["cmk"] += 1
            totals["cmk"] += 1

        if is_transit:
            by_service[svc]["transit"] += 1
            totals["transit"] += 1

    return {
        "per_resource": resource_map,
        "by_service": dict(by_service),
        "totals": totals,
    }


def _enrich_from_emitted(entry: Dict, emitted: Dict, service: str):
    """Extract encryption status from discovery emitted_fields."""
    if service == "kms":
        entry["encrypted_at_rest"] = True  # KMS keys are encryption resources themselves
        entry["key_type"] = "CUSTOMER" if emitted.get("KeyManager") == "CUSTOMER" else "AWS"
        entry["rotation_compliant"] = emitted.get("KeyRotationEnabled", False)
        entry["algorithm"] = emitted.get("KeySpec") or (
            emitted.get("EncryptionAlgorithms", [None])[0]
            if isinstance(emitted.get("EncryptionAlgorithms"), list) else None
        )
    elif service in ("acm", "acm-pca"):
        entry["algorithm"] = emitted.get("KeyAlgorithm")
    elif service == "secretsmanager":
        entry["encrypted_at_rest"] = bool(emitted.get("KmsKeyId"))
        entry["rotation_compliant"] = emitted.get("RotationEnabled", False)


def _enrich_from_check(entry: Dict, cf: Dict):
    """Enrich resource encryption status from check finding PASS/FAIL."""
    rule_id = (cf.get("rule_id") or "").lower()
    status = cf.get("status", "").upper()

    if "rotation" in rule_id:
        entry["rotation_compliant"] = (status == "PASS")
    elif "cmek" in rule_id or "customer_managed" in rule_id:
        if status == "PASS":
            entry["key_type"] = "customer_managed"
    elif "encryption" in rule_id or "encrypt" in rule_id:
        if "transit" in rule_id or "tls" in rule_id:
            entry["encrypted_in_transit"] = (status == "PASS")
        else:
            entry["encrypted_at_rest"] = (status == "PASS")


def _default_resource(finding: Dict) -> Dict:
    """Create a default resource entry from a finding dict."""
    return {
        "resource_uid": finding.get("resource_uid", ""),
        "resource_type": finding.get("resource_type", ""),
        "service": finding.get("service", "unknown"),
        "region": finding.get("region", ""),
        "account_id": finding.get("account_id", ""),
        "provider": finding.get("provider", "aws"),
        "encrypted_at_rest": None,
        "encrypted_in_transit": None,
        "key_type": None,
        "algorithm": None,
        "rotation_compliant": None,
    }


def _default_resource_from_enhanced(ed: Dict) -> Dict:
    """Create a default resource entry from enhanced datasec row."""
    return {
        "resource_uid": ed.get("resource_arn", ""),
        "resource_type": ed.get("resource_type", ""),
        "service": ed.get("data_store_service", "unknown"),
        "region": ed.get("region", ""),
        "account_id": ed.get("account_id", ""),
        "provider": ed.get("csp", "aws"),
        "encrypted_at_rest": ed.get("encryption_at_rest"),
        "encrypted_in_transit": ed.get("encryption_in_transit"),
        "key_type": ed.get("kms_key_type"),
        "algorithm": ed.get("encryption_algorithm"),
        "rotation_compliant": ed.get("kms_key_rotation"),
    }
