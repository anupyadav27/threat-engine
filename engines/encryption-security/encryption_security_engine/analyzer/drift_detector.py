"""
Encryption Drift Detector.

Detects encryption configuration changes between scans:
  - Resources that lost encryption (downgrade → CRITICAL)
  - Key rotation disabled (→ HIGH)
  - Algorithm downgrade (AES-256 → AES-128 → MEDIUM)
  - Transit encryption removed (→ HIGH)
  - KMS key disabled or scheduled for deletion (→ CRITICAL)

Uses two approaches:
  1. config_hash comparison from inventory (fast, coarse)
  2. CIEM CloudTrail events (real-time, fine-grained)
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Algorithm strength ordering (higher = stronger)
ALGORITHM_STRENGTH = {
    "AES-256": 100, "AES_256": 100, "SYMMETRIC_DEFAULT": 95,
    "AES-128": 70, "AES_128": 70,
    "RSA_4096": 100, "RSA_3072": 90, "RSA_2048": 80, "RSA_1024": 30,
    "EC_secp384r1": 100, "EC_prime256v1": 95,
}

# KMS events that indicate encryption drift
DRIFT_EVENT_NAMES = {
    "DisableKey": ("CRITICAL", "KMS key disabled"),
    "ScheduleKeyDeletion": ("CRITICAL", "KMS key scheduled for deletion"),
    "DisableKeyRotation": ("HIGH", "Key rotation disabled"),
    "DeleteBucketEncryption": ("CRITICAL", "S3 bucket encryption removed"),
    "PutBucketEncryption": ("MEDIUM", "S3 bucket encryption changed"),
    "DeleteAlias": ("MEDIUM", "KMS alias deleted"),
}


def detect_drift_from_events(
    ciem_events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Detect encryption drift from CloudTrail events.

    Args:
        ciem_events: KMS and encryption config events from CIEMEncryptionReader.

    Returns:
        List of drift findings from event analysis.
    """
    findings = []

    for event in ciem_events:
        event_name = event.get("event_name", "")
        error_code = event.get("error_code")

        # Skip failed events
        if error_code:
            continue

        if event_name not in DRIFT_EVENT_NAMES:
            continue

        severity, description = DRIFT_EVENT_NAMES[event_name]

        # Extract caller info
        user_identity = event.get("user_identity") or {}
        caller = "unknown"
        if isinstance(user_identity, dict):
            caller = (
                user_identity.get("arn")
                or user_identity.get("principalId")
                or user_identity.get("userName")
                or "unknown"
            )

        resource_arn = event.get("resource_arn", "")
        event_time = event.get("event_time", "")

        findings.append({
            "drift_type": "event_based",
            "event_name": event_name,
            "severity": severity,
            "title": description,
            "description": (
                f"{description}: {resource_arn or 'unknown resource'} "
                f"by {caller} at {event_time}"
            ),
            "remediation": _get_event_remediation(event_name),
            "resource_arn": resource_arn,
            "account_id": event.get("account_id"),
            "region": event.get("region"),
            "event_time": event_time,
            "caller": caller,
            "request_parameters": event.get("request_parameters"),
        })

    # Sort by severity then time
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: (severity_order.get(f["severity"], 9), f.get("event_time", "")))

    logger.info(f"Drift detection (events): {len(findings)} drift findings from {len(ciem_events)} events")
    return findings


def detect_drift_from_config(
    current_coverage: Dict[str, Dict[str, Any]],
    previous_coverage: Optional[Dict[str, Dict[str, Any]]] = None,
    current_hashes: Optional[Dict[str, str]] = None,
    previous_hashes: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Detect encryption drift by comparing current vs previous scan state.

    Args:
        current_coverage: Current per-resource encryption status.
        previous_coverage: Previous scan per-resource encryption status.
        current_hashes: Current config hashes from inventory.
        previous_hashes: Previous config hashes from inventory.

    Returns:
        List of drift findings from state comparison.
    """
    findings = []

    if not previous_coverage:
        logger.info("No previous coverage data — skipping config-based drift detection")
        return findings

    for uid, current in current_coverage.items():
        previous = previous_coverage.get(uid)
        if not previous:
            continue  # New resource, no drift

        base_info = {
            "drift_type": "config_based",
            "resource_uid": uid,
            "resource_type": current.get("resource_type", ""),
            "service": current.get("service", ""),
            "account_id": current.get("account_id", ""),
            "region": current.get("region", ""),
        }

        # 1. Encryption removed (was encrypted, now not)
        if previous.get("encrypted_at_rest") is True and current.get("encrypted_at_rest") is False:
            findings.append({
                **base_info,
                "severity": "CRITICAL",
                "title": "Encryption at rest removed",
                "description": (
                    f"Resource {uid} was previously encrypted at rest "
                    f"but encryption has been removed."
                ),
                "remediation": "Re-enable encryption at rest immediately",
                "previous_state": {"encrypted_at_rest": True},
                "current_state": {"encrypted_at_rest": False},
            })

        # 2. Key type downgraded (CMK → managed → none)
        prev_key = previous.get("key_type")
        curr_key = current.get("key_type")
        if _is_key_downgrade(prev_key, curr_key):
            findings.append({
                **base_info,
                "severity": "HIGH",
                "title": f"Encryption key downgraded: {prev_key} → {curr_key}",
                "description": (
                    f"Resource {uid} was using {prev_key} encryption "
                    f"but has been downgraded to {curr_key}."
                ),
                "remediation": f"Restore encryption to {prev_key} level",
                "previous_state": {"key_type": prev_key},
                "current_state": {"key_type": curr_key},
            })

        # 3. Rotation disabled
        if previous.get("rotation_compliant") is True and current.get("rotation_compliant") is False:
            findings.append({
                **base_info,
                "severity": "HIGH",
                "title": "Key rotation disabled",
                "description": (
                    f"Key rotation for resource {uid} was previously enabled "
                    f"but has been disabled."
                ),
                "remediation": "Re-enable automatic key rotation",
                "previous_state": {"rotation_compliant": True},
                "current_state": {"rotation_compliant": False},
            })

        # 4. Transit encryption removed
        if previous.get("encrypted_in_transit") is True and current.get("encrypted_in_transit") is False:
            findings.append({
                **base_info,
                "severity": "HIGH",
                "title": "Transit encryption removed",
                "description": (
                    f"Resource {uid} previously enforced transit encryption "
                    f"but it has been removed."
                ),
                "remediation": "Re-enable TLS/SSL enforcement for data in transit",
                "previous_state": {"encrypted_in_transit": True},
                "current_state": {"encrypted_in_transit": False},
            })

        # 5. Algorithm downgrade
        prev_algo = previous.get("algorithm")
        curr_algo = current.get("algorithm")
        if prev_algo and curr_algo and _is_algorithm_downgrade(prev_algo, curr_algo):
            findings.append({
                **base_info,
                "severity": "MEDIUM",
                "title": f"Encryption algorithm downgraded: {prev_algo} → {curr_algo}",
                "description": (
                    f"Resource {uid} encryption algorithm changed from "
                    f"{prev_algo} to weaker {curr_algo}."
                ),
                "remediation": f"Restore encryption algorithm to {prev_algo} or stronger",
                "previous_state": {"algorithm": prev_algo},
                "current_state": {"algorithm": curr_algo},
            })

    # Also detect drift via config hash changes
    if current_hashes and previous_hashes:
        changed_resources = set()
        for uid, curr_hash in current_hashes.items():
            prev_hash = previous_hashes.get(uid)
            if prev_hash and prev_hash != curr_hash:
                changed_resources.add(uid)

        # Only flag resources with hash changes not already caught above
        existing_uids = {f.get("resource_uid") for f in findings}
        for uid in changed_resources - existing_uids:
            if uid in current_coverage:
                findings.append({
                    "drift_type": "config_hash",
                    "resource_uid": uid,
                    "resource_type": current_coverage[uid].get("resource_type", ""),
                    "account_id": current_coverage[uid].get("account_id", ""),
                    "region": current_coverage[uid].get("region", ""),
                    "severity": "LOW",
                    "title": "Encryption configuration changed",
                    "description": f"Resource {uid} configuration hash changed between scans",
                    "remediation": "Review the configuration change to ensure no security regression",
                })

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 9))

    logger.info(f"Drift detection (config): {len(findings)} drift findings")
    return findings


def _is_key_downgrade(prev: Optional[str], curr: Optional[str]) -> bool:
    """Check if key type was downgraded."""
    rank = {"CUSTOMER": 3, "customer_managed": 3, "AWS": 2, "aws_managed": 2, "none": 1, None: 0}
    return rank.get(prev, 0) > rank.get(curr, 0)


def _is_algorithm_downgrade(prev: str, curr: str) -> bool:
    """Check if algorithm was downgraded."""
    prev_score = ALGORITHM_STRENGTH.get(prev, 50)
    curr_score = ALGORITHM_STRENGTH.get(curr, 50)
    return prev_score > curr_score and (prev_score - curr_score) >= 20


def _get_event_remediation(event_name: str) -> str:
    """Return remediation guidance for a drift event."""
    remediations = {
        "DisableKey": "Re-enable the KMS key immediately or ensure a replacement key is in use",
        "ScheduleKeyDeletion": "Cancel key deletion if unintended. Ensure dependent resources have migrated to a new key",
        "DisableKeyRotation": "Re-enable automatic key rotation for compliance",
        "DeleteBucketEncryption": "Re-apply bucket default encryption with AES-256 or aws:kms",
        "PutBucketEncryption": "Verify the new encryption configuration meets security requirements",
        "DeleteAlias": "Verify the alias deletion was intentional and update any references",
    }
    return remediations.get(event_name, "Review the change and revert if unauthorized")
