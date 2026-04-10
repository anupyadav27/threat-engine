"""
Attack Surface Analyzer — Identify database-specific attack vectors.

Evaluates each database in the inventory against a set of risk conditions
and emits prioritized attack-surface findings.  Each finding carries a
severity (CRITICAL / HIGH / MEDIUM / LOW) and a machine-readable risk_type.

Risk conditions evaluated:
  1. Publicly accessible DB                           → CRITICAL
  2. Sensitive data + public access                   → CRITICAL
  3. No IAM authentication                            → HIGH
  4. No encryption at rest                            → HIGH
  5. No audit logging                                 → HIGH
  6. No backup / deletion protection                  → HIGH
  7. No VPC (non-serverless)                          → HIGH
  8. Sensitive data + no encryption                   → CRITICAL
  9. Multi-AZ disabled (production risk)              → MEDIUM
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Risk type constants ──────────────────────────────────────────────────────
RISK_PUBLIC_ACCESS = "public_access"
RISK_SENSITIVE_PUBLIC = "sensitive_data_public_access"
RISK_NO_IAM_AUTH = "no_iam_authentication"
RISK_NO_ENCRYPTION = "no_encryption_at_rest"
RISK_NO_AUDIT_LOG = "no_audit_logging"
RISK_NO_BACKUP = "no_backup_protection"
RISK_NO_VPC = "no_vpc_isolation"
RISK_SENSITIVE_UNENCRYPTED = "sensitive_data_unencrypted"
RISK_NO_MULTI_AZ = "no_multi_az"

# Serverless services that don't need VPC checks
_SERVERLESS_SERVICES = frozenset({"dynamodb", "timestream", "keyspaces"})

# Classifications considered sensitive
_SENSITIVE_CLASSIFICATIONS = frozenset({
    "confidential", "sensitive", "highly_confidential",
    "pii", "phi", "pci", "restricted",
})


def _finding_id(resource_uid: str, risk_type: str) -> str:
    """Deterministic finding ID from resource + risk type."""
    raw = f"{risk_type}|{resource_uid}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _has_audit_logging(db_entry: Dict[str, Any]) -> bool:
    """Check whether the DB has any audit-logging checks passing.

    Uses the domain_findings summary attached by inventory_builder.
    """
    domain_findings = db_entry.get("domain_findings") or {}
    audit = domain_findings.get("audit_logging", {})
    return audit.get("pass", 0) > 0


def _has_backup(db_entry: Dict[str, Any]) -> bool:
    """Check whether backup/deletion protection is in place."""
    if db_entry.get("backup_enabled"):
        return True
    domain_findings = db_entry.get("domain_findings") or {}
    backup = domain_findings.get("backup_recovery", {})
    return backup.get("pass", 0) > 0 and backup.get("fail", 0) == 0


def _is_sensitive(classification: str) -> bool:
    """Return True if the data classification is considered sensitive."""
    return (classification or "").lower() in _SENSITIVE_CLASSIFICATIONS


def analyze_attack_surface(
    db_inventory: List[Dict[str, Any]],
    datasec_classification: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Identify attack-surface risks across all databases in the inventory.

    Args:
        db_inventory: Output of ``inventory_builder.build_db_inventory``.
            Each entry must have at minimum: resource_uid, db_service,
            publicly_accessible, encryption_at_rest, iam_auth_enabled,
            backup_enabled, multi_az, vpc_id, data_classification,
            domain_findings.
        datasec_classification: Optional additional datasec rows. If
            provided, these override the data_classification already on
            inventory entries.

    Returns:
        List of attack-surface finding dicts, sorted by severity
        (CRITICAL first).
    """
    # Build optional override map from datasec
    classification_override: Dict[str, str] = {}
    if datasec_classification:
        for ds in datasec_classification:
            uid = ds.get("resource_uid", "")
            classification_override[uid] = ds.get(
                "data_classification", "unclassified"
            )

    findings: List[Dict[str, Any]] = []
    now = datetime.now(timezone.utc).isoformat()

    for db in db_inventory:
        resource_uid = db.get("resource_uid", "")
        db_service = db.get("db_service", "unknown")
        resource_name = db.get("resource_name", "")
        account_id = db.get("account_id", "")
        region = db.get("region", "")
        provider = db.get("provider", "aws")

        classification = classification_override.get(
            resource_uid, db.get("data_classification", "unclassified")
        )
        is_sensitive = _is_sensitive(classification)
        is_public = db.get("publicly_accessible", False)
        has_encryption = db.get("encryption_at_rest", False)
        has_iam = db.get("iam_auth_enabled", False)
        has_backup = _has_backup(db)
        has_audit = _has_audit_logging(db)
        has_multi_az = db.get("multi_az", False)
        vpc_id = db.get("vpc_id", "")
        is_serverless = db_service in _SERVERLESS_SERVICES

        base = {
            "resource_uid": resource_uid,
            "resource_name": resource_name,
            "db_service": db_service,
            "account_id": account_id,
            "region": region,
            "provider": provider,
            "data_classification": classification,
            "detected_at": now,
        }

        # 1. Publicly accessible database
        if is_public:
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_PUBLIC_ACCESS),
                "risk_type": RISK_PUBLIC_ACCESS,
                "severity": "CRITICAL",
                "title": f"Publicly accessible {db_service} database",
                "description": (
                    f"{db_service.upper()} resource '{resource_name}' is publicly "
                    f"accessible. This exposes the database to potential unauthorized "
                    f"access from the internet."
                ),
                "recommendation": (
                    "Disable public access and ensure the database is only "
                    "reachable through private networking (VPC)."
                ),
            })

        # 2. Sensitive data + public access
        if is_sensitive and is_public:
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_SENSITIVE_PUBLIC),
                "risk_type": RISK_SENSITIVE_PUBLIC,
                "severity": "CRITICAL",
                "title": f"Sensitive data in publicly accessible {db_service}",
                "description": (
                    f"{db_service.upper()} resource '{resource_name}' contains "
                    f"{classification} data and is publicly accessible. This is "
                    f"an immediate data breach risk."
                ),
                "recommendation": (
                    "Immediately disable public access. Review access logs for "
                    "unauthorized access. Classify and restrict data exposure."
                ),
            })

        # 3. No IAM authentication
        if not has_iam:
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_NO_IAM_AUTH),
                "risk_type": RISK_NO_IAM_AUTH,
                "severity": "HIGH",
                "title": f"No IAM authentication on {db_service} database",
                "description": (
                    f"{db_service.upper()} resource '{resource_name}' does not "
                    f"have IAM authentication enabled. Credentials may be "
                    f"long-lived and harder to rotate."
                ),
                "recommendation": (
                    "Enable IAM database authentication to leverage short-lived "
                    "tokens and centralized access control."
                ),
            })

        # 4. No encryption at rest
        if not has_encryption:
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_NO_ENCRYPTION),
                "risk_type": RISK_NO_ENCRYPTION,
                "severity": "HIGH",
                "title": f"No encryption at rest on {db_service} database",
                "description": (
                    f"{db_service.upper()} resource '{resource_name}' does not "
                    f"have encryption at rest enabled. Data stored on disk is "
                    f"vulnerable to physical media theft."
                ),
                "recommendation": (
                    "Enable encryption at rest using AWS KMS. For existing "
                    "unencrypted databases, create an encrypted snapshot and "
                    "restore from it."
                ),
            })

        # 5. No audit logging
        if not has_audit:
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_NO_AUDIT_LOG),
                "risk_type": RISK_NO_AUDIT_LOG,
                "severity": "HIGH",
                "title": f"No audit logging on {db_service} database",
                "description": (
                    f"{db_service.upper()} resource '{resource_name}' has no "
                    f"audit logging configured. Security incidents may go "
                    f"undetected."
                ),
                "recommendation": (
                    "Enable audit logging and export logs to CloudWatch. "
                    "Configure alerting for anomalous activity."
                ),
            })

        # 6. No backup / deletion protection
        if not has_backup:
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_NO_BACKUP),
                "risk_type": RISK_NO_BACKUP,
                "severity": "HIGH",
                "title": f"No backup protection on {db_service} database",
                "description": (
                    f"{db_service.upper()} resource '{resource_name}' does not "
                    f"have adequate backup or deletion protection. Data loss "
                    f"from accidental deletion or ransomware is unrecoverable."
                ),
                "recommendation": (
                    "Enable automated backups, point-in-time recovery, and "
                    "deletion protection."
                ),
            })

        # 7. No VPC (non-serverless only)
        if not is_serverless and not vpc_id:
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_NO_VPC),
                "risk_type": RISK_NO_VPC,
                "severity": "HIGH",
                "title": f"No VPC isolation for {db_service} database",
                "description": (
                    f"{db_service.upper()} resource '{resource_name}' is not "
                    f"deployed inside a VPC. Network-level isolation is absent."
                ),
                "recommendation": (
                    "Deploy the database inside a private VPC with appropriate "
                    "security groups and NACLs."
                ),
            })

        # 8. Sensitive data + no encryption
        if is_sensitive and not has_encryption:
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_SENSITIVE_UNENCRYPTED),
                "risk_type": RISK_SENSITIVE_UNENCRYPTED,
                "severity": "CRITICAL",
                "title": f"Sensitive data stored unencrypted in {db_service}",
                "description": (
                    f"{db_service.upper()} resource '{resource_name}' contains "
                    f"{classification} data without encryption at rest. This "
                    f"violates data protection regulations."
                ),
                "recommendation": (
                    "Immediately enable encryption at rest. Review compliance "
                    "requirements for the data classification level."
                ),
            })

        # 9. Multi-AZ disabled
        if not has_multi_az:
            findings.append({
                **base,
                "finding_id": _finding_id(resource_uid, RISK_NO_MULTI_AZ),
                "risk_type": RISK_NO_MULTI_AZ,
                "severity": "MEDIUM",
                "title": f"Multi-AZ not enabled for {db_service} database",
                "description": (
                    f"{db_service.upper()} resource '{resource_name}' is not "
                    f"configured for Multi-AZ deployment. A single availability "
                    f"zone failure would cause downtime."
                ),
                "recommendation": (
                    "Enable Multi-AZ deployment for production databases to "
                    "ensure high availability."
                ),
            })

    # Sort by severity: CRITICAL > HIGH > MEDIUM > LOW
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f.get("severity", "LOW"), 3))

    logger.info(
        "Attack surface analysis: %d findings across %d databases "
        "(CRITICAL=%d, HIGH=%d, MEDIUM=%d)",
        len(findings),
        len(db_inventory),
        sum(1 for f in findings if f["severity"] == "CRITICAL"),
        sum(1 for f in findings if f["severity"] == "HIGH"),
        sum(1 for f in findings if f["severity"] == "MEDIUM"),
    )

    return findings
