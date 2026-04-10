"""
Inventory Builder — Build a unified database inventory from discovery resources.

Cross-references:
  - Discovery resources → extract DB metadata (engine, version, instance class, etc.)
  - Check findings     → compute pass/fail counts per resource
  - DataSec data       → attach data classification labels

Supported services: rds, dynamodb, redshift, elasticache, neptune,
                    documentdb, opensearch, timestream, keyspaces, dax
"""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional

from .rule_categorizer import categorize_finding, get_service_from_rule, is_db_rule

logger = logging.getLogger(__name__)

# ── Service-specific config extractors ───────────────────────────────────────
# Each function receives the raw discovery resource dict and returns a partial
# inventory dict with service-specific fields.

def _extract_rds(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract RDS-specific fields from a discovery resource."""
    config = r.get("configuration") or r.get("config") or {}
    return {
        "db_engine": config.get("Engine", ""),
        "db_engine_version": config.get("EngineVersion", ""),
        "instance_class": config.get("DBInstanceClass", ""),
        "publicly_accessible": config.get("PubliclyAccessible", False),
        "encryption_at_rest": config.get("StorageEncrypted", False),
        "iam_auth_enabled": config.get("IAMDatabaseAuthenticationEnabled", False),
        "backup_enabled": (config.get("BackupRetentionPeriod", 0) or 0) > 0,
        "multi_az": config.get("MultiAZ", False),
        "vpc_id": (config.get("DBSubnetGroup") or {}).get("VpcId", ""),
        "storage_type": config.get("StorageType", ""),
        "allocated_storage_gb": config.get("AllocatedStorage"),
    }


def _extract_dynamodb(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract DynamoDB-specific fields."""
    config = r.get("configuration") or r.get("config") or {}
    sse = config.get("SSEDescription") or {}
    return {
        "db_engine": "dynamodb",
        "db_engine_version": "",
        "instance_class": config.get("TableClass", "STANDARD"),
        "publicly_accessible": False,  # DynamoDB is always behind IAM
        "encryption_at_rest": sse.get("Status") == "ENABLED",
        "iam_auth_enabled": True,  # DynamoDB uses IAM natively
        "backup_enabled": bool(config.get("PointInTimeRecoveryDescription", {}).get("PointInTimeRecoveryStatus") == "ENABLED"),
        "multi_az": True,  # DynamoDB is always multi-AZ
        "vpc_id": "",
        "billing_mode": config.get("BillingModeSummary", {}).get("BillingMode", ""),
    }


def _extract_redshift(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract Redshift-specific fields."""
    config = r.get("configuration") or r.get("config") or {}
    return {
        "db_engine": "redshift",
        "db_engine_version": config.get("ClusterVersion", ""),
        "instance_class": config.get("NodeType", ""),
        "publicly_accessible": config.get("PubliclyAccessible", False),
        "encryption_at_rest": config.get("Encrypted", False),
        "iam_auth_enabled": False,
        "backup_enabled": (config.get("AutomatedSnapshotRetentionPeriod", 0) or 0) > 0,
        "multi_az": config.get("MultiAZ", False),
        "vpc_id": (config.get("VpcId") or ""),
        "number_of_nodes": config.get("NumberOfNodes", 1),
    }


def _extract_elasticache(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract ElastiCache-specific fields."""
    config = r.get("configuration") or r.get("config") or {}
    return {
        "db_engine": config.get("Engine", "redis"),
        "db_engine_version": config.get("EngineVersion", ""),
        "instance_class": config.get("CacheNodeType", ""),
        "publicly_accessible": False,
        "encryption_at_rest": config.get("AtRestEncryptionEnabled", False),
        "iam_auth_enabled": False,
        "backup_enabled": (config.get("SnapshotRetentionLimit", 0) or 0) > 0,
        "multi_az": config.get("AutomaticFailover") == "enabled",
        "vpc_id": "",
        "transit_encryption": config.get("TransitEncryptionEnabled", False),
    }


def _extract_neptune(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract Neptune-specific fields."""
    config = r.get("configuration") or r.get("config") or {}
    return {
        "db_engine": "neptune",
        "db_engine_version": config.get("EngineVersion", ""),
        "instance_class": config.get("DBInstanceClass", ""),
        "publicly_accessible": config.get("PubliclyAccessible", False),
        "encryption_at_rest": config.get("StorageEncrypted", False),
        "iam_auth_enabled": config.get("IAMDatabaseAuthenticationEnabled", False),
        "backup_enabled": (config.get("BackupRetentionPeriod", 0) or 0) > 0,
        "multi_az": config.get("MultiAZ", False),
        "vpc_id": (config.get("DBSubnetGroup") or {}).get("VpcId", ""),
    }


def _extract_opensearch(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract OpenSearch-specific fields."""
    config = r.get("configuration") or r.get("config") or {}
    encrypt_cfg = config.get("EncryptionAtRestOptions") or {}
    node_cfg = config.get("ClusterConfig") or {}
    vpc_cfg = config.get("VPCOptions") or {}
    return {
        "db_engine": "opensearch",
        "db_engine_version": config.get("EngineVersion", ""),
        "instance_class": node_cfg.get("InstanceType", ""),
        "publicly_accessible": not bool(vpc_cfg.get("VPCId")),
        "encryption_at_rest": encrypt_cfg.get("Enabled", False),
        "iam_auth_enabled": bool(
            (config.get("AdvancedSecurityOptions") or {}).get("Enabled")
        ),
        "backup_enabled": bool(
            (config.get("SnapshotOptions") or {}).get("AutomatedSnapshotStartHour") is not None
        ),
        "multi_az": node_cfg.get("ZoneAwarenessEnabled", False),
        "vpc_id": vpc_cfg.get("VPCId", ""),
        "instance_count": node_cfg.get("InstanceCount", 1),
    }


def _extract_timestream(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract Timestream-specific fields."""
    config = r.get("configuration") or r.get("config") or {}
    return {
        "db_engine": "timestream",
        "db_engine_version": "",
        "instance_class": "serverless",
        "publicly_accessible": False,
        "encryption_at_rest": True,  # Timestream encrypts by default
        "iam_auth_enabled": True,
        "backup_enabled": True,
        "multi_az": True,  # Timestream is always multi-AZ
        "vpc_id": "",
        "kms_key_id": config.get("KmsKeyId", ""),
    }


def _extract_keyspaces(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract Keyspaces-specific fields."""
    config = r.get("configuration") or r.get("config") or {}
    return {
        "db_engine": "cassandra",
        "db_engine_version": "",
        "instance_class": "serverless",
        "publicly_accessible": False,
        "encryption_at_rest": True,  # Keyspaces encrypts by default
        "iam_auth_enabled": True,
        "backup_enabled": bool(
            config.get("pointInTimeRecovery", {}).get("status") == "ENABLED"
        ),
        "multi_az": True,
        "vpc_id": "",
    }


def _extract_generic(r: Dict[str, Any]) -> Dict[str, Any]:
    """Fallback extractor for unrecognized services (documentdb, dax, etc.)."""
    config = r.get("configuration") or r.get("config") or {}
    return {
        "db_engine": config.get("Engine", ""),
        "db_engine_version": config.get("EngineVersion", ""),
        "instance_class": config.get("DBInstanceClass") or config.get("NodeType", ""),
        "publicly_accessible": config.get("PubliclyAccessible", False),
        "encryption_at_rest": config.get("StorageEncrypted", False),
        "iam_auth_enabled": config.get("IAMDatabaseAuthenticationEnabled", False),
        "backup_enabled": (config.get("BackupRetentionPeriod", 0) or 0) > 0,
        "multi_az": config.get("MultiAZ", False),
        "vpc_id": (config.get("DBSubnetGroup") or {}).get("VpcId", ""),
    }


_SERVICE_EXTRACTORS = {
    "rds": _extract_rds,
    "dynamodb": _extract_dynamodb,
    "redshift": _extract_redshift,
    "elasticache": _extract_elasticache,
    "neptune": _extract_neptune,
    "opensearch": _extract_opensearch,
    "timestream": _extract_timestream,
    "keyspaces": _extract_keyspaces,
}


def _detect_service(resource: Dict[str, Any]) -> str:
    """Infer the DB service from a discovery resource dict.

    Checks ``resource_type`` first, then falls back to ``resource_uid`` (ARN).
    """
    rt = (resource.get("resource_type") or "").lower()
    uid = (resource.get("resource_uid") or "").lower()

    for svc in _SERVICE_EXTRACTORS:
        if svc in rt or f":{svc}:" in uid or f"/{svc}/" in uid:
            return svc

    # Additional patterns
    if "docdb" in rt or "docdb" in uid or "documentdb" in rt:
        return "documentdb"
    if "dax" in rt or ":dax:" in uid:
        return "dax"

    return "unknown"


def build_db_inventory(
    discovery_resources: List[Dict[str, Any]],
    check_findings: Optional[List[Dict[str, Any]]] = None,
    datasec_data: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Build a unified database inventory from discovery and cross-engine data.

    Args:
        discovery_resources: Raw discovery resource dicts.  Each should have
            at minimum ``resource_uid``, ``resource_type``, and a
            ``configuration`` / ``config`` sub-dict.
        check_findings: Optional check engine findings with ``rule_id``,
            ``resource_uid``, and ``status``.
        datasec_data: Optional data-security classifications with
            ``resource_uid`` and ``data_classification``.

    Returns:
        List of inventory dicts, one per database resource.
    """
    check_findings = check_findings or []
    datasec_data = datasec_data or []

    # ── Index check findings by resource_uid ─────────────────────────────
    check_by_resource: Dict[str, Dict[str, int]] = defaultdict(
        lambda: {"pass": 0, "fail": 0}
    )
    domain_findings_by_resource: Dict[str, Dict[str, Dict[str, int]]] = defaultdict(
        lambda: defaultdict(lambda: {"pass": 0, "fail": 0})
    )

    for f in check_findings:
        rule_id = f.get("rule_id", "")
        if not is_db_rule(rule_id):
            continue
        uid = f.get("resource_uid", "")
        status = (f.get("status") or "").upper()
        domain = categorize_finding(rule_id, f)

        if status == "PASS":
            check_by_resource[uid]["pass"] += 1
            domain_findings_by_resource[uid][domain]["pass"] += 1
        else:
            check_by_resource[uid]["fail"] += 1
            domain_findings_by_resource[uid][domain]["fail"] += 1

    # ── Index datasec classifications by resource_uid ────────────────────
    classification_by_uid: Dict[str, str] = {}
    for ds in datasec_data:
        uid = ds.get("resource_uid", "")
        classification_by_uid[uid] = ds.get("data_classification", "unclassified")

    # ── Build inventory entries ──────────────────────────────────────────
    inventory: List[Dict[str, Any]] = []

    for resource in discovery_resources:
        db_service = _detect_service(resource)
        if db_service == "unknown":
            continue

        resource_uid = resource.get("resource_uid", "")
        resource_name = (
            resource.get("resource_name")
            or resource.get("name")
            or resource_uid.split("/")[-1].split(":")[-1]
        )

        extractor = _SERVICE_EXTRACTORS.get(db_service, _extract_generic)
        entry = extractor(resource)

        # Common fields
        entry["resource_uid"] = resource_uid
        entry["resource_name"] = resource_name
        entry["db_service"] = db_service
        entry["account_id"] = resource.get("account_id", "")
        entry["region"] = resource.get("region", "")
        entry["provider"] = resource.get("provider", "aws")

        # Check findings cross-reference
        ck = check_by_resource.get(resource_uid, {"pass": 0, "fail": 0})
        entry["check_pass_count"] = ck["pass"]
        entry["check_fail_count"] = ck["fail"]
        entry["check_total"] = ck["pass"] + ck["fail"]

        # Per-domain check summary
        domain_summary = {}
        if resource_uid in domain_findings_by_resource:
            for domain, counts in domain_findings_by_resource[resource_uid].items():
                domain_summary[domain] = {
                    "pass": counts["pass"],
                    "fail": counts["fail"],
                }
        entry["domain_findings"] = domain_summary

        # DataSec cross-reference
        entry["data_classification"] = classification_by_uid.get(
            resource_uid, "unclassified"
        )

        inventory.append(entry)

    logger.info(
        "Built DB inventory: %d resources across %d services",
        len(inventory),
        len({e["db_service"] for e in inventory}),
    )

    return inventory
