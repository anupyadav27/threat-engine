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


# ── Azure extractors ─────────────────────────────────────────────────────────

def _extract_azure_sql(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract Azure SQL Database / Managed Instance fields."""
    config = r.get("configuration") or r.get("config") or {}
    props = config.get("properties") or config
    return {
        "db_engine": "azure_sql",
        "db_engine_version": props.get("currentServiceObjectiveName", ""),
        "instance_class": props.get("sku", {}).get("name", "") if isinstance(props.get("sku"), dict) else props.get("sku", ""),
        "publicly_accessible": props.get("publicNetworkAccess", "Enabled") == "Enabled",
        "encryption_at_rest": props.get("transparentDataEncryption", {}).get("status", "Disabled") == "Enabled"
            if isinstance(props.get("transparentDataEncryption"), dict) else False,
        "iam_auth_enabled": bool(props.get("administrators", {}).get("azureADOnlyAuthentication")),
        "backup_enabled": True,  # Azure SQL always has automated backups
        "multi_az": bool(props.get("zoneRedundant", False)),
        "vpc_id": props.get("privateEndpointConnections", [{}])[0].get("id", "") if props.get("privateEndpointConnections") else "",
    }


def _extract_azure_cosmosdb(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract Azure Cosmos DB fields."""
    config = r.get("configuration") or r.get("config") or {}
    props = config.get("properties") or config
    return {
        "db_engine": "cosmosdb",
        "db_engine_version": props.get("apiProperties", {}).get("serverVersion", "") if isinstance(props.get("apiProperties"), dict) else "",
        "instance_class": "",
        "publicly_accessible": props.get("publicNetworkAccess", "Enabled") == "Enabled",
        "encryption_at_rest": True,  # CosmosDB always encrypts at rest
        "iam_auth_enabled": bool(props.get("disableLocalAuth", False)),
        "backup_enabled": (props.get("backupPolicy", {}).get("type") is not None),
        "multi_az": bool(props.get("enableMultipleWriteLocations", False)),
        "vpc_id": props.get("virtualNetworkRules", [{}])[0].get("id", "") if props.get("virtualNetworkRules") else "",
    }


# ── GCP extractors ────────────────────────────────────────────────────────────

def _extract_gcp_cloudsql(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract GCP Cloud SQL fields."""
    config = r.get("configuration") or r.get("config") or {}
    settings = config.get("settings") or config
    return {
        "db_engine": config.get("databaseVersion", ""),
        "db_engine_version": config.get("databaseVersion", ""),
        "instance_class": settings.get("tier", ""),
        "publicly_accessible": bool(
            any(n.get("kind") == "sql#aclEntry" and n.get("value") == "0.0.0.0/0"
                for n in settings.get("ipConfiguration", {}).get("authorizedNetworks", []))
        ),
        "encryption_at_rest": True,  # GCP encrypts all data at rest by default
        "iam_auth_enabled": settings.get("databaseFlags", [{}])[0].get("value") == "on"
            if settings.get("databaseFlags") else False,
        "backup_enabled": settings.get("backupConfiguration", {}).get("enabled", False),
        "multi_az": settings.get("availabilityType", "ZONAL") == "REGIONAL",
        "vpc_id": settings.get("ipConfiguration", {}).get("privateNetwork", ""),
    }


def _extract_gcp_spanner(r: Dict[str, Any]) -> Dict[str, Any]:
    """Extract GCP Spanner fields."""
    config = r.get("configuration") or r.get("config") or {}
    return {
        "db_engine": "spanner",
        "db_engine_version": "",
        "instance_class": config.get("config", ""),
        "publicly_accessible": False,  # Spanner is always private
        "encryption_at_rest": True,  # Always encrypted
        "iam_auth_enabled": True,  # Always uses IAM
        "backup_enabled": True,
        "multi_az": True,  # Always multi-region
        "vpc_id": "",
        "processing_units": config.get("processingUnits", 0),
    }


_SERVICE_EXTRACTORS = {
    # AWS
    "rds": _extract_rds,
    "dynamodb": _extract_dynamodb,
    "redshift": _extract_redshift,
    "elasticache": _extract_elasticache,
    "neptune": _extract_neptune,
    "opensearch": _extract_opensearch,
    "timestream": _extract_timestream,
    "keyspaces": _extract_keyspaces,
    # Azure
    "sql": _extract_azure_sql,
    "azure_sql": _extract_azure_sql,
    "cosmosdb": _extract_azure_cosmosdb,
    "cosmos_db": _extract_azure_cosmosdb,
    # GCP
    "cloudsql": _extract_gcp_cloudsql,
    "spanner": _extract_gcp_spanner,
}


def _detect_service(resource: Dict[str, Any]) -> str:
    """Infer the DB service from a discovery resource dict.

    Checks ``resource_type`` first, then falls back to ``resource_uid``.
    Supports AWS, Azure, and GCP resource types.
    """
    rt = (resource.get("resource_type") or "").lower()
    uid = (resource.get("resource_uid") or "").lower()

    for svc in _SERVICE_EXTRACTORS:
        if svc in rt or f":{svc}:" in uid or f"/{svc}/" in uid:
            return svc

    # AWS additional patterns
    if "docdb" in rt or "docdb" in uid or "documentdb" in rt:
        return "documentdb"
    if "dax" in rt or ":dax:" in uid:
        return "dax"

    # Azure patterns
    if "microsoft.sql" in rt or "microsoft.sql" in uid or "azure.sql" in rt:
        return "sql"
    if "microsoft.documentdb" in rt or "cosmosdb" in rt or "cosmos" in rt:
        return "cosmosdb"
    if "microsoft.dbforpostgresql" in rt or "azure.postgresql" in rt:
        return "sql"  # treat as generic SQL
    if "microsoft.dbformysql" in rt or "azure.mysql" in rt:
        return "sql"
    if "microsoft.cache" in rt or "azure.cache" in rt:
        return "elasticache"  # Redis Cache → elasticache pattern

    # GCP patterns
    if "google.cloud.sql" in rt or "sqladmin" in rt or "gcp.sql" in rt:
        return "cloudsql"
    if "google.spanner" in rt or "gcp.spanner" in rt:
        return "spanner"
    if "google.bigtable" in rt or "gcp.bigtable" in rt:
        return "bigtable"
    if "google.firestore" in rt or "gcp.firestore" in rt:
        return "firestore"

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

    # ── Non-instance resource_types to skip (metadata, snapshots, not live DBs) ──
    _SKIP_RESOURCE_TYPES = frozenset({
        "db_engine_version", "db_snapshot", "cluster_snapshot",
        "db_cluster_snapshot", "db_cluster_snapshot_attribute", "db_snapshot_attribute",
        "certificate", "option_group", "db_security_group",
        "db_parameter_group", "db_cluster_parameter_group", "db_subnet_group",
        "db_log_file", "event_subscription", "global_cluster",
        # ElastiCache non-instances
        "cache_subnet_group", "cache_parameter_group", "cache_security_group",
        # Redshift non-instances
        "cluster_parameter_group", "cluster_subnet_group",
        # Generic
        "parameter_group", "subnet_group", "security_group",
    })

    # ── Build inventory entries (deduplicate by resource_uid) ────────────
    inventory: List[Dict[str, Any]] = []
    seen_uids: set = set()

    for resource in discovery_resources:
        # Skip metadata resources that aren't actual DB instances
        rt = (resource.get("resource_type") or "").lower().replace("-", "_")
        if rt in _SKIP_RESOURCE_TYPES:
            continue
        # Skip resources whose UID is a synthetic bulk-API key, not a real resource
        uid = resource.get("resource_uid", "")
        if uid and "describe_" in uid:
            continue
        # Skip snapshot ARNs by UID pattern (catch anything missed by resource_type)
        if uid and (":snapshot:" in uid or "/snapshots/" in uid):
            continue

        # Deduplicate: keep first occurrence of each resource_uid
        if uid in seen_uids:
            continue
        seen_uids.add(uid)

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
