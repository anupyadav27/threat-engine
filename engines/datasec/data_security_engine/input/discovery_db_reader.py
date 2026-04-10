"""
DataSec — Discovery DB Reader

Loads raw data store resource metadata from the discoveries database.
Used to enrich the data catalog with name, size, tags, owner, creation date.

Services: s3, rds, dynamodb, redshift, elasticache, efs, fsx, documentdb,
          neptune, glue, opensearch, glacier, kms, secretsmanager.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Set

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# Discovery IDs for data store services
DATA_STORE_DISCOVERY_MAP = {
    "s3_buckets":        "aws.s3.list_buckets",
    "rds_instances":     "aws.rds.describe_db_instances",
    "rds_clusters":      "aws.rds.describe_db_clusters",
    "dynamodb_tables":   "aws.dynamodb.list_tables",
    "redshift_clusters": "aws.redshift.describe_clusters",
    "elasticache":       "aws.elasticache.describe_cache_clusters",
    "efs_filesystems":   "aws.efs.describe_file_systems",
    "documentdb":        "aws.docdb.describe_db_clusters",
    "neptune":           "aws.neptune.describe_db_clusters",
    "opensearch":        "aws.opensearch.list_domain_names",
    "glacier_vaults":    "aws.glacier.list_vaults",
    "kms_keys":          "aws.kms.list_keys",
    "secrets":           "aws.secretsmanager.list_secrets",
    "glue_databases":    "aws.glue.get_databases",
    "ecr_repos":         "aws.ecr.describe_repositories",
    "fsx_filesystems":   "aws.fsx.describe_file_systems",
}


def _get_discoveries_conn():
    return psycopg2.connect(
        host=os.getenv("DISCOVERIES_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("DISCOVERIES_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("DISCOVERIES_DB_NAME", "threat_engine_discoveries"),
        user=os.getenv("DISCOVERIES_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("DISCOVERIES_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


class DataStoreDiscoveryReader:
    """Read data store metadata from the discoveries database."""

    def load_data_store_metadata(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: Optional[str] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """
        Load metadata for all data store resources.

        Returns:
            Dict keyed by resource_uid with metadata dicts containing:
            name, size_bytes, record_count, owner, tags, creation_date, etc.
        """
        discovery_ids = list(DATA_STORE_DISCOVERY_MAP.values())
        conn = _get_discoveries_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT resource_uid, resource_id, discovery_id, region,
                           service, raw_response, emitted_fields
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND discovery_id = ANY(%s)
                """
                params = [scan_run_id, tenant_id, discovery_ids]
                if account_id:
                    query += " AND account_id = %s"
                    params.append(account_id)

                cur.execute(query, params)
                rows = cur.fetchall()
        finally:
            conn.close()

        metadata: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            uid = row.get("resource_uid", "")
            if not uid:
                continue

            raw = row.get("raw_response") or {}
            emitted = row.get("emitted_fields") or {}

            meta = _extract_metadata(raw, emitted, row.get("service", ""), row.get("discovery_id", ""))
            meta["resource_uid"] = uid
            meta["resource_id"] = row.get("resource_id", "")
            meta["service"] = row.get("service", "")
            meta["region"] = row.get("region", "")

            metadata[uid] = meta

        logger.info("Loaded metadata for %d data store resources", len(metadata))
        return metadata


def _extract_metadata(
    raw: Dict[str, Any],
    emitted: Dict[str, Any],
    service: str,
    discovery_id: str,
) -> Dict[str, Any]:
    """Extract human-readable metadata from raw discovery response."""
    meta: Dict[str, Any] = {}

    # Name — varies by service
    meta["name"] = (
        raw.get("Name")
        or raw.get("BucketName")
        or raw.get("DBInstanceIdentifier")
        or raw.get("DBClusterIdentifier")
        or raw.get("TableName")
        or raw.get("ClusterIdentifier")
        or raw.get("CacheClusterId")
        or raw.get("FileSystemId")
        or raw.get("DomainName")
        or raw.get("VaultName")
        or raw.get("RepositoryName")
        or emitted.get("resource_id", "")
    )

    # Size
    meta["size_bytes"] = (
        raw.get("ContentLength")
        or raw.get("AllocatedStorage")
        or raw.get("SizeInMegaBytes")
        or raw.get("SizeInBytes")
        or raw.get("NumberOfBytes")
        or 0
    )
    # RDS stores in GB
    if "AllocatedStorage" in raw and meta["size_bytes"]:
        meta["size_bytes"] = int(meta["size_bytes"]) * 1024 * 1024 * 1024

    # Record count (DynamoDB)
    meta["record_count"] = raw.get("ItemCount") or raw.get("NumberOfArchives") or 0

    # Tags
    tags = raw.get("Tags") or raw.get("TagSet") or raw.get("TagList") or []
    if isinstance(tags, list):
        meta["tags"] = {t.get("Key", ""): t.get("Value", "") for t in tags if isinstance(t, dict)}
    elif isinstance(tags, dict):
        meta["tags"] = tags
    else:
        meta["tags"] = {}

    # Owner from tags
    meta["owner"] = meta["tags"].get("Owner", meta["tags"].get("owner", ""))

    # Creation date
    meta["creation_date"] = (
        raw.get("CreationDate")
        or raw.get("InstanceCreateTime")
        or raw.get("ClusterCreateTime")
        or raw.get("CreationDateTime")
        or raw.get("CreateDate")
        or None
    )

    # Encryption status (basic detection from raw)
    meta["encryption_at_rest"] = (
        raw.get("ServerSideEncryptionConfiguration") is not None
        or raw.get("StorageEncrypted", False)
        or raw.get("Encrypted", False)
        or raw.get("KmsKeyId") is not None
        or raw.get("EncryptionConfiguration") is not None
    )

    # Public access
    meta["is_public"] = (
        raw.get("PubliclyAccessible", False)
        or raw.get("PublicAccessBlockConfiguration") == {}
    )

    # Versioning (S3)
    meta["versioning_enabled"] = raw.get("VersioningConfiguration", {}).get("Status") == "Enabled"

    # Backup
    meta["backup_enabled"] = raw.get("BackupRetentionPeriod", 0) > 0

    return meta
