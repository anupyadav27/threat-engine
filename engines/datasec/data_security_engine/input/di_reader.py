"""
DataSec DI Reader — reads from asset_inventory (threat_engine_di).

Drop-in replacement for DataStoreDiscoveryReader. Returns the same
Dict[resource_uid, metadata] structure from load_data_store_metadata()
so the datasec catalog enrichment step works without changes.

Active when DI_ENGINE_ENABLED=true on the engine pod.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from psycopg2.extras import RealDictCursor

from engine_common.db_connections import get_di_conn

logger = logging.getLogger(__name__)

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


class DataStoreDIReader:
    """Reads data store metadata from asset_inventory in threat_engine_di."""

    def load_data_store_metadata(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: Optional[str] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Load metadata for all data store resources.

        Returns Dict keyed by resource_uid — same shape as DataStoreDiscoveryReader.
        """
        discovery_ids = list(DATA_STORE_DISCOVERY_MAP.values())
        conn = get_di_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                query = """
                    SELECT resource_uid, discovery_id, region,
                           service, raw_response, emitted_fields
                    FROM asset_inventory
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND discovery_id = ANY(%s)
                """
                params = [scan_run_id, tenant_id, discovery_ids]
                # Skip account_id filter when scan_run_id present — DI stores cloud
                # account number; callers pass internal UUID.
                if account_id and not scan_run_id:
                    query += " AND account_id = %s"
                    params.append(account_id)

                cur.execute(query, params)
                rows = cur.fetchall()
        finally:
            conn.close()

        from data_security_engine.input.discovery_db_reader import _extract_metadata

        metadata: Dict[str, Dict[str, Any]] = {}
        for row in rows:
            uid = row.get("resource_uid", "")
            if not uid:
                continue

            raw = row.get("raw_response") or {}
            emitted = row.get("emitted_fields") or {}

            meta = _extract_metadata(raw, emitted, row.get("service", ""), row.get("discovery_id", ""))
            meta["resource_uid"] = uid
            meta["resource_id"] = uid
            meta["service"] = row.get("service", "")
            meta["region"] = row.get("region", "")

            metadata[uid] = meta

        logger.info(
            "DataStoreDIReader: %d data store assets for scan %s",
            len(metadata), scan_run_id,
        )
        return metadata
