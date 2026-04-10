"""
DataSec — Inventory Reader

Reads inventory relationships to build data lineage:
  - replication (S3 cross-region replication)
  - backs_up_to (RDS snapshots)
  - replicates_to (DynamoDB global tables)
  - stores_data_in (Lambda → S3, Glue → S3)
  - publishes_to (Kinesis → S3, SNS → SQS)
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)

# Relationship types that represent data flows
DATA_FLOW_RELATIONSHIP_TYPES = {
    "replicates_to",
    "backs_up_to",
    "stores_data_in",
    "publishes_to",
    "subscribes_to",
    "reads_from",
    "writes_to",
    "exports_to",
    "imports_from",
}

# Data store resource types
DATA_STORE_RESOURCE_TYPES = {
    "s3.resource", "s3.bucket", "rds.instance", "rds.db-instance",
    "rds.cluster", "rds.db-cluster", "dynamodb.table", "dynamodb.resource",
    "redshift.cluster", "redshift.resource", "elasticache.cluster",
    "efs.file-system", "elasticfilesystem.file-system",
    "docdb.cluster", "neptune.cluster", "glue.database",
    "opensearch.domain", "glacier.vault",
}


def _get_inventory_conn():
    return psycopg2.connect(
        host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
        user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
        connect_timeout=10,
    )


class DataStoreInventoryReader:
    """Read data store relationships from inventory for lineage building."""

    def load_data_flow_relationships(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Load relationships that represent data flows between resources.

        Returns list of dicts with source_uid, target_uid, relationship_type, etc.
        """
        conn = _get_inventory_conn()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        source_resource_uid,
                        source_resource_type,
                        target_resource_uid,
                        target_resource_type,
                        relationship_type,
                        relationship_data
                    FROM inventory_relationships
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND (
                          relationship_type = ANY(%s)
                          OR source_resource_type = ANY(%s)
                          OR target_resource_type = ANY(%s)
                      )
                """, [
                    scan_run_id, tenant_id,
                    list(DATA_FLOW_RELATIONSHIP_TYPES),
                    list(DATA_STORE_RESOURCE_TYPES),
                    list(DATA_STORE_RESOURCE_TYPES),
                ])
                rows = cur.fetchall()

            logger.info("Loaded %d data flow relationships from inventory", len(rows))
            return [dict(r) for r in rows]
        except Exception as e:
            logger.warning("Could not load inventory relationships: %s", e)
            return []
        finally:
            conn.close()

    def build_lineage_records(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """
        Build datasec_lineage records from inventory relationships.

        Returns list of dicts ready for insertion into datasec_lineage table.
        """
        relationships = self.load_data_flow_relationships(scan_run_id, tenant_id)
        lineage = []

        for rel in relationships:
            src_uid = rel.get("source_resource_uid", "")
            dst_uid = rel.get("target_resource_uid", "")
            rel_type = rel.get("relationship_type", "")

            if not src_uid or not dst_uid:
                continue

            # Extract regions from ARN if possible
            src_region = _extract_region_from_arn(src_uid)
            dst_region = _extract_region_from_arn(dst_uid)

            # Extract account from ARN
            src_account = _extract_account_from_arn(src_uid)
            dst_account = _extract_account_from_arn(dst_uid)

            transfer_type = _map_relationship_to_transfer_type(rel_type)

            lineage.append({
                "scan_run_id": scan_run_id,
                "tenant_id": tenant_id,
                "source_uid": src_uid,
                "source_type": rel.get("source_resource_type", ""),
                "source_region": src_region,
                "destination_uid": dst_uid,
                "destination_type": rel.get("target_resource_type", ""),
                "destination_region": dst_region,
                "transfer_type": transfer_type,
                "is_cross_region": src_region != dst_region and src_region and dst_region,
                "is_cross_account": src_account != dst_account and src_account and dst_account,
                "relationship_source": "inventory",
            })

        logger.info("Built %d lineage records from inventory relationships", len(lineage))
        return lineage


def _extract_region_from_arn(arn: str) -> str:
    """Extract region from ARN: arn:aws:service:region:account:resource."""
    parts = arn.split(":")
    return parts[3] if len(parts) > 3 else ""


def _extract_account_from_arn(arn: str) -> str:
    """Extract account from ARN."""
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 else ""


def _map_relationship_to_transfer_type(rel_type: str) -> str:
    """Map inventory relationship type to lineage transfer type."""
    mapping = {
        "replicates_to": "replication",
        "backs_up_to": "backup",
        "stores_data_in": "etl",
        "publishes_to": "streaming",
        "subscribes_to": "streaming",
        "reads_from": "read",
        "writes_to": "write",
        "exports_to": "export",
        "imports_from": "import",
    }
    return mapping.get(rel_type, "unknown")
