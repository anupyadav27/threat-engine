"""
Inventory DB Reader for Encryption Engine.

Reads resource-to-KMS-key relationships from inventory_relationships
and resource metadata from inventory_findings in threat_engine_inventory.
"""

import os
import logging
from typing import List, Dict, Any, Optional

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger(__name__)


def _get_inventory_conn():
    """Get connection to the Inventory database."""
    return psycopg2.connect(
        host=os.getenv("INVENTORY_DB_HOST", os.getenv("DB_HOST", "localhost")),
        port=int(os.getenv("INVENTORY_DB_PORT", os.getenv("DB_PORT", "5432"))),
        dbname=os.getenv("INVENTORY_DB_NAME", "threat_engine_inventory"),
        user=os.getenv("INVENTORY_DB_USER", os.getenv("DB_USER", "postgres")),
        password=os.getenv("INVENTORY_DB_PASSWORD", os.getenv("DB_PASSWORD", "")),
        sslmode=os.getenv("DB_SSLMODE", "prefer"),
    )


class InventoryReader:
    """Reads resource relationships and metadata from Inventory DB."""

    def __init__(self):
        self.conn = None

    def _ensure_conn(self):
        if self.conn is None or self.conn.closed:
            self.conn = _get_inventory_conn()

    def load_kms_relationships(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load relationships where target or source is a KMS key.

        Returns edges like: S3 bucket → uses → KMS key.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        source_uid, source_type,
                        target_uid, target_type,
                        relationship_type, relationship_label,
                        metadata
                    FROM inventory_relationships
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND (
                          target_type ILIKE '%%kms%%'
                          OR source_type ILIKE '%%kms%%'
                          OR relationship_type ILIKE '%%encrypt%%'
                          OR relationship_type ILIKE '%%kms%%'
                      )
                """, (scan_run_id, tenant_id))
                rows = cur.fetchall()
                logger.info(f"Inventory: loaded {len(rows)} KMS relationships for scan {scan_run_id}")
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load KMS relationships: {e}", exc_info=True)
            return []

    def load_resource_encryption_fields(
        self,
        scan_run_id: str,
        tenant_id: str,
    ) -> List[Dict[str, Any]]:
        """Load inventory_findings with encryption-related fields in finding_data.

        Useful for extracting kms_key_id references embedded in resource metadata.
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT
                        resource_uid, resource_type, resource_name,
                        account_id, region, provider,
                        finding_data, config_hash
                    FROM inventory_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND (
                          finding_data::text ILIKE '%%kms%%'
                          OR finding_data::text ILIKE '%%encrypt%%'
                          OR finding_data::text ILIKE '%%ServerSideEncryption%%'
                      )
                """, (scan_run_id, tenant_id))
                rows = cur.fetchall()
                logger.info(f"Inventory: loaded {len(rows)} resources with encryption fields")
                return [dict(r) for r in rows]
        except Exception as e:
            logger.error(f"Failed to load inventory encryption fields: {e}", exc_info=True)
            return []

    def load_config_hashes(
        self,
        scan_run_id: str,
        tenant_id: str,
        resource_uids: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """Load config_hash values for drift detection.

        Returns: {resource_uid: config_hash}
        """
        self._ensure_conn()
        try:
            with self.conn.cursor(cursor_factory=RealDictCursor) as cur:
                if resource_uids:
                    cur.execute("""
                        SELECT resource_uid, config_hash
                        FROM inventory_findings
                        WHERE scan_run_id = %s
                          AND tenant_id = %s
                          AND resource_uid = ANY(%s)
                    """, (scan_run_id, tenant_id, resource_uids))
                else:
                    cur.execute("""
                        SELECT resource_uid, config_hash
                        FROM inventory_findings
                        WHERE scan_run_id = %s
                          AND tenant_id = %s
                          AND config_hash IS NOT NULL
                    """, (scan_run_id, tenant_id))
                return {r["resource_uid"]: r["config_hash"] for r in cur.fetchall()}
        except Exception as e:
            logger.error(f"Failed to load config hashes: {e}", exc_info=True)
            return {}

    def close(self):
        if self.conn and not self.conn.closed:
            self.conn.close()
