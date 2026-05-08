"""Inventory reader for Encryption Security Engine."""

from typing import Any, Dict, List, Optional

from engine_common.base_reader import BaseDBReader
from engine_common.db_connections import get_inventory_conn


class InventoryReader(BaseDBReader):
    def __init__(self):
        super().__init__(get_inventory_conn)

    def load_kms_relationships(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        """Load relationships where source or target is a KMS key.

        Column aliases map inventory_relationships columns to the names
        expected by downstream analyzers (key_inventory_builder, dependency_graph).
        """
        return self._safe_fetch("""
            SELECT
                from_uid            AS source_uid,
                from_resource_type  AS source_type,
                to_uid              AS target_uid,
                to_resource_type    AS target_type,
                relation_type       AS relationship_type,
                metadata
            FROM inventory_relationships
            WHERE scan_run_id = %s
              AND tenant_id = %s
              AND (
                  to_resource_type ILIKE '%%kms%%'
                  OR from_resource_type ILIKE '%%kms%%'
                  OR relation_type ILIKE '%%encrypt%%'
                  OR relation_type ILIKE '%%kms%%'
              )
        """, (scan_run_id, tenant_id), f"KMS relationships for scan {scan_run_id}")

    def load_resource_encryption_fields(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        """Load inventory_findings that reference KMS or encryption fields."""
        return self._safe_fetch("""
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
        """, (scan_run_id, tenant_id), f"inventory encryption fields for scan {scan_run_id}")

    def load_config_hashes(
        self,
        scan_run_id: str,
        tenant_id: str,
        resource_uids: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """Load config_hash values keyed by resource_uid."""
        if resource_uids:
            rows = self._safe_fetch("""
                SELECT resource_uid, config_hash
                FROM inventory_findings
                WHERE scan_run_id = %s AND tenant_id = %s AND resource_uid = ANY(%s)
            """, (scan_run_id, tenant_id, resource_uids), "config hashes (filtered)")
        else:
            rows = self._safe_fetch("""
                SELECT resource_uid, config_hash
                FROM inventory_findings
                WHERE scan_run_id = %s AND tenant_id = %s AND config_hash IS NOT NULL
            """, (scan_run_id, tenant_id), "config hashes (all)")
        return {r["resource_uid"]: r["config_hash"] for r in rows}
