"""
Base inventory reader — loads from inventory_findings, optionally joined with
di_resource_catalog for canonical type/ARN patterns.

Domain engine readers subclass this and add resource-type-specific filters.

Usage:
    from engine_common.base_inventory_reader import BaseInventoryReader

    class EncryptionInventoryReader(BaseInventoryReader):
        RESOURCE_PREFIXES = ["kms.", "acm.", "secretsmanager."]

        def load_encryption_assets(self, scan_run_id, tenant_id, account_id=None):
            return self.load_by_prefixes(scan_run_id, tenant_id,
                                         self.RESOURCE_PREFIXES, account_id)
"""

from typing import Any, Dict, List, Optional

from .base_reader import BaseDBReader
from .db_connections import get_inventory_conn, get_di_conn

_INVENTORY_COLS = """
    inv.resource_uid, inv.resource_type, inv.resource_name,
    inv.service, inv.region, inv.account_id, inv.provider,
    inv.properties, inv.tags,
    inv.first_seen_at, inv.last_seen_at,
    inv.is_active, inv.config_hash
"""


class BaseInventoryReader(BaseDBReader):
    """Read from inventory_findings, optionally filtered by resource_type."""

    # Subclasses may set this to auto-limit queries to their domain
    RESOURCE_PREFIXES: List[str] = []

    def __init__(self):
        super().__init__(get_inventory_conn)

    def load_by_prefix(
        self,
        scan_run_id: str,
        tenant_id: str,
        resource_type_prefix: str,
        account_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Load inventory_findings where resource_type LIKE prefix%."""
        sql = f"""
            SELECT {_INVENTORY_COLS}
            FROM inventory_findings inv
            WHERE inv.scan_run_id = %s
              AND inv.tenant_id = %s
              AND inv.resource_type LIKE %s
        """
        params: list = [scan_run_id, tenant_id, f"{resource_type_prefix}%"]
        if account_id:
            sql += " AND inv.account_id = %s"
            params.append(account_id)
        return self._safe_fetch(
            sql, params,
            f"inventory resource_type~{resource_type_prefix} for scan {scan_run_id}",
        )

    def load_by_prefixes(
        self,
        scan_run_id: str,
        tenant_id: str,
        prefixes: List[str],
        account_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Load inventory_findings matching any of the given resource_type prefixes."""
        if not prefixes:
            return []
        conditions = " OR ".join(["inv.resource_type LIKE %s"] * len(prefixes))
        sql = f"""
            SELECT {_INVENTORY_COLS}
            FROM inventory_findings inv
            WHERE inv.scan_run_id = %s
              AND inv.tenant_id = %s
              AND ({conditions})
        """
        params: list = [scan_run_id, tenant_id] + [f"{p}%" for p in prefixes]
        if account_id:
            sql += " AND inv.account_id = %s"
            params.append(account_id)
        return self._safe_fetch(
            sql, params,
            f"inventory [{', '.join(prefixes)}] for scan {scan_run_id}",
        )

    def load_by_service(
        self,
        scan_run_id: str,
        tenant_id: str,
        service: str,
        account_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Load inventory_findings for a single service name."""
        sql = f"""
            SELECT {_INVENTORY_COLS}
            FROM inventory_findings inv
            WHERE inv.scan_run_id = %s
              AND inv.tenant_id = %s
              AND inv.service = %s
        """
        params: list = [scan_run_id, tenant_id, service]
        if account_id:
            sql += " AND inv.account_id = %s"
            params.append(account_id)
        return self._safe_fetch(
            sql, params,
            f"inventory service={service} for scan {scan_run_id}",
        )

    def load_identifier_patterns(
        self,
        provider: str,
        resource_type_prefixes: Optional[List[str]] = None,
    ) -> Dict[str, Dict[str, Any]]:
        """Load di_resource_catalog for ARN/ID patterns.

        Returns: {service.canonical_type → {identifier_pattern, primary_param, ...}}

        Use this for inventory categorization instead of static lookup dicts.
        """
        sql = """
            SELECT service, canonical_type, identifier_pattern,
                   primary_param, csp
            FROM di_resource_catalog
            WHERE csp = %s
              AND identifier_pattern IS NOT NULL
              AND identifier_pattern != ''
        """
        params: list = [provider]
        if resource_type_prefixes:
            conditions = " OR ".join(
                ["canonical_type LIKE %s"] * len(resource_type_prefixes)
            )
            sql += f" AND ({conditions})"
            params.extend([f"{p}%" for p in resource_type_prefixes])

        try:
            conn = get_di_conn()
            try:
                from psycopg2.extras import RealDictCursor
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute(sql, params)
                    rows = cur.fetchall()
            finally:
                conn.close()
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("load_identifier_patterns failed: %s", exc)
            rows = []
        return {
            f"{r['service']}.{r['canonical_type']}": dict(r)
            for r in rows
        }
