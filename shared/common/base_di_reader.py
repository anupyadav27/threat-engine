"""
Base DI reader — loads from asset_inventory (threat_engine_di) by service.

Drop-in replacement for BaseDiscoveryReader. Engine-specific di_reader.py
files subclass this instead of BaseDiscoveryReader. Returns identical column
shapes so all downstream engine logic works without changes.
"""

from typing import Any, Dict, List, Optional

from .base_reader import BaseDBReader
from .db_connections import get_di_conn

_DI_COLS = """
    resource_uid,
    resource_uid AS resource_id,
    resource_type, service,
    region, account_id, provider,
    emitted_fields, raw_response,
    config_hash,
    NULL::text AS version,
    first_seen_at,
    discovery_id
"""


class BaseDIReader(BaseDBReader):
    """Reads from asset_inventory in threat_engine_di.

    Identical interface to BaseDiscoveryReader so all engine subclasses
    can swap parent class without changing any service-specific methods.
    """

    def __init__(self):
        super().__init__(get_di_conn)

    def load_by_service(
        self,
        scan_run_id: str,
        tenant_id: str,
        service: str,
        account_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        sql = f"""
            SELECT {_DI_COLS}
            FROM asset_inventory
            WHERE scan_run_id = %s
              AND tenant_id = %s
              AND service = %s
        """
        params: list = [scan_run_id, tenant_id, service]
        if account_id:
            sql += " AND account_id = %s"
            params.append(account_id)
        return self._safe_fetch(sql, params, f"{service} DI assets for scan {scan_run_id}")

    def load_by_services(
        self,
        scan_run_id: str,
        tenant_id: str,
        services,
        account_id: Optional[str] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        result: Dict[str, List[Dict[str, Any]]] = {}
        for service in services:
            rows = self.load_by_service(scan_run_id, tenant_id, service, account_id)
            if rows:
                result[service] = rows
        return result

    def load_by_resource_type(
        self,
        scan_run_id: str,
        tenant_id: str,
        resource_type_prefix: str,
        account_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        sql = f"""
            SELECT {_DI_COLS}
            FROM asset_inventory
            WHERE scan_run_id = %s
              AND tenant_id = %s
              AND resource_type LIKE %s
        """
        params: list = [scan_run_id, tenant_id, f"{resource_type_prefix}%"]
        if account_id:
            sql += " AND account_id = %s"
            params.append(account_id)
        return self._safe_fetch(
            sql, params,
            f"resource_type~{resource_type_prefix} DI assets for scan {scan_run_id}",
        )

    def load_flat(
        self,
        scan_run_id: str,
        tenant_id: str,
        services,
        account_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        grouped = self.load_by_services(scan_run_id, tenant_id, services, account_id)
        return [r for rows in grouped.values() for r in rows]
