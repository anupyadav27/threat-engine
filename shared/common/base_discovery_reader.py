"""
Base discovery reader — loads from discovery_findings by service.

Domain engine readers subclass this and add service-specific methods.

Usage:
    from engine_common.base_discovery_reader import BaseDiscoveryReader

    class DiscoveryReader(BaseDiscoveryReader):
        def load_all_rds_resources(self, scan_run_id, tenant_id, account_id=None):
            return self.load_by_service(scan_run_id, tenant_id, "rds", account_id)
"""

from typing import Any, Dict, List, Optional

from .base_reader import BaseDBReader
from .db_connections import get_discoveries_conn

_DISCOVERY_COLS = """
    resource_uid, resource_id, resource_type, service,
    region, account_id, provider,
    emitted_fields, raw_response,
    config_hash, version, first_seen_at
"""


class BaseDiscoveryReader(BaseDBReader):
    def __init__(self):
        super().__init__(get_discoveries_conn)

    def load_by_service(
        self,
        scan_run_id: str,
        tenant_id: str,
        service: str,
        account_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Load discovery_findings for a single service."""
        sql = f"""
            SELECT {_DISCOVERY_COLS}
            FROM discovery_findings
            WHERE scan_run_id = %s
              AND tenant_id = %s
              AND service = %s
        """
        params: list = [scan_run_id, tenant_id, service]
        if account_id:
            sql += " AND account_id = %s"
            params.append(account_id)
        return self._safe_fetch(sql, params, f"{service} discovery resources for scan {scan_run_id}")

    def load_by_services(
        self,
        scan_run_id: str,
        tenant_id: str,
        services,
        account_id: Optional[str] = None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Load discovery_findings for multiple services, grouped by service name.

        Returns a dict {service: [resource, ...]} — only non-empty services included.
        Callers that need a flat list should use:
            flat = [r for items in result.values() for r in items]
        """
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
        """Load discovery_findings by resource_type LIKE prefix%.

        Useful when a CSP uses a single discovery service but multiple resource types
        (e.g. 'rds.cluster', 'rds.instance', 'rds.snapshot' all have prefix 'rds.').
        """
        sql = f"""
            SELECT {_DISCOVERY_COLS}
            FROM discovery_findings
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
            f"resource_type~{resource_type_prefix} discovery for scan {scan_run_id}",
        )

    def load_flat(
        self,
        scan_run_id: str,
        tenant_id: str,
        services,
        account_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Like load_by_services() but returns a flat list instead of a grouped dict."""
        grouped = self.load_by_services(scan_run_id, tenant_id, services, account_id)
        return [r for rows in grouped.values() for r in rows]
