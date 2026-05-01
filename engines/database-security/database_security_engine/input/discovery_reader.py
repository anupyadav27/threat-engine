"""Discovery reader for Database Security Engine."""

from typing import Any, Dict, List, Optional

from engine_common.base_discovery_reader import BaseDiscoveryReader

DB_SERVICES = (
    "rds", "dynamodb", "redshift", "elasticache", "neptune",
    "documentdb", "opensearch", "timestream", "keyspaces", "dax",
)


class DiscoveryReader(BaseDiscoveryReader):
    def load_all_db_resources(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: Optional[str] = None,
        services=None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Load DB resources. services override comes from providers/ factory."""
        service_set = services if services is not None else DB_SERVICES
        return self.load_by_services(scan_run_id, tenant_id, service_set, account_id)

    def load_by_service(self, scan_run_id: str, tenant_id: str, service: str, account_id: Optional[str] = None) -> List[Dict[str, Any]]:
        return super().load_by_service(scan_run_id, tenant_id, service, account_id)


# Backwards-compat alias
DBDiscoveryReader = DiscoveryReader
