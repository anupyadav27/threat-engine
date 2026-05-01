"""Discovery reader for Container Security Engine."""

from typing import Any, Dict, List, Optional

from engine_common.base_discovery_reader import BaseDiscoveryReader

CONTAINER_SERVICES = ("eks", "ecs", "ecr", "fargate", "lambda")


class ContainerDiscoveryReader(BaseDiscoveryReader):
    def load_all_container_resources(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: Optional[str] = None,
        services=None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Load container resources. services override comes from providers/ factory."""
        service_set = services if services is not None else CONTAINER_SERVICES
        return self.load_by_services(scan_run_id, tenant_id, service_set, account_id)
