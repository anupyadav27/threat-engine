"""DI reader for Container Security Engine — reads from asset_inventory."""

from typing import Any, Dict, List, Optional

from engine_common.base_di_reader import BaseDIReader

CONTAINER_SERVICES = ("eks", "ecs", "ecr", "fargate", "lambda")


class ContainerDIReader(BaseDIReader):
    def load_all_container_resources(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: Optional[str] = None,
        services=None,
    ) -> Dict[str, List[Dict[str, Any]]]:
        service_set = services if services is not None else CONTAINER_SERVICES
        return self.load_by_services(scan_run_id, tenant_id, service_set, account_id)
