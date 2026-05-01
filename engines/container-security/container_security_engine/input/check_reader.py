"""Check reader for Container Security Engine."""

from typing import Any, Dict, List

from engine_common.base_check_reader import BaseCheckReader


class ContainerCheckReader(BaseCheckReader):
    ENGINE_SCOPE = "container_security"

    def load_container_check_findings(self, scan_run_id: str, tenant_id: str) -> List[Dict[str, Any]]:
        return self.load_check_findings(scan_run_id, tenant_id)
