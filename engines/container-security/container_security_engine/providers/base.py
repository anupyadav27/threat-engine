"""Base provider interface for the Container Security engine."""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class BaseContainerSecurityProvider(ABC):

    @property
    @abstractmethod
    def discovery_services(self) -> List[str]:
        """CSP-specific container service names to load from discovery_findings."""

    @property
    @abstractmethod
    def inventory_resource_prefixes(self) -> List[str]:
        """resource_type prefixes for inventory_findings."""

    @property
    def check_scope_column(self) -> str:
        return "container_security"

    def is_supported(self) -> bool:
        return True

    def enrich_resources(self, resources: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        return resources

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn: Any,
        check_conn: Optional[Any] = None,
    ) -> Optional[List[Dict[str, Any]]]:
        """Pattern A: provider-specific rule findings from discovery data.

        Default returns None (Pattern B — check rules only).
        Override in providers that have rich workload-level analysis.
        """
        return None
