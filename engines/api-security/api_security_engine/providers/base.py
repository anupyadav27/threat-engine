from abc import ABC, abstractmethod
from typing import Any, Dict, List


class BaseAPISecProvider(ABC):
    """Base class for all CSP API security providers."""

    @abstractmethod
    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discoveries_conn,
        check_conn,
    ) -> List[Dict[str, Any]]:
        """Return list of api_security finding dicts."""
        ...
