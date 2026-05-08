"""Base class for CIEM CSP providers."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Type


class BaseCIEMProvider(ABC):
    @abstractmethod
    def get_parsers(self) -> Dict[str, Type]:
        """Return dict of source_type → parser class."""

    @abstractmethod
    def get_readers(self) -> Dict[str, Type]:
        """Return dict of storage_type → reader class."""

    @abstractmethod
    def create_session(
        self,
        region: str,
        account_id: str,
        credentials: Optional[Dict] = None,
    ) -> Optional[Any]:
        """Create CSP-specific cloud session for reading logs.

        Args:
            region: Cloud region string.
            account_id: Cloud account / subscription / project ID.
            credentials: Resolved credentials dict from Secrets Manager
                (same structure as discovery engine uses). Falls back to
                environment / instance-profile if None or empty.
        """
