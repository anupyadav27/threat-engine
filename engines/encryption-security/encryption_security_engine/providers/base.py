"""Base provider interface for the Encryption Security engine."""
from abc import ABC, abstractmethod
from typing import Any, Dict, List


class BaseEncryptionProvider(ABC):

    @property
    @abstractmethod
    def key_services(self) -> List[str]:
        """Discovery services for encryption keys/KMS."""

    @property
    @abstractmethod
    def cert_services(self) -> List[str]:
        """Discovery services for certificates."""

    @property
    @abstractmethod
    def secrets_services(self) -> List[str]:
        """Discovery services for secrets management."""

    @property
    def all_services(self) -> List[str]:
        return sorted(set(self.key_services + self.cert_services + self.secrets_services))

    @property
    @abstractmethod
    def inventory_resource_prefixes(self) -> List[str]:
        """resource_type prefixes for inventory_findings."""

    @property
    def check_scope_column(self) -> str:
        return "encryption_security"

    def is_supported(self) -> bool:
        return True

    def enrich_resources(self, resources: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        return resources
