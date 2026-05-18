"""Base provider interface for the Encryption Security engine."""
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


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

    def analyze(
        self,
        scan_run_id: str,
        tenant_id: str,
        account_id: str,
        discovery_resources: Dict[str, List[Dict[str, Any]]],
    ) -> Optional[List[Dict[str, Any]]]:
        """Pattern A: rule-based findings from discovery data.

        Returns None to signal Pattern B fallback (coverage-based analysis).
        Subclasses override to produce named rule findings (KMS rotation,
        cert expiry, TLS version, secrets rotation).
        """
        return None

    def enrich_resources(self, resources: List[Dict[str, Any]], context: Dict[str, Any]) -> List[Dict[str, Any]]:
        return resources
