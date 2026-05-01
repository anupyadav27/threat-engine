"""Azure CIEM provider — parsers, readers, and session creation."""

import logging
from typing import Any, Dict, Optional, Type

from .base import BaseCIEMProvider

logger = logging.getLogger(__name__)


class AzureCIEMProvider(BaseCIEMProvider):
    def get_parsers(self) -> Dict[str, Type]:
        extra: Dict[str, Type] = {}
        try:
            from ciem_engine.parser.azure_activity_parser import AzureActivityParser
            from ciem_engine.parser.azure_nsg_flow_parser import AzureNSGFlowParser
            extra["azure_activity"] = AzureActivityParser
            extra["azure_nsg_flow"] = AzureNSGFlowParser
        except ImportError:
            pass
        return extra

    def get_readers(self) -> Dict[str, Type]:
        extra: Dict[str, Type] = {}
        try:
            from ciem_engine.reader.azure_blob_reader import AzureBlobReader
            extra["azure_blob"] = AzureBlobReader
        except ImportError:
            pass
        try:
            from ciem_engine.reader.azure_monitor_reader import AzureMonitorReader
            extra["azure_monitor"] = AzureMonitorReader
        except ImportError:
            pass
        return extra

    def create_session(
        self,
        region: str,
        account_id: str,
        credentials: Optional[dict] = None,
    ) -> Optional[Any]:
        creds = credentials or {}
        cred_type = creds.get("credential_type", "")
        try:
            if cred_type in ("service_principal", "client_secret", "azure_service_principal"):
                from azure.identity import ClientSecretCredential
                return ClientSecretCredential(
                    tenant_id=creds.get("tenant_id", ""),
                    client_id=creds.get("client_id", ""),
                    client_secret=creds.get("client_secret", ""),
                )
            from azure.identity import DefaultAzureCredential
            return DefaultAzureCredential()
        except ImportError:
            logger.warning("azure-identity not installed — Azure log collection unavailable")
            return None
