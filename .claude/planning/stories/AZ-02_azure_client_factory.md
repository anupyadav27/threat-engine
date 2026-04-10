---
story_id: AZ-02
title: Implement AzureClientFactory
status: done
sprint: azure-track-wave-2
depends_on: [AZ-01]
blocks: [AZ-03, AZ-04]
sme: Python/azure-mgmt-* engineer
estimate: 1 day
---

# Story: Implement AzureClientFactory

## Context
Every Azure SDK client requires a `credential` object and a `subscription_id`. The factory centralizes this so scanners never construct clients directly. It maps the `service` string from `rule_discoveries` table to the correct Azure SDK client class.

Credential must come from Secrets Manager (via `credential_ref`), not bare env vars — see AZ-17b for full resolution path. For this story, accept a pre-resolved dict `{"tenant_id": ..., "client_id": ..., "client_secret": ..., "subscription_id": ...}`.

## Files to Modify

- `engines/discoveries/providers/azure/client_factory.py` — full implementation

## Implementation Notes

```python
"""Azure SDK client factory for CSPM discovery."""
from typing import Dict, Any
import importlib

# Map service name (from rule_discoveries.service) → Azure SDK module + class
_CLIENT_MAP: Dict[str, tuple[str, str]] = {
    "compute":          ("azure.mgmt.compute",          "ComputeManagementClient"),
    "network":          ("azure.mgmt.network",           "NetworkManagementClient"),
    "storage":          ("azure.mgmt.storage",           "StorageManagementClient"),
    "keyvault":         ("azure.mgmt.keyvault",          "KeyVaultManagementClient"),
    "sql":              ("azure.mgmt.sql",               "SqlManagementClient"),
    "authorization":    ("azure.mgmt.authorization",     "AuthorizationManagementClient"),
    "containerservice": ("azure.mgmt.containerservice",  "ContainerServiceClient"),
    "web":              ("azure.mgmt.web",               "WebSiteManagementClient"),
    "monitor":          ("azure.mgmt.monitor",           "MonitorManagementClient"),
    "security":         ("azure.mgmt.security",          "SecurityCenter"),
    "resource":         ("azure.mgmt.resource",          "ResourceManagementClient"),
    "cosmosdb":         ("azure.mgmt.cosmosdb",          "CosmosDBManagementClient"),
    "dns":              ("azure.mgmt.dns",               "DnsManagementClient"),
}

class AzureClientFactory:
    def __init__(self, credentials: Dict[str, str]) -> None:
        """
        Args:
            credentials: dict with tenant_id, client_id, client_secret, subscription_id
        """
        from azure.identity import ClientSecretCredential
        self._credential = ClientSecretCredential(
            tenant_id=credentials["tenant_id"],
            client_id=credentials["client_id"],
            client_secret=credentials["client_secret"],
        )
        self._subscription_id = credentials["subscription_id"]
    
    def get_client(self, service: str) -> Any:
        """Return Azure SDK client for given service name.
        
        Args:
            service: Service name matching rule_discoveries.service column
            
        Returns:
            Initialized Azure SDK management client
            
        Raises:
            ValueError: If service name is not in _CLIENT_MAP
        """
        if service not in _CLIENT_MAP:
            raise ValueError(f"Unknown Azure service: {service!r}. "
                             f"Known services: {list(_CLIENT_MAP.keys())}")
        module_path, class_name = _CLIENT_MAP[service]
        module = importlib.import_module(module_path)
        client_class = getattr(module, class_name)
        return client_class(self._credential, self._subscription_id)
```

**Why `importlib`?** Avoids importing all azure-mgmt-* packages at module load time. Only imports the SDK for services actually in `rule_discoveries`.

## Acceptance Criteria
- [ ] `AzureClientFactory(credentials).get_client("compute")` returns `ComputeManagementClient` instance
- [ ] `get_client("unknown_service")` raises `ValueError` with helpful message listing known services
- [ ] `importlib.import_module` is used — not top-level imports of all azure-mgmt packages
- [ ] Unit test with mock `ClientSecretCredential` passes (credential object created correctly)
- [ ] All 13 service mappings in `_CLIENT_MAP` are present

## Definition of Done
- [ ] `client_factory.py` implemented with all 13 services
- [ ] Unit tests written (mock azure.identity, mock azure.mgmt.compute)
- [ ] Type hints on all public methods
- [ ] Google-style docstrings