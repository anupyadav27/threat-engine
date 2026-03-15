"""
Azure Discovery Scanner

Multi-cloud architecture: Uses a service handler registry pattern where each Azure
service has a registered handler. New services are added by defining a handler function
and registering it — no hardcoded if/elif chains.

Currently supported:
- resource_groups (Global)
- compute (Regional - Virtual Machines)
- sql (PaaS - SQL Servers)
- storage (SaaS - Storage Accounts)

Extends to all Azure services by adding handler functions.
"""

from typing import Dict, List, Any, Optional, Tuple, Callable
import logging
import asyncio
import importlib
from concurrent.futures import ThreadPoolExecutor
from common.models.provider_interface import DiscoveryScanner, AuthenticationError, DiscoveryError

logger = logging.getLogger(__name__)

# Thread pool for blocking Azure SDK calls
_AZURE_EXECUTOR = ThreadPoolExecutor(max_workers=10)

# Default Azure regions for scanning
DEFAULT_AZURE_REGIONS = [
    'eastus', 'eastus2', 'westus', 'westus2', 'centralus',
    'northeurope', 'westeurope', 'southeastasia', 'eastasia',
    'australiaeast', 'japaneast', 'uksouth', 'canadacentral',
    'centralindia', 'koreacentral', 'brazilsouth',
]

# ─── Service Handler Registry ──────────────────────────────────────
#
# Each handler: fn(credential, subscription_id, region, config) -> List[Dict]
# Add new services by defining a handler and adding to this dict.
# The discovery engine calls scan_service(service, region, config)
# which dispatches to the appropriate handler.
#
AZURE_SERVICE_HANDLERS: Dict[str, Callable] = {}


def azure_handler(service_name: str):
    """Decorator to register an Azure service discovery handler."""
    def decorator(fn: Callable):
        AZURE_SERVICE_HANDLERS[service_name] = fn
        return fn
    return decorator


# ─── Azure Management Client Factory ───────────────────────────────

# Maps service name -> (module_path, class_name) for Azure SDK clients
AZURE_CLIENT_MAP = {
    'resource_groups': ('azure.mgmt.resource', 'ResourceManagementClient'),
    'compute': ('azure.mgmt.compute', 'ComputeManagementClient'),
    'sql': ('azure.mgmt.sql', 'SqlManagementClient'),
    'storage': ('azure.mgmt.storage', 'StorageManagementClient'),
    'network': ('azure.mgmt.network', 'NetworkManagementClient'),
    'keyvault': ('azure.mgmt.keyvault', 'KeyVaultManagementClient'),
    'web': ('azure.mgmt.web', 'WebSiteManagementClient'),
    'monitor': ('azure.mgmt.monitor', 'MonitorManagementClient'),
    'containerservice': ('azure.mgmt.containerservice', 'ContainerServiceClient'),
    'cosmosdb': ('azure.mgmt.cosmosdb', 'CosmosDBManagementClient'),
}


def _get_azure_client(credential, subscription_id: str, service: str):
    """Factory: returns an Azure management client for the given service."""
    if service not in AZURE_CLIENT_MAP:
        raise DiscoveryError(f"No Azure client mapping for service: {service}. "
                             f"Add it to AZURE_CLIENT_MAP in service_scanner.py")
    module_path, class_name = AZURE_CLIENT_MAP[service]
    module = importlib.import_module(module_path)
    client_class = getattr(module, class_name)
    return client_class(credential, subscription_id)


def _serialize_azure_resource(resource, discovery_id: str, resource_type: str) -> Dict[str, Any]:
    """
    Convert an Azure SDK resource object to a serializable dict.

    This is the standard serialization for any Azure management resource.
    Handles common fields (id, name, location, tags) and falls back to
    as_dict() for complete serialization.
    """
    # Use as_dict() if available (all Azure SDK model objects support this)
    if hasattr(resource, 'as_dict'):
        item = resource.as_dict()
    elif hasattr(resource, '__dict__'):
        item = {k: v for k, v in resource.__dict__.items() if not k.startswith('_')}
    else:
        item = {'raw': str(resource)}

    # Ensure standard fields
    item.setdefault('id', getattr(resource, 'id', ''))
    item.setdefault('name', getattr(resource, 'name', ''))
    item.setdefault('location', getattr(resource, 'location', ''))
    item['resource_type'] = resource_type
    item['_discovery_id'] = discovery_id

    # Map Azure 'id' to standard resource identifier fields used by database_manager
    azure_resource_id = item.get('id', '')
    item['resource_arn'] = azure_resource_id      # Azure resource ID as ARN equivalent
    item['resource_id'] = azure_resource_id
    item['resource_uid'] = azure_resource_id

    # Build _raw_response (everything except internal/metadata fields)
    item['_raw_response'] = {k: v for k, v in item.items()
                             if not k.startswith('_') and k not in (
                                 'resource_arn', 'resource_uid', 'resource_id', 'resource_type')}

    # Normalize tags
    tags = getattr(resource, 'tags', None)
    if tags and not isinstance(tags, dict):
        item['tags'] = dict(tags)

    return item


# ─── Service Handlers ───────────────────────────────────────────────
# Each handler is a simple function that takes (credential, sub_id, region, config)
# and returns a list of resource dicts. Add new ones freely.

@azure_handler('resource_groups')
def _scan_resource_groups(credential, subscription_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover Azure resource groups (global — not region-specific)."""
    client = _get_azure_client(credential, subscription_id, 'resource_groups')
    resources = []
    for rg in client.resource_groups.list():
        item = _serialize_azure_resource(rg, 'azure.resource_groups.list', 'Microsoft.Resources/resourceGroups')
        resources.append(item)
    logger.info(f"  resource_groups: {len(resources)} found")
    return resources


@azure_handler('compute')
def _scan_compute(credential, subscription_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover Azure virtual machines, filtered by region."""
    client = _get_azure_client(credential, subscription_id, 'compute')
    resources = []
    for vm in client.virtual_machines.list_all():
        vm_location = (getattr(vm, 'location', '') or '').lower().replace(' ', '')
        if region and region.lower() != vm_location:
            continue
        item = _serialize_azure_resource(vm, 'azure.compute.virtual_machines.list_all', 'Microsoft.Compute/virtualMachines')
        resources.append(item)
    logger.info(f"  compute/{region}: {len(resources)} VMs found")
    return resources


@azure_handler('sql')
def _scan_sql(credential, subscription_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover Azure SQL servers, filtered by region."""
    client = _get_azure_client(credential, subscription_id, 'sql')
    resources = []
    for server in client.servers.list():
        server_location = (getattr(server, 'location', '') or '').lower().replace(' ', '')
        if region and region.lower() != server_location:
            continue
        item = _serialize_azure_resource(server, 'azure.sql.servers.list', 'Microsoft.Sql/servers')
        resources.append(item)
    logger.info(f"  sql/{region}: {len(resources)} SQL servers found")
    return resources


@azure_handler('storage')
def _scan_storage(credential, subscription_id: str, region: str, config: Dict) -> List[Dict]:
    """Discover Azure storage accounts (global — not region-specific)."""
    client = _get_azure_client(credential, subscription_id, 'storage')
    resources = []
    for account in client.storage_accounts.list():
        item = _serialize_azure_resource(account, 'azure.storage.storage_accounts.list', 'Microsoft.Storage/storageAccounts')
        resources.append(item)
    logger.info(f"  storage: {len(resources)} storage accounts found")
    return resources


# ─── Main Scanner Class ─────────────────────────────────────────────

class AzureDiscoveryScanner(DiscoveryScanner):
    """
    Azure-specific discovery scanner implementation.

    Uses a handler registry pattern: AZURE_SERVICE_HANDLERS maps service names
    to handler functions. To add a new Azure service, just define a handler
    function with the @azure_handler('service_name') decorator above.
    """

    def __init__(self, credentials: Dict[str, Any], **kwargs):
        super().__init__(credentials, **kwargs)
        self.credential = None
        self.subscription_id = credentials.get('subscription_id')

    def authenticate(self) -> Any:
        """
        Authenticate to Azure using provided credentials.

        Supports:
        - Service Principal (client_id, client_secret, tenant_id)
        - Managed Identity
        - Application Default (DefaultAzureCredential — picks up CLI, env, managed identity)
        """
        try:
            cred_type = self.credentials.get('credential_type', '').lower()

            if cred_type in ('service_principal', 'azure_service_principal'):
                from azure.identity import ClientSecretCredential
                self.credential = ClientSecretCredential(
                    tenant_id=self.credentials['tenant_id'],
                    client_id=self.credentials['client_id'],
                    client_secret=self.credentials['client_secret']
                )
                logger.info("Azure authentication successful (Service Principal)")

            elif cred_type == 'managed_identity':
                from azure.identity import ManagedIdentityCredential
                self.credential = ManagedIdentityCredential()
                logger.info("Azure authentication successful (Managed Identity)")

            elif cred_type == 'application_default':
                from azure.identity import DefaultAzureCredential
                self.credential = DefaultAzureCredential()
                logger.info("Azure authentication successful (DefaultAzureCredential)")

            else:
                from azure.identity import DefaultAzureCredential
                self.credential = DefaultAzureCredential()
                logger.info(f"Azure auth: unknown type '{cred_type}', using DefaultAzureCredential")

            return self.credential

        except Exception as e:
            logger.error(f"Azure authentication failed: {e}")
            raise AuthenticationError(f"Azure authentication failed: {e}")

    async def scan_service(
        self,
        service: str,
        region: str,
        config: Dict[str, Any]
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        """
        Execute Azure service discovery.

        Dispatches to the registered handler for the service.
        Runs Azure SDK calls in a thread pool (SDK is blocking).
        Returns (discoveries, scan_metadata) tuple.
        """
        handler = AZURE_SERVICE_HANDLERS.get(service)
        if not handler:
            logger.warning(f"Azure: no handler registered for service '{service}'. "
                           f"Available: {list(AZURE_SERVICE_HANDLERS.keys())}")
            return [], {'service': service, 'region': region, 'error': f'No handler for {service}'}

        loop = asyncio.get_event_loop()
        try:
            discoveries = await loop.run_in_executor(
                _AZURE_EXECUTOR,
                handler,
                self.credential,
                self.subscription_id,
                region,
                config
            )
            scan_metadata = {
                'service': service,
                'region': region,
                'resource_count': len(discoveries),
                'provider': 'azure',
            }
            logger.info(f"Azure {service}/{region}: {len(discoveries)} resources discovered")
            return discoveries, scan_metadata

        except Exception as e:
            logger.error(f"Azure scan_service failed for {service}/{region}: {e}")
            return [], {'service': service, 'region': region, 'error': str(e)}

    def get_client(self, service: str, region: str) -> Any:
        """Get Azure SDK client for specific service."""
        return _get_azure_client(self.credential, self.subscription_id, service)

    def extract_resource_identifier(
        self,
        item: Dict[str, Any],
        service: str,
        region: str,
        account_id: str,
        resource_type: Optional[str] = None
    ) -> Dict[str, str]:
        """
        Extract resource identifiers from Azure response.

        Azure resource ID format:
        /subscriptions/{sub}/resourceGroups/{rg}/providers/{provider}/{type}/{name}
        """
        resource_id = item.get('id', '')
        resource_name = item.get('name', '')

        if not resource_type:
            resource_type = item.get('resource_type', '')
            if not resource_type and '/providers/' in resource_id:
                parts = resource_id.split('/providers/')
                if len(parts) > 1:
                    provider_parts = parts[-1].split('/')
                    if len(provider_parts) >= 2:
                        resource_type = f"{provider_parts[0]}/{provider_parts[1]}"

        return {
            'resource_arn': resource_id,
            'resource_id': resource_id,
            'resource_name': resource_name,
            'resource_uid': resource_id,
            'resource_type': resource_type,
        }

    def get_service_client_name(self, service: str) -> str:
        """Map service name to Azure SDK client class name."""
        if service in AZURE_CLIENT_MAP:
            return AZURE_CLIENT_MAP[service][1]
        return service

    async def list_available_regions(self) -> List[str]:
        """List available Azure regions for the subscription."""
        try:
            from azure.mgmt.subscription import SubscriptionClient
            client = SubscriptionClient(self.credential)
            regions = []
            for location in client.subscriptions.list_locations(self.subscription_id):
                regions.append(location.name)
            logger.info(f"Azure: {len(regions)} regions available")
            return sorted(regions)
        except Exception as e:
            logger.warning(f"Failed to list Azure regions, using defaults: {e}")
            return DEFAULT_AZURE_REGIONS

    def get_account_id(self) -> str:
        """Return subscription ID as account identifier."""
        return self.subscription_id or ''
