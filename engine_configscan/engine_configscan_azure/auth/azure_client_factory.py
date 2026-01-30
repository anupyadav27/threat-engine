"""
Azure Client Factory
Provides centralized client management for all Azure services, similar to boto3 for AWS
"""

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from typing import Dict, Optional, Any
import os
import logging

logger = logging.getLogger(__name__)


class AzureClientFactory:
    """
    Centralized Azure client factory similar to boto3.
    Maps service names to their appropriate Azure SDK clients.
    """
    
    # Service name → (package, client_class, client_params)
    SERVICE_CLIENT_MAPPING = {
        # Core Management
        'resource': ('azure.mgmt.resource', 'ResourceManagementClient', {}),
        'subscription': ('azure.mgmt.subscription', 'SubscriptionClient', {}),
        'managementgroup': ('azure.mgmt.managementgroups', 'ManagementGroupsAPI', {}),
        'managementgroups': ('azure.mgmt.managementgroups', 'ManagementGroupsAPI', {}),
        'policy': ('azure.mgmt.resource.policy', 'PolicyClient', {}),
        'rbac': ('azure.mgmt.authorization', 'AuthorizationManagementClient', {}),
        'authorization': ('azure.mgmt.authorization', 'AuthorizationManagementClient', {}),
        
        # Compute & Containers
        'compute': ('azure.mgmt.compute', 'ComputeManagementClient', {}),
        'vm': ('azure.mgmt.compute', 'ComputeManagementClient', {}),
        'virtualmachines': ('azure.mgmt.compute', 'ComputeManagementClient', {}),
        'disk': ('azure.mgmt.compute', 'ComputeManagementClient', {}),
        'aks': ('azure.mgmt.containerservice', 'ContainerServiceClient', {}),
        'kubernetes': ('azure.mgmt.containerservice', 'ContainerServiceClient', {}),
        'containerservice': ('azure.mgmt.containerservice', 'ContainerServiceClient', {}),
        'container': ('azure.mgmt.containerinstance', 'ContainerInstanceManagementClient', {}),
        'containerregistry': ('azure.mgmt.containerregistry', 'ContainerRegistryManagementClient', {}),
        
        # Storage
        'storage': ('azure.mgmt.storage', 'StorageManagementClient', {}),
        'storageaccount': ('azure.mgmt.storage', 'StorageManagementClient', {}),
        'blob': ('azure.storage.blob', 'BlobServiceClient', {'connection_string_based': True}),
        'files': ('azure.storage.fileshare', 'ShareServiceClient', {'connection_string_based': True}),
        
        # Networking
        'network': ('azure.mgmt.network', 'NetworkManagementClient', {}),
        'networksecuritygroup': ('azure.mgmt.network', 'NetworkManagementClient', {}),
        'vpn': ('azure.mgmt.network', 'NetworkManagementClient', {}),
        'loadbalancer': ('azure.mgmt.network', 'NetworkManagementClient', {}),
        'load': ('azure.mgmt.network', 'NetworkManagementClient', {}),
        'dns': ('azure.mgmt.dns', 'DnsManagementClient', {}),
        'cdn': ('azure.mgmt.cdn', 'CdnManagementClient', {}),
        'front': ('azure.mgmt.frontdoor', 'FrontDoorManagementClient', {}),
        'traffic': ('azure.mgmt.trafficmanager', 'TrafficManagerManagementClient', {}),
        
        # Databases
        'sql': ('azure.mgmt.sql', 'SqlManagementClient', {}),
        'sqlserver': ('azure.mgmt.sql', 'SqlManagementClient', {}),
        'mysql': ('azure.mgmt.rdbms.mysql', 'MySQLManagementClient', {}),
        'postgresql': ('azure.mgmt.rdbms.postgresql', 'PostgreSQLManagementClient', {}),
        'mariadb': ('azure.mgmt.rdbms.mariadb', 'MariaDBManagementClient', {}),
        'cosmosdb': ('azure.mgmt.cosmosdb', 'CosmosDBManagementClient', {}),
        'cosmos': ('azure.mgmt.cosmosdb', 'CosmosDBManagementClient', {}),
        'redis': ('azure.mgmt.redis', 'RedisManagementClient', {}),
        'cache': ('azure.mgmt.redis', 'RedisManagementClient', {}),
        
        # Identity & Security (Microsoft Graph)
        'aad': ('msgraph', 'GraphServiceClient', {'graph_based': True}),
        'ad': ('msgraph', 'GraphServiceClient', {'graph_based': True}),
        'entra': ('msgraph', 'GraphServiceClient', {'graph_based': True}),
        'entrad': ('msgraph', 'GraphServiceClient', {'graph_based': True}),
        'graph': ('msgraph', 'GraphServiceClient', {'graph_based': True}),
        'user': ('msgraph', 'GraphServiceClient', {'graph_based': True}),
        'password': ('msgraph', 'GraphServiceClient', {'graph_based': True}),
        'intune': ('msgraph', 'GraphServiceClient', {'graph_based': True}),
        
        # Security & Monitoring
        'security': ('azure.mgmt.security', 'SecurityCenter', {}),
        'securitycenter': ('azure.mgmt.security', 'SecurityCenter', {}),
        'defender': ('azure.mgmt.security', 'SecurityCenter', {}),
        'monitor': ('azure.mgmt.monitor', 'MonitorManagementClient', {}),
        'log': ('azure.mgmt.loganalytics', 'LogAnalyticsManagementClient', {}),
        'audit': ('azure.mgmt.monitor', 'MonitorManagementClient', {}),
        
        # Key Vault
        'keyvault': ('azure.mgmt.keyvault', 'KeyVaultManagementClient', {}),
        'key': ('azure.keyvault.keys', 'KeyClient', {'keyvault_dataplane': True}),
        'certificates': ('azure.keyvault.certificates', 'CertificateClient', {'keyvault_dataplane': True}),
        
        # App Services
        'app': ('azure.mgmt.web', 'WebSiteManagementClient', {}),
        'appservice': ('azure.mgmt.web', 'WebSiteManagementClient', {}),
        'webapp': ('azure.mgmt.web', 'WebSiteManagementClient', {}),
        'web': ('azure.mgmt.web', 'WebSiteManagementClient', {}),
        'function': ('azure.mgmt.web', 'WebSiteManagementClient', {}),
        'functionapp': ('azure.mgmt.web', 'WebSiteManagementClient', {}),
        'functions': ('azure.mgmt.web', 'WebSiteManagementClient', {}),
        'site': ('azure.mgmt.web', 'WebSiteManagementClient', {}),
        'api': ('azure.mgmt.apimanagement', 'ApiManagementClient', {}),
        'logic': ('azure.mgmt.logic', 'LogicManagementClient', {}),
        
        # Data & Analytics
        'data': ('azure.mgmt.datafactory', 'DataFactoryManagementClient', {}),
        'databricks': ('azure.mgmt.databricks', 'AzureDatabricksManagementClient', {}),
        'synapse': ('azure.mgmt.synapse', 'SynapseManagementClient', {}),
        'hdinsight': ('azure.mgmt.hdinsight', 'HDInsightManagementClient', {}),
        'search': ('azure.mgmt.search', 'SearchManagementClient', {}),
        'aisearch': ('azure.mgmt.search', 'SearchManagementClient', {}),
        'purview': ('azure.mgmt.purview', 'PurviewManagementClient', {}),
        
        # Backup & Recovery
        'backup': ('azure.mgmt.recoveryservices', 'RecoveryServicesClient', {}),
        'recoveryservices': ('azure.mgmt.recoveryservices', 'RecoveryServicesClient', {}),
        'recoveryservicesbackup': ('azure.mgmt.recoveryservices', 'RecoveryServicesClient', {}),
        'dataprotection': ('azure.mgmt.dataprotection', 'DataProtectionClient', {}),
        
        # Other Services
        'automation': ('azure.mgmt.automation', 'AutomationClient', {}),
        'patch': ('azure.mgmt.automation', 'AutomationClient', {}),
        'batch': ('azure.mgmt.batch', 'BatchManagementClient', {}),
        'billing': ('azure.mgmt.billing', 'BillingManagementClient', {}),
        'cost': ('azure.mgmt.costmanagement', 'CostManagementClient', {}),
        'event': ('azure.mgmt.eventgrid', 'EventGridManagementClient', {}),
        'eventhub': ('azure.mgmt.eventhub', 'EventHubManagementClient', {}),
        'eventhubs': ('azure.mgmt.eventhub', 'EventHubManagementClient', {}),
        'iot': ('azure.mgmt.iothub', 'IotHubClient', {}),
        'notification': ('azure.mgmt.notificationhubs', 'NotificationHubsManagementClient', {}),
        'power': ('azure.mgmt.powerbiembedded', 'PowerBIEmbeddedManagementClient', {}),
        'netappfiles': ('azure.mgmt.netapp', 'NetAppManagementClient', {}),
        'elastic': ('azure.mgmt.elastic', 'ElasticManagementClient', {}),
        'machine': ('azure.mgmt.machinelearningservices', 'MachineLearningServicesManagementClient', {}),
        
        # Additional services
        'kusto': ('azure.mgmt.kusto', 'KustoManagementClient', {}),
        'loganalytics': ('azure.mgmt.loganalytics', 'LogAnalyticsManagementClient', {}),
        'managedidentity': ('azure.mgmt.msi', 'ManagedServiceIdentityClient', {}),
        'servicebus': ('azure.mgmt.servicebus', 'ServiceBusManagementClient', {}),
        'signalr': ('azure.mgmt.signalr', 'SignalRManagementClient', {}),
        'streamanalytics': ('azure.mgmt.streamanalytics', 'StreamAnalyticsManagementClient', {}),
    }
    
    def __init__(self, subscription_id: Optional[str] = None, credential: Optional[Any] = None):
        """
        Initialize Azure Client Factory
        
        Args:
            subscription_id: Azure subscription ID (from env if not provided)
            credential: Azure credential object (DefaultAzureCredential if not provided)
        """
        self.subscription_id = subscription_id or os.getenv('AZURE_SUBSCRIPTION_ID')
        if not self.subscription_id:
            raise ValueError("AZURE_SUBSCRIPTION_ID must be set in environment or passed as parameter")
        
        # Initialize credential
        if credential:
            self.credential = credential
        else:
            # Try service principal first, then default
            client_id = os.getenv('AZURE_CLIENT_ID')
            client_secret = os.getenv('AZURE_CLIENT_SECRET')
            tenant_id = os.getenv('AZURE_TENANT_ID')
            
            if client_id and client_secret and tenant_id:
                self.credential = ClientSecretCredential(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret
                )
                logger.info("Using ClientSecretCredential")
            else:
                self.credential = DefaultAzureCredential()
                logger.info("Using DefaultAzureCredential")
        
        self._client_cache: Dict[str, Any] = {}
    
    def get_client(self, service_name: str) -> Any:
        """
        Get or create a client for the specified Azure service
        
        Args:
            service_name: Service name (e.g., 'compute', 'storage', 'network')
        
        Returns:
            Initialized Azure SDK client
        
        Raises:
            ValueError: If service is not supported
        """
        service_name = service_name.lower()
        
        # Check cache
        if service_name in self._client_cache:
            return self._client_cache[service_name]
        
        # Get service mapping
        if service_name not in self.SERVICE_CLIENT_MAPPING:
            raise ValueError(
                f"Service '{service_name}' not supported. "
                f"Available services: {', '.join(sorted(self.SERVICE_CLIENT_MAPPING.keys()))}"
            )
        
        package_name, client_class_name, client_params = self.SERVICE_CLIENT_MAPPING[service_name]
        
        try:
            # Import the module dynamically
            module = __import__(package_name, fromlist=[client_class_name])
            client_class = getattr(module, client_class_name)
            
            # Create client based on type
            if client_params.get('graph_based'):
                # Microsoft Graph SDK
                client = client_class(credentials=self.credential)
            elif client_params.get('keyvault_dataplane'):
                # Key Vault data plane - needs vault URL
                # This will be passed at runtime from the rules
                logger.warning(f"Key Vault data plane client '{service_name}' requires vault_url parameter")
                return client_class  # Return class, not instance
            elif client_params.get('connection_string_based'):
                # Storage data plane - needs connection string or account URL
                logger.warning(f"Storage data plane client '{service_name}' requires connection_string/account_url")
                return client_class  # Return class, not instance
            else:
                # Standard management plane client
                client = client_class(
                    credential=self.credential,
                    subscription_id=self.subscription_id
                )
            
            # Cache the client
            self._client_cache[service_name] = client
            logger.info(f"Created client for service: {service_name} ({client_class_name})")
            
            return client
            
        except ImportError as e:
            raise ImportError(
                f"Failed to import {package_name}.{client_class_name}. "
                f"Install package: pip install {package_name.replace('.', '-')}\n"
                f"Error: {e}"
            )
        except Exception as e:
            raise RuntimeError(
                f"Failed to create client for service '{service_name}': {e}"
            )
    
    def list_available_services(self) -> list:
        """Return list of all supported service names"""
        return sorted(self.SERVICE_CLIENT_MAPPING.keys())
    
    def get_service_info(self, service_name: str) -> dict:
        """Get package and client information for a service"""
        service_name = service_name.lower()
        if service_name not in self.SERVICE_CLIENT_MAPPING:
            raise ValueError(f"Service '{service_name}' not supported")
        
        package_name, client_class_name, client_params = self.SERVICE_CLIENT_MAPPING[service_name]
        return {
            'service': service_name,
            'package': package_name,
            'client_class': client_class_name,
            'pip_install': f"pip install {package_name.replace('.', '-')}",
            'params': client_params
        }
    
    def clear_cache(self):
        """Clear all cached clients"""
        self._client_cache.clear()
        logger.info("Client cache cleared")


# Convenience function similar to boto3.client()
_default_factory = None

def get_azure_client(service_name: str, subscription_id: Optional[str] = None) -> Any:
    """
    Convenience function to get Azure client, similar to boto3.client()
    
    Args:
        service_name: Azure service name
        subscription_id: Optional subscription ID (uses default if not provided)
    
    Returns:
        Azure SDK client instance
    
    Example:
        >>> compute_client = get_azure_client('compute')
        >>> vms = compute_client.virtual_machines.list_all()
    """
    global _default_factory
    
    if _default_factory is None or (subscription_id and subscription_id != _default_factory.subscription_id):
        _default_factory = AzureClientFactory(subscription_id=subscription_id)
    
    return _default_factory.get_client(service_name)


if __name__ == "__main__":
    # Test the factory
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    try:
        factory = AzureClientFactory()
        print(f"✓ Factory initialized for subscription: {factory.subscription_id}")
        print(f"\n✓ Available services ({len(factory.list_available_services())}):")
        
        # Group by package
        from collections import defaultdict
        by_package = defaultdict(list)
        for service in factory.list_available_services():
            info = factory.get_service_info(service)
            by_package[info['package']].append(service)
        
        for package, services in sorted(by_package.items()):
            print(f"\n  {package}:")
            for service in services:
                print(f"    - {service}")
        
        # Test a few clients
        print("\n✓ Testing client creation:")
        test_services = ['compute', 'storage', 'network', 'security']
        for service in test_services:
            try:
                client = factory.get_client(service)
                print(f"  ✓ {service}: {type(client).__name__}")
            except Exception as e:
                print(f"  ✗ {service}: {e}")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        sys.exit(1)

