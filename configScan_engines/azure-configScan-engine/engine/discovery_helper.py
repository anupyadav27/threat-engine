"""
Discovery Helper - Maps services to Azure SDK methods for resource discovery
"""

from typing import Dict, List, Tuple, Optional, Any
import logging

logger = logging.getLogger(__name__)


class DiscoveryHelper:
    """
    Helper class to map service names and actions to correct Azure SDK methods
    """
    
    # Service → List of (sub_client, method_name, use_list_all)
    # use_list_all: True if should try list_all() when action is 'list'
    # Maps all 21 services from services/ folder
    SERVICE_DISCOVERY_MAP: Dict[str, List[Tuple[str, str, bool]]] = {
        # New services
        'kusto': [
            ('clusters', 'list', False),
        ],
        'loganalytics': [
            ('workspaces', 'list', False),
        ],
        'managedidentity': [
            ('user_assigned_identities', 'list_by_subscription', False),
        ],
        'servicebus': [
            ('namespaces', 'list', False),
        ],
        'signalr': [
            ('signal_r', 'list_by_subscription', False),
        ],
        'streamanalytics': [
            ('streaming_jobs', 'list', False),
        ],
        'api': [
            ('api_management_service', 'list', False),
        ],
        'authorization': [
            ('role_assignments', 'list', True),
            ('role_definitions', 'list', True),
            ('role_eligibility_schedule_requests', 'list', True),
            ('deny_assignments', 'list', True),
        ],
        'automation': [
            ('automation_account', 'list_by_subscription', False),
        ],
        'batch': [
            ('batch_account', 'list', False),
        ],
        'compute': [
            ('virtual_machines', 'list_all', False),
            ('disks', 'list', False),
            ('availability_sets', 'list_by_subscription', False),
            ('virtual_machine_scale_sets', 'list_all', False),
        ],
        'container': [
            ('container_groups', 'list', False),
        ],
        'containerservice': [
            ('managed_clusters', 'list', False),
        ],
        'cosmosdb': [
            ('database_accounts', 'list', False),
        ],
        'eventhub': [
            ('namespaces', 'list', False),
        ],
        'keyvault': [
            ('vaults', 'list_by_subscription', False),
            ('managed_hsms', 'list_by_subscription', False),
        ],
        'managementgroups': [
            ('management_groups', 'list', False),
        ],
        'mariadb': [
            ('servers', 'list', False),
        ],
        'monitor': [
            ('action_groups', 'list_by_subscription', False),
            ('activity_log_alerts', 'list_by_subscription', False),
            ('metric_alerts', 'list_by_subscription', False),
            ('log_profiles', 'list', False),
        ],
        'mysql': [
            ('servers', 'list', False),
        ],
        'network': [
            ('virtual_networks', 'list_all', False),
            ('network_security_groups', 'list_all', False),
            ('public_ip_addresses', 'list_all', False),
            ('load_balancers', 'list_all', False),
            ('network_interfaces', 'list_all', False),
            ('application_gateways', 'list_all', False),
            ('dns_zones', 'list', False),
            ('profiles', 'list', False),  # CDN, Traffic Manager
        ],
        'postgresql': [
            ('servers', 'list', False),
        ],
        'recoveryservicesbackup': [
            ('vaults', 'list', False),
        ],
        'sql': [
            ('servers', 'list', False),
            ('databases', 'list_by_server', False),
        ],
        'storage': [
            ('storage_accounts', 'list', False),
        ],
        'subscription': [
            ('subscriptions', 'list', False),
            ('resource_groups', 'list', False),
        ],
        'web': [
            ('app_service_plans', 'list', False),
            ('web_apps', 'list', False),
            ('static_sites', 'list', False),
        ],
    }
    
    # Action mapping: YAML action → (preferred_method, fallback_methods)
    ACTION_METHOD_MAP: Dict[str, Tuple[str, List[str]]] = {
        'list': ('list', ['list_all', 'list_by_subscription']),
        'list_by_resource_group': ('list_by_resource_group', ['list_by_subscription', 'list_all']),
        'list_by_subscription': ('list_by_subscription', ['list_all', 'list']),
    }
    
    @classmethod
    def find_discovery_method(cls, azure_client: Any, service_name: str, action: str) -> Optional[Any]:
        """
        Find the correct Azure SDK method for discovery
        
        Args:
            azure_client: Azure SDK client instance
            service_name: Service name (e.g., 'api', 'network')
            action: Action from YAML (e.g., 'list', 'list_by_resource_group')
        
        Returns:
            Method object if found, None otherwise
        """
        # Get service-specific mappings
        service_mappings = cls.SERVICE_DISCOVERY_MAP.get(service_name, [])
        
        # Try service-specific mappings first
        for sub_client_name, method_name, use_list_all in service_mappings:
            if hasattr(azure_client, sub_client_name):
                sub_client = getattr(azure_client, sub_client_name)
                
                # Try exact method name first
                if hasattr(sub_client, method_name):
                    method = getattr(sub_client, method_name)
                    logger.debug(f"Found {service_name}.{sub_client_name}.{method_name}")
                    return method
                
                # If action is 'list' and use_list_all is True, try list_all
                if action == 'list' and use_list_all and hasattr(sub_client, 'list_all'):
                    method = getattr(sub_client, 'list_all')
                    logger.debug(f"Found {service_name}.{sub_client_name}.list_all")
                    return method
        
        # Fallback: Try common patterns
        preferred_method, fallback_methods = cls.ACTION_METHOD_MAP.get(action, (action, []))
        
        # Try service-specific sub-clients
        for sub_client_name, _, _ in service_mappings:
            if hasattr(azure_client, sub_client_name):
                sub_client = getattr(azure_client, sub_client_name)
                
                # Try preferred method
                if hasattr(sub_client, preferred_method):
                    method = getattr(sub_client, preferred_method)
                    logger.debug(f"Found {service_name}.{sub_client_name}.{preferred_method} (fallback)")
                    return method
                
                # Try fallback methods
                for fallback in fallback_methods:
                    if hasattr(sub_client, fallback):
                        method = getattr(sub_client, fallback)
                        logger.debug(f"Found {service_name}.{sub_client_name}.{fallback} (fallback)")
                        return method
        
        # Try common sub-client names
        common_sub_clients = [
            'api_management_service', 'namespaces', 'workspaces', 'registries',
            'virtual_networks', 'network_security_groups', 'vaults',
            'storage_accounts', 'servers', 'databases'
        ]
        
        for sub_client_name in common_sub_clients:
            if hasattr(azure_client, sub_client_name):
                sub_client = getattr(azure_client, sub_client_name)
                
                if hasattr(sub_client, preferred_method):
                    method = getattr(sub_client, preferred_method)
                    logger.debug(f"Found {sub_client_name}.{preferred_method} (common)")
                    return method
                
                for fallback in fallback_methods:
                    if hasattr(sub_client, fallback):
                        method = getattr(sub_client, fallback)
                        logger.debug(f"Found {sub_client_name}.{fallback} (common)")
                        return method
        
        # Last resort: Try direct on client
        if hasattr(azure_client, preferred_method):
            method = getattr(azure_client, preferred_method)
            logger.debug(f"Found {preferred_method} directly on client")
            return method
        
        return None
    
    @classmethod
    def execute_discovery(cls, method: Any, action: str, params: Dict, 
                         subscription_id: str, credential: Any) -> Any:
        """
        Execute discovery method with proper handling
        
        Args:
            method: Azure SDK method to call
            action: Action name from YAML
            params: Parameters from YAML
            subscription_id: Azure subscription ID
            credential: Azure credential
        
        Returns:
            Response from Azure SDK (will be converted to list)
        """
        from azure.mgmt.resource import ResourceManagementClient
        
        # Handle list_by_resource_group without resource_group param
        if action == 'list_by_resource_group':
            if 'resource_group' in params and params.get('resource_group'):
                # Resource group provided
                return method(**params)
            else:
                # Prefer list_by_subscription if available
                parent = method.__self__ if hasattr(method, '__self__') else None
                if parent and hasattr(parent, 'list_by_subscription'):
                    logger.debug("Using list_by_subscription instead of list_by_resource_group")
                    return parent.list_by_subscription()
                else:
                    # Get all resource groups and iterate
                    resource_client = ResourceManagementClient(credential, subscription_id)
                    all_resources = []
                    
                    try:
                        resource_groups = resource_client.resource_groups.list()
                        for rg in resource_groups:
                            try:
                                rg_response = method(resource_group_name=rg.name)
                                if hasattr(rg_response, '__iter__') and not isinstance(rg_response, (str, dict, bytes)):
                                    all_resources.extend(list(rg_response))
                            except Exception as e:
                                logger.debug(f"Failed to list resources in RG {rg.name}: {e}")
                                continue
                        
                        return all_resources
                    except Exception as e:
                        logger.warning(f"Failed to get resource groups: {e}")
                        return []
        
        # Handle regular list operations
        if action == 'list':
            # Try list_all first if available (for network resources)
            if hasattr(method, '__self__'):
                parent = method.__self__
                if hasattr(parent, 'list_all'):
                    try:
                        return parent.list_all()
                    except:
                        # Fallback to list
                        pass
        
        # Default: call method with params
        return method(**params) if params else method()
