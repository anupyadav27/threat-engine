"""
OCI Python SDK Introspector

Introspects the Oracle Cloud Infrastructure (OCI) Python SDK to extract:
- Service operations
- Response field structures
- Field types and metadata

Similar to Azure/K8s SDK introspection approach.
"""

import json
import oci
import inspect
from typing import Dict, List, Any, Optional


class OCISDKIntrospector:
    """Introspect OCI Python SDK for field and operation information"""
    
    # OCI services and their client classes
    OCI_SERVICES = {
        'compute': {
            'client_class': 'ComputeClient',
            'module': 'oci.core',
            'main_operations': ['list_instances', 'get_instance', 'list_images']
        },
        'object_storage': {
            'client_class': 'ObjectStorageClient',
            'module': 'oci.object_storage',
            'main_operations': ['list_buckets', 'get_bucket', 'list_objects']
        },
        'virtual_network': {
            'client_class': 'VirtualNetworkClient',
            'module': 'oci.core',
            'main_operations': ['list_vcns', 'get_vcn', 'list_security_lists', 'list_subnets']
        },
        'identity': {
            'client_class': 'IdentityClient',
            'module': 'oci.identity',
            'main_operations': ['list_users', 'list_groups', 'list_policies', 'list_compartments']
        },
        'block_storage': {
            'client_class': 'BlockstorageClient',
            'module': 'oci.core',
            'main_operations': ['list_volumes', 'get_volume', 'list_volume_backups']
        },
        'load_balancer': {
            'client_class': 'LoadBalancerClient',
            'module': 'oci.load_balancer',
            'main_operations': ['list_load_balancers', 'get_load_balancer']
        },
        'database': {
            'client_class': 'DatabaseClient',
            'module': 'oci.database',
            'main_operations': ['list_db_systems', 'get_db_system', 'list_autonomous_databases']
        },
        'key_management': {
            'client_class': 'KmsVaultClient',
            'module': 'oci.key_management',
            'main_operations': ['list_vaults', 'get_vault']
        },
        'container_engine': {
            'client_class': 'ContainerEngineClient',
            'module': 'oci.container_engine',
            'main_operations': ['list_clusters', 'get_cluster', 'list_node_pools']
        },
        'functions': {
            'client_class': 'FunctionsManagementClient',
            'module': 'oci.functions',
            'main_operations': ['list_applications', 'list_functions']
        }
    }
    
    def __init__(self):
        self.stats = {
            'services_processed': 0,
            'operations_found': 0,
            'fields_extracted': 0
        }
        self.catalog = {}
    
    def get_client_class(self, module_name: str, class_name: str):
        """Dynamically import and return client class"""
        try:
            module = __import__(module_name, fromlist=[class_name])
            return getattr(module, class_name)
        except Exception as e:
            print(f"    Error importing {module_name}.{class_name}: {e}")
            return None
    
    def extract_response_fields(self, method_name: str, method_obj) -> Dict[str, Any]:
        """Extract fields from method response type hints or docstring"""
        fields = {}
        
        try:
            # Try to get return type annotation
            if hasattr(method_obj, '__annotations__'):
                return_type = method_obj.__annotations__.get('return')
                if return_type:
                    # Introspect the return type
                    if hasattr(return_type, '__annotations__'):
                        for field_name, field_type in return_type.__annotations__.items():
                            fields[field_name] = {
                                'type': self.python_type_to_json_type(field_type),
                                'source': 'type_hint'
                            }
        except Exception:
            pass
        
        return fields
    
    def python_type_to_json_type(self, py_type) -> str:
        """Convert Python type to JSON schema type"""
        type_str = str(py_type).lower()
        
        if 'bool' in type_str:
            return 'boolean'
        elif 'int' in type_str:
            return 'integer'
        elif 'float' in type_str or 'double' in type_str:
            return 'number'
        elif 'list' in type_str or 'sequence' in type_str:
            return 'array'
        elif 'dict' in type_str or 'mapping' in type_str:
            return 'object'
        else:
            return 'string'
    
    def introspect_client(self, service_name: str, config: Dict) -> Dict[str, Any]:
        """Introspect an OCI client"""
        print(f"  Introspecting {service_name}...")
        
        client_class = self.get_client_class(config['module'], config['client_class'])
        
        if not client_class:
            return {}
        
        service_catalog = {
            'service': service_name,
            'module': config['module'],
            'client_class': config['client_class'],
            'operations': []
        }
        
        # Get all methods from client
        for method_name in dir(client_class):
            # Skip private/magic methods
            if method_name.startswith('_'):
                continue
            
            try:
                method = getattr(client_class, method_name)
                if not callable(method):
                    continue
                
                # Focus on list/get operations
                if any(method_name.startswith(prefix) for prefix in ['list_', 'get_']):
                    operation_def = {
                        'operation': method_name,
                        'python_method': method_name,
                        'operation_type': 'list' if method_name.startswith('list_') else 'get',
                        'description': (method.__doc__ or '').split('\n')[0] if method.__doc__ else '',
                        'item_fields': self.extract_response_fields(method_name, method)
                    }
                    
                    service_catalog['operations'].append(operation_def)
                    self.stats['operations_found'] += 1
                    
            except Exception as e:
                pass
        
        print(f"    Found {len(service_catalog['operations'])} operations")
        self.stats['services_processed'] += 1
        
        return service_catalog
    
    def generate_catalog(self) -> Dict[str, Any]:
        """Generate full OCI SDK catalog"""
        print("=" * 80)
        print("OCI Python SDK Introspection")
        print("=" * 80)
        print()
        
        for service_name, config in self.OCI_SERVICES.items():
            service_catalog = self.introspect_client(service_name, config)
            if service_catalog:
                self.catalog[service_name] = service_catalog
        
        return self.catalog
    
    def save_catalog(self, output_file: str):
        """Save catalog to JSON"""
        with open(output_file, 'w') as f:
            json.dump(self.catalog, f, indent=2)
        print(f"\n✅ Saved catalog to {output_file}")
    
    def print_stats(self):
        """Print statistics"""
        print("\n" + "=" * 80)
        print("OCI SDK Introspection Statistics")
        print("=" * 80)
        print(f"Services processed:    {self.stats['services_processed']}")
        print(f"Operations found:      {self.stats['operations_found']}")
        print(f"Fields extracted:      {self.stats['fields_extracted']}")
        print("=" * 80)


def main():
    print("=" * 80)
    print("Oracle Cloud Infrastructure (OCI) SDK Introspector")
    print("=" * 80)
    print()
    
    introspector = OCISDKIntrospector()
    catalog = introspector.generate_catalog()
    
    output_file = 'oci_sdk_catalog.json'
    introspector.save_catalog(output_file)
    
    introspector.print_stats()
    
    print()
    print("=" * 80)
    print(f"✅ OCI SDK catalog created: {output_file}")
    print("=" * 80)


if __name__ == '__main__':
    main()

