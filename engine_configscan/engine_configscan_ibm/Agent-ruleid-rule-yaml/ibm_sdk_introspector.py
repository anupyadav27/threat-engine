"""
IBM Cloud SDK Introspector

Introspects IBM Cloud Python SDKs to extract service operations and field structures.
IBM Cloud uses multiple SDK packages (ibm-vpc, ibm-platform-services, etc.)
"""

import json
import inspect
from typing import Dict, List, Any


class IBMSDKIntrospector:
    """Introspect IBM Cloud SDKs"""
    
    # IBM Cloud service SDK packages
    IBM_SERVICES = {
        'vpc': {
            'package': 'ibm_vpc',
            'service_class': 'VpcV1',
            'description': 'Virtual Private Cloud'
        },
        'iam': {
            'package': 'ibm_platform_services',
            'service_class': 'IamIdentityV1',
            'description': 'Identity and Access Management'
        },
        'resource_controller': {
            'package': 'ibm_platform_services',
            'service_class': 'ResourceControllerV2',
            'description': 'Resource Controller'
        },
        'resource_manager': {
            'package': 'ibm_platform_services',
            'service_class': 'ResourceManagerV2',
            'description': 'Resource Manager'
        },
        'key_protect': {
            'package': 'ibm_key_protect_api',
            'service_class': 'IbmKeyProtectApiV2',
            'description': 'Key Protect'
        },
        'object_storage': {
            'package': 'ibm_boto3',
            'service_class': 's3',
            'description': 'Cloud Object Storage (S3-compatible)'
        }
    }
    
    def __init__(self):
        self.stats = {
            'services_processed': 0,
            'operations_found': 0,
            'fields_extracted': 0
        }
        self.catalog = {}
    
    def get_service_class(self, package_name: str, class_name: str):
        """Dynamically import service class"""
        try:
            module = __import__(package_name, fromlist=[class_name])
            return getattr(module, class_name, None)
        except Exception as e:
            print(f"    Error importing {package_name}.{class_name}: {e}")
            return None
    
    def introspect_service(self, service_name: str, config: Dict) -> Dict[str, Any]:
        """Introspect an IBM Cloud service"""
        print(f"  Introspecting {service_name}...")
        
        service_class = self.get_service_class(config['package'], config['service_class'])
        
        if not service_class:
            print(f"    ❌ Could not load {config['service_class']}")
            return {}
        
        service_catalog = {
            'service': service_name,
            'package': config['package'],
            'service_class': config['service_class'],
            'description': config['description'],
            'operations': []
        }
        
        # Get methods
        operation_count = 0
        for method_name in dir(service_class):
            if method_name.startswith('_'):
                continue
            
            try:
                method = getattr(service_class, method_name)
                if callable(method):
                    # Focus on common operation patterns
                    if any(method_name.startswith(prefix) for prefix in ['list_', 'get_', 'create_', 'update_', 'delete_']):
                        operation_def = {
                            'operation': method_name,
                            'python_method': method_name,
                            'description': (method.__doc__ or '').split('\n')[0] if method.__doc__ else '',
                            'item_fields': {}
                        }
                        
                        service_catalog['operations'].append(operation_def)
                        operation_count += 1
                        self.stats['operations_found'] += 1
            except:
                pass
        
        print(f"    Found {operation_count} operations")
        self.stats['services_processed'] += 1
        
        return service_catalog
    
    def generate_catalog(self) -> Dict[str, Any]:
        """Generate IBM Cloud SDK catalog"""
        print("=" * 80)
        print("IBM Cloud SDK Introspection")
        print("=" * 80)
        print()
        
        for service_name, config in self.IBM_SERVICES.items():
            service_catalog = self.introspect_service(service_name, config)
            if service_catalog:
                self.catalog[service_name] = service_catalog
        
        return self.catalog
    
    def save_catalog(self, output_file: str):
        """Save catalog"""
        with open(output_file, 'w') as f:
            json.dump(self.catalog, f, indent=2)
        print(f"\n✅ Saved catalog to {output_file}")
    
    def print_stats(self):
        """Print statistics"""
        print("\n" + "=" * 80)
        print("IBM Cloud SDK Introspection Statistics")
        print("=" * 80)
        print(f"Services processed:    {self.stats['services_processed']}")
        print(f"Operations found:      {self.stats['operations_found']}")
        print(f"Fields extracted:      {self.stats['fields_extracted']}")
        print("=" * 80)


def main():
    print("=" * 80)
    print("IBM Cloud SDK Introspector")
    print("=" * 80)
    print()
    
    introspector = IBMSDKIntrospector()
    catalog = introspector.generate_catalog()
    
    output_file = 'ibm_sdk_catalog.json'
    introspector.save_catalog(output_file)
    
    introspector.print_stats()
    
    print()
    print("=" * 80)
    print("✅ IBM Cloud SDK catalog created!")
    print("=" * 80)


if __name__ == '__main__':
    main()

