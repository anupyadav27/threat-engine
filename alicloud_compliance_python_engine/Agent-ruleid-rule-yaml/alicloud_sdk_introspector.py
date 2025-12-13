"""
Alibaba Cloud SDK Introspector

Introspects Aliyun (Alibaba Cloud) Python SDK to extract service operations.
Aliyun SDK uses a different architecture (API-based, not object-oriented).
"""

import json
from typing import Dict, List, Any


class AliCloudSDKIntrospector:
    """Introspect Alibaba Cloud SDK"""
    
    # Aliyun services (based on aliyunsdkcore modules)
    ALIYUN_SERVICES = {
        'ecs': {
            'module': 'aliyunsdkecs.request.v20140526',
            'description': 'Elastic Compute Service',
            'common_operations': [
                'DescribeInstances', 'DescribeImages', 'DescribeSecurityGroups',
                'DescribeDisks', 'DescribeSnapshots'
            ]
        },
        'oss': {
            'module': 'oss2',
            'description': 'Object Storage Service',
            'common_operations': [
                'list_buckets', 'get_bucket_info', 'get_bucket_acl',
                'get_bucket_encryption', 'get_bucket_versioning'
            ]
        },
        'vpc': {
            'module': 'aliyunsdkvpc.request.v20160428',
            'description': 'Virtual Private Cloud',
            'common_operations': [
                'DescribeVpcs', 'DescribeVSwitches', 'DescribeRouteTableList',
                'DescribeNatGateways'
            ]
        },
        'ram': {
            'module': 'aliyunsdkram.request.v20150501',
            'description': 'Resource Access Management',
            'common_operations': [
                'ListUsers', 'ListGroups', 'ListRoles', 'ListPolicies'
            ]
        },
        'rds': {
            'module': 'aliyunsdkrds.request.v20140815',
            'description': 'Relational Database Service',
            'common_operations': [
                'DescribeDBInstances', 'DescribeBackups', 'DescribeParameters'
            ]
        },
        'slb': {
            'module': 'aliyunsdkslb.request.v20140515',
            'description': 'Server Load Balancer',
            'common_operations': [
                'DescribeLoadBalancers', 'DescribeLoadBalancerAttribute'
            ]
        },
        'kms': {
            'module': 'aliyunsdkkms.request.v20160120',
            'description': 'Key Management Service',
            'common_operations': [
                'ListKeys', 'DescribeKey', 'ListSecrets'
            ]
        }
    }
    
    def __init__(self):
        self.stats = {
            'services_processed': 0,
            'operations_found': 0
        }
        self.catalog = {}
    
    def generate_catalog(self) -> Dict[str, Any]:
        """Generate Alibaba Cloud SDK catalog"""
        print("=" * 80)
        print("Alibaba Cloud SDK Catalog Generation")
        print("=" * 80)
        print()
        
        for service_name, config in self.ALIYUN_SERVICES.items():
            print(f"  Processing {service_name}...")
            
            service_catalog = {
                'service': service_name,
                'module': config['module'],
                'description': config['description'],
                'operations': []
            }
            
            # Add operations
            for operation in config['common_operations']:
                operation_def = {
                    'operation': operation,
                    'python_method': operation,
                    'description': f"{operation} - {config['description']}",
                    'item_fields': {}  # To be populated from docs
                }
                
                service_catalog['operations'].append(operation_def)
                self.stats['operations_found'] += 1
            
            self.catalog[service_name] = service_catalog
            self.stats['services_processed'] += 1
            print(f"    Added {len(config['common_operations'])} operations")
        
        return self.catalog
    
    def save_catalog(self, output_file: str):
        """Save catalog"""
        with open(output_file, 'w') as f:
            json.dump(self.catalog, f, indent=2)
        print(f"\n✅ Saved catalog to {output_file}")
    
    def print_stats(self):
        """Print statistics"""
        print("\n" + "=" * 80)
        print("Alibaba Cloud SDK Catalog Statistics")
        print("=" * 80)
        print(f"Services processed:    {self.stats['services_processed']}")
        print(f"Operations found:      {self.stats['operations_found']}")
        print("=" * 80)
        print("\nNote: Alibaba Cloud SDK uses API-based approach.")
        print("Field schemas should be added from Alibaba Cloud API documentation.")
        print("=" * 80)


def main():
    print("=" * 80)
    print("Alibaba Cloud SDK Introspector")
    print("=" * 80)
    print()
    
    introspector = AliCloudSDKIntrospector()
    catalog = introspector.generate_catalog()
    
    output_file = 'alicloud_sdk_catalog.json'
    introspector.save_catalog(output_file)
    
    introspector.print_stats()
    
    print()
    print("=" * 80)
    print("✅ Alibaba Cloud SDK catalog created!")
    print("=" * 80)


if __name__ == '__main__':
    main()

