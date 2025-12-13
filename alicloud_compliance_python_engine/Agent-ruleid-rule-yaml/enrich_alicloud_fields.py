"""
Alibaba Cloud Field Enrichment Script

Enriches Alibaba Cloud SDK catalog with field schemas based on
Alibaba Cloud API documentation.
"""

import json
from typing import Dict, Any


class AliCloudFieldEnricher:
    """Enrich Alibaba Cloud catalog with field metadata"""
    
    # Common Aliyun fields
    COMMON_FIELDS = {
        'RequestId': {
            'type': 'string',
            'description': 'Request ID',
            'compliance_category': 'general'
        },
        'InstanceId': {
            'type': 'string',
            'description': 'Instance ID',
            'compliance_category': 'identity',
            'operators': ['equals', 'not_equals', 'in']
        },
        'InstanceName': {
            'type': 'string',
            'description': 'Instance name',
            'compliance_category': 'identity',
            'operators': ['equals', 'contains']
        },
        'Status': {
            'type': 'string',
            'description': 'Resource status',
            'compliance_category': 'general',
            'operators': ['equals', 'not_equals']
        },
        'CreationTime': {
            'type': 'string',
            'format': 'date-time',
            'description': 'Creation time',
            'compliance_category': 'general'
        },
        'RegionId': {
            'type': 'string',
            'description': 'Region ID',
            'compliance_category': 'availability'
        },
        'ZoneId': {
            'type': 'string',
            'description': 'Zone ID',
            'compliance_category': 'availability'
        },
        'Tags': {
            'type': 'array',
            'description': 'Resource tags',
            'compliance_category': 'general',
            'operators': ['contains', 'not_empty']
        }
    }
    
    # Service-specific fields
    SERVICE_FIELDS = {
        'ecs': {
            'DescribeInstances': {
                'ImageId': {
                    'type': 'string',
                    'compliance_category': 'security',
                    'security_impact': 'medium'
                },
                'InstanceType': {
                    'type': 'string',
                    'description': 'Instance type/specification'
                },
                'VpcAttributes': {
                    'type': 'object',
                    'compliance_category': 'network',
                    'nested_fields': {
                        'VpcId': {'type': 'string'},
                        'VSwitchId': {'type': 'string'},
                        'PrivateIpAddress': {'type': 'array'}
                    }
                },
                'SecurityGroupIds': {
                    'type': 'array',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                },
                'PublicIpAddress': {
                    'type': 'array',
                    'compliance_category': 'network',
                    'security_impact': 'medium'
                },
                'EipAddress': {
                    'type': 'object',
                    'compliance_category': 'network'
                }
            },
            'DescribeSecurityGroups': {
                'SecurityGroupName': {'type': 'string'},
                'VpcId': {'type': 'string'},
                'Permissions': {
                    'type': 'object',
                    'compliance_category': 'security',
                    'security_impact': 'high',
                    'nested_fields': {
                        'Permission': {'type': 'array'}
                    }
                }
            }
        },
        'oss': {
            'list_buckets': {
                'name': {'type': 'string', 'compliance_category': 'identity'},
                'location': {'type': 'string', 'compliance_category': 'availability'},
                'creation_date': {'type': 'string', 'format': 'date-time'},
                'storage_class': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['Standard', 'IA', 'Archive', 'ColdArchive'],
                    'compliance_category': 'general'
                }
            },
            'get_bucket_info': {
                'acl': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['private', 'public-read', 'public-read-write'],
                    'compliance_category': 'security',
                    'security_impact': 'high'
                },
                'versioning': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['Enabled', 'Suspended'],
                    'compliance_category': 'data_protection'
                },
                'server_side_encryption_rule': {
                    'type': 'object',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                }
            }
        },
        'vpc': {
            'DescribeVpcs': {
                'VpcId': {'type': 'string', 'compliance_category': 'identity'},
                'VpcName': {'type': 'string'},
                'CidrBlock': {'type': 'string', 'compliance_category': 'network'},
                'IsDefault': {'type': 'boolean'}
            }
        },
        'ram': {
            'ListUsers': {
                'UserName': {'type': 'string', 'compliance_category': 'identity'},
                'Email': {'type': 'string'},
                'MFABindRequired': {
                    'type': 'boolean',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                }
            },
            'ListPolicies': {
                'PolicyName': {'type': 'string'},
                'PolicyType': {'type': 'string', 'enum': True, 'possible_values': ['System', 'Custom']},
                'AttachmentCount': {'type': 'integer'}
            }
        },
        'rds': {
            'DescribeDBInstances': {
                'DBInstanceId': {'type': 'string', 'compliance_category': 'identity'},
                'Engine': {'type': 'string'},
                'EngineVersion': {'type': 'string'},
                'SSLExpireTime': {
                    'type': 'string',
                    'format': 'date-time',
                    'compliance_category': 'security',
                    'security_impact': 'medium'
                },
                'SecurityIPList': {
                    'type': 'string',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                }
            }
        },
        'kms': {
            'ListKeys': {
                'KeyId': {'type': 'string', 'compliance_category': 'identity'},
                'KeyState': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['Enabled', 'Disabled', 'PendingDeletion'],
                    'compliance_category': 'security'
                }
            }
        }
    }
    
    def __init__(self):
        self.stats = {
            'services_enriched': 0,
            'operations_enriched': 0,
            'fields_added': 0
        }
    
    def get_service_fields(self, service_name: str, operation_name: str) -> Dict:
        """Get fields for operation"""
        fields = self.COMMON_FIELDS.copy()
        
        if service_name in self.SERVICE_FIELDS:
            for pattern, pattern_fields in self.SERVICE_FIELDS[service_name].items():
                if pattern in operation_name:
                    fields.update(pattern_fields)
                    break
        
        return fields
    
    def enrich_operation(self, service_name: str, operation: Dict) -> Dict:
        """Enrich operation"""
        enriched = operation.copy()
        operation_name = operation.get('operation', '')
        
        fields = self.get_service_fields(service_name, operation_name)
        enriched['item_fields'] = fields
        
        self.stats['fields_added'] += len(fields)
        self.stats['operations_enriched'] += 1
        
        return enriched
    
    def enrich_service(self, service_name: str, service_data: Dict) -> Dict:
        """Enrich service"""
        enriched = service_data.copy()
        
        enriched_operations = []
        for operation in service_data.get('operations', []):
            enriched_op = self.enrich_operation(service_name, operation)
            enriched_operations.append(enriched_op)
        
        enriched['operations'] = enriched_operations
        self.stats['services_enriched'] += 1
        
        return enriched
    
    def enrich_catalog(self, catalog: Dict) -> Dict:
        """Enrich catalog"""
        enriched = {}
        
        for service_name, service_data in catalog.items():
            print(f"Enriching {service_name}...")
            enriched[service_name] = self.enrich_service(service_name, service_data)
        
        return enriched
    
    def print_stats(self):
        """Print statistics"""
        print("\n" + "=" * 80)
        print("Alibaba Cloud Field Enrichment Statistics")
        print("=" * 80)
        print(f"Services enriched:      {self.stats['services_enriched']}")
        print(f"Operations enriched:    {self.stats['operations_enriched']}")
        print(f"Fields added:           {self.stats['fields_added']}")
        print("=" * 80)


def main():
    print("=" * 80)
    print("Alibaba Cloud Field Enrichment")
    print("=" * 80)
    print()
    
    # Load catalog
    print("Loading alicloud_sdk_catalog.json...")
    with open('alicloud_sdk_catalog.json') as f:
        catalog = json.load(f)
    
    print(f"✅ Loaded {len(catalog)} services")
    print()
    
    # Enrich
    enricher = AliCloudFieldEnricher()
    enriched = enricher.enrich_catalog(catalog)
    
    # Save
    output_file = 'alicloud_sdk_catalog_enhanced.json'
    print(f"\nSaving to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(enriched, f, indent=2)
    
    print(f"✅ Saved")
    
    enricher.print_stats()
    
    print()
    print("=" * 80)
    print(f"✅ Alibaba Cloud catalog enhanced: {output_file}")
    print("=" * 80)


if __name__ == '__main__':
    main()

