"""
IBM Cloud Field Enrichment Script

Enriches IBM Cloud SDK catalog with field schemas based on IBM Cloud documentation.
"""

import json
from typing import Dict, Any


class IBMFieldEnricher:
    """Enrich IBM catalog with field metadata"""
    
    # Common IBM Cloud fields
    COMMON_FIELDS = {
        'id': {
            'type': 'string',
            'description': 'Resource ID',
            'compliance_category': 'identity',
            'operators': ['equals', 'not_equals', 'exists']
        },
        'crn': {
            'type': 'string',
            'description': 'Cloud Resource Name',
            'compliance_category': 'identity',
            'operators': ['equals', 'contains', 'exists']
        },
        'name': {
            'type': 'string',
            'description': 'Resource name',
            'compliance_category': 'identity',
            'operators': ['equals', 'contains', 'not_empty']
        },
        'created_at': {
            'type': 'string',
            'format': 'date-time',
            'description': 'Creation timestamp',
            'compliance_category': 'general'
        },
        'updated_at': {
            'type': 'string',
            'format': 'date-time',
            'description': 'Last update timestamp',
            'compliance_category': 'general'
        },
        'resource_group_id': {
            'type': 'string',
            'compliance_category': 'identity'
        },
        'tags': {
            'type': 'array',
            'compliance_category': 'general',
            'operators': ['contains', 'not_empty']
        }
    }
    
    # Service-specific fields
    SERVICE_FIELDS = {
        'vpc': {
            'list': {
                'default_network_acl': {
                    'type': 'object',
                    'compliance_category': 'network'
                },
                'default_security_group': {
                    'type': 'object',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                },
                'default_routing_table': {
                    'type': 'object',
                    'compliance_category': 'network'
                },
                'status': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['available', 'deleting', 'failed', 'pending'],
                    'compliance_category': 'general'
                }
            }
        },
        'iam': {
            'list': {
                'iam_id': {'type': 'string', 'compliance_category': 'identity'},
                'entity_tag': {'type': 'string'},
                'account_id': {'type': 'string', 'compliance_category': 'identity'},
                'description': {'type': 'string'}
            }
        },
        'key_protect': {
            'list': {
                'state': {
                    'type': 'integer',
                    'enum': True,
                    'possible_values': [0, 1, 2, 3, 4, 5],
                    'description': 'Key state (0=Pre-activation, 1=Active, 2=Suspended, 3=Deactivated, 4=Destroyed)',
                    'compliance_category': 'security'
                },
                'extractable': {
                    'type': 'boolean',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                },
                'dual_auth_delete': {
                    'type': 'object',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                }
            }
        },
        'object_storage': {
            'list': {
                'versioning': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['Enabled', 'Suspended'],
                    'compliance_category': 'data_protection'
                },
                'encryption': {
                    'type': 'object',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                },
                'public_access_block_configuration': {
                    'type': 'object',
                    'compliance_category': 'security',
                    'security_impact': 'high',
                    'nested_fields': {
                        'BlockPublicAcls': {'type': 'boolean'},
                        'IgnorePublicAcls': {'type': 'boolean'},
                        'BlockPublicPolicy': {'type': 'boolean'},
                        'RestrictPublicBuckets': {'type': 'boolean'}
                    }
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
        """Get fields for a service operation"""
        fields = self.COMMON_FIELDS.copy()
        
        if service_name in self.SERVICE_FIELDS:
            # Match operation patterns
            for pattern, pattern_fields in self.SERVICE_FIELDS[service_name].items():
                if pattern in operation_name:
                    fields.update(pattern_fields)
                    break
        
        return fields
    
    def enrich_operation(self, service_name: str, operation: Dict) -> Dict:
        """Enrich operation with fields"""
        enriched = operation.copy()
        operation_name = operation.get('operation', '')
        
        if 'list_' in operation_name or 'get_' in operation_name:
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
        print("IBM Field Enrichment Statistics")
        print("=" * 80)
        print(f"Services enriched:      {self.stats['services_enriched']}")
        print(f"Operations enriched:    {self.stats['operations_enriched']}")
        print(f"Fields added:           {self.stats['fields_added']}")
        print("=" * 80)


def main():
    print("=" * 80)
    print("IBM Cloud Field Enrichment")
    print("=" * 80)
    print()
    
    # Load catalog
    print("Loading ibm_sdk_catalog.json...")
    try:
        with open('ibm_sdk_catalog.json') as f:
            catalog = json.load(f)
    except:
        # Create empty catalog if doesn't exist
        catalog = {}
        print("⚠️  Creating new catalog (SDK introspection didn't run)")
    
    print(f"Loaded {len(catalog)} services")
    print()
    
    # Enrich
    enricher = IBMFieldEnricher()
    enriched = enricher.enrich_catalog(catalog) if catalog else {}
    
    # Save
    output_file = 'ibm_sdk_catalog_enhanced.json'
    print(f"\nSaving to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(enriched, f, indent=2)
    
    print(f"✅ Saved")
    
    enricher.print_stats()
    
    print()
    print("=" * 80)
    print(f"✅ IBM catalog enhanced: {output_file}")
    print("=" * 80)


if __name__ == '__main__':
    main()

