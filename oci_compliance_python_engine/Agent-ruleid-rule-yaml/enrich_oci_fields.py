"""
OCI Field Enrichment Script

Enriches OCI SDK catalog with field schemas based on Oracle Cloud documentation
and common API response patterns.
"""

import json
from typing import Dict, Any


class OCIFieldEnricher:
    """Enrich OCI catalog with field metadata"""
    
    # Common OCI response fields
    COMMON_FIELDS = {
        'id': {
            'type': 'string',
            'description': 'OCID (Oracle Cloud ID)',
            'compliance_category': 'identity',
            'operators': ['equals', 'not_equals', 'exists']
        },
        'compartment_id': {
            'type': 'string',
            'description': 'Compartment OCID',
            'compliance_category': 'identity',
            'operators': ['equals', 'not_equals', 'in']
        },
        'display_name': {
            'type': 'string',
            'description': 'User-friendly name',
            'compliance_category': 'identity',
            'operators': ['equals', 'contains', 'not_empty']
        },
        'lifecycle_state': {
            'type': 'string',
            'enum': True,
            'possible_values': ['CREATING', 'ACTIVE', 'INACTIVE', 'UPDATING', 'DELETING', 'DELETED', 'FAILED'],
            'compliance_category': 'general',
            'operators': ['equals', 'not_equals', 'in']
        },
        'time_created': {
            'type': 'string',
            'format': 'date-time',
            'description': 'Creation timestamp',
            'compliance_category': 'general'
        },
        'freeform_tags': {
            'type': 'object',
            'description': 'Free-form tags',
            'compliance_category': 'general',
            'operators': ['exists', 'not_empty']
        },
        'defined_tags': {
            'type': 'object',
            'description': 'Defined tags',
            'compliance_category': 'general',
            'operators': ['exists', 'not_empty']
        }
    }
    
    # Service-specific field patterns
    SERVICE_FIELDS = {
        'compute': {
            'list_instances': {
                'availability_domain': {
                    'type': 'string',
                    'compliance_category': 'availability'
                },
                'shape': {
                    'type': 'string',
                    'description': 'Instance shape (e.g., VM.Standard2.1)',
                    'compliance_category': 'general'
                },
                'image_id': {
                    'type': 'string',
                    'compliance_category': 'security',
                    'security_impact': 'medium'
                },
                'metadata': {
                    'type': 'object',
                    'compliance_category': 'general'
                },
                'source_details': {
                    'type': 'object',
                    'nested_fields': {
                        'source_type': {'type': 'string'},
                        'boot_volume_id': {'type': 'string'}
                    }
                }
            },
            'get_instance': {
                'availability_domain': {'type': 'string'},
                'shape': {'type': 'string'},
                'image_id': {'type': 'string'},
                'is_pv_encryption_in_transit_enabled': {
                    'type': 'boolean',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                }
            }
        },
        'object_storage': {
            'list_buckets': {
                'name': {'type': 'string', 'compliance_category': 'identity'},
                'namespace': {'type': 'string', 'compliance_category': 'identity'},
                'public_access_type': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['NoPublicAccess', 'ObjectRead', 'ObjectReadWithoutList'],
                    'compliance_category': 'security',
                    'security_impact': 'high',
                    'operators': ['equals', 'not_equals']
                },
                'storage_tier': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['Standard', 'Archive'],
                    'compliance_category': 'general'
                },
                'versioning': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['Enabled', 'Suspended'],
                    'compliance_category': 'data_protection'
                }
            },
            'get_bucket': {
                'kms_key_id': {
                    'type': 'string',
                    'compliance_category': 'security',
                    'security_impact': 'high',
                    'description': 'KMS key for encryption'
                },
                'object_events_enabled': {
                    'type': 'boolean',
                    'compliance_category': 'security',
                    'security_impact': 'medium'
                }
            }
        },
        'virtual_network': {
            'list_vcns': {
                'cidr_block': {
                    'type': 'string',
                    'compliance_category': 'network'
                },
                'cidr_blocks': {
                    'type': 'array',
                    'compliance_category': 'network'
                }
            },
            'list_security_lists': {
                'egress_security_rules': {
                    'type': 'array',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                },
                'ingress_security_rules': {
                    'type': 'array',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                }
            }
        },
        'identity': {
            'list_users': {
                'email': {'type': 'string', 'compliance_category': 'identity'},
                'is_mfa_activated': {
                    'type': 'boolean',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                }
            },
            'list_policies': {
                'statements': {
                    'type': 'array',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                }
            }
        },
        'key_management': {
            'list_vaults': {
                'crypto_endpoint': {'type': 'string'},
                'management_endpoint': {'type': 'string'},
                'vault_type': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['VIRTUAL_PRIVATE', 'DEFAULT']
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
    
    def enrich_operation(self, service_name: str, operation: Dict) -> Dict:
        """Enrich an operation with field metadata"""
        enriched = operation.copy()
        operation_name = operation.get('operation', '')
        
        # Add common fields
        fields = self.COMMON_FIELDS.copy()
        
        # Add service-specific fields
        if service_name in self.SERVICE_FIELDS:
            if operation_name in self.SERVICE_FIELDS[service_name]:
                fields.update(self.SERVICE_FIELDS[service_name][operation_name])
                self.stats['operations_enriched'] += 1
        
        enriched['item_fields'] = fields
        self.stats['fields_added'] += len(fields)
        
        return enriched
    
    def enrich_service(self, service_name: str, service_data: Dict) -> Dict:
        """Enrich a service with field metadata"""
        enriched = service_data.copy()
        
        enriched_operations = []
        for operation in service_data.get('operations', []):
            enriched_op = self.enrich_operation(service_name, operation)
            enriched_operations.append(enriched_op)
        
        enriched['operations'] = enriched_operations
        self.stats['services_enriched'] += 1
        
        return enriched
    
    def enrich_catalog(self, catalog: Dict) -> Dict:
        """Enrich the entire catalog"""
        enriched = {}
        
        for service_name, service_data in catalog.items():
            print(f"Enriching {service_name}...")
            enriched[service_name] = self.enrich_service(service_name, service_data)
        
        return enriched
    
    def print_stats(self):
        """Print statistics"""
        print("\n" + "=" * 80)
        print("OCI Field Enrichment Statistics")
        print("=" * 80)
        print(f"Services enriched:      {self.stats['services_enriched']}")
        print(f"Operations enriched:    {self.stats['operations_enriched']}")
        print(f"Fields added:           {self.stats['fields_added']}")
        print("=" * 80)


def main():
    print("=" * 80)
    print("OCI Field Enrichment")
    print("=" * 80)
    print()
    
    # Load catalog
    print("Loading oci_sdk_catalog.json...")
    with open('oci_sdk_catalog.json') as f:
        catalog = json.load(f)
    
    print(f"✅ Loaded {len(catalog)} services")
    print()
    
    # Enrich
    enricher = OCIFieldEnricher()
    enriched = enricher.enrich_catalog(catalog)
    
    # Save
    output_file = 'oci_sdk_catalog_enhanced.json'
    print(f"\nSaving to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(enriched, f, indent=2)
    
    print(f"✅ Saved")
    
    enricher.print_stats()
    
    print()
    print("=" * 80)
    print(f"✅ OCI catalog enhanced: {output_file}")
    print("=" * 80)


if __name__ == '__main__':
    main()

