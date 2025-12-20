"""
GCP API Field Enrichment Script

Enriches GCP API catalog with field information based on:
1. Common GCP response patterns
2. GCP API documentation standards
3. Service-specific field schemas

This works with the Discovery API-based catalog.
"""

import json
import re
from typing import Dict, List, Any


class GCPAPIFieldEnricher:
    """Enrich GCP API catalog with field metadata"""
    
    # Common GCP response fields across all services
    COMMON_RESPONSE_FIELDS = {
        'kind': {
            'type': 'string',
            'description': 'Resource type identifier',
            'example': 'storage#bucket',
            'compliance_category': 'identity'
        },
        'id': {
            'type': 'string',
            'description': 'Unique resource identifier',
            'compliance_category': 'identity',
            'operators': ['equals', 'not_equals', 'exists']
        },
        'name': {
            'type': 'string',
            'description': 'Resource name',
            'compliance_category': 'identity',
            'operators': ['equals', 'not_equals', 'contains', 'in']
        },
        'selfLink': {
            'type': 'string',
            'description': 'Server-defined URL for the resource',
            'compliance_category': 'identity'
        },
        'creationTimestamp': {
            'type': 'string',
            'format': 'date-time',
            'description': 'Creation timestamp in RFC3339',
            'compliance_category': 'general'
        },
        'description': {
            'type': 'string',
            'description': 'Resource description',
            'compliance_category': 'general'
        },
        'labels': {
            'type': 'object',
            'description': 'User-defined labels (key-value pairs)',
            'compliance_category': 'general',
            'operators': ['exists', 'not_empty']
        },
        'etag': {
            'type': 'string',
            'description': 'Entity tag for optimistic concurrency',
            'compliance_category': 'general'
        },
        'type': {
            'type': 'string',
            'description': 'Resource type or category',
            'compliance_category': 'identity',
            'operators': ['equals', 'not_equals', 'in', 'not_in']
        },
        'status': {
            'type': 'string',
            'description': 'Resource status',
            'compliance_category': 'general',
            'operators': ['equals', 'not_equals', 'in', 'not_in']
        },
        'state': {
            'type': 'string',
            'description': 'Resource state',
            'compliance_category': 'general',
            'operators': ['equals', 'not_equals', 'in', 'not_in']
        },
        'category': {
            'type': 'string',
            'description': 'Resource category',
            'compliance_category': 'general',
            'operators': ['equals', 'not_equals', 'in', 'not_in']
        },
        'level': {
            'type': 'string',
            'description': 'Level or severity',
            'compliance_category': 'general',
            'operators': ['equals', 'not_equals', 'in', 'not_in']
        },
        'mode': {
            'type': 'string',
            'description': 'Mode or configuration',
            'compliance_category': 'general',
            'operators': ['equals', 'not_equals', 'in', 'not_in']
        },
        'format': {
            'type': 'string',
            'description': 'Format or encoding',
            'compliance_category': 'general',
            'operators': ['equals', 'not_equals', 'in', 'not_in']
        },
        'role': {
            'type': 'string',
            'description': 'Role or permission',
            'compliance_category': 'identity',
            'operators': ['equals', 'not_equals', 'in', 'not_in']
        },
        'class': {
            'type': 'string',
            'description': 'Class or tier',
            'compliance_category': 'general',
            'operators': ['equals', 'not_equals', 'in', 'not_in']
        },
        'tier': {
            'type': 'string',
            'description': 'Tier or level',
            'compliance_category': 'general',
            'operators': ['equals', 'not_equals', 'in', 'not_in']
        },
        'language': {
            'type': 'string',
            'description': 'Language or locale',
            'compliance_category': 'general',
            'operators': ['equals', 'not_equals', 'in', 'not_in']
        }
    }
    
    # Service-specific field patterns
    SERVICE_FIELD_PATTERNS = {
        'storage': {
            'buckets': {
                'iamConfiguration': {
                    'type': 'object',
                    'description': 'IAM configuration',
                    'compliance_category': 'security',
                    'security_impact': 'high',
                    'nested_fields': {
                        'uniformBucketLevelAccess': {
                            'type': 'object',
                            'nested_fields': {
                                'enabled': {'type': 'boolean', 'compliance_category': 'security'}
                            }
                        },
                        'publicAccessPrevention': {
                            'type': 'string',
                            'enum': True,
                            'possible_values': ['inherited', 'enforced'],
                            'compliance_category': 'security',
                            'security_impact': 'high'
                        }
                    }
                },
                'encryption': {
                    'type': 'object',
                    'description': 'Encryption configuration',
                    'compliance_category': 'security',
                    'security_impact': 'high',
                    'nested_fields': {
                        'defaultKmsKeyName': {'type': 'string'}
                    }
                },
                'versioning': {
                    'type': 'object',
                    'compliance_category': 'data_protection',
                    'nested_fields': {
                        'enabled': {'type': 'boolean'}
                    }
                },
                'logging': {
                    'type': 'object',
                    'compliance_category': 'security',
                    'security_impact': 'medium',
                    'nested_fields': {
                        'logBucket': {'type': 'string'},
                        'logObjectPrefix': {'type': 'string'}
                    }
                },
                'lifecycle': {
                    'type': 'object',
                    'compliance_category': 'data_protection'
                },
                'location': {
                    'type': 'string',
                    'compliance_category': 'availability',
                    'description': 'Geographic location'
                },
                'locationType': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['region', 'dual-region', 'multi-region'],
                    'compliance_category': 'availability'
                },
                'storageClass': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['STANDARD', 'NEARLINE', 'COLDLINE', 'ARCHIVE'],
                    'compliance_category': 'general'
                }
            },
            'objects': {
                'size': {
                    'type': 'integer',
                    'description': 'Object size in bytes'
                },
                'contentType': {
                    'type': 'string',
                    'description': 'MIME content type'
                },
                'crc32c': {
                    'type': 'string',
                    'description': 'CRC32C checksum'
                },
                'md5Hash': {
                    'type': 'string',
                    'description': 'MD5 hash (base64)'
                }
            }
        },
        'compute': {
            'instances': {
                'status': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['PROVISIONING', 'STAGING', 'RUNNING', 'STOPPING', 'STOPPED', 'TERMINATED'],
                    'compliance_category': 'general'
                },
                'machineType': {
                    'type': 'string',
                    'description': 'Machine type URL',
                    'compliance_category': 'general'
                },
                'zone': {
                    'type': 'string',
                    'description': 'Zone URL',
                    'compliance_category': 'availability'
                },
                'canIpForward': {
                    'type': 'boolean',
                    'description': 'Allow IP forwarding',
                    'compliance_category': 'network',
                    'security_impact': 'medium'
                },
                'disks': {
                    'type': 'array',
                    'description': 'Attached disks',
                    'compliance_category': 'general'
                },
                'networkInterfaces': {
                    'type': 'array',
                    'description': 'Network interfaces',
                    'compliance_category': 'network'
                },
                'serviceAccounts': {
                    'type': 'array',
                    'description': 'Service accounts',
                    'compliance_category': 'identity',
                    'security_impact': 'high'
                },
                'shieldedInstanceConfig': {
                    'type': 'object',
                    'compliance_category': 'security',
                    'security_impact': 'high',
                    'nested_fields': {
                        'enableSecureBoot': {'type': 'boolean'},
                        'enableVtpm': {'type': 'boolean'},
                        'enableIntegrityMonitoring': {'type': 'boolean'}
                    }
                },
                'deletionProtection': {
                    'type': 'boolean',
                    'compliance_category': 'data_protection'
                }
            },
            'firewalls': {
                'allowed': {
                    'type': 'array',
                    'description': 'Allowed protocols and ports',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                },
                'denied': {
                    'type': 'array',
                    'description': 'Denied protocols and ports',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                },
                'sourceRanges': {
                    'type': 'array',
                    'description': 'Source IP ranges',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                },
                'direction': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['INGRESS', 'EGRESS'],
                    'compliance_category': 'network'
                },
                'disabled': {
                    'type': 'boolean',
                    'compliance_category': 'security'
                }
            }
        },
        'container': {
            'clusters': {
                'status': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['PROVISIONING', 'RUNNING', 'RECONCILING', 'STOPPING', 'ERROR', 'DEGRADED'],
                    'compliance_category': 'general'
                },
                'masterAuth': {
                    'type': 'object',
                    'compliance_category': 'security',
                    'security_impact': 'high',
                    'nested_fields': {
                        'clientCertificateConfig': {
                            'type': 'object',
                            'nested_fields': {
                                'issueClientCertificate': {'type': 'boolean'}
                            }
                        }
                    }
                },
                'privateClusterConfig': {
                    'type': 'object',
                    'compliance_category': 'network',
                    'security_impact': 'high',
                    'nested_fields': {
                        'enablePrivateNodes': {'type': 'boolean'},
                        'enablePrivateEndpoint': {'type': 'boolean'}
                    }
                },
                'networkPolicy': {
                    'type': 'object',
                    'compliance_category': 'security',
                    'security_impact': 'medium',
                    'nested_fields': {
                        'enabled': {'type': 'boolean'}
                    }
                },
                'binaryAuthorization': {
                    'type': 'object',
                    'compliance_category': 'security',
                    'security_impact': 'high',
                    'nested_fields': {
                        'enabled': {'type': 'boolean'}
                    }
                },
                'workloadIdentityConfig': {
                    'type': 'object',
                    'compliance_category': 'identity',
                    'security_impact': 'high'
                }
            }
        },
        'cloudkms': {
            'keyRings': {
                'location': {
                    'type': 'string',
                    'compliance_category': 'availability'
                }
            },
            'cryptoKeys': {
                'purpose': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['ENCRYPT_DECRYPT', 'ASYMMETRIC_SIGN', 'ASYMMETRIC_DECRYPT', 'MAC'],
                    'compliance_category': 'security'
                },
                'rotationPeriod': {
                    'type': 'string',
                    'description': 'Rotation period duration',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                },
                'nextRotationTime': {
                    'type': 'string',
                    'format': 'date-time',
                    'compliance_category': 'security'
                }
            }
        },
        'secretmanager': {
            'secrets': {
                'replication': {
                    'type': 'object',
                    'compliance_category': 'availability',
                    'nested_fields': {
                        'automatic': {'type': 'object'},
                        'userManaged': {'type': 'object'}
                    }
                },
                'rotation': {
                    'type': 'object',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                }
            }
        },
        'iam': {
            'serviceAccounts': {
                'email': {
                    'type': 'string',
                    'compliance_category': 'identity'
                },
                'disabled': {
                    'type': 'boolean',
                    'compliance_category': 'identity',
                    'security_impact': 'medium'
                },
                'oauth2ClientId': {
                    'type': 'string',
                    'compliance_category': 'identity'
                }
            },
            'roles': {
                'title': {
                    'type': 'string',
                    'compliance_category': 'identity'
                },
                'includedPermissions': {
                    'type': 'array',
                    'compliance_category': 'security',
                    'security_impact': 'high'
                },
                'stage': {
                    'type': 'string',
                    'enum': True,
                    'possible_values': ['ALPHA', 'BETA', 'GA', 'DEPRECATED', 'DISABLED'],
                    'compliance_category': 'general'
                }
            }
        }
    }
    
    def __init__(self):
        self.stats = {
            'services_processed': 0,
            'resources_enriched': 0,
            'fields_added': 0,
            'operations_enriched': 0
        }
    
    def get_resource_fields(self, service_name: str, resource_name: str) -> Dict[str, Any]:
        """Get field schema for a specific resource"""
        fields = {}
        
        # Add common fields
        fields.update(self.COMMON_RESPONSE_FIELDS.copy())
        
        # Add service-specific fields
        if service_name in self.SERVICE_FIELD_PATTERNS:
            service_patterns = self.SERVICE_FIELD_PATTERNS[service_name]
            
            # Try exact match first
            if resource_name in service_patterns:
                fields.update(service_patterns[resource_name])
            else:
                # Try partial match (e.g., 'buckets' matches 'buckets' resource)
                for pattern_name, pattern_fields in service_patterns.items():
                    if pattern_name in resource_name.lower() or resource_name.lower() in pattern_name:
                        fields.update(pattern_fields)
                        break
        
        return fields
    
    def enrich_operation(self, operation: Dict[str, Any], service_name: str, resource_name: str) -> Dict[str, Any]:
        """Enrich a single operation with field metadata"""
        enriched = operation.copy()
        
        # Only enrich list/get operations (they return data)
        op_name = operation.get('operation', '').lower()
        if op_name in ['list', 'get', 'aggregatedlist', 'listinstances']:
            # Get field schema for this resource
            fields = self.get_resource_fields(service_name, resource_name)
            
            if fields:
                # Convert to enhanced format
                enriched['item_fields'] = fields
                self.stats['fields_added'] += len(fields)
                self.stats['operations_enriched'] += 1
        
        return enriched
    
    def enrich_resource(self, resource_data: Dict[str, Any], service_name: str, resource_name: str) -> Dict[str, Any]:
        """Enrich a resource with field metadata"""
        enriched = resource_data.copy()
        
        # Enrich independent operations
        if 'independent' in resource_data:
            enriched['independent'] = [
                self.enrich_operation(op, service_name, resource_name)
                for op in resource_data['independent']
            ]
        
        # Enrich dependent operations
        if 'dependent' in resource_data:
            enriched['dependent'] = [
                self.enrich_operation(op, service_name, resource_name)
                for op in resource_data['dependent']
            ]
        
        self.stats['resources_enriched'] += 1
        return enriched
    
    def enrich_service(self, service_data: Dict[str, Any], service_name: str) -> Dict[str, Any]:
        """Enrich a service with field metadata"""
        enriched = service_data.copy()
        
        if 'resources' in service_data:
            enriched_resources = {}
            for resource_name, resource_data in service_data['resources'].items():
                enriched_resources[resource_name] = self.enrich_resource(
                    resource_data, service_name, resource_name
                )
            enriched['resources'] = enriched_resources
        
        self.stats['services_processed'] += 1
        return enriched
    
    def enrich_catalog(self, catalog: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich the entire catalog"""
        enriched_catalog = {}
        
        for service_name, service_data in catalog.items():
            print(f"Enriching {service_name}...")
            enriched_catalog[service_name] = self.enrich_service(service_data, service_name)
        
        return enriched_catalog
    
    def print_stats(self):
        """Print enrichment statistics"""
        print("\n" + "=" * 80)
        print("Field Enrichment Statistics")
        print("=" * 80)
        print(f"Services processed:     {self.stats['services_processed']}")
        print(f"Resources enriched:     {self.stats['resources_enriched']}")
        print(f"Operations enriched:    {self.stats['operations_enriched']}")
        print(f"Fields added:           {self.stats['fields_added']}")
        print("=" * 80)


def main():
    print("=" * 80)
    print("GCP API Field Enrichment")
    print("=" * 80)
    print()
    
    # Load enhanced catalog (with parameters already enhanced)
    print("Loading gcp_api_dependencies_enhanced.json...")
    with open('gcp_api_dependencies_enhanced.json', 'r') as f:
        catalog = json.load(f)
    
    print(f"✅ Loaded {len(catalog)} services")
    print()
    
    # Enrich with field metadata
    print("Enriching with field metadata...")
    print()
    enricher = GCPAPIFieldEnricher()
    enriched_catalog = enricher.enrich_catalog(catalog)
    
    # Save enriched catalog
    output_file = 'gcp_api_dependencies_fully_enhanced.json'
    print()
    print(f"Saving to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(enriched_catalog, f, indent=2)
    
    print(f"✅ Saved")
    
    # Print statistics
    enricher.print_stats()
    
    print()
    print("=" * 80)
    print("✅ Field enrichment complete!")
    print("=" * 80)
    print()
    print(f"Output file: {output_file}")
    print("=" * 80)


if __name__ == '__main__':
    main()

