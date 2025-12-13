"""
Kubernetes API Catalog Generator

Creates a comprehensive K8s API catalog similar to Azure/GCP catalogs.
Based on Kubernetes API resources and field specifications.
"""

import json
from typing import Dict, List, Any


class K8sAPICatalogGenerator:
    """Generate K8s API catalog with field metadata"""
    
    # Kubernetes API resources with field definitions
    K8S_RESOURCES = {
        'pod': {
            'api_version': 'v1',
            'kind': 'Pod',
            'description': 'Pod is a collection of containers that can run on a host',
            'operations': ['list', 'get', 'create', 'update', 'delete', 'patch'],
            'fields': {
                'apiVersion': {
                    'type': 'string',
                    'description': 'APIVersion defines the versioned schema',
                    'compliance_category': 'general'
                },
                'kind': {
                    'type': 'string',
                    'description': 'Kind is a string value representing the REST resource',
                    'compliance_category': 'identity'
                },
                'metadata': {
                    'type': 'object',
                    'description': 'Standard object metadata',
                    'compliance_category': 'identity',
                    'nested_fields': {
                        'name': {'type': 'string', 'compliance_category': 'identity'},
                        'namespace': {'type': 'string', 'compliance_category': 'identity'},
                        'labels': {'type': 'object', 'compliance_category': 'general'},
                        'annotations': {'type': 'object', 'compliance_category': 'general'},
                        'creationTimestamp': {'type': 'string', 'format': 'date-time'},
                        'uid': {'type': 'string', 'compliance_category': 'identity'}
                    }
                },
                'spec': {
                    'type': 'object',
                    'description': 'Specification of the desired behavior of the pod',
                    'compliance_category': 'general',
                    'nested_fields': {
                        'containers': {
                            'type': 'array',
                            'compliance_category': 'general',
                            'item_schema': {
                                'name': {'type': 'string'},
                                'image': {'type': 'string', 'compliance_category': 'security', 'security_impact': 'high'},
                                'imagePullPolicy': {'type': 'string', 'enum': True, 'possible_values': ['Always', 'Never', 'IfNotPresent']},
                                'securityContext': {
                                    'type': 'object',
                                    'compliance_category': 'security',
                                    'security_impact': 'high',
                                    'nested_fields': {
                                        'runAsUser': {'type': 'integer'},
                                        'runAsNonRoot': {'type': 'boolean', 'security_impact': 'high'},
                                        'readOnlyRootFilesystem': {'type': 'boolean', 'security_impact': 'high'},
                                        'allowPrivilegeEscalation': {'type': 'boolean', 'security_impact': 'high'},
                                        'privileged': {'type': 'boolean', 'security_impact': 'high'},
                                        'capabilities': {
                                            'type': 'object',
                                            'security_impact': 'high',
                                            'nested_fields': {
                                                'add': {'type': 'array'},
                                                'drop': {'type': 'array'}
                                            }
                                        }
                                    }
                                },
                                'resources': {
                                    'type': 'object',
                                    'compliance_category': 'general',
                                    'nested_fields': {
                                        'limits': {'type': 'object'},
                                        'requests': {'type': 'object'}
                                    }
                                }
                            }
                        },
                        'hostNetwork': {'type': 'boolean', 'compliance_category': 'network', 'security_impact': 'high'},
                        'hostPID': {'type': 'boolean', 'compliance_category': 'security', 'security_impact': 'high'},
                        'hostIPC': {'type': 'boolean', 'compliance_category': 'security', 'security_impact': 'high'},
                        'serviceAccountName': {'type': 'string', 'compliance_category': 'identity', 'security_impact': 'medium'},
                        'automountServiceAccountToken': {'type': 'boolean', 'compliance_category': 'security', 'security_impact': 'medium'},
                        'securityContext': {
                            'type': 'object',
                            'compliance_category': 'security',
                            'security_impact': 'high',
                            'nested_fields': {
                                'runAsUser': {'type': 'integer'},
                                'runAsNonRoot': {'type': 'boolean'},
                                'fsGroup': {'type': 'integer'},
                                'seLinuxOptions': {'type': 'object'},
                                'seccompProfile': {'type': 'object'}
                            }
                        },
                        'volumes': {'type': 'array', 'compliance_category': 'storage'}
                    }
                },
                'status': {
                    'type': 'object',
                    'description': 'Most recently observed status of the pod',
                    'compliance_category': 'general',
                    'nested_fields': {
                        'phase': {'type': 'string', 'enum': True, 'possible_values': ['Pending', 'Running', 'Succeeded', 'Failed', 'Unknown']},
                        'conditions': {'type': 'array'},
                        'podIP': {'type': 'string'},
                        'startTime': {'type': 'string', 'format': 'date-time'}
                    }
                }
            }
        },
        'service': {
            'api_version': 'v1',
            'kind': 'Service',
            'description': 'Service is a named abstraction of software service',
            'operations': ['list', 'get', 'create', 'update', 'delete'],
            'fields': {
                'metadata': {
                    'type': 'object',
                    'compliance_category': 'identity',
                    'nested_fields': {
                        'name': {'type': 'string'},
                        'namespace': {'type': 'string'},
                        'annotations': {'type': 'object'}
                    }
                },
                'spec': {
                    'type': 'object',
                    'nested_fields': {
                        'type': {'type': 'string', 'enum': True, 'possible_values': ['ClusterIP', 'NodePort', 'LoadBalancer', 'ExternalName']},
                        'selector': {'type': 'object'},
                        'ports': {'type': 'array'},
                        'externalTrafficPolicy': {'type': 'string', 'compliance_category': 'network'}
                    }
                }
            }
        },
        'namespace': {
            'api_version': 'v1',
            'kind': 'Namespace',
            'description': 'Namespace provides a scope for names',
            'operations': ['list', 'get', 'create', 'delete'],
            'fields': {
                'metadata': {
                    'type': 'object',
                    'nested_fields': {
                        'name': {'type': 'string'},
                        'labels': {'type': 'object'},
                        'annotations': {'type': 'object'}
                    }
                },
                'spec': {
                    'type': 'object',
                    'nested_fields': {
                        'finalizers': {'type': 'array'}
                    }
                },
                'status': {
                    'type': 'object',
                    'nested_fields': {
                        'phase': {'type': 'string', 'enum': True, 'possible_values': ['Active', 'Terminating']}
                    }
                }
            }
        },
        'secret': {
            'api_version': 'v1',
            'kind': 'Secret',
            'description': 'Secret holds secret data',
            'operations': ['list', 'get', 'create', 'update', 'delete'],
            'fields': {
                'metadata': {
                    'type': 'object',
                    'nested_fields': {
                        'name': {'type': 'string'},
                        'namespace': {'type': 'string'}
                    }
                },
                'type': {'type': 'string', 'compliance_category': 'security'},
                'data': {'type': 'object', 'compliance_category': 'security', 'security_impact': 'high'},
                'stringData': {'type': 'object', 'compliance_category': 'security', 'security_impact': 'high'},
                'immutable': {'type': 'boolean', 'compliance_category': 'security', 'security_impact': 'medium'}
            }
        },
        'configmap': {
            'api_version': 'v1',
            'kind': 'ConfigMap',
            'description': 'ConfigMap holds configuration data',
            'operations': ['list', 'get', 'create', 'update', 'delete'],
            'fields': {
                'metadata': {
                    'type': 'object',
                    'nested_fields': {
                        'name': {'type': 'string'},
                        'namespace': {'type': 'string'}
                    }
                },
                'data': {'type': 'object'},
                'binaryData': {'type': 'object'},
                'immutable': {'type': 'boolean'}
            }
        },
        'networkpolicy': {
            'api_version': 'networking.k8s.io/v1',
            'kind': 'NetworkPolicy',
            'description': 'NetworkPolicy describes network policies for pods',
            'operations': ['list', 'get', 'create', 'update', 'delete'],
            'fields': {
                'metadata': {'type': 'object'},
                'spec': {
                    'type': 'object',
                    'compliance_category': 'network',
                    'security_impact': 'high',
                    'nested_fields': {
                        'podSelector': {'type': 'object'},
                        'policyTypes': {'type': 'array'},
                        'ingress': {'type': 'array'},
                        'egress': {'type': 'array'}
                    }
                }
            }
        },
        'ingress': {
            'api_version': 'networking.k8s.io/v1',
            'kind': 'Ingress',
            'description': 'Ingress is a collection of rules for HTTP routing',
            'operations': ['list', 'get', 'create', 'update', 'delete'],
            'fields': {
                'metadata': {'type': 'object'},
                'spec': {
                    'type': 'object',
                    'nested_fields': {
                        'rules': {'type': 'array', 'compliance_category': 'network'},
                        'tls': {'type': 'array', 'compliance_category': 'security', 'security_impact': 'high'}
                    }
                }
            }
        },
        'persistentvolume': {
            'api_version': 'v1',
            'kind': 'PersistentVolume',
            'description': 'PersistentVolume represents a piece of storage',
            'operations': ['list', 'get', 'create', 'delete'],
            'fields': {
                'metadata': {'type': 'object'},
                'spec': {
                    'type': 'object',
                    'compliance_category': 'storage',
                    'nested_fields': {
                        'capacity': {'type': 'object'},
                        'accessModes': {'type': 'array'},
                        'persistentVolumeReclaimPolicy': {'type': 'string', 'enum': True, 'possible_values': ['Retain', 'Delete', 'Recycle']},
                        'storageClassName': {'type': 'string'}
                    }
                }
            }
        },
        'role': {
            'api_version': 'rbac.authorization.k8s.io/v1',
            'kind': 'Role',
            'description': 'Role contains rules that represent a set of permissions',
            'operations': ['list', 'get', 'create', 'update', 'delete'],
            'fields': {
                'metadata': {'type': 'object'},
                'rules': {
                    'type': 'array',
                    'compliance_category': 'security',
                    'security_impact': 'high',
                    'item_schema': {
                        'apiGroups': {'type': 'array'},
                        'resources': {'type': 'array'},
                        'verbs': {'type': 'array'}
                    }
                }
            }
        },
        'rolebinding': {
            'api_version': 'rbac.authorization.k8s.io/v1',
            'kind': 'RoleBinding',
            'description': 'RoleBinding references a role but contains a list of users',
            'operations': ['list', 'get', 'create', 'update', 'delete'],
            'fields': {
                'metadata': {'type': 'object'},
                'roleRef': {'type': 'object', 'compliance_category': 'security', 'security_impact': 'high'},
                'subjects': {'type': 'array', 'compliance_category': 'identity', 'security_impact': 'high'}
            }
        }
    }
    
    def __init__(self):
        self.stats = {
            'resources_processed': 0,
            'fields_added': 0,
            'operations_created': 0
        }
    
    def generate_catalog(self) -> Dict[str, Any]:
        """Generate the full K8s API catalog"""
        catalog = {}
        
        for resource_name, resource_config in self.K8S_RESOURCES.items():
            print(f"Generating {resource_name}...")
            
            resource_catalog = {
                'resource': resource_name,
                'api_version': resource_config['api_version'],
                'kind': resource_config['kind'],
                'description': resource_config['description'],
                'operations': []
            }
            
            # Generate operations
            for operation in resource_config['operations']:
                op_def = self.generate_operation(operation, resource_name, resource_config)
                resource_catalog['operations'].append(op_def)
                self.stats['operations_created'] += 1
            
            catalog[resource_name] = resource_catalog
            self.stats['resources_processed'] += 1
            self.stats['fields_added'] += len(resource_config.get('fields', {}))
        
        return catalog
    
    def generate_operation(self, operation: str, resource_name: str, resource_config: Dict) -> Dict:
        """Generate operation definition"""
        op = {
            'operation': operation,
            'http_method': self.get_http_method(operation),
            'description': f"{operation.title()} {resource_name}",
            'parameters': self.get_parameters(operation, resource_name),
            'item_fields': resource_config.get('fields', {}) if operation in ['list', 'get'] else {}
        }
        
        return op
    
    def get_http_method(self, operation: str) -> str:
        """Map operation to HTTP method"""
        mapping = {
            'list': 'GET',
            'get': 'GET',
            'create': 'POST',
            'update': 'PUT',
            'delete': 'DELETE',
            'patch': 'PATCH'
        }
        return mapping.get(operation, 'GET')
    
    def get_parameters(self, operation: str, resource_name: str) -> Dict:
        """Get common parameters for operation"""
        params = {}
        
        if operation == 'list':
            params = {
                'namespace': {
                    'type': 'string',
                    'description': 'Object name and auth scope, such as for teams and projects',
                    'required': False
                },
                'labelSelector': {
                    'type': 'string',
                    'description': 'A selector to restrict the list of returned objects by their labels',
                    'required': False
                },
                'fieldSelector': {
                    'type': 'string',
                    'description': 'A selector to restrict the list of returned objects by their fields',
                    'required': False
                },
                'limit': {
                    'type': 'integer',
                    'description': 'Maximum number of responses to return',
                    'range': [1, 500],
                    'recommended': 100,
                    'required': False
                },
                'continue': {
                    'type': 'string',
                    'description': 'Continue token for pagination',
                    'required': False
                }
            }
        elif operation == 'get':
            params = {
                'name': {
                    'type': 'string',
                    'description': 'Name of the resource',
                    'required': True
                },
                'namespace': {
                    'type': 'string',
                    'description': 'Namespace of the resource',
                    'required': False
                }
            }
        
        return params
    
    def print_stats(self):
        """Print generation statistics"""
        print("\n" + "=" * 80)
        print("K8s API Catalog Generation Statistics")
        print("=" * 80)
        print(f"Resources processed:   {self.stats['resources_processed']}")
        print(f"Operations created:    {self.stats['operations_created']}")
        print(f"Fields added:          {self.stats['fields_added']}")
        print("=" * 80)


def main():
    print("=" * 80)
    print("Kubernetes API Catalog Generator")
    print("=" * 80)
    print()
    
    generator = K8sAPICatalogGenerator()
    catalog = generator.generate_catalog()
    
    # Save catalog
    output_file = 'k8s_api_catalog_enhanced.json'
    print(f"\nSaving to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(catalog, f, indent=2)
    
    print(f"✅ Saved")
    
    generator.print_stats()
    
    print()
    print("=" * 80)
    print(f"✅ K8s API catalog created: {output_file}")
    print("=" * 80)


if __name__ == '__main__':
    main()

