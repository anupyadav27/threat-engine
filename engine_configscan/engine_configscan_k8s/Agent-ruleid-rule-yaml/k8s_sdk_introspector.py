"""
Kubernetes Python SDK Introspector

Introspects the Kubernetes Python SDK to extract actual field information,
similar to how we did it for Azure SDK.

This ensures the catalog matches the exact fields available in the SDK.
"""

import json
from typing import Dict, List, Any, Optional
from kubernetes import client


class K8sSDKIntrospector:
    """Introspect Kubernetes Python SDK for field information"""
    
    # Map of K8s resources to their SDK model classes
    K8S_RESOURCE_MODELS = {
        'pod': {
            'model_class': client.V1Pod,
            'list_model': client.V1PodList,
            'api_version': 'v1',
            'operations': ['list', 'get', 'create', 'update', 'delete', 'patch']
        },
        'service': {
            'model_class': client.V1Service,
            'list_model': client.V1ServiceList,
            'api_version': 'v1',
            'operations': ['list', 'get', 'create', 'update', 'delete']
        },
        'namespace': {
            'model_class': client.V1Namespace,
            'list_model': client.V1NamespaceList,
            'api_version': 'v1',
            'operations': ['list', 'get', 'create', 'delete']
        },
        'secret': {
            'model_class': client.V1Secret,
            'list_model': client.V1SecretList,
            'api_version': 'v1',
            'operations': ['list', 'get', 'create', 'update', 'delete']
        },
        'configmap': {
            'model_class': client.V1ConfigMap,
            'list_model': client.V1ConfigMapList,
            'api_version': 'v1',
            'operations': ['list', 'get', 'create', 'update', 'delete']
        },
        'deployment': {
            'model_class': client.V1Deployment,
            'list_model': client.V1DeploymentList,
            'api_version': 'apps/v1',
            'operations': ['list', 'get', 'create', 'update', 'delete', 'patch']
        },
        'statefulset': {
            'model_class': client.V1StatefulSet,
            'list_model': client.V1StatefulSetList,
            'api_version': 'apps/v1',
            'operations': ['list', 'get', 'create', 'update', 'delete']
        },
        'daemonset': {
            'model_class': client.V1DaemonSet,
            'list_model': client.V1DaemonSetList,
            'api_version': 'apps/v1',
            'operations': ['list', 'get', 'create', 'update', 'delete']
        },
        'networkpolicy': {
            'model_class': client.V1NetworkPolicy,
            'list_model': client.V1NetworkPolicyList,
            'api_version': 'networking.k8s.io/v1',
            'operations': ['list', 'get', 'create', 'update', 'delete']
        },
        'ingress': {
            'model_class': client.V1Ingress,
            'list_model': client.V1IngressList,
            'api_version': 'networking.k8s.io/v1',
            'operations': ['list', 'get', 'create', 'update', 'delete']
        },
        'persistentvolume': {
            'model_class': client.V1PersistentVolume,
            'list_model': client.V1PersistentVolumeList,
            'api_version': 'v1',
            'operations': ['list', 'get', 'create', 'delete']
        },
        'persistentvolumeclaim': {
            'model_class': client.V1PersistentVolumeClaim,
            'list_model': client.V1PersistentVolumeClaimList,
            'api_version': 'v1',
            'operations': ['list', 'get', 'create', 'update', 'delete']
        },
        'serviceaccount': {
            'model_class': client.V1ServiceAccount,
            'list_model': client.V1ServiceAccountList,
            'api_version': 'v1',
            'operations': ['list', 'get', 'create', 'update', 'delete']
        },
        'role': {
            'model_class': client.V1Role,
            'list_model': client.V1RoleList,
            'api_version': 'rbac.authorization.k8s.io/v1',
            'operations': ['list', 'get', 'create', 'update', 'delete']
        },
        'rolebinding': {
            'model_class': client.V1RoleBinding,
            'list_model': client.V1RoleBindingList,
            'api_version': 'rbac.authorization.k8s.io/v1',
            'operations': ['list', 'get', 'create', 'update', 'delete']
        },
        'clusterrole': {
            'model_class': client.V1ClusterRole,
            'list_model': client.V1ClusterRoleList,
            'api_version': 'rbac.authorization.k8s.io/v1',
            'operations': ['list', 'get', 'create', 'update', 'delete']
        },
        'clusterrolebinding': {
            'model_class': client.V1ClusterRoleBinding,
            'list_model': client.V1ClusterRoleBindingList,
            'api_version': 'rbac.authorization.k8s.io/v1',
            'operations': ['list', 'get', 'create', 'update', 'delete']
        }
    }
    
    # Security-critical field patterns
    SECURITY_FIELD_PATTERNS = [
        'privileged', 'hostNetwork', 'hostPID', 'hostIPC', 'hostPath',
        'securityContext', 'runAsUser', 'runAsNonRoot', 'readOnlyRootFilesystem',
        'allowPrivilegeEscalation', 'capabilities', 'seLinuxOptions',
        'seccompProfile', 'appArmorProfile', 'tls', 'secret', 'certificate'
    ]
    
    def __init__(self):
        self.stats = {
            'resources_processed': 0,
            'fields_extracted': 0,
            'operations_created': 0
        }
        self.catalog = {}
    
    def get_field_type(self, field_name: str, field_value: Any) -> str:
        """Determine field type from SDK attribute"""
        if field_value is None:
            return 'string'  # Default
        
        type_name = type(field_value).__name__
        
        if type_name in ['bool', 'bool_']:
            return 'boolean'
        elif type_name in ['int', 'int32', 'int64', 'long']:
            return 'integer'
        elif type_name in ['float', 'double']:
            return 'number'
        elif type_name in ['str', 'string']:
            return 'string'
        elif type_name in ['list', 'V1ListMeta']:
            return 'array'
        elif type_name in ['dict', 'object'] or type_name.startswith('V1'):
            return 'object'
        else:
            return 'string'
    
    def is_security_field(self, field_name: str) -> bool:
        """Check if field is security-related"""
        field_lower = field_name.lower()
        return any(pattern.lower() in field_lower for pattern in self.SECURITY_FIELD_PATTERNS)
    
    def get_compliance_category(self, field_name: str) -> str:
        """Determine compliance category"""
        field_lower = field_name.lower()
        
        if any(term in field_lower for term in ['security', 'privileged', 'capabilities', 'selinux', 'seccomp', 'apparmor']):
            return 'security'
        elif any(term in field_lower for term in ['network', 'ip', 'port', 'ingress', 'egress']):
            return 'network'
        elif any(term in field_lower for term in ['volume', 'storage', 'persistent']):
            return 'storage'
        elif any(term in field_lower for term in ['name', 'uid', 'namespace', 'labels', 'annotations']):
            return 'identity'
        elif any(term in field_lower for term in ['secret', 'configmap', 'certificate', 'tls']):
            return 'data_protection'
        else:
            return 'general'
    
    def introspect_model(self, model_class) -> Dict[str, Any]:
        """Introspect a K8s model class to extract fields"""
        fields = {}
        
        try:
            # Get openapi types (field definitions from SDK)
            if hasattr(model_class, 'openapi_types'):
                openapi_types = model_class.openapi_types
                attribute_map = getattr(model_class, 'attribute_map', {})
                
                for attr_name, openapi_type in openapi_types.items():
                    # Get the actual field name (CamelCase)
                    field_name = attribute_map.get(attr_name, attr_name)
                    
                    # Determine type
                    field_type = self.parse_swagger_type(openapi_type)
                    
                    # Build field metadata
                    field_meta = {
                        'type': field_type,
                        'sdk_attribute': attr_name,
                        'compliance_category': self.get_compliance_category(field_name)
                    }
                    
                    # Add security impact if security-related
                    if self.is_security_field(field_name):
                        field_meta['security_impact'] = 'high'
                    
                    # Add operators based on type
                    field_meta['operators'] = self.get_operators_for_type(field_type)
                    
                    # Check if it's a nested object (another V1 model)
                    if openapi_type.startswith('V1') or openapi_type.startswith('object'):
                        # Try to introspect nested model
                        nested_class = self.get_nested_model_class(openapi_type)
                        if nested_class:
                            field_meta['nested_fields'] = self.introspect_model(nested_class)
                    
                    fields[field_name] = field_meta
                    self.stats['fields_extracted'] += 1
        
        except Exception as e:
            print(f"    Warning: Could not introspect {model_class.__name__}: {e}")
        
        return fields
    
    def parse_swagger_type(self, swagger_type: str) -> str:
        """Parse swagger type string to our type"""
        if swagger_type == 'bool':
            return 'boolean'
        elif swagger_type in ['int', 'int32', 'int64']:
            return 'integer'
        elif swagger_type in ['float', 'double']:
            return 'number'
        elif swagger_type == 'str':
            return 'string'
        elif swagger_type == 'datetime':
            return 'string'  # With format: date-time
        elif swagger_type.startswith('list['):
            return 'array'
        elif swagger_type.startswith('dict('):
            return 'object'
        elif swagger_type.startswith('V1'):
            return 'object'
        else:
            return 'string'
    
    def get_nested_model_class(self, swagger_type: str):
        """Get nested model class from swagger type"""
        if swagger_type.startswith('V1'):
            try:
                return getattr(client, swagger_type)
            except AttributeError:
                return None
        return None
    
    def get_operators_for_type(self, field_type: str) -> List[str]:
        """Get valid operators for field type"""
        operator_map = {
            'string': ['equals', 'not_equals', 'contains', 'in', 'not_empty', 'exists'],
            'boolean': ['equals', 'not_equals'],
            'integer': ['equals', 'not_equals', 'gt', 'lt', 'gte', 'lte'],
            'number': ['equals', 'not_equals', 'gt', 'lt', 'gte', 'lte'],
            'object': ['exists', 'not_empty'],
            'array': ['contains', 'not_empty', 'exists']
        }
        return operator_map.get(field_type, ['equals', 'exists'])
    
    def introspect_resource(self, resource_name: str, resource_config: Dict) -> Dict[str, Any]:
        """Introspect a K8s resource"""
        print(f"  Introspecting {resource_name}...")
        
        model_class = resource_config['model_class']
        
        # Introspect the model
        fields = self.introspect_model(model_class)
        
        # Build resource catalog
        resource_catalog = {
            'resource': resource_name,
            'api_version': resource_config['api_version'],
            'kind': model_class.__name__.replace('V1', ''),
            'sdk_model': model_class.__name__,
            'operations': []
        }
        
        # Generate operations
        for operation in resource_config['operations']:
            op_def = {
                'operation': operation,
                'http_method': self.get_http_method(operation),
                'description': f"{operation.title()} {resource_name}",
                'item_fields': fields if operation in ['list', 'get'] else {}
            }
            resource_catalog['operations'].append(op_def)
            self.stats['operations_created'] += 1
        
        self.stats['resources_processed'] += 1
        return resource_catalog
    
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
    
    def generate_catalog(self) -> Dict[str, Any]:
        """Generate full K8s SDK catalog"""
        print("=" * 80)
        print("Kubernetes Python SDK Introspection")
        print("=" * 80)
        print()
        
        for resource_name, resource_config in self.K8S_RESOURCE_MODELS.items():
            try:
                resource_catalog = self.introspect_resource(resource_name, resource_config)
                self.catalog[resource_name] = resource_catalog
            except Exception as e:
                print(f"  ❌ Error processing {resource_name}: {e}")
        
        return self.catalog
    
    def save_catalog(self, output_file: str):
        """Save catalog to JSON"""
        with open(output_file, 'w') as f:
            json.dump(self.catalog, f, indent=2)
        print(f"\n✅ Saved catalog to {output_file}")
    
    def print_stats(self):
        """Print statistics"""
        print("\n" + "=" * 80)
        print("K8s SDK Introspection Statistics")
        print("=" * 80)
        print(f"Resources processed:   {self.stats['resources_processed']}")
        print(f"Operations created:    {self.stats['operations_created']}")
        print(f"Fields extracted:      {self.stats['fields_extracted']}")
        print("=" * 80)


def main():
    print("=" * 80)
    print("Kubernetes Python SDK Field Introspector")
    print("=" * 80)
    print()
    
    introspector = K8sSDKIntrospector()
    catalog = introspector.generate_catalog()
    
    output_file = 'k8s_api_catalog_from_sdk.json'
    introspector.save_catalog(output_file)
    
    introspector.print_stats()
    
    print()
    print("=" * 80)
    print(f"✅ K8s SDK catalog created: {output_file}")
    print("=" * 80)
    print()
    print("This catalog contains actual SDK fields that match your YAML rules!")
    print("=" * 80)


if __name__ == '__main__':
    main()

