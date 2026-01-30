"""
Azure SDK Catalog Enhancer

Enhances azure_sdk_dependencies_with_python_names.json with:
1. Item fields metadata (types, operators, compliance categories)
2. Optional parameters metadata (types, descriptions, examples)
"""

import json
import re
from typing import Dict, List, Any


class AzureSDKEnhancer:
    """Enhance Azure SDK catalog with metadata"""
    
    # Field type detection patterns
    BOOLEAN_PATTERNS = [
        'enabled', 'disabled', 'deleted', 'required', 'allowed', 'is_',
        'has_', 'can_', 'supports_', 'allow_', 'enable_', 'disable_'
    ]
    
    INTEGER_PATTERNS = [
        'count', 'size', 'mb', 'gb', 'tb', 'number', 'port', 'days',
        'hours', 'minutes', 'seconds', 'timeout', 'limit', 'max_',
        'min_', 'capacity', 'cores', 'memory', 'disk', 'quota'
    ]
    
    ENUM_PATTERNS = [
        'status', 'state', 'access', 'tier', 'sku', 'level', 'type',
        'kind', 'mode', 'action', 'direction', 'protocol'
    ]
    
    # Compliance category detection
    SECURITY_KEYWORDS = [
        'public', 'private', 'encryption', 'firewall', 'network', 'auth',
        'security', 'access', 'identity', 'credential', 'key', 'secret',
        'certificate', 'ssl', 'tls', 'https'
    ]
    
    DATA_PROTECTION_KEYWORDS = [
        'backup', 'restore', 'retention', 'delete', 'soft_delete',
        'purge', 'recovery', 'snapshot', 'replication', 'redundancy'
    ]
    
    NETWORK_KEYWORDS = [
        'network', 'vnet', 'subnet', 'endpoint', 'firewall', 'route',
        'dns', 'ip', 'address', 'gateway', 'load_balancer'
    ]
    
    IDENTITY_KEYWORDS = [
        'identity', 'principal', 'role', 'permission', 'rbac',
        'managed_identity', 'service_principal'
    ]
    
    # Operator mappings by type
    OPERATORS_BY_TYPE = {
        'string': ['equals', 'not_equals', 'contains', 'in', 'not_empty', 'exists'],
        'boolean': ['equals', 'not_equals'],
        'integer': ['equals', 'not_equals', 'gt', 'lt', 'gte', 'lte'],
        'object': ['exists', 'not_empty'],
        'array': ['contains', 'not_empty', 'exists']
    }
    
    # Common optional parameters
    COMMON_PARAMS_METADATA = {
        'filter': {
            'type': 'string',
            'description': 'OData filter expression',
            'example': "location eq 'eastus'"
        },
        'top': {
            'type': 'integer',
            'description': 'Maximum number of results to return',
            'range': [1, 1000],
            'default': 100,
            'recommended': 50
        },
        'skip': {
            'type': 'integer',
            'description': 'Number of results to skip',
            'default': 0
        },
        'orderby': {
            'type': 'string',
            'description': 'OData orderby expression',
            'example': 'name asc'
        },
        'expand': {
            'type': 'string',
            'description': 'Expand related resources',
            'common_values': ['instanceView', 'zones', 'properties']
        },
        'select': {
            'type': 'string',
            'description': 'Select specific properties to return',
            'example': 'name,location,properties/provisioningState'
        },
        'maxpagesize': {
            'type': 'integer',
            'description': 'Maximum page size',
            'range': [1, 1000],
            'default': 100
        },
        'include': {
            'type': 'string',
            'description': 'Include additional information'
        }
    }
    
    def __init__(self):
        self.stats = {
            'services_processed': 0,
            'operations_enhanced': 0,
            'fields_enhanced': 0,
            'params_enhanced': 0
        }
    
    def detect_field_type(self, field_name: str) -> str:
        """Detect field type from field name"""
        field_lower = field_name.lower()
        
        # Boolean detection
        for pattern in self.BOOLEAN_PATTERNS:
            if pattern in field_lower:
                return 'boolean'
        
        # Integer detection
        for pattern in self.INTEGER_PATTERNS:
            if pattern in field_lower:
                return 'integer'
        
        # Common field names
        if field_name in ['id', 'name', 'type', 'location', 'etag', 'version']:
            return 'string'
        
        if field_name in ['tags', 'metadata', 'properties']:
            return 'object'
        
        if field_name.endswith('s') and field_name not in ['status', 'address']:
            return 'array'
        
        # Enum detection (default to string with enum flag)
        for pattern in self.ENUM_PATTERNS:
            if pattern in field_lower:
                return 'string_enum'
        
        return 'string'
    
    def detect_compliance_category(self, field_name: str) -> str:
        """Detect compliance category from field name"""
        field_lower = field_name.lower()
        
        # Security
        if any(kw in field_lower for kw in self.SECURITY_KEYWORDS):
            return 'security'
        
        # Data protection
        if any(kw in field_lower for kw in self.DATA_PROTECTION_KEYWORDS):
            return 'data_protection'
        
        # Network
        if any(kw in field_lower for kw in self.NETWORK_KEYWORDS):
            return 'network'
        
        # Identity
        if any(kw in field_lower for kw in self.IDENTITY_KEYWORDS):
            return 'identity'
        
        # Common fields
        if field_name in ['id', 'name', 'type']:
            return 'identity'
        
        if field_name in ['location', 'zones', 'region']:
            return 'availability'
        
        if field_name in ['tags', 'metadata']:
            return 'general'
        
        return 'general'
    
    def detect_security_impact(self, field_name: str, field_type: str) -> str:
        """Detect security impact level"""
        field_lower = field_name.lower()
        
        high_impact_keywords = [
            'public', 'encryption', 'firewall', 'access', 'auth',
            'credential', 'key', 'secret', 'password'
        ]
        
        medium_impact_keywords = [
            'network', 'identity', 'role', 'permission', 'logging',
            'monitoring', 'audit'
        ]
        
        if any(kw in field_lower for kw in high_impact_keywords):
            return 'high'
        
        if any(kw in field_lower for kw in medium_impact_keywords):
            return 'medium'
        
        return 'low'
    
    def enhance_field(self, field_name: str) -> Dict[str, Any]:
        """Enhance a single field with metadata"""
        field_type = self.detect_field_type(field_name)
        compliance_category = self.detect_compliance_category(field_name)
        
        metadata = {
            'type': field_type.replace('_enum', ''),
            'compliance_category': compliance_category
        }
        
        # Add operators based on type
        base_type = field_type.replace('_enum', '')
        metadata['operators'] = self.OPERATORS_BY_TYPE.get(base_type, self.OPERATORS_BY_TYPE['string'])
        
        # Add enum flag and possible values placeholder for enums
        if field_type == 'string_enum':
            metadata['enum'] = True
            metadata['possible_values'] = []  # To be filled with actual values
        
        # Add boolean possible values
        if field_type == 'boolean':
            metadata['possible_values'] = [True, False]
        
        # Add security impact for security-related fields
        if compliance_category == 'security':
            metadata['security_impact'] = self.detect_security_impact(field_name, field_type)
        
        # Add description placeholder
        metadata['description'] = f"{field_name.replace('_', ' ').title()}"
        
        return metadata
    
    def enhance_optional_params(self, params: List[str]) -> Dict[str, Dict[str, Any]]:
        """Enhance optional parameters with metadata"""
        enhanced = {}
        
        for param in params:
            if param in self.COMMON_PARAMS_METADATA:
                enhanced[param] = self.COMMON_PARAMS_METADATA[param].copy()
                self.stats['params_enhanced'] += 1
            else:
                # Generic enhancement for unknown params
                enhanced[param] = {
                    'type': 'string',
                    'description': f"{param.replace('_', ' ').title()}"
                }
                self.stats['params_enhanced'] += 1
        
        return enhanced
    
    def enhance_item_fields(self, fields: List[str]) -> Dict[str, Dict[str, Any]]:
        """Enhance item fields from array to object with metadata"""
        if not fields:
            return {}
        
        enhanced = {}
        for field in fields:
            enhanced[field] = self.enhance_field(field)
            self.stats['fields_enhanced'] += 1
        
        return enhanced
    
    def enhance_operation(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance a single operation"""
        enhanced_op = operation.copy()
        
        # Enhance optional_params
        if 'optional_params' in operation and isinstance(operation['optional_params'], list):
            enhanced_op['optional_params'] = self.enhance_optional_params(operation['optional_params'])
        
        # Enhance item_fields
        if 'item_fields' in operation and isinstance(operation['item_fields'], list):
            enhanced_op['item_fields'] = self.enhance_item_fields(operation['item_fields'])
        
        # Enhance output_fields (keep as array but could be enhanced too)
        # For now, keeping output_fields as is since they're top-level response fields
        
        self.stats['operations_enhanced'] += 1
        return enhanced_op
    
    def enhance_category(self, category: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance a category (independent/dependent operations)"""
        enhanced_category = category.copy()
        
        # Enhance independent operations
        if 'independent' in category:
            enhanced_category['independent'] = [
                self.enhance_operation(op) for op in category['independent']
            ]
        
        # Enhance dependent operations
        if 'dependent' in category:
            enhanced_category['dependent'] = [
                self.enhance_operation(op) for op in category['dependent']
            ]
        
        return enhanced_category
    
    def enhance_service(self, service_data: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance a single service"""
        enhanced_service = service_data.copy()
        
        # Enhance operations_by_category
        if 'operations_by_category' in service_data:
            enhanced_categories = {}
            for category_name, category_data in service_data['operations_by_category'].items():
                enhanced_categories[category_name] = self.enhance_category(category_data)
            
            enhanced_service['operations_by_category'] = enhanced_categories
        
        self.stats['services_processed'] += 1
        return enhanced_service
    
    def enhance_catalog(self, catalog: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance the entire catalog"""
        enhanced_catalog = {}
        
        for service_name, service_data in catalog.items():
            print(f"Enhancing {service_name}...")
            enhanced_catalog[service_name] = self.enhance_service(service_data)
        
        return enhanced_catalog


def main():
    print("=" * 80)
    print("Azure SDK Catalog Enhancer")
    print("=" * 80)
    print()
    
    # Load original catalog
    print("Loading azure_sdk_dependencies_with_python_names.json...")
    with open('azure_sdk_dependencies_with_python_names.json', 'r') as f:
        catalog = json.load(f)
    
    print(f"✅ Loaded {len(catalog)} services")
    print()
    
    # Enhance catalog
    print("Enhancing catalog...")
    print()
    enhancer = AzureSDKEnhancer()
    enhanced_catalog = enhancer.enhance_catalog(catalog)
    
    # Save enhanced catalog
    output_file = 'azure_sdk_dependencies_enhanced.json'
    print()
    print(f"Saving enhanced catalog to {output_file}...")
    with open(output_file, 'w') as f:
        json.dump(enhanced_catalog, f, indent=2)
    
    print(f"✅ Saved")
    print()
    
    # Print statistics
    print("=" * 80)
    print("Enhancement Statistics")
    print("=" * 80)
    print(f"Services processed:    {enhancer.stats['services_processed']}")
    print(f"Operations enhanced:   {enhancer.stats['operations_enhanced']}")
    print(f"Fields enhanced:       {enhancer.stats['fields_enhanced']}")
    print(f"Parameters enhanced:   {enhancer.stats['params_enhanced']}")
    print()
    print(f"✅ Enhanced catalog saved to: {output_file}")
    print("=" * 80)


if __name__ == '__main__':
    main()

