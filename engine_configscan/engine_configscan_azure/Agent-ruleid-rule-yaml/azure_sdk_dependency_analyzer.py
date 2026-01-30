"""
Azure SDK Dependency Analyzer

Utility to search and analyze Azure SDK operations from the dependencies catalog.
Similar to boto3_dependency_analyzer.py but for Azure.
"""

import json
from typing import Dict, List, Optional, Any
from difflib import get_close_matches


class AzureSDKAnalyzer:
    """Analyzes Azure SDK dependencies to find operations and fields."""
    
    def __init__(self, dependencies_file: str = 'azure_sdk_dependencies_enhanced.json'):
        """
        Initialize analyzer with Azure SDK dependencies.
        
        Args:
            dependencies_file: Path to Azure SDK dependencies JSON (enhanced version)
        """
        with open(dependencies_file, 'r') as f:
            self.data = json.load(f)
        
        # Build searchable indexes
        self._build_indexes()
    
    def _build_indexes(self):
        """Build search indexes for fast lookups."""
        self.all_operations = {}  # service.operation -> operation_data
        self.service_operations = {}  # service -> list of operations
        
        for service, service_data in self.data.items():
            self.service_operations[service] = []
            
            for op in service_data['independent'] + service_data['dependent']:
                key = f"{service}.{op['operation']}"
                self.all_operations[key] = {
                    **op,
                    'service': service,
                    'is_independent': op in service_data['independent']
                }
                self.service_operations[service].append(op['operation'])
    
    def find_operation(self, service: str, operation_name: str) -> Optional[Dict[str, Any]]:
        """
        Find an operation by service and name.
        
        Args:
            service: Azure service name (e.g., 'compute', 'storage')
            operation_name: Operation name (e.g., 'list', 'list_virtual_machines')
        
        Returns:
            Operation data or None
        """
        key = f"{service}.{operation_name}"
        return self.all_operations.get(key)
    
    def find_operation_fuzzy(self, service: str, operation_name: str, threshold: float = 0.6) -> Optional[Dict[str, Any]]:
        """
        Find operation with fuzzy matching.
        
        Args:
            service: Azure service name
            operation_name: Partial or misspelled operation name
            threshold: Similarity threshold (0.0-1.0)
        
        Returns:
            Best matching operation or None
        """
        if service not in self.service_operations:
            return None
        
        operations = self.service_operations[service]
        matches = get_close_matches(operation_name, operations, n=1, cutoff=threshold)
        
        if matches:
            return self.find_operation(service, matches[0])
        
        return None
    
    def find_list_operations(self, service: str) -> List[Dict[str, Any]]:
        """
        Find all list operations for a service.
        
        Args:
            service: Azure service name
        
        Returns:
            List of independent (list) operations
        """
        if service not in self.data:
            return []
        
        return self.data[service]['independent']
    
    def get_operation_fields(self, service: str, operation_name: str) -> Dict[str, Any]:
        """
        Get all fields available from an operation.
        
        Args:
            service: Azure service name
            operation_name: Operation name
        
        Returns:
            Dict with output_fields, main_output_field, and item_fields
        """
        op = self.find_operation(service, operation_name)
        if not op:
            return {
                'output_fields': [],
                'main_output_field': None,
                'item_fields': []
            }
        
        # Handle both old (list) and enhanced (dict) catalog formats
        item_fields = op.get('item_fields', [])
        if isinstance(item_fields, dict):
            # Enhanced catalog - convert dict to list of field names
            item_fields = list(item_fields.keys())
        
        return {
            'output_fields': op.get('output_fields', []),
            'main_output_field': op.get('main_output_field'),
            'item_fields': item_fields  # Now always a list
        }
    
    def validate_field(self, service: str, operation_name: str, field_name: str) -> Dict[str, Any]:
        """
        Validate if a field exists in operation output.
        Handles nested fields like 'properties.field_name'
        
        Args:
            service: Azure service name
            operation_name: Operation name
            field_name: Field name to validate (can be nested with dots)
        
        Returns:
            Validation result with exists, correct_name, validation status
        """
        fields = self.get_operation_fields(service, operation_name)
        all_fields = fields['item_fields'] + fields['output_fields']
        
        # Exact match
        if field_name in all_fields:
            return {
                'exists': True,
                'correct_name': field_name,
                'validation': 'exact_match',
                'in_item_fields': field_name in fields['item_fields'],
                'in_output_fields': field_name in fields['output_fields']
            }
        
        # Check for nested fields (e.g., 'properties.field_name')
        if '.' in field_name:
            parts = field_name.split('.')
            base_field = parts[0]
            
            # Check if base field exists
            if base_field in all_fields:
                return {
                    'exists': True,
                    'correct_name': field_name,
                    'validation': 'nested_field_base_exists',
                    'base_field': base_field,
                    'note': f'Base field "{base_field}" exists, nested path assumed valid'
                }
            elif base_field in all_fields:
                return {
                    'exists': True,
                    'correct_name': field_name,
                    'validation': 'nested_field',
                    'note': 'Nested field validation - base exists'
                }
        
        # Case-insensitive match
        for field in all_fields:
            if field.lower() == field_name.lower():
                return {
                    'exists': True,
                    'correct_name': field,
                    'validation': 'case_mismatch',
                    'original': field_name,
                    'in_item_fields': field in fields['item_fields'],
                    'in_output_fields': field in fields['output_fields']
                }
        
        # Fuzzy match
        matches = get_close_matches(field_name, all_fields, n=1, cutoff=0.8)
        if matches:
            return {
                'exists': True,
                'correct_name': matches[0],
                'validation': 'fuzzy_match',
                'original': field_name,
                'similarity': 'high',
                'in_item_fields': matches[0] in fields['item_fields'],
                'in_output_fields': matches[0] in fields['output_fields']
            }
        
        return {
            'exists': False,
            'correct_name': None,
            'validation': 'not_found',
            'suggestion': 'Field may be computed or from nested object'
        }
    
    def get_service_info(self, service: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a service.
        
        Args:
            service: Azure service name
        
        Returns:
            Service information or None
        """
        return self.data.get(service)
    
    def search_operations_by_keyword(self, keyword: str, service: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Search operations containing a keyword.
        
        Args:
            keyword: Keyword to search for
            service: Optional service to limit search
        
        Returns:
            List of matching operations
        """
        results = []
        keyword_lower = keyword.lower()
        
        search_space = {}
        if service and service in self.data:
            search_space[service] = self.data[service]
        else:
            search_space = self.data
        
        for svc, svc_data in search_space.items():
            for op in svc_data['independent'] + svc_data['dependent']:
                if keyword_lower in op['operation'].lower():
                    results.append({
                        **op,
                        'service': svc,
                        'is_independent': op in svc_data['independent']
                    })
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about Azure SDK coverage."""
        stats = {
            'total_services': len(self.data),
            'total_operations': len(self.all_operations),
            'services': {}
        }
        
        for service, service_data in self.data.items():
            stats['services'][service] = {
                'total_operations': service_data['total_operations'],
                'independent': len(service_data['independent']),
                'dependent': len(service_data['dependent']),
                'categories': len(service_data.get('operations_by_category', {}))
            }
        
        return stats


# Convenience functions
def load_analyzer() -> AzureSDKAnalyzer:
    """Load the Azure SDK analyzer."""
    return AzureSDKAnalyzer()


if __name__ == '__main__':
    # Test the analyzer
    analyzer = load_analyzer()
    
    print("=" * 80)
    print("Azure SDK Dependency Analyzer - Test")
    print("=" * 80)
    print()
    
    # Test 1: Find compute list operation
    print("Test 1: Find compute list_virtual_machines")
    print("-" * 80)
    op = analyzer.find_operation('compute', 'list')
    if op:
        print(f"✅ Found: {op['operation']}")
        print(f"  - Python method: {op['python_method']}")
        print(f"  - Independent: {op['is_independent']}")
        print(f"  - Output fields: {op.get('output_fields', [])[:5]}...")
        print(f"  - Item fields: {op.get('item_fields', [])[:5]}...")
    print()
    
    # Test 2: Validate field
    print("Test 2: Validate 'name' field in compute.list")
    print("-" * 80)
    validation = analyzer.validate_field('compute', 'list', 'name')
    print(f"  - Exists: {validation['exists']}")
    print(f"  - Validation: {validation['validation']}")
    print(f"  - In item fields: {validation.get('in_item_fields', False)}")
    print()
    
    # Test 3: List operations
    print("Test 3: List operations for storage")
    print("-" * 80)
    storage_ops = analyzer.find_list_operations('storage')
    print(f"✅ Found {len(storage_ops)} list operations:")
    for op in storage_ops[:3]:
        print(f"  - {op['operation']}")
    print()
    
    # Test 4: Statistics
    print("Test 4: Statistics")
    print("-" * 80)
    stats = analyzer.get_statistics()
    print(f"Total Services: {stats['total_services']}")
    print(f"Total Operations: {stats['total_operations']}")
    print()
    print("Top 5 services:")
    sorted_services = sorted(stats['services'].items(), 
                            key=lambda x: x[1]['total_operations'], 
                            reverse=True)[:5]
    for svc, svc_stats in sorted_services:
        print(f"  - {svc}: {svc_stats['total_operations']} operations")
    print()
    
    print("=" * 80)

