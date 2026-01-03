"""
Field to operation mapping
"""

from typing import Dict, List, Set
from collections import defaultdict

class FieldMapper:
    """Maps fields to operations that produce them"""
    
    def __init__(self, service_data: Dict):
        self.direct_vars = service_data["direct_vars"]
        self.dependency_index = service_data["dependency_index"]
        self.boto3_deps = service_data["boto3_deps"]
        
        # Build field to operations map
        self.field_to_operations: Dict[str, List[str]] = self._build_field_map()
        self.operation_to_fields: Dict[str, Set[str]] = self._build_operation_map()
    
    def _build_field_map(self) -> Dict[str, List[str]]:
        """Build map from field names to operations"""
        field_map = defaultdict(list)
        
        fields = self.direct_vars.get("fields", {})
        for field_name, field_data in fields.items():
            operations = field_data.get("operations", [])
            for op in operations:
                field_map[field_name].append(op)
        
        return dict(field_map)
    
    def _build_operation_map(self) -> Dict[str, Set[str]]:
        """Build map from operations to fields they produce"""
        op_map = defaultdict(set)
        
        fields = self.direct_vars.get("fields", {})
        for field_name, field_data in fields.items():
            operations = field_data.get("operations", [])
            for op in operations:
                op_map[op].add(field_name)
        
        return dict(op_map)
    
    def get_operations_for_field(self, field_name: str) -> List[str]:
        """Get all operations that produce a field"""
        return self.field_to_operations.get(field_name, [])
    
    def get_fields_for_operation(self, operation_name: str) -> Set[str]:
        """Get all fields produced by an operation"""
        return self.operation_to_fields.get(operation_name, set())
    
    def get_available_fields(self) -> List[str]:
        """Get list of all available fields"""
        return list(self.direct_vars.get("fields", {}).keys())
    
    def get_field_info(self, field_name: str) -> Dict:
        """Get detailed information about a field"""
        fields = self.direct_vars.get("fields", {})
        return fields.get(field_name, {})

