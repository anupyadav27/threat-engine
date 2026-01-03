"""
Dependency resolution for operations
"""

from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
try:
    from ..models.discovery_chain import DiscoveryChain, DiscoveryCall
except ImportError:
    from models.discovery_chain import DiscoveryChain, DiscoveryCall

class DependencyResolver:
    """Resolves operation dependencies and builds discovery chains"""
    
    def __init__(self, service_name: str, service_data: Dict):
        self.service_name = service_name
        self.boto3_deps = service_data["boto3_deps"]
        self.dependency_index = service_data["dependency_index"]
        
        # Get service data from boto3_deps
        service_key = service_name
        if service_key not in self.boto3_deps:
            # Try alternative keys
            for key in self.boto3_deps.keys():
                if key.lower() == service_name.lower():
                    service_key = key
                    break
        
        self.service_data = self.boto3_deps.get(service_key, {})
        self.dependency_graph = self._build_dependency_graph()
    
    def _build_dependency_graph(self) -> Dict:
        """Build dependency graph from boto3 data"""
        graph = {}
        
        # Map independent operations
        independent = {
            op["operation"]: op 
            for op in self.service_data.get("independent", [])
        }
        
        # Map dependent operations
        dependent = {
            op["operation"]: op 
            for op in self.service_data.get("dependent", [])
        }
        
        # Build graph
        for op_name, op_data in {**independent, **dependent}.items():
            item_fields = op_data.get("item_fields", {})
            # Handle both dict and list formats
            if isinstance(item_fields, dict):
                item_fields_list = list(item_fields.keys())
            elif isinstance(item_fields, list):
                item_fields_list = item_fields
            else:
                item_fields_list = []
            
            graph[op_name] = {
                "is_independent": op_name in independent,
                "required_params": op_data.get("required_params", []),
                "optional_params": op_data.get("optional_params", []),
                "python_method": op_data.get("python_method"),
                "yaml_action": op_data.get("yaml_action"),
                "main_output_field": op_data.get("main_output_field"),
                "item_fields": item_fields_list
            }
        
        return graph
    
    def resolve_chain(self, operation_name: str, visited: Set[str] = None) -> List[str]:
        """
        Resolve dependency chain for an operation
        
        Returns list of operations in dependency order (root first)
        """
        if visited is None:
            visited = set()
        
        if operation_name in visited:
            return []  # Circular dependency
        
        if operation_name not in self.dependency_graph:
            return []
        
        visited.add(operation_name)
        op_data = self.dependency_graph[operation_name]
        
        # If independent, this is the root
        if op_data["is_independent"]:
            return [operation_name]
        
        # If dependent, trace required params
        required_params = op_data["required_params"]
        if not required_params:
            return [operation_name]
        
        # Find operations that produce required params
        provider_chains = []
        for param in required_params:
            providers = self._find_operations_producing_param(param)
            for provider_op in providers:
                if provider_op != operation_name:
                    provider_chain = self.resolve_chain(provider_op, visited.copy())
                    if provider_chain:
                        provider_chains.append(provider_chain)
        
        # Return first valid chain
        if provider_chains:
            return provider_chains[0] + [operation_name]
        
        return [operation_name]
    
    def _find_operations_producing_param(self, param_name: str) -> List[str]:
        """Find operations that produce a given parameter"""
        param_entity = f"{self.service_name}.{param_name.lower().replace('_', '_')}"
        
        producing_ops = []
        entity_paths = self.dependency_index.get("entity_paths", {})
        
        for entity_path, paths in entity_paths.items():
            for path_data in paths:
                produces = path_data.get("produces", {})
                for op_name, produced_vars in produces.items():
                    if isinstance(produced_vars, list):
                        if param_entity in produced_vars:
                            producing_ops.append(op_name)
        
        return list(set(producing_ops))
    
    def build_discovery_chain(self, operation_chain: List[str]) -> Optional[DiscoveryChain]:
        """Build DiscoveryChain from operation chain"""
        if not operation_chain:
            return None
        
        root_op = operation_chain[0]
        root_data = self.dependency_graph[root_op]
        
        discovery_id = f"aws.{self.service_name}.{root_data['python_method']}"
        
        chain = DiscoveryChain(
            discovery_id=discovery_id,
            action=root_data['python_method'],
            main_output_field=root_data['main_output_field'],
            item_fields=root_data['item_fields']
        )
        
        # Handle dependent operations
        if len(operation_chain) > 1:
            dependent_op = operation_chain[-1]
            dependent_data = self.dependency_graph[dependent_op]
            
            # Find which field from root provides the required param
            required_param = dependent_data['required_params'][0] if dependent_data['required_params'] else None
            
            if required_param:
                param_to_field = self._map_param_to_field(
                    required_param, 
                    root_data['item_fields']
                )
                
                if param_to_field:
                    chain.for_each = discovery_id
                    chain.calls = [
                        DiscoveryCall(
                            action=dependent_data['python_method'],
                            params={required_param: f"{{{{ item.{param_to_field} }}}}"}
                        )
                    ]
                    chain.main_output_field = dependent_data['main_output_field']
                    chain.item_fields = dependent_data['item_fields']
        
        return chain
    
    def _map_param_to_field(self, param_name: str, available_fields: List[str]) -> Optional[str]:
        """Map parameter name to available field name"""
        param_lower = param_name.lower()
        
        # Direct match
        if param_name in available_fields:
            return param_name
        
        # Common patterns
        if param_lower.endswith('arn') and 'arn' in available_fields:
            return 'arn'
        if param_lower.endswith('name') and 'name' in available_fields:
            return 'name'
        if param_lower.endswith('id') and 'id' in available_fields:
            return 'id'
        
        # Partial matches
        for field in available_fields:
            field_lower = field.lower()
            if param_lower in field_lower or field_lower in param_lower:
                return field
        
        return None
    
    def get_independent_operations(self) -> List[str]:
        """Get all independent operations"""
        return [
            op_name for op_name, op_data in self.dependency_graph.items()
            if op_data["is_independent"]
        ]

