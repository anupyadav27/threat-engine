"""
YAML file generator
"""

import yaml
from typing import Dict, List
from pathlib import Path
try:
    from ..models.field_selection import FieldSelection
    from ..models.discovery_chain import DiscoveryChain, DiscoveryCall
except ImportError:
    from models.field_selection import FieldSelection
    from models.discovery_chain import DiscoveryChain, DiscoveryCall
from .dependency_resolver import DependencyResolver
from .field_mapper import FieldMapper

class YAMLGenerator:
    """Generates YAML files from field selections"""
    
    def __init__(self, service_name: str, service_data: Dict):
        self.service_name = service_name
        self.dependency_resolver = DependencyResolver(service_name, service_data)
        self.field_mapper = FieldMapper(service_data)
    
    def generate(self, field_selections: List[FieldSelection], output_path: Path = None, logical_operator: str = "single", rule_id: str = None) -> str:
        """
        Generate YAML file from field selections
        
        Args:
            field_selections: List of field selections
            output_path: Optional path to save YAML file
            logical_operator: "single", "all", or "any" for multiple conditions
            rule_id: Optional rule_id (if not provided, uses first selection's rule_id)
        
        Returns:
            YAML string
        """
        # Resolve all dependencies
        discovery_chains = self._resolve_all_dependencies(field_selections)
        
        # Build YAML structure
        yaml_data = {
            "version": "1.0",
            "provider": "aws",
            "service": self.service_name,
            "services": {
                "client": self.service_name,
                "module": "boto3.client"
            },
            "discovery": [],
            "checks": []
        }
        
        # Build discovery section
        for chain in discovery_chains:
            yaml_data["discovery"].append(chain.to_yaml_dict())
        
        # Build checks section
        # Group selections by rule_id if multiple rules
        rules_dict = {}
        for selection in field_selections:
            rule_id_key = rule_id or selection.rule_id
            if rule_id_key not in rules_dict:
                rules_dict[rule_id_key] = []
            rules_dict[rule_id_key].append(selection)
        
        # Generate check for each rule
        for rule_id_key, selections in rules_dict.items():
            # Find discovery that covers all fields
            discovery_id = self._find_common_discovery_for_fields(
                [s.field_name for s in selections],
                discovery_chains
            )
            
            # Build conditions
            if len(selections) == 1 or logical_operator == "single":
                # Single condition
                conditions = self._build_condition(selections[0])
            else:
                # Multiple conditions with all/any
                conditions_list = [self._build_condition(s) for s in selections]
                conditions = {logical_operator: conditions_list}
            
            check_entry = {
                "rule_id": rule_id_key,
                "for_each": discovery_id,
                "conditions": conditions
            }
            
            yaml_data["checks"].append(check_entry)
        
        # Convert to YAML string
        yaml_str = yaml.dump(yaml_data, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        # Save if output path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(yaml_str)
        
        return yaml_str
    
    def _find_common_discovery_for_fields(
        self,
        field_names: List[str],
        discovery_chains: List[DiscoveryChain]
    ) -> str:
        """Find discovery that provides all required fields"""
        # Try to find a discovery that has all fields
        for chain in discovery_chains:
            has_all_fields = all(
                field_name in chain.item_fields 
                for field_name in field_names
            )
            if has_all_fields:
                return chain.discovery_id
        
        # Fallback to first discovery that has the first field
        if discovery_chains:
            for chain in discovery_chains:
                if field_names[0] in chain.item_fields:
                    return chain.discovery_id
        
        # Final fallback
        return discovery_chains[0].discovery_id if discovery_chains else ""
    
    def _resolve_all_dependencies(self, field_selections: List[FieldSelection]) -> List[DiscoveryChain]:
        """Resolve all dependencies for selected fields"""
        required_operations = set()
        
        # Find operations for each field
        for selection in field_selections:
            operations = self.field_mapper.get_operations_for_field(selection.field_name)
            required_operations.update(operations)
        
        # Resolve chains
        discovery_chains = []
        processed_operations = set()
        
        for op_name in required_operations:
            if op_name in processed_operations:
                continue
            
            chain = self.dependency_resolver.resolve_chain(op_name)
            if chain:
                discovery_chain = self.dependency_resolver.build_discovery_chain(chain)
                if discovery_chain:
                    discovery_chains.append(discovery_chain)
                    processed_operations.update(chain)
        
        return discovery_chains
    
    def _find_discovery_for_field(self, field_name: str, discovery_chains: List[DiscoveryChain]) -> str:
        """Find which discovery provides the field"""
        for chain in discovery_chains:
            if field_name in chain.item_fields:
                return chain.discovery_id
        
        # Fallback to first discovery
        return discovery_chains[0].discovery_id if discovery_chains else ""
    
    def _build_condition(self, selection: FieldSelection) -> Dict:
        """Build condition structure"""
        var_path = f"item.{selection.field_name}"
        
        if selection.operator == "exists" and selection.value is None:
            return {
                "var": var_path,
                "op": "exists",
                "value": None
            }
        
        # Handle 'all' and 'any' conditions (for future multi-field support)
        if isinstance(selection.value, dict) and ("all" in selection.value or "any" in selection.value):
            return selection.value
        
        return {
            "var": var_path,
            "op": selection.operator,
            "value": selection.value
        }

