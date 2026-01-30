"""
YAML file generator
"""

import yaml
from typing import Dict, List, Optional
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
    """Generates YAML files from field selections with provider awareness and merging"""
    
    def __init__(self, service_name: str, provider: str, service_data: Dict, config=None):
        """
        Initialize YAML generator
        
        Args:
            service_name: Service name (e.g., 'iam')
            provider: Provider name (e.g., 'aws', 'azure')
            service_data: Service data dictionary
            config: Config instance for provider adapter access
        """
        self.service_name = service_name
        self.provider = provider
        self.service_data = service_data
        self.config = config
        self.dependency_resolver = DependencyResolver(service_name, provider, service_data, config)
        self.field_mapper = FieldMapper(service_data)
        self.provider_adapter = config.get_provider_adapter(provider) if config else None
    
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
        
        # Load existing YAML if it exists (for merging)
        existing_yaml_data = self._load_existing_yaml(output_path) if output_path else None
        
        # Build YAML structure (merge with existing or create new)
        if existing_yaml_data:
            yaml_data = self._merge_with_existing(existing_yaml_data, field_selections, discovery_chains, logical_operator, rule_id)
        else:
            yaml_data = self._build_new_yaml(field_selections, discovery_chains, logical_operator, rule_id)
        
        # Convert to YAML string
        yaml_str = yaml.dump(yaml_data, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        # Save if output path provided
        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(yaml_str)
        
        return yaml_str
    
    def _load_existing_yaml(self, output_path: Path) -> Optional[Dict]:
        """Load existing YAML file if it exists"""
        if not output_path or not output_path.exists():
            return None
        
        try:
            with open(output_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception:
            return None
    
    def _merge_with_existing(self, existing_data: Dict, field_selections: List[FieldSelection], 
                            discovery_chains: List[DiscoveryChain], logical_operator: str, rule_id: str) -> Dict:
        """Merge new rules with existing YAML data"""
        # Start with existing structure
        yaml_data = existing_data.copy()
        
        # Ensure discovery and checks lists exist
        if "discovery" not in yaml_data:
            yaml_data["discovery"] = []
        if "checks" not in yaml_data:
            yaml_data["checks"] = []
        
        # Get existing discovery IDs to avoid duplicates
        existing_discovery_ids = {d.get("discovery_id") for d in yaml_data.get("discovery", []) if d.get("discovery_id")}
        
        # Get existing rule IDs to avoid duplicates
        existing_rule_ids = {check.get("rule_id") for check in yaml_data.get("checks", []) if check.get("rule_id")}
        
        # Merge discovery entries (avoid duplicates by discovery_id)
        for chain in discovery_chains:
            if chain.discovery_id not in existing_discovery_ids:
                yaml_data["discovery"].append(chain.to_yaml_dict())
                existing_discovery_ids.add(chain.discovery_id)
        
        # Build checks section
        # Group selections by rule_id if multiple rules
        rules_dict = {}
        for selection in field_selections:
            rule_id_key = rule_id or selection.rule_id
            if rule_id_key not in rules_dict:
                rules_dict[rule_id_key] = []
            rules_dict[rule_id_key].append(selection)
        
        # Generate check for each rule (skip if rule_id already exists)
        for rule_id_key, selections in rules_dict.items():
            # Skip if rule_id already exists
            if rule_id_key in existing_rule_ids:
                continue
            
            # Find discovery that covers all fields
            discovery_id = self._find_common_discovery_for_fields(
                [s.field_name for s in selections],
                discovery_chains
            )
            
            # Build conditions (use discovery item fields to canonicalize var paths)
            chain = next((c for c in discovery_chains if c.discovery_id == discovery_id), None)
            item_fields = chain.item_fields if chain else []

            if len(selections) == 1 or logical_operator == "single":
                # Single condition
                conditions = self._build_condition(selections[0], item_fields=item_fields)
            else:
                # Multiple conditions with all/any
                conditions_list = [self._build_condition(s, item_fields=item_fields) for s in selections]
                conditions = {logical_operator: conditions_list}
            
            check_entry = {
                "rule_id": rule_id_key,
                "for_each": discovery_id,
                "conditions": conditions
            }
            
            yaml_data["checks"].append(check_entry)
        
        return yaml_data
    
    def _build_new_yaml(self, field_selections: List[FieldSelection], discovery_chains: List[DiscoveryChain],
                       logical_operator: str, rule_id: str) -> Dict:
        """Build new YAML structure"""
        # Get provider-specific module pattern
        if self.provider_adapter:
            sdk_module = self.provider_adapter.get_sdk_module_pattern()
            provider_name = self.provider
        else:
            # Fallback for backward compatibility
            sdk_module = "boto3.client"
            provider_name = self.provider or "aws"
        
        yaml_data = {
            "version": "1.0",
            "provider": provider_name,
            "service": self.service_name,
            "services": {
                "client": self.service_name,
                "module": sdk_module
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
            
            # Build conditions (use discovery item fields to canonicalize var paths)
            chain = next((c for c in discovery_chains if c.discovery_id == discovery_id), None)
            item_fields = chain.item_fields if chain else []

            if len(selections) == 1 or logical_operator == "single":
                # Single condition
                conditions = self._build_condition(selections[0], item_fields=item_fields)
            else:
                # Multiple conditions with all/any
                conditions_list = [self._build_condition(s, item_fields=item_fields) for s in selections]
                conditions = {logical_operator: conditions_list}
            
            check_entry = {
                "rule_id": rule_id_key,
                "for_each": discovery_id,
                "conditions": conditions
            }
            
            yaml_data["checks"].append(check_entry)
        
        return yaml_data
    
    def _find_common_discovery_for_fields(
        self,
        field_names: List[str],
        discovery_chains: List[DiscoveryChain]
    ) -> str:
        """Find best discovery for required fields (case-insensitive, prefers maximum coverage)."""
        if not discovery_chains or not field_names:
            return discovery_chains[0].discovery_id if discovery_chains else ""

        required = {f.lower() for f in field_names if isinstance(f, str)}

        best_chain = None
        best_coverage = -1
        best_is_full = False

        for chain in discovery_chains:
            provided = {f.lower() for f in (chain.item_fields or []) if isinstance(f, str)}
            coverage = len(required.intersection(provided))
            is_full = coverage == len(required)

            # Prefer full coverage; otherwise maximize coverage
            if is_full and not best_is_full:
                best_chain = chain
                best_coverage = coverage
                best_is_full = True
            elif is_full and best_is_full and coverage > best_coverage:
                best_chain = chain
                best_coverage = coverage
            elif not best_is_full and coverage > best_coverage:
                best_chain = chain
                best_coverage = coverage

        return best_chain.discovery_id if best_chain else discovery_chains[0].discovery_id
    
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
    
    def _build_condition(self, selection: FieldSelection, item_fields: Optional[List[str]] = None) -> Dict:
        """Build condition structure"""
        # Canonicalize field name to match the *selected discovery* item keys (case-insensitive)
        field_name = selection.field_name
        try:
            if item_fields:
                by_lower = {f.lower(): f for f in item_fields if isinstance(f, str)}
                if isinstance(field_name, str):
                    field_name = by_lower.get(field_name.lower(), field_name)
        except Exception:
            pass

        var_path = f"item.{field_name}"
        
        if selection.operator in ("exists", "not_exists") and selection.value is None:
            return {
                "var": var_path,
                "op": selection.operator,
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

