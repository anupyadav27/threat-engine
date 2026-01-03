"""
API Interface for YAML Rule Builder
Designed to be called from UI or other applications
"""

from pathlib import Path
from typing import Dict, List, Optional, Any
import json

# Handle both package and direct execution
try:
    from .config import Config
    from .core.data_loader import DataLoader
    from .core.yaml_generator import YAMLGenerator
    from .core.rule_comparator import RuleComparator
    from .core.metadata_generator import MetadataGenerator
    from .core.field_mapper import FieldMapper
    from .models.rule import Rule
    from .models.field_selection import FieldSelection
    from .utils.validators import Validator
except ImportError:
    from config import Config
    from core.data_loader import DataLoader
    from core.yaml_generator import YAMLGenerator
    from core.rule_comparator import RuleComparator
    from core.metadata_generator import MetadataGenerator
    from core.field_mapper import FieldMapper
    from models.rule import Rule
    from models.field_selection import FieldSelection
    from utils.validators import Validator

class RuleBuilderAPI:
    """
    API interface for building rules programmatically
    
    Designed for UI integration:
    - Accepts structured input (title, description, remediation, service, conditions)
    - Returns structured output (YAML path, metadata path, existing rules found)
    - Handles multiple conditions with all/any logic
    """
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self._service_cache: Dict[str, Dict] = {}
    
    def get_available_services(self) -> List[str]:
        """Get list of available AWS services"""
        try:
            from .commands.list_services import list_services
        except ImportError:
            from commands.list_services import list_services
        return list_services(self.config)
    
    def get_service_fields(self, service_name: str) -> Dict[str, Dict]:
        """Get all available fields for a service with their metadata"""
        if not self.config.validate_service(service_name):
            raise ValueError(f"Service '{service_name}' not found or invalid")
        
        loader = DataLoader(self.config)
        service_data = loader.load_service_data(service_name)
        
        mapper = FieldMapper(service_data)
        fields = mapper.get_available_fields()
        
        result = {}
        for field_name in fields:
            field_info = mapper.get_field_info(field_name)
            result[field_name] = {
                "operators": field_info.get("operators", []),
                "type": field_info.get("type", "string"),
                "enum": field_info.get("enum", False),
                "possible_values": field_info.get("possible_values"),
                "operations": field_info.get("operations", [])
            }
        
        return result
    
    def validate_rule(self, rule: Rule) -> Dict[str, Any]:
        """
        Validate a rule before generation
        
        Returns:
            {
                "valid": bool,
                "errors": List[str],
                "warnings": List[str],
                "existing_rules": List[Dict]  # Matching existing rules
            }
        """
        errors = []
        warnings = []
        existing_rules = []
        
        # Load service data
        loader = DataLoader(self.config)
        service_data = loader.load_service_data(rule.service)
        
        mapper = FieldMapper(service_data)
        validator = Validator()
        generator = YAMLGenerator(rule.service, service_data)
        comparator = RuleComparator(rule.service, self.config)
        
        # Validate each condition
        for condition in rule.conditions:
            field_info = mapper.get_field_info(condition.field_name)
            if not field_info:
                errors.append(f"Field '{condition.field_name}' not found in service '{rule.service}'")
                continue
            
            if not validator.validate_operator(field_info, condition.operator):
                errors.append(f"Operator '{condition.operator}' not valid for field '{condition.field_name}'")
            
            if not validator.validate_value(field_info, condition.operator, condition.value):
                warnings.append(f"Value '{condition.value}' may not be valid for field '{condition.field_name}'")
        
        # Check for existing rules
        discovery_chains = generator._resolve_all_dependencies(rule.conditions)
        
        # Find discovery_id that covers all fields
        discovery_id = self._find_common_discovery(rule.conditions, discovery_chains, generator)
        
        if discovery_id:
            # Check if rule already exists
            # For multiple conditions, check if all conditions match
            if len(rule.conditions) == 1:
                existing = comparator.find_matching_rule(
                    rule.conditions[0],
                    discovery_id
                )
                if existing:
                    existing_rules.append({
                        "rule_id": existing["rule_id"],
                        "source_file": existing["source_file"],
                        "for_each": existing["for_each"]
                    })
            else:
                # For multiple conditions, we'd need to check all conditions match
                # This is more complex - for now, just check first condition
                existing = comparator.find_matching_rule(
                    rule.conditions[0],
                    discovery_id
                )
                if existing:
                    existing_rules.append({
                        "rule_id": existing["rule_id"],
                        "source_file": existing["source_file"],
                        "for_each": existing["for_each"],
                        "note": "Partial match - check all conditions manually"
                    })
        
        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "existing_rules": existing_rules
        }
    
    def generate_rule(
        self,
        rule: Rule,
        output_path: Optional[Path] = None,
        create_metadata: bool = True
    ) -> Dict[str, Any]:
        """
        Generate YAML and metadata for a rule
        
        Args:
            rule: Rule object with all conditions and metadata
            output_path: Optional custom output path for YAML
            create_metadata: Whether to create metadata file
        
        Returns:
            {
                "success": bool,
                "yaml_path": str,
                "metadata_path": Optional[str],
                "existing_rules_found": List[Dict],
                "errors": List[str]
            }
        """
        errors = []
        existing_rules_found = []
        
        try:
            # Load service data
            loader = DataLoader(self.config)
            service_data = loader.load_service_data(rule.service)
            
            # Validate rule
            validation = self.validate_rule(rule)
            if not validation["valid"]:
                return {
                    "success": False,
                    "errors": validation["errors"],
                    "yaml_path": None,
                    "metadata_path": None,
                    "existing_rules_found": []
                }
            
            existing_rules_found = validation["existing_rules"]
            
            # Generate YAML
            generator = YAMLGenerator(rule.service, service_data)
            
            if output_path is None:
                output_path = self.config.get_output_path(rule.service) / f"{rule.service}.yaml"
            
            # Generate YAML with multiple conditions support
            yaml_str = generator.generate(
                rule.conditions, 
                output_path,
                logical_operator=rule.logical_operator,
                rule_id=rule.rule_id
            )
            
            # Generate metadata if requested
            metadata_path = None
            if create_metadata:
                metadata_gen = MetadataGenerator(rule.service, self.config)
                
                # Use first condition for metadata (or combine all)
                first_condition = rule.conditions[0]
                metadata_path = metadata_gen.generate_metadata(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    description=rule.description,
                    remediation=rule.remediation,
                    field_name=first_condition.field_name,
                    operator=first_condition.operator,
                    value=first_condition.value
                )
            
            return {
                "success": True,
                "yaml_path": str(output_path),
                "metadata_path": str(metadata_path) if metadata_path else None,
                "existing_rules_found": existing_rules_found,
                "errors": []
            }
            
        except Exception as e:
            return {
                "success": False,
                "errors": [str(e)],
                "yaml_path": None,
                "metadata_path": None,
                "existing_rules_found": existing_rules_found
            }
    
    def _find_common_discovery(
        self,
        conditions: List[FieldSelection],
        discovery_chains: List,
        generator: YAMLGenerator
    ) -> Optional[str]:
        """Find a discovery_id that provides all required fields"""
        if not conditions:
            return None
        
        # Try to find a discovery that has all fields
        for chain in discovery_chains:
            has_all_fields = all(
                cond.field_name in chain.item_fields 
                for cond in conditions
            )
            if has_all_fields:
                return chain.discovery_id
        
        # Fallback to first discovery that has the first field
        if discovery_chains:
            return discovery_chains[0].discovery_id
        
        return None
    
    def create_rule_from_ui_input(self, ui_input: Dict[str, Any]) -> Rule:
        """
        Create a Rule object from UI input
        
        Expected UI input format:
        {
            "service": "accessanalyzer",
            "title": "Rule Title",
            "description": "Rule description",
            "remediation": "Remediation steps",
            "rule_id": "aws.accessanalyzer.resource.rule_name",
            "conditions": [
                {
                    "field_name": "status",
                    "operator": "equals",
                    "value": "ACTIVE"
                },
                {
                    "field_name": "statusReason",
                    "operator": "exists",
                    "value": null
                }
            ],
            "logical_operator": "all"  # or "any"
        }
        """
        conditions = [
            FieldSelection(
                field_name=cond["field_name"],
                operator=cond["operator"],
                value=cond.get("value"),
                rule_id=ui_input["rule_id"]
            )
            for cond in ui_input.get("conditions", [])
        ]
        
        return Rule(
            rule_id=ui_input["rule_id"],
            service=ui_input["service"],
            title=ui_input["title"],
            description=ui_input["description"],
            remediation=ui_input["remediation"],
            conditions=conditions,
            logical_operator=ui_input.get("logical_operator", "single"),
            is_custom=True
        )

