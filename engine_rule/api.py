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
    API interface for building rules programmatically with multi-CSP support
    
    Designed for UI integration:
    - Accepts structured input with explicit provider (title, description, remediation, provider, service, conditions)
    - Returns structured output (YAML path, metadata path, existing rules found)
    - Handles multiple conditions with all/any logic
    - Provider isolation: Rules only compared within same provider
    """
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self._service_cache: Dict[str, Dict] = {}  # Key: f"{provider}:{service_name}"
    
    def get_providers(self) -> List[str]:
        """Get list of registered CSP providers"""
        return list(self.config._provider_registry.keys())
    
    def get_provider_status(self, provider: str) -> Dict[str, any]:
        """
        Get status and capabilities for a provider
        
        Returns:
            Dictionary with provider status information
        """
        try:
            from .core.provider_validator import ProviderValidator
        except ImportError:
            from core.provider_validator import ProviderValidator
        
        validator = ProviderValidator(self.config)
        return validator.get_provider_status(provider)
    
    def get_all_providers_status(self) -> Dict[str, Dict]:
        """Get status for all registered providers"""
        try:
            from .core.provider_validator import ProviderValidator
        except ImportError:
            from core.provider_validator import ProviderValidator
        
        validator = ProviderValidator(self.config)
        return validator.get_all_providers_status()
    
    def get_available_services(self, provider: str) -> List[str]:
        """
        Get list of available services for a specific provider
        
        Args:
            provider: Provider name (e.g., 'aws', 'azure') - REQUIRED
            
        Returns:
            List of service names
        """
        if not provider:
            raise ValueError("provider parameter is required")
        
        try:
            from .commands.list_services import list_services
        except ImportError:
            from commands.list_services import list_services
        
        # Filter services by provider
        all_services = list_services(self.config, provider)
        return all_services
    
    def get_service_fields(self, provider: str, service_name: str) -> Dict[str, Dict]:
        """
        Get all available fields for a service in a specific provider with their metadata
        
        Args:
            provider: Provider name (e.g., 'aws', 'azure') - REQUIRED
            service_name: Service name (e.g., 'iam', 's3') - REQUIRED
            
        Returns:
            Dictionary of field names to field metadata
        """
        if not provider:
            raise ValueError("provider parameter is required")
        if not service_name:
            raise ValueError("service_name parameter is required")
        
        if not self.config.validate_service(service_name, provider):
            raise ValueError(f"Service '{service_name}' not found or invalid for provider '{provider}'")
        
        loader = DataLoader(self.config)
        service_data = loader.load_service_data(service_name, provider)
        
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
    
    def validate_rule(self, rule: Rule, provider: str = None) -> Dict[str, Any]:
        """
        Validate a rule before generation with two-phase matching
        
        Args:
            rule: Rule object with conditions
            provider: Optional provider name (defaults to rule.provider)
            
        Returns:
            {
                "valid": bool,
                "errors": List[str],
                "warnings": List[str],
                "existing_rules": List[Dict]  # Matching existing rules (two-phase)
            }
        """
        # Use rule.provider if provider not provided
        if not provider:
            provider = rule.provider
        if not provider:
            raise ValueError("provider is required (either as parameter or in rule.provider)")
        
        # Validate provider matches rule.provider
        if rule.provider and rule.provider != provider:
            return {
                "valid": False,
                "errors": [f"Provider mismatch: rule.provider={rule.provider}, provided={provider}"],
                "warnings": [],
                "existing_rules": []
            }
        
        errors = []
        warnings = []
        existing_rules = []
        
        # Load service data with provider
        loader = DataLoader(self.config)
        service_data = loader.load_service_data(rule.service, provider)
        
        mapper = FieldMapper(service_data)
        validator = Validator()
        generator = YAMLGenerator(rule.service, provider, service_data, self.config)
        comparator = RuleComparator(rule.service, provider, self.config)
        
        # Canonicalize field names (case-insensitive) to avoid mismatches like Status vs status
        try:
            available_fields = mapper.get_available_fields()
            fields_by_lower = {f.lower(): f for f in available_fields if isinstance(f, str)}
            for condition in rule.conditions:
                if isinstance(condition.field_name, str):
                    canonical = fields_by_lower.get(condition.field_name.lower())
                    if canonical:
                        condition.field_name = canonical
        except Exception:
            pass

        # Validate each condition
        for condition in rule.conditions:
            field_info = mapper.get_field_info(condition.field_name)
            if not field_info:
                errors.append(f"Field '{condition.field_name}' not found in service '{rule.service}'")
                continue
            
            if not validator.validate_operator(field_info, condition.operator):
                errors.append(f"Operator '{condition.operator}' not valid for field '{condition.field_name}'")

            # Avoid generating nonsensical YAML like "equals: null" (use exists/not_exists instead)
            if condition.value is None and condition.operator not in ("exists", "not_exists"):
                errors.append(
                    f"Operator '{condition.operator}' requires a non-null value for field '{condition.field_name}'. "
                    f"Use operator 'exists' with value null if you want a presence check."
                )
            
            if not validator.validate_value(field_info, condition.operator, condition.value):
                warnings.append(f"Value '{condition.value}' may not be valid for field '{condition.field_name}'")

        # Ensure all selected fields are compatible (can be evaluated on the same discovery item)
        # If not, generating YAML with logical_operator=all/any would produce broken references.
        if not errors and len(rule.conditions) > 1:
            discovery_chains = generator._resolve_all_dependencies(rule.conditions)
            required = [c.field_name for c in rule.conditions]
            required_lower = [f.lower() for f in required if isinstance(f, str)]

            # Compute best coverage chain
            best_chain = None
            best_covered = set()
            for chain in discovery_chains:
                provided = {f.lower() for f in (chain.item_fields or []) if isinstance(f, str)}
                covered = provided.intersection(required_lower)
                if len(covered) > len(best_covered):
                    best_chain = chain
                    best_covered = covered

            if best_chain is not None and len(best_covered) < len(set(required_lower)):
                missing = sorted(set(required_lower) - best_covered)

                # Build helpful mapping: field -> discoveries that provide it
                field_to_discoveries = {}
                for fld in sorted(set(required_lower)):
                    providers = []
                    for chain in discovery_chains:
                        provided = {f.lower() for f in (chain.item_fields or []) if isinstance(f, str)}
                        if fld in provided:
                            providers.append(chain.discovery_id)
                    field_to_discoveries[fld] = providers[:5]

                errors.append(
                    "Selected fields span multiple resources/discoveries; they cannot be combined with "
                    f"logical_operator='{rule.logical_operator}' in a single check. "
                    f"Missing fields from chosen discovery '{best_chain.discovery_id}': {missing}. "
                    f"Field providers: {field_to_discoveries}"
                )
        
        # Two-phase rule comparison
        # Phase 1: Compare without for_each (wider net)
        candidates = comparator._find_candidates_without_for_each(rule.conditions[0])
        
        if candidates:
            # Phase 2: Resolve dependencies to get for_each, then refine
            discovery_chains = generator._resolve_all_dependencies(rule.conditions)
            discovery_id = self._find_common_discovery(rule.conditions, discovery_chains, generator)
            
            if discovery_id:
                # Refine match with for_each
                existing = comparator.find_matching_rule(rule.conditions[0], discovery_id)
                if existing:
                    existing_rules.append({
                        "rule_id": existing["rule_id"],
                        "source_file": existing["source_file"],
                        "for_each": existing["for_each"],
                        "note": "Exact match (Phase 2 with for_each)"
                    })
                elif candidates:
                    # Phase 1 match but no Phase 2 match (different for_each)
                    existing_rules.append({
                        "rule_id": candidates[0]["rule_id"],
                        "source_file": candidates[0]["source_file"],
                        "for_each": candidates[0].get("for_each"),
                        "note": "Phase 1 match (same field+op+value, different for_each)"
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
        provider: str,
        output_path: Optional[Path] = None,
        create_metadata: bool = True
    ) -> Dict[str, Any]:
        """
        Generate YAML and metadata for a rule with provider awareness
        
        Args:
            rule: Rule object with all conditions and metadata
            provider: Provider name (e.g., 'aws', 'azure') - REQUIRED
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
        if not provider:
            raise ValueError("provider parameter is required")
        
        errors = []
        existing_rules_found = []
        
        try:
            # Validate provider matches rule
            if rule.provider and rule.provider != provider:
                return {
                    "success": False,
                    "errors": [f"Provider mismatch: rule.provider={rule.provider}, provided={provider}"],
                    "yaml_path": None,
                    "metadata_path": None,
                    "existing_rules_found": []
                }
            
            # Load service data with provider
            loader = DataLoader(self.config)
            service_data = loader.load_service_data(rule.service, provider)
            
            # Validate rule with provider
            validation = self.validate_rule(rule, provider)
            if not validation["valid"]:
                return {
                    "success": False,
                    "errors": validation["errors"],
                    "yaml_path": None,
                    "metadata_path": None,
                    "existing_rules_found": []
                }
            
            existing_rules_found = validation["existing_rules"]
            
            # Generate YAML with provider awareness
            generator = YAMLGenerator(rule.service, provider, service_data, self.config)
            
            if output_path is None:
                output_path = self.config.get_output_path(rule.service, provider) / f"{rule.service}.yaml"
            
            # Generate YAML with multiple conditions support (includes merging)
            yaml_str = generator.generate(
                rule.conditions, 
                output_path,
                logical_operator=rule.logical_operator,
                rule_id=rule.rule_id
            )
            
            # Generate metadata if requested with provider awareness
            metadata_path = None
            if create_metadata:
                metadata_gen = MetadataGenerator(rule.service, provider, self.config)
                
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
        
        # Extract provider from input (required) or from rule_id
        provider = ui_input.get("provider")
        if not provider:
            # Try to extract from rule_id prefix
            rule_id = ui_input.get("rule_id", "")
            if rule_id:
                parts = rule_id.split(".")
                if parts:
                    provider = parts[0]
        
        if not provider:
            raise ValueError(
                "provider is required in input or must be extractable from rule_id. "
                "Example: {'provider': 'aws', 'rule_id': 'aws.iam.resource.rule'} or "
                "{'rule_id': 'aws.iam.resource.rule'} (provider auto-detected)"
            )
        
        return Rule(
            rule_id=ui_input["rule_id"],
            service=ui_input["service"],
            provider=provider,  # REQUIRED
            title=ui_input["title"],
            description=ui_input["description"],
            remediation=ui_input["remediation"],
            conditions=conditions,
            logical_operator=ui_input.get("logical_operator", "single"),
            is_custom=True
        )

