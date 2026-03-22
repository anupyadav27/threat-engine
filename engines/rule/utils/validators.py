"""
Validation utilities
"""

from typing import List, Optional
try:
    from ..models.field_selection import FieldSelection
except ImportError:
    from models.field_selection import FieldSelection

class Validator:
    """Validation utilities"""
    
    @staticmethod
    def validate_operator(field_info: dict, operator: str) -> bool:
        """Validate operator is allowed for field"""
        # 'exists' / 'not_exists' are supported universally by the rule engine (presence/absence checks)
        if operator in ("exists", "not_exists"):
            return True
        allowed_operators = field_info.get("operators", [])
        return operator in allowed_operators
    
    @staticmethod
    def validate_value(field_info: dict, operator: str, value: any) -> bool:
        """Validate value is appropriate for field and operator"""
        if operator in ("exists", "not_exists"):
            return value is None
        
        if field_info.get("enum"):
            possible_values = field_info.get("possible_values", [])
            return value in possible_values
        
        # Type validation
        field_type = field_info.get("type", "string")
        if field_type == "integer":
            return isinstance(value, int)
        elif field_type == "boolean":
            return isinstance(value, bool)
        
        return True
    
    @staticmethod
    def validate_rule_id(rule_id: str, provider: str = None) -> bool:
        """
        Validate rule ID format for a specific provider
        
        Args:
            rule_id: Rule ID to validate
            provider: Provider name (e.g., 'aws', 'azure'). If None, validates any valid provider prefix.
            
        Returns:
            True if valid, False otherwise
        """
        parts = rule_id.split(".")
        if len(parts) < 4:
            return False
        
        # Valid provider prefixes
        valid_providers = ["aws", "azure", "gcp", "oci", "alicloud", "ibm"]
        
        provider_prefix = parts[0]
        if provider_prefix not in valid_providers:
            return False
        
        # If provider specified, must match
        if provider:
            return provider_prefix == provider
        
        return True

