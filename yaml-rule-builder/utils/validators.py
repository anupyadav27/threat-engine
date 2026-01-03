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
        allowed_operators = field_info.get("operators", [])
        return operator in allowed_operators
    
    @staticmethod
    def validate_value(field_info: dict, operator: str, value: any) -> bool:
        """Validate value is appropriate for field and operator"""
        if operator == "exists":
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
    def validate_rule_id(rule_id: str) -> bool:
        """Validate rule ID format"""
        # Format: aws.service.resource.rule_name
        parts = rule_id.split(".")
        return len(parts) >= 4 and parts[0] == "aws"

