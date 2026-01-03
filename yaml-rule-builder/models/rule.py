"""
Rule model - represents a complete rule with multiple conditions
"""

from dataclasses import dataclass, field
from typing import List, Optional, Literal
from .field_selection import FieldSelection

@dataclass
class Rule:
    """
    Represents a complete compliance rule with metadata and conditions
    
    A rule can have:
    - Single condition: one field + operator + value
    - Multiple conditions: multiple fields with all/any logic
    """
    rule_id: str
    service: str
    title: str
    description: str
    remediation: str
    conditions: List[FieldSelection]  # List of field selections
    logical_operator: Literal["all", "any", "single"] = "single"  # all=AND, any=OR, single=one condition
    is_custom: bool = True
    
    def __post_init__(self):
        """Validate rule"""
        if not self.rule_id:
            raise ValueError("rule_id is required")
        if not self.service:
            raise ValueError("service is required")
        if not self.title:
            raise ValueError("title is required")
        if not self.description:
            raise ValueError("description is required")
        if not self.remediation:
            raise ValueError("remediation is required")
        if not self.conditions:
            raise ValueError("At least one condition is required")
        
        # Auto-detect logical operator if single condition
        if len(self.conditions) == 1:
            self.logical_operator = "single"
        elif self.logical_operator == "single":
            # Default to "all" if multiple conditions
            self.logical_operator = "all"
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            "rule_id": self.rule_id,
            "service": self.service,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "conditions": [cond.to_dict() for cond in self.conditions],
            "logical_operator": self.logical_operator,
            "is_custom": self.is_custom
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        """Create from dictionary"""
        conditions = [
            FieldSelection.from_dict(cond) 
            for cond in data.get("conditions", [])
        ]
        
        return cls(
            rule_id=data["rule_id"],
            service=data["service"],
            title=data["title"],
            description=data["description"],
            remediation=data["remediation"],
            conditions=conditions,
            logical_operator=data.get("logical_operator", "single"),
            is_custom=data.get("is_custom", True)
        )
    
    def get_all_fields(self) -> List[str]:
        """Get all field names used in conditions"""
        return [cond.field_name for cond in self.conditions]

