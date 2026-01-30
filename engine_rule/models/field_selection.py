"""
Field selection data model - Updated with metadata fields
"""

from dataclasses import dataclass, field
from typing import Any, Optional

@dataclass
class FieldSelection:
    """Represents a user's field selection for a rule"""
    field_name: str
    operator: str
    value: Any
    rule_id: str
    rule_description: Optional[str] = None
    title: Optional[str] = None
    description: Optional[str] = None
    remediation: Optional[str] = None
    is_custom: bool = field(default=True)  # Mark as custom by default
    
    def __post_init__(self):
        """Validate field selection"""
        if not self.field_name:
            raise ValueError("field_name is required")
        if not self.operator:
            raise ValueError("operator is required")
        if not self.rule_id:
            raise ValueError("rule_id is required")
    
    def to_dict(self) -> dict:
        """Convert to dictionary"""
        return {
            "field_name": self.field_name,
            "operator": self.operator,
            "value": self.value,
            "rule_id": self.rule_id,
            "rule_description": self.rule_description,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "is_custom": self.is_custom
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> "FieldSelection":
        """Create from dictionary"""
        return cls(
            field_name=data["field_name"],
            operator=data["operator"],
            value=data.get("value"),
            rule_id=data["rule_id"],
            rule_description=data.get("rule_description"),
            title=data.get("title"),
            description=data.get("description"),
            remediation=data.get("remediation"),
            is_custom=data.get("is_custom", True)
        )

