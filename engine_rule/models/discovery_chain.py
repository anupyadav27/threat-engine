"""
Discovery chain data models
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

@dataclass
class DiscoveryCall:
    """Represents a single API call in discovery"""
    action: str
    save_as: str = "response"
    params: Optional[Dict[str, Any]] = None
    on_error: Optional[str] = None

@dataclass
class DiscoveryChain:
    """Represents a complete discovery operation chain"""
    discovery_id: str
    action: str
    main_output_field: str
    item_fields: List[str] = field(default_factory=list)
    for_each: Optional[str] = None
    calls: List[DiscoveryCall] = field(default_factory=list)
    emit_items_for: Optional[str] = None
    emit_as: str = "item"
    
    def __post_init__(self):
        """Initialize default values"""
        if not self.calls:
            call = DiscoveryCall(action=self.action)
            if self.for_each:
                # Add params from for_each context
                pass
            self.calls = [call]
        
        if not self.emit_items_for and self.main_output_field:
            self.emit_items_for = f"{{{{ response.{self.main_output_field} }}}}"
    
    def to_yaml_dict(self) -> dict:
        """Convert to YAML dictionary structure"""
        result = {
            "discovery_id": self.discovery_id,
            "calls": []
        }
        
        # Add for_each if present
        if self.for_each:
            result["for_each"] = self.for_each
        
        # Build calls
        for call in self.calls:
            call_dict = {
                "action": call.action,
                "save_as": call.save_as
            }
            if call.params:
                call_dict["params"] = call.params
            if call.on_error:
                call_dict["on_error"] = call.on_error
            result["calls"].append(call_dict)
        
        # Build emit
        result["emit"] = {
            "as": self.emit_as
        }
        
        if self.emit_items_for:
            result["emit"]["items_for"] = self.emit_items_for
        
        # Add item fields
        if self.item_fields:
            result["emit"]["item"] = {
                field: f"{{{{ item.{field} }}}}" 
                for field in self.item_fields
            }
        else:
            result["emit"]["item"] = {}
        
        return result

