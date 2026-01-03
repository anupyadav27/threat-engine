"""
Rule comparator - checks if a rule already exists
"""

import yaml
from pathlib import Path
from typing import Dict, List, Optional, Tuple
try:
    from ..models.field_selection import FieldSelection
except ImportError:
    from models.field_selection import FieldSelection

class RuleComparator:
    """Compares rules to find existing matches"""
    
    def __init__(self, service_name: str, config):
        self.service_name = service_name
        self.config = config
        self.existing_rules = self._load_existing_rules()
    
    def _load_existing_rules(self) -> List[Dict]:
        """Load all existing rules from YAML files"""
        rules = []
        service_dir = self.config.output_dir / self.service_name / "rules"
        
        if not service_dir.exists():
            return rules
        
        # Load main service YAML
        service_yaml = service_dir / f"{self.service_name}.yaml"
        if service_yaml.exists():
            try:
                with open(service_yaml, 'r') as f:
                    data = yaml.safe_load(f)
                    checks = data.get("checks", [])
                    for check in checks:
                        rules.append({
                            "rule_id": check.get("rule_id"),
                            "for_each": check.get("for_each"),
                            "conditions": check.get("conditions", {}),
                            "source_file": str(service_yaml)
                        })
            except Exception as e:
                # If file can't be loaded, return empty list
                pass
        
        return rules
    
    def normalize_condition(self, condition: Dict) -> Dict:
        """
        Normalize condition for comparison
        
        Handles:
        - Single condition: {var, op, value}
        - All condition: {all: [{var, op, value}, ...]}
        - Any condition: {any: [{var, op, value}, ...]}
        """
        if "all" in condition:
            # For 'all' conditions, we compare each sub-condition
            return {
                "type": "all",
                "conditions": [self._normalize_single_condition(c) for c in condition["all"]]
            }
        elif "any" in condition:
            return {
                "type": "any",
                "conditions": [self._normalize_single_condition(c) for c in condition["any"]]
            }
        else:
            return {
                "type": "single",
                "condition": self._normalize_single_condition(condition)
            }
    
    def _normalize_single_condition(self, condition: Dict) -> Dict:
        """Normalize a single condition"""
        var = condition.get("var", "")
        # Remove "item." prefix if present
        if var.startswith("item."):
            var = var[5:]
        
        return {
            "var": var,
            "op": condition.get("op", ""),
            "value": condition.get("value")
        }
    
    def find_matching_rule(self, selection: FieldSelection, for_each: str) -> Optional[Dict]:
        """
        Find existing rule that matches the selection
        
        Compares:
        - for_each (discovery_id)
        - var (field name)
        - op (operator)
        - value (expected value)
        """
        # Normalize the new selection
        new_condition = {
            "var": f"item.{selection.field_name}",
            "op": selection.operator,
            "value": selection.value
        }
        normalized_new = self.normalize_condition(new_condition)
        
        # Compare with existing rules
        for rule in self.existing_rules:
            if rule["for_each"] != for_each:
                continue
            
            existing_conditions = rule.get("conditions", {})
            normalized_existing = self.normalize_condition(existing_conditions)
            
            # Compare normalized conditions
            if self._conditions_match(normalized_new, normalized_existing):
                return rule
        
        return None
    
    def _conditions_match(self, norm1: Dict, norm2: Dict) -> bool:
        """Check if two normalized conditions match"""
        if norm1["type"] != norm2["type"]:
            return False
        
        if norm1["type"] == "single":
            c1 = norm1["condition"]
            c2 = norm2["condition"]
            return (
                c1["var"] == c2["var"] and
                c1["op"] == c2["op"] and
                c1["value"] == c2["value"]
            )
        elif norm1["type"] in ["all", "any"]:
            # For all/any, check if all conditions match (order-independent)
            conds1 = sorted(norm1["conditions"], key=lambda x: (x["var"], x["op"], str(x["value"])))
            conds2 = sorted(norm2["conditions"], key=lambda x: (x["var"], x["op"], str(x["value"])))
            
            if len(conds1) != len(conds2):
                return False
            
            for c1, c2 in zip(conds1, conds2):
                if not (c1["var"] == c2["var"] and c1["op"] == c2["op"] and c1["value"] == c2["value"]):
                    return False
            
            return True
        
        return False

