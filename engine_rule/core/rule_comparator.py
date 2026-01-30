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
    """
    Compares rules to find existing matches with two-phase matching:
    1. Phase 1: Compare without for_each (wider net)
    2. Phase 2: Refine with for_each (exact match)
    
    Provider isolation: Rules only compared within same provider
    """
    
    def __init__(self, service_name: str, provider: str, config):
        """
        Initialize rule comparator
        
        Args:
            service_name: Service name (e.g., 'iam', 's3')
            provider: Provider name (e.g., 'aws', 'azure') - REQUIRED for isolation
            config: Config instance
        """
        if not provider:
            raise ValueError("provider is required for rule comparison")
        
        self.service_name = service_name
        self.provider = provider
        self.config = config
        self.provider_adapter = config.get_provider_adapter(provider)
        self.existing_rules = self._load_existing_rules()
    
    def _load_existing_rules(self) -> List[Dict]:
        """Load all existing rules from YAML files for this provider"""
        rules = []
        
        # Get provider-specific output directory
        service_dir = self.config.get_output_path(self.service_name, self.provider)
        
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
                        rule_id = check.get("rule_id", "")
                        # Only include rules from same provider (provider isolation)
                        if rule_id.startswith(f"{self.provider}."):
                            rules.append({
                                "rule_id": rule_id,
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
    
    def find_matching_rule(self, selection: FieldSelection, for_each: Optional[str] = None) -> Optional[Dict]:
        """
        Two-phase rule comparison:
        
        1. Phase 1 (without for_each): Match by provider + service + var + op + value (wider net)
        2. Phase 2 (with for_each): Refine matches using for_each if provided (exact match)
        
        Args:
            selection: Field selection to match
            for_each: Optional discovery_id for Phase 2 refinement
            
        Returns:
            Matching rule dict or None
        """
        # Phase 1: Initial matching without for_each (wider net)
        candidates = self._find_candidates_without_for_each(selection)
        
        if not candidates:
            return None
        
        # Phase 2: Refine with for_each if available (exact match)
        if for_each:
            for candidate in candidates:
                if candidate.get("for_each") == for_each:
                    return candidate
            # If for_each provided but no exact match, return None
            return None
        
        # If no for_each yet, return first candidate (will refine later)
        return candidates[0] if candidates else None
    
    def _find_candidates_without_for_each(self, selection: FieldSelection) -> List[Dict]:
        """
        Phase 1: Find matching rules without requiring for_each match
        
        Provider isolation: Only compares rules from same provider
        Matches by: service + var + op + value
        """
        # Normalize the new selection
        new_condition = {
            "var": f"item.{selection.field_name}",
            "op": selection.operator,
            "value": selection.value
        }
        normalized_new = self.normalize_condition(new_condition)
        
        candidates = []
        provider_prefix = f"{self.provider}."  # Provider isolation
        
        for rule in self.existing_rules:
            # Provider isolation: Filter by provider prefix
            rule_id = rule.get("rule_id", "")
            if not rule_id.startswith(provider_prefix):
                continue
            
            # Compare conditions (var + op + value) without for_each
            existing_conditions = rule.get("conditions", {})
            normalized_existing = self.normalize_condition(existing_conditions)
            
            if self._conditions_match(normalized_new, normalized_existing):
                candidates.append(rule)
        
        return candidates
    
    def _normalize_selection(self, selection: FieldSelection) -> Dict:
        """Normalize a field selection for comparison"""
        condition = {
            "var": f"item.{selection.field_name}",
            "op": selection.operator,
            "value": selection.value
        }
        return self.normalize_condition(condition)
    
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

