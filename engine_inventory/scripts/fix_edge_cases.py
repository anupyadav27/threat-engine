#!/usr/bin/env python3
"""
Fix edge cases in generated relationships

Fixes common issues:
- Invalid EC2 resource types (ec2.instance, ec2.vpc, ec2.network-interface, ec2.vpn-gateway)
- Invalid apigatewayv2 resource types
- Other type mismatches
"""

import json
from pathlib import Path
from typing import Dict, List, Any

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "engine_inventory" / "inventory_engine" / "config"
CLASSIFICATION_INDEX_FILE = CONFIG_DIR / "aws_inventory_classification_index.json"

# Type corrections - these types are VALID for relationships (used in CORE_RELATION_MAP)
# even if not in classification index
VALID_RELATIONSHIP_TYPES = {
    "ec2.instance",  # Used in CORE_RELATION_MAP
    "ec2.vpc",  # Used in CORE_RELATION_MAP
    "ec2.network-interface",  # Used in CORE_RELATION_MAP
    "ec2.subnet",  # Used in CORE_RELATION_MAP
    "ec2.security-group",  # Used in CORE_RELATION_MAP
}

# Type corrections for invalid types
TYPE_CORRECTIONS = {
    # API Gateway v2 - integration doesn't exist
    "apigatewayv2.integration": None,  # Remove these relationships
    # VPN gateway - use the correct type
    "ec2.vpn-gateway": "ec2.vpn-connection-vpn-gateway",
}

def load_json(path: Path) -> Dict:
    with open(path, "r") as f:
        return json.load(f)

def get_valid_ec2_types(classification: Dict) -> Dict[str, str]:
    """Get valid EC2 resource types from classification index."""
    valid_types = {}
    classifications = classification.get("classifications", {})
    by_service_resource = classifications.get("by_service_resource", {})
    
    for key, info in by_service_resource.items():
        if key.startswith("ec2."):
            norm_type = info.get("normalized_type", "")
            if norm_type:
                valid_types[f"ec2.{norm_type}"] = True
    
    return valid_types

def find_best_match(invalid_type: str, valid_types: Dict[str, bool], context: str = "") -> str:
    """Find the best matching valid type for an invalid type."""
    # Direct lookup
    if invalid_type in TYPE_CORRECTIONS:
        correction = TYPE_CORRECTIONS[invalid_type]
        if correction is None:
            return None  # Should be removed
        if correction in valid_types:
            return correction
    
    # Try to find similar types
    invalid_base = invalid_type.split(".")[-1]
    for valid_type in valid_types.keys():
        if invalid_base in valid_type.lower():
            return valid_type
    
    # For EC2, try common patterns
    if invalid_type == "ec2.instance":
        # Look for instance-related types
        for valid_type in valid_types.keys():
            if "instance" in valid_type and "imag-source-instance" in valid_type:
                return valid_type
    
    if invalid_type == "ec2.vpc":
        # VPC is often referenced through security groups or other resources
        # Use a common VPC reference type
        for valid_type in valid_types.keys():
            if "vpc" in valid_type and "primary" in valid_type:
                return valid_type
    
    if invalid_type == "ec2.network-interface":
        # Network interface types
        for valid_type in valid_types.keys():
            if "network-interface" in valid_type or "network-interfac" in valid_type:
                return valid_type
    
    if invalid_type == "ec2.vpn-gateway":
        # VPN gateway types
        for valid_type in valid_types.keys():
            if "vpn-gateway" in valid_type or "vpn-connection" in valid_type:
                return valid_type
    
    return None

def fix_relationship(rel: Dict[str, Any], valid_types: Dict[str, bool]) -> Dict[str, Any]:
    """Fix a single relationship."""
    from_type = rel.get("from_type", "")
    to_type = rel.get("to_type", "")
    issue = rel.get("_issue", "")
    
    fixed = False
    
    # Check if types are valid relationship types (even if not in classification index)
    if from_type in VALID_RELATIONSHIP_TYPES:
        # Valid relationship type, just remove the flag
        fixed = True
    
    if to_type in VALID_RELATIONSHIP_TYPES:
        # Valid relationship type, just remove the flag
        fixed = True
    
    # Fix from_type
    if "Invalid from_type" in issue:
        if from_type in VALID_RELATIONSHIP_TYPES:
            fixed = True
        else:
            corrected_from = find_best_match(from_type, valid_types)
            if corrected_from:
                rel["from_type"] = corrected_from
                fixed = True
            else:
                # Can't fix, mark for removal
                rel["_remove"] = True
                return rel
    
    # Fix to_type
    if "Invalid to_type" in issue:
        if to_type in VALID_RELATIONSHIP_TYPES:
            fixed = True
        elif TYPE_CORRECTIONS.get(to_type) is None:
            # Should be removed
            rel["_remove"] = True
            return rel
        else:
            corrected_to = TYPE_CORRECTIONS.get(to_type)
            if corrected_to:
                rel["to_type"] = corrected_to
                fixed = True
            else:
                corrected_to = find_best_match(to_type, valid_types)
                if corrected_to:
                    rel["to_type"] = corrected_to
                    fixed = True
    
    if fixed:
        rel.pop("_needs_review", None)
        rel.pop("_issue", None)
        rel["_fixed"] = True
    
    return rel

def process_file(file_path: Path, valid_types: Dict[str, bool]) -> Dict[str, Any]:
    """Process a single fixed relationships file."""
    data = load_json(file_path)
    relationships = data.get("relationships", [])
    
    fixed_rels = []
    removed = 0
    
    for rel in relationships:
        # Remove relationships with invalid types that should be removed
        from_type = rel.get("from_type", "")
        to_type = rel.get("to_type", "")
        
        # Remove apigatewayv2.integration relationships
        if "apigatewayv2.integration" in from_type or "apigatewayv2.integration" in to_type:
            removed += 1
            continue
        
        if rel.get("_needs_review") or rel.get("_issue"):
            fixed_rel = fix_relationship(rel.copy(), valid_types)
            if fixed_rel.get("_remove"):
                removed += 1
            else:
                fixed_rels.append(fixed_rel)
        else:
            fixed_rels.append(rel)
    
    data["relationships"] = fixed_rels
    data["_fix_summary"] = {
        "total": len(relationships),
        "fixed": len([r for r in fixed_rels if r.get("_fixed")]),
        "removed": removed,
        "remaining": len(fixed_rels)
    }
    
    return data

def main():
    print("Fixing edge cases in generated relationships...")
    
    # Load classification index
    classification = load_json(CLASSIFICATION_INDEX_FILE)
    valid_types = get_valid_ec2_types(classification)
    
    # Process all fixed relationship files
    fixed_files = list(CONFIG_DIR.glob("fixed_relationships_*.json"))
    
    total_fixed = 0
    total_removed = 0
    
    for file_path in sorted(fixed_files):
        print(f"Processing {file_path.name}...")
        data = process_file(file_path, valid_types)
        
        summary = data.get("_fix_summary", {})
        total_fixed += summary.get("fixed", 0)
        total_removed += summary.get("removed", 0)
        
        # Save fixed file
        with open(file_path, "w") as f:
            json.dump(data, f, indent=2)
    
    print(f"\n✅ Fixed {total_fixed} relationships")
    print(f"🗑️  Removed {total_removed} invalid relationships")
    print(f"\nNext: Run merge_generated_relationships.py to merge fixes")

if __name__ == "__main__":
    main()
