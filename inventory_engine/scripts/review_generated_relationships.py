#!/usr/bin/env python3
"""
Review and validate generated relationships

Checks for common issues:
- Invalid resource types (should match classification index)
- Invalid relation types
- Incorrect target types (e.g., backup.key -> kms.key)
- Missing required fields
"""

import json
from pathlib import Path
from typing import Dict, List, Set

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "inventory-engine" / "inventory_engine" / "config"
CLASSIFICATION_INDEX_FILE = CONFIG_DIR / "aws_inventory_classification_index.json"
RELATION_TYPES_FILE = CONFIG_DIR / "relation_types.json"

# Common corrections
CORRECTIONS = {
    "backup.key": "kms.key",
    "config.topic": "sns.topic",
    "cloudwatch.entry": None,  # Doesn't exist
    "eks.role": "iam.role",
    "eks.policy": "iam.policy",
}

def load_json(path: Path) -> Dict:
    with open(path, "r") as f:
        return json.load(f)

def get_all_resource_types(classification: Dict) -> Set[str]:
    """Get all valid resource types from classification index."""
    resource_types = set()
    c = classification.get("classifications", {})
    
    # From by_service_resource
    by_sr = c.get("by_service_resource", {}) or {}
    for sr_key, info in by_sr.items():
        if not isinstance(sr_key, str) or "." not in sr_key:
            continue
        svc, _raw_rt = sr_key.split(".", 1)
        norm_rt = (info or {}).get("normalized_type") or (info or {}).get("resource_type") or _raw_rt
        if norm_rt:
            import re
            norm_rt = re.sub(r"_+", "-", str(norm_rt)).strip("-")
            resource_types.add(f"{svc}.{norm_rt}")
    
    # From by_discovery_operation
    by_op = c.get("by_discovery_operation", {}) or {}
    for op_key, info in by_op.items():
        svc = (info or {}).get("service")
        norm_rt = (info or {}).get("normalized_type") or (info or {}).get("resource_type")
        if svc and norm_rt:
            import re
            norm_rt = re.sub(r"_+", "-", str(norm_rt)).strip("-")
            resource_types.add(f"{svc}.{norm_rt}")
    
    return resource_types

def review_file(file_path: Path, valid_resource_types: Set[str], valid_relation_types: Set[str]) -> Dict:
    """Review a single generated relationships file."""
    data = load_json(file_path)
    service = data.get("service", "unknown")
    relationships = data.get("relationships", [])
    
    issues = []
    warnings = []
    corrected = []
    
    for rel in relationships:
        from_type = rel.get("from_type", "")
        to_type = rel.get("to_type", "")
        relation_type = rel.get("relation_type", "")
        
        # Check from_type
        if from_type not in valid_resource_types:
            issues.append(f"Invalid from_type: {from_type}")
        
        # Check to_type
        if to_type in CORRECTIONS:
            corrected_to = CORRECTIONS[to_type]
            if corrected_to:
                warnings.append(f"{from_type} -> {to_type}: Should be {corrected_to}")
                rel["to_type"] = corrected_to
                corrected.append(rel)
            else:
                issues.append(f"Invalid to_type (doesn't exist): {to_type}")
        elif to_type not in valid_resource_types:
            issues.append(f"Invalid to_type: {to_type}")
        
        # Check relation_type
        if relation_type not in valid_relation_types:
            issues.append(f"Invalid relation_type: {relation_type}")
    
    return {
        "service": service,
        "total": len(relationships),
        "issues": issues,
        "warnings": warnings,
        "corrected": len(corrected),
        "valid": len(relationships) - len(issues)
    }

def main():
    classification = load_json(CLASSIFICATION_INDEX_FILE)
    relation_types_data = load_json(RELATION_TYPES_FILE)
    
    valid_resource_types = get_all_resource_types(classification)
    valid_relation_types = {rt["id"] for rt in relation_types_data.get("relation_types", [])}
    
    # Find all generated files
    generated_files = list(CONFIG_DIR.glob("generated_relationships_*.json"))
    
    print(f"Reviewing {len(generated_files)} generated relationship files...\n")
    
    all_issues = []
    all_warnings = []
    
    for file_path in sorted(generated_files):
        result = review_file(file_path, valid_resource_types, valid_relation_types)
        
        print(f"Service: {result['service']}")
        print(f"  Total relationships: {result['total']}")
        print(f"  Valid: {result['valid']}")
        print(f"  Issues: {len(result['issues'])}")
        print(f"  Warnings: {len(result['warnings'])}")
        print(f"  Corrected: {result['corrected']}")
        
        if result['issues']:
            print(f"  Issues:")
            for issue in result['issues']:
                print(f"    - {issue}")
                all_issues.append(f"{result['service']}: {issue}")
        
        if result['warnings']:
            print(f"  Warnings:")
            for warning in result['warnings'][:3]:  # Show first 3
                print(f"    - {warning}")
                all_warnings.append(f"{result['service']}: {warning}")
        
        print()
    
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"Total files reviewed: {len(generated_files)}")
    print(f"Total issues: {len(all_issues)}")
    print(f"Total warnings: {len(all_warnings)}")
    
    if all_issues:
        print(f"\nTop issues:")
        from collections import Counter
        issue_counts = Counter([i.split(': ')[1] for i in all_issues])
        for issue, count in issue_counts.most_common(5):
            print(f"  {issue}: {count}")

if __name__ == "__main__":
    main()
