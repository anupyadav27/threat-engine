#!/usr/bin/env python3
"""
Auto-fix common issues in generated relationships

Fixes:
1. Cross-service type corrections (*.key → kms.key, *.role → iam.role, etc.)
2. ARN pattern corrections
3. Resource type validations
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Set

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = PROJECT_ROOT / "engine_inventory" / "inventory_engine" / "config"
CLASSIFICATION_INDEX_FILE = CONFIG_DIR / "aws_inventory_classification_index.json"

# Cross-service type corrections
TYPE_CORRECTIONS = {
    # KMS keys
    r"^.*\.key$": "kms.key",  # Any service.key → kms.key (when pattern suggests KMS)
    
    # IAM roles
    r"^.*\.role$": "iam.role",  # Any service.role → iam.role (when pattern suggests IAM)
    
    # IAM policies
    r"^.*\.policy$": "iam.policy",  # Any service.policy → iam.policy (when pattern suggests IAM)
    
    # SNS topics
    r"^.*\.topic$": "sns.topic",  # Any service.topic → sns.topic (when pattern suggests SNS)
    
    # CloudWatch Logs
    r"^cloudwatch\.log-group$": "logs.group",
    r"^cloudwatch\.logs-group$": "logs.group",
}

# Pattern-based corrections (check target_uid_pattern)
def should_correct_to_kms(to_type: str, pattern: str) -> bool:
    """Check if should correct to kms.key"""
    if "kms" in pattern.lower() or "arn:aws:kms" in pattern.lower():
        return to_type.endswith(".key") and to_type != "kms.key"
    return False

def should_correct_to_iam(to_type: str, pattern: str) -> bool:
    """Check if should correct to iam.role or iam.policy"""
    if "iam" in pattern.lower() or "arn:aws:iam" in pattern.lower():
        if to_type.endswith(".role") and to_type != "iam.role":
            return True
        if to_type.endswith(".policy") and to_type != "iam.policy":
            return True
    return False

def should_correct_to_sns(to_type: str, pattern: str) -> bool:
    """Check if should correct to sns.topic"""
    if "sns" in pattern.lower() or "arn:aws:sns" in pattern.lower():
        return to_type.endswith(".topic") and to_type != "sns.topic"
    return False

def fix_relationship(rel: Dict[str, Any]) -> Dict[str, Any]:
    """Fix a single relationship."""
    to_type = rel.get("to_type", "")
    pattern = rel.get("target_uid_pattern", "")
    fixed = False
    
    # Pattern-based corrections
    if should_correct_to_kms(to_type, pattern):
        rel["to_type"] = "kms.key"
        fixed = True
    elif should_correct_to_iam(to_type, pattern):
        if to_type.endswith(".role"):
            rel["to_type"] = "iam.role"
        elif to_type.endswith(".policy"):
            rel["to_type"] = "iam.policy"
        fixed = True
    elif should_correct_to_sns(to_type, pattern):
        rel["to_type"] = "sns.topic"
        fixed = True
    
    # Direct corrections
    if to_type == "cloudwatch.log-group" or to_type == "cloudwatch.logs-group":
        rel["to_type"] = "logs.group"
        fixed = True
    
    return rel, fixed

def load_classification_index() -> Dict:
    """Load classification index to validate resource types."""
    with open(CLASSIFICATION_INDEX_FILE, "r") as f:
        return json.load(f)

def get_valid_resource_types(classification: Dict) -> Set[str]:
    """Get all valid resource types."""
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
            norm_rt = re.sub(r"_+", "-", str(norm_rt)).strip("-")
            resource_types.add(f"{svc}.{norm_rt}")
    
    # From by_discovery_operation
    by_op = c.get("by_discovery_operation", {}) or {}
    for op_key, info in by_op.items():
        svc = (info or {}).get("service")
        norm_rt = (info or {}).get("normalized_type") or (info or {}).get("resource_type")
        if svc and norm_rt:
            norm_rt = re.sub(r"_+", "-", str(norm_rt)).strip("-")
            resource_types.add(f"{svc}.{norm_rt}")
    
    return resource_types

def process_file(file_path: Path, valid_types: Set[str]) -> Dict[str, Any]:
    """Process a single generated relationships file."""
    with open(file_path, "r") as f:
        data = json.load(f)
    
    relationships = data.get("relationships", [])
    fixed_count = 0
    invalid_count = 0
    fixed_rels = []
    
    for rel in relationships:
        # Fix relationship
        fixed_rel, was_fixed = fix_relationship(rel.copy())
        
        # Check if types are valid
        from_type = fixed_rel.get("from_type", "")
        to_type = fixed_rel.get("to_type", "")
        
        from_valid = from_type in valid_types
        to_valid = to_type in valid_types
        
        if was_fixed:
            fixed_count += 1
        
        if from_valid and to_valid:
            fixed_rels.append(fixed_rel)
        else:
            invalid_count += 1
            # Keep it but mark as needing review
            fixed_rel["_needs_review"] = True
            if not from_valid:
                fixed_rel["_issue"] = f"Invalid from_type: {from_type}"
            if not to_valid:
                fixed_rel["_issue"] = f"Invalid to_type: {to_type}"
            fixed_rels.append(fixed_rel)
    
    return {
        "service": data.get("service", ""),
        "total": len(relationships),
        "fixed": fixed_count,
        "invalid": invalid_count,
        "valid": len([r for r in fixed_rels if not r.get("_needs_review")]),
        "relationships": fixed_rels
    }

def main():
    """Process all generated relationship files."""
    classification = load_classification_index()
    valid_types = get_valid_resource_types(classification)
    
    generated_files = list(CONFIG_DIR.glob("generated_relationships_*.json"))
    
    print(f"Processing {len(generated_files)} files...\n")
    
    results = []
    total_fixed = 0
    total_invalid = 0
    
    for file_path in sorted(generated_files):
        result = process_file(file_path, valid_types)
        results.append(result)
        total_fixed += result["fixed"]
        total_invalid += result["invalid"]
        
        # Save fixed version
        output_data = {
            "service": result["service"],
            "generated_at": json.load(open(file_path))["generated_at"],
            "model": json.load(open(file_path))["model"],
            "fixed": True,
            "relationships": result["relationships"]
        }
        
        # Save to fixed file
        fixed_file = CONFIG_DIR / f"fixed_relationships_{result['service']}.json"
        with open(fixed_file, "w") as f:
            json.dump(output_data, f, indent=2)
        
        print(f"{result['service']}: {result['fixed']} fixed, {result['invalid']} invalid, {result['valid']} valid")
    
    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"Total files: {len(generated_files)}")
    print(f"Total fixed: {total_fixed}")
    print(f"Total invalid (needs review): {total_invalid}")
    
    # Save summary
    summary_file = CONFIG_DIR / "fix_summary.json"
    with open(summary_file, "w") as f:
        json.dump({
            "total_files": len(generated_files),
            "total_fixed": total_fixed,
            "total_invalid": total_invalid,
            "results": results
        }, f, indent=2)
    
    print(f"\nFixed files saved to: {CONFIG_DIR}/fixed_relationships_*.json")
    print(f"Summary saved to: {summary_file}")

if __name__ == "__main__":
    main()
