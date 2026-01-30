#!/usr/bin/env python3
"""
SageMaker Metadata Review Analysis Script
Analyzes sagemaker service metadata for consolidation and cross-service placement opportunities.
"""

import json
import yaml
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional
from datetime import datetime

# Service path
SERVICE_PATH = Path(__file__).parent
METADATA_PATH = SERVICE_PATH / "metadata"
METADATA_MAPPING_FILE = SERVICE_PATH / "metadata_mapping.json"
BOTO3_DEPS_FILE = Path("/Users/apple/Desktop/threat-engine/pythonsdk-database/aws/sagemaker/boto3_dependencies_with_python_names_fully_enriched.json")

# Common dependency services
COMMON_DEPENDENCIES = {"iam", "s3", "kms", "cloudwatch", "cloudtrail", "acm"}

def normalize_check_signature(rule: Dict) -> str:
    """Normalize check signature for comparison"""
    method = rule.get("python_method", "")
    path = rule.get("response_path", "")
    operator = rule.get("logical_operator") or "null"
    
    # Sort nested fields by field_path for consistent comparison
    nested_fields = rule.get("nested_field", [])
    sorted_fields = sorted(
        nested_fields,
        key=lambda x: (
            x.get("field_path", ""),
            x.get("operator", ""),
            str(x.get("expected_value", "")),
            str(x.get("value", ""))
        )
    )
    
    # Create signature string
    field_signatures = []
    for field in sorted_fields:
        field_sig = f"{field.get('field_path', '')}:{field.get('operator', '')}:{field.get('expected_value', '')}:{field.get('value', '')}"
        field_signatures.append(field_sig)
    
    signature = f"{method}|{path}|{operator}|{'|'.join(field_signatures)}"
    return signature

def load_metadata_files() -> Dict[str, Dict]:
    """Load all metadata YAML files"""
    metadata = {}
    for yaml_file in METADATA_PATH.glob("*.yaml"):
        try:
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)
                rule_id = data.get("rule_id", "")
                metadata[rule_id] = data
        except Exception as e:
            print(f"Error loading {yaml_file}: {e}")
    return metadata

def check_method_ownership(method: str) -> Tuple[Optional[str], int]:
    """Check which service(s) a method belongs to"""
    if not BOTO3_DEPS_FILE.exists():
        return None, 0
    
    try:
        with open(BOTO3_DEPS_FILE, 'r') as f:
            boto3_data = json.load(f)
        
        # Check if method exists in sagemaker service
        sagemaker_data = boto3_data.get("sagemaker", {})
        sagemaker_ops = sagemaker_data.get("independent", []) + sagemaker_data.get("dependent", [])
        sagemaker_has_method = any(
            op.get("python_method") == method 
            for op in sagemaker_ops
        )
        
        # Search all other service files in the pythonsdk-database
        service_count = 0
        first_other_service = None
        boto3_base = BOTO3_DEPS_FILE.parent.parent
        
        for service_dir in boto3_base.iterdir():
            if not service_dir.is_dir() or service_dir.name == "sagemaker":
                continue
            
            deps_file = service_dir / "boto3_dependencies_with_python_names_fully_enriched.json"
            if not deps_file.exists():
                continue
            
            try:
                with open(deps_file, 'r') as f:
                    service_data = json.load(f)
                    service_name = list(service_data.keys())[0] if service_data else None
                    if not service_name:
                        continue
                    
                    service_info = service_data.get(service_name, {})
                    ops = service_info.get("independent", []) + service_info.get("dependent", [])
                    if any(op.get("python_method") == method for op in ops):
                        service_count += 1
                        if service_count == 1:
                            first_other_service = service_name
            except Exception:
                continue
        
        if sagemaker_has_method:
            if service_count > 0:
                return "sagemaker", service_count + 1  # Ambiguous
            return "sagemaker", 1  # Only in sagemaker
        elif service_count > 0:
            return first_other_service, service_count  # Not in sagemaker, in other service(s)
        else:
            return None, 0  # Not found
    except Exception as e:
        print(f"Error checking method ownership: {e}")
        return None, 0

def extract_service_from_rule_id(rule_id: str) -> str:
    """Extract service name from rule_id (e.g., aws.sagemaker.endpoint.x -> sagemaker)"""
    parts = rule_id.split(".")
    if len(parts) >= 2 and parts[0] == "aws":
        return parts[1]
    return ""

def get_field_paths(rule: Dict) -> Set[str]:
    """Extract all field paths from a rule"""
    fields = set()
    for nested_field in rule.get("nested_field", []):
        field_path = nested_field.get("field_path", "")
        if field_path:
            fields.add(field_path)
    return fields

def is_subset(rule1_fields: Set[str], rule2_fields: Set[str]) -> bool:
    """Check if rule1_fields is a subset of rule2_fields"""
    return rule1_fields.issubset(rule2_fields) and rule1_fields != rule2_fields

def calculate_consolidation_confidence(rule1: Dict, rule2: Dict, rule1_fields: Set[str], rule2_fields: Set[str]) -> float:
    """Calculate confidence score for consolidation"""
    sig1 = normalize_check_signature(rule1)
    sig2 = normalize_check_signature(rule2)
    
    if sig1 == sig2:
        return 95.0  # Exact duplicate
    
    if is_subset(rule1_fields, rule2_fields) or is_subset(rule2_fields, rule1_fields):
        return 88.0  # Field subset/superset
    
    # Check for overlap
    overlap = rule1_fields.intersection(rule2_fields)
    if overlap:
        return 80.0  # Some overlap
    
    return 50.0  # Different checks

def calculate_cross_service_confidence(method_service: Optional[str], rule_service: str, service_count: int, is_common: bool) -> float:
    """Calculate confidence score for cross-service placement"""
    if method_service is None:
        return 50.0  # Method not found
    
    if method_service != rule_service:
        if is_common:
            return 95.0  # Common dependency service
        elif service_count == 1:
            return 90.0  # Clear ownership
        else:
            return 80.0  # Ambiguous
    
    return 0.0  # Same service, not cross-service

def get_review_needed(confidence: float) -> str:
    """Determine if review is needed based on confidence"""
    if confidence >= 90:
        return "none"
    elif confidence >= 75:
        return "optional"
    else:
        return "required"

def extract_compliance_standards(metadata: Dict) -> List[str]:
    """Extract compliance standards from metadata"""
    compliance = []
    
    # Check if there's a 'compliance' key with a list
    if "compliance" in metadata:
        comp_value = metadata["compliance"]
        if isinstance(comp_value, list):
            # Filter out URLs and only keep compliance IDs
            for item in comp_value:
                if isinstance(item, str) and not item.startswith("http"):
                    compliance.append(item)
        elif isinstance(comp_value, str) and not comp_value.startswith("http"):
            compliance.append(comp_value)
    
    # Also check for boolean compliance flags
    for key, value in metadata.items():
        if isinstance(value, bool) and value and key.startswith(("cis_", "iso_", "nist_", "soc2_", "gdpr_", "hipaa_", "pci_")):
            compliance.append(key)
    
    return compliance

def main():
    """Main analysis function"""
    print("Loading metadata mapping...")
    with open(METADATA_MAPPING_FILE, 'r') as f:
        mapping_data = json.load(f)
    
    rules = mapping_data.get("sagemaker_metadata_mapping", [])
    print(f"Found {len(rules)} rules")
    
    print("Loading metadata files...")
    metadata_files = load_metadata_files()
    print(f"Loaded {len(metadata_files)} metadata files")
    
    # Group rules by normalized signature
    signature_groups = defaultdict(list)
    for rule in rules:
        rule_id = rule.get("rule_id", "")
        signature = normalize_check_signature(rule)
        signature_groups[signature].append((rule_id, rule))
    
    # Find duplicates
    duplicates = []
    for signature, rule_list in signature_groups.items():
        if len(rule_list) > 1:
            # Multiple rules with same signature
            rule_ids = [r[0] for r in rule_list]
            rules_data = [r[1] for r in rule_list]
            
            # Get compliance info for each rule
            rule_compliance = []
            for rule_id, rule_data in rule_list:
                meta = metadata_files.get(rule_id, {})
                compliance = extract_compliance_standards(meta)
                rule_compliance.append({
                    "rule_id": rule_id,
                    "compliance": compliance,
                    "compliance_count": len(compliance)
                })
            
            # Sort by compliance count (keep the one with most compliance)
            rule_compliance.sort(key=lambda x: x["compliance_count"], reverse=True)
            keep_rule = rule_compliance[0]
            remove_rules = rule_compliance[1:]
            
            # Find the rule data for the kept rule
            keep_rule_data = next(r[1] for r in rule_list if r[0] == keep_rule["rule_id"])
            keep_fields = get_field_paths(keep_rule_data)
            
            remove_list = []
            for remove_rule in remove_rules:
                remove_rule_data = next(r[1] for r in rule_list if r[0] == remove_rule["rule_id"])
                remove_fields = get_field_paths(remove_rule_data)
                
                confidence = calculate_consolidation_confidence(
                    keep_rule_data, remove_rule_data, keep_fields, remove_fields
                )
                
                # Determine reason
                if confidence >= 90:
                    reason = "Exact duplicate check signature"
                elif is_subset(remove_fields, keep_fields):
                    reason = f"Subset of {keep_rule['rule_id']} - checks {len(remove_fields)} of {len(keep_fields)} fields"
                elif is_subset(keep_fields, remove_fields):
                    reason = f"Superset relationship - {keep_rule['rule_id']} checks {len(keep_fields)} fields, this checks {len(remove_fields)}"
                else:
                    reason = "Similar check signature with overlap"
                
                remove_list.append({
                    "rule_id": remove_rule["rule_id"],
                    "metadata_file": f"{remove_rule['rule_id']}.yaml",
                    "replaced_by": keep_rule["rule_id"],
                    "reason": reason,
                    "compliance_count": remove_rule["compliance_count"],
                    "compliance": remove_rule["compliance"],
                    "confidence_percentage": confidence,
                    "review_needed": get_review_needed(confidence),
                    "action": "merge_compliance_to_kept_rule",
                    "compliance_merged": False
                })
            
            if remove_list:
                duplicates.append({
                    "keep": {
                        "rule_id": keep_rule["rule_id"],
                        "metadata_file": f"{keep_rule['rule_id']}.yaml",
                        "reason": "More comprehensive (checks all fields)" if len(keep_fields) > 0 else "More compliance standards",
                        "compliance_count": keep_rule["compliance_count"],
                        "compliance": keep_rule["compliance"]
                    },
                    "remove": remove_list
                })
    
    # Find similar checks (subset/superset relationships)
    similar_checks = []
    rule_dict = {r.get("rule_id"): r for r in rules}
    
    for i, (rule_id1, rule1) in enumerate(rule_dict.items()):
        fields1 = get_field_paths(rule1)
        if not fields1:
            continue
        
        for rule_id2, rule2 in list(rule_dict.items())[i+1:]:
            if rule_id1 == rule_id2:
                continue
            
            fields2 = get_field_paths(rule2)
            if not fields2:
                continue
            
            # Check subset/superset relationship
            if is_subset(fields1, fields2):
                # rule1 is subset of rule2, keep rule2
                keep_id, remove_id = rule_id2, rule_id1
                keep_rule, remove_rule = rule2, rule1
                keep_fields, remove_fields = fields2, fields1
            elif is_subset(fields2, fields1):
                # rule2 is subset of rule1, keep rule1
                keep_id, remove_id = rule_id1, rule_id2
                keep_rule, remove_rule = rule1, rule2
                keep_fields, remove_fields = fields1, fields2
            else:
                continue
            
            # Check if already in duplicates
            already_handled = False
            for dup_group in duplicates:
                if remove_id in [r["rule_id"] for r in dup_group["remove"]]:
                    already_handled = True
                    break
            
            if already_handled:
                continue
            
            meta1 = metadata_files.get(keep_id, {})
            meta2 = metadata_files.get(remove_id, {})
            compliance1 = extract_compliance_standards(meta1)
            compliance2 = extract_compliance_standards(meta2)
            
            confidence = calculate_consolidation_confidence(keep_rule, remove_rule, keep_fields, remove_fields)
            
            similar_checks.append({
                "keep": {
                    "rule_id": keep_id,
                    "metadata_file": f"{keep_id}.yaml",
                    "reason": f"Superset - checks {len(keep_fields)} fields vs {len(remove_fields)}",
                    "compliance_count": len(compliance1),
                    "compliance": compliance1
                },
                "remove": [{
                    "rule_id": remove_id,
                    "metadata_file": f"{remove_id}.yaml",
                    "replaced_by": keep_id,
                    "reason": f"Subset of {keep_id} - checks only {len(remove_fields)} of {len(keep_fields)} fields",
                    "compliance_count": len(compliance2),
                    "compliance": compliance2,
                    "confidence_percentage": confidence,
                    "review_needed": get_review_needed(confidence),
                    "action": "merge_compliance_to_kept_rule",
                    "compliance_merged": False
                }]
            })
    
    # Cross-service analysis
    cross_service_suggestions = []
    for rule in rules:
        rule_id = rule.get("rule_id", "")
        method = rule.get("python_method", "")
        
        if not method:
            continue
        
        rule_service = extract_service_from_rule_id(rule_id)
        method_service, service_count = check_method_ownership(method)
        
        if method_service and method_service != rule_service:
            is_common = method_service in COMMON_DEPENDENCIES
            confidence = calculate_cross_service_confidence(method_service, rule_service, service_count, is_common)
            
            meta = metadata_files.get(rule_id, {})
            compliance = extract_compliance_standards(meta)
            
            cross_service_suggestions.append({
                "rule_id": rule_id,
                "metadata_file": f"{rule_id}.yaml",
                "current_service": rule_service,
                "suggested_service": method_service,
                "reason": f"Uses {method_service} API methods ({method} is {method_service} method)",
                "python_method": method,
                "confidence_percentage": confidence,
                "review_needed": get_review_needed(confidence),
                "has_compliance": len(compliance) > 0,
                "compliance_count": len(compliance),
                "compliance": compliance,
                "is_common_dependency": is_common,
                "method_ambiguous": service_count > 1,
                "service_count_for_method": service_count
            })
    
    # Generate recommendations
    recommendations = []
    
    if duplicates:
        recommendations.append({
            "priority": "high",
            "action": "consolidate",
            "rule_ids": [r["rule_id"] for dup in duplicates for r in dup["remove"]],
            "description": f"Merge {sum(len(dup['remove']) for dup in duplicates)} duplicate rules checking same fields",
            "impact": "Reduces duplicate rules, improves maintainability"
        })
    
    if similar_checks:
        recommendations.append({
            "priority": "medium",
            "action": "consolidate",
            "rule_ids": [r["rule_id"] for sim in similar_checks for r in sim["remove"]],
            "description": f"Merge {len(similar_checks)} similar rules with subset relationships",
            "impact": "Consolidates overlapping checks"
        })
    
    if cross_service_suggestions:
        recommendations.append({
            "priority": "medium",
            "action": "move",
            "rule_ids": [cs["rule_id"] for cs in cross_service_suggestions],
            "description": f"Move {len(cross_service_suggestions)} rules to appropriate services based on API method ownership",
            "impact": "Better service organization"
        })
    
    # Calculate average confidence scores
    consolidation_confidences = []
    for dup in duplicates:
        consolidation_confidences.extend([r["confidence_percentage"] for r in dup["remove"]])
    for sim in similar_checks:
        consolidation_confidences.extend([r["confidence_percentage"] for r in sim["remove"]])
    
    cross_service_confidences = [cs["confidence_percentage"] for cs in cross_service_suggestions]
    
    avg_consolidation = sum(consolidation_confidences) / len(consolidation_confidences) if consolidation_confidences else 0.0
    avg_cross_service = sum(cross_service_confidences) / len(cross_service_confidences) if cross_service_confidences else 0.0
    
    # Generate output
    output = {
        "service": "sagemaker",
        "review_date": datetime.now().strftime("%Y-%m-%d"),
        "review_summary": {
            "total_rules": len(rules),
            "rules_reviewed": len(rules),
            "consolidation_opportunities": len(duplicates) + len(similar_checks),
            "cross_service_suggestions": len(cross_service_suggestions)
        },
        "consolidation_suggestions": {
            "duplicates": duplicates,
            "similar_checks": similar_checks
        },
        "cross_service_suggestions": cross_service_suggestions,
        "confidence_scores": {
            "consolidation_opportunities": round(avg_consolidation, 1) if avg_consolidation > 0 else 0.0,
            "cross_service_placement": round(avg_cross_service, 1) if avg_cross_service > 0 else 0.0
        },
        "recommendations": recommendations
    }
    
    # Write output
    output_file = SERVICE_PATH / "metadata_review_report.json"
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\nAnalysis complete!")
    print(f"Found {len(duplicates)} duplicate groups")
    print(f"Found {len(similar_checks)} similar check groups")
    print(f"Found {len(cross_service_suggestions)} cross-service suggestions")
    print(f"Report written to: {output_file}")
    
    return output

if __name__ == "__main__":
    main()

