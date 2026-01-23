#!/usr/bin/env python3
"""
SES Metadata Review Analysis Script
Analyzes ses service metadata for consolidation and cross-service placement opportunities.
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
BOTO3_DEPS_FILE = Path("/Users/apple/Desktop/threat-engine/pythonsdk-database/aws/ses/boto3_dependencies_with_python_names_fully_enriched.json")

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
        rule_id = yaml_file.stem
        with open(yaml_file, 'r') as f:
            data = yaml.safe_load(f)
            metadata[rule_id] = data
    return metadata

def check_method_ownership(method: str) -> Tuple[Optional[str], int]:
    """Check which service(s) a method belongs to"""
    if not BOTO3_DEPS_FILE.exists():
        return None, 0
    
    try:
        with open(BOTO3_DEPS_FILE, 'r') as f:
            boto3_data = json.load(f)
        
        # Check if method exists in ses service
        ses_ops = boto3_data.get("ses", {}).get("operations", [])
        ses_has_method = any(
            op.get("python_method") == method 
            for op in ses_ops
        )
        
        # Count how many services have this method
        service_count = 0
        for service_name, service_data in boto3_data.items():
            if service_name == "ses":
                continue
            ops = service_data.get("operations", [])
            if any(op.get("python_method") == method for op in ops):
                service_count += 1
                if service_count == 1:
                    first_other_service = service_name
        
        if ses_has_method:
            if service_count > 0:
                return "ses", service_count + 1  # Ambiguous
            return "ses", 1  # Only in ses
        elif service_count > 0:
            return first_other_service, service_count  # Not in ses, in other service(s)
        else:
            return None, 0  # Not found
    except Exception as e:
        print(f"Error checking method ownership: {e}")
        return None, 0

def extract_service_from_rule_id(rule_id: str) -> str:
    """Extract service name from rule_id (e.g., aws.ses.email.x -> ses)"""
    parts = rule_id.split(".")
    if len(parts) >= 2 and parts[0] == "aws":
        return parts[1]
    return ""

def analyze_consolidation(mapping_data: List[Dict], metadata: Dict[str, Dict]) -> Dict:
    """Analyze consolidation opportunities"""
    # Group rules by normalized signature
    signature_groups = defaultdict(list)
    
    for rule in mapping_data:
        rule_id = rule.get("rule_id")
        signature = normalize_check_signature(rule)
        signature_groups[signature].append({
            "rule_id": rule_id,
            "rule": rule,
            "metadata": metadata.get(rule_id, {})
        })
    
    duplicates = []
    similar_checks = []
    
    for signature, rules in signature_groups.items():
        if len(rules) > 1:
            # Exact duplicates
            # Sort by compliance count (descending)
            rules_sorted = sorted(
                rules,
                key=lambda x: len(x.get("metadata", {}).get("compliance", [])),
                reverse=True
            )
            
            keep = rules_sorted[0]
            remove_list = []
            
            for remove_rule in rules_sorted[1:]:
                keep_compliance = set(keep["metadata"].get("compliance", []))
                remove_compliance = set(remove_rule["metadata"].get("compliance", []))
                
                # Calculate confidence
                if signature == normalize_check_signature(remove_rule["rule"]):
                    confidence = 95.0  # Exact duplicate
                else:
                    confidence = 88.0  # Very similar
                
                remove_list.append({
                    "rule_id": remove_rule["rule_id"],
                    "metadata_file": f"{remove_rule['rule_id']}.yaml",
                    "replaced_by": keep["rule_id"],
                    "reason": "Exact duplicate check signature",
                    "compliance_count": len(remove_compliance),
                    "compliance": list(remove_compliance),
                    "confidence_percentage": confidence,
                    "review_needed": "none" if confidence >= 90 else "optional",
                    "action": "merge_compliance_to_kept_rule",
                    "compliance_merged": False
                })
            
            if remove_list:
                duplicates.append({
                    "keep": {
                        "rule_id": keep["rule_id"],
                        "metadata_file": f"{keep['rule_id']}.yaml",
                        "reason": "More comprehensive (checks all fields)",
                        "compliance_count": len(keep["metadata"].get("compliance", [])),
                        "compliance": keep["metadata"].get("compliance", [])
                    },
                    "remove": remove_list
                })
    
    # Track rules already marked for removal to avoid circular dependencies
    removed_rule_ids = set()
    for dup in duplicates:
        removed_rule_ids.update(r["rule_id"] for r in dup["remove"])
    
    # Check for field subset/superset relationships
    for i, rule1 in enumerate(mapping_data):
        rule_id1 = rule1.get("rule_id")
        if rule_id1 in removed_rule_ids:
            continue
            
        for j, rule2 in enumerate(mapping_data[i+1:], start=i+1):
            rule_id2 = rule2.get("rule_id")
            if rule_id2 in removed_rule_ids:
                continue
            
            if rule1.get("python_method") != rule2.get("python_method"):
                continue
            if rule1.get("response_path") != rule2.get("response_path"):
                continue
            
            # Create full field signatures (including operator and values) for proper comparison
            fields1 = set()
            for f in rule1.get("nested_field", []):
                field_sig = f"{f.get('field_path', '')}:{f.get('operator', '')}:{f.get('expected_value', '')}:{f.get('value', '')}"
                fields1.add(field_sig)
            
            fields2 = set()
            for f in rule2.get("nested_field", []):
                field_sig = f"{f.get('field_path', '')}:{f.get('operator', '')}:{f.get('expected_value', '')}:{f.get('value', '')}"
                fields2.add(field_sig)
            
            # Only consider true subset relationships (not equal sets)
            if fields1.issubset(fields2) and fields1 != fields2:
                keep_id, remove_id = rule_id2, rule_id1
                keep_meta, remove_meta = metadata.get(rule_id2, {}), metadata.get(rule_id1, {})
                keep_compliance, remove_compliance = len(keep_meta.get("compliance", [])), len(remove_meta.get("compliance", []))
            elif fields2.issubset(fields1) and fields1 != fields2:
                keep_id, remove_id = rule_id1, rule_id2
                keep_meta, remove_meta = metadata.get(rule_id1, {}), metadata.get(rule_id2, {})
                keep_compliance, remove_compliance = len(keep_meta.get("compliance", [])), len(remove_meta.get("compliance", []))
            else:
                continue  # Not a subset relationship
            
            # Check if already handled
            already_handled = False
            for dup in duplicates:
                if remove_id in [r["rule_id"] for r in dup["remove"]]:
                    already_handled = True
                    break
            for sim in similar_checks:
                if remove_id in [r["rule_id"] for r in sim["remove"]]:
                    already_handled = True
                    break
            
            if not already_handled:
                keep_fields = fields1 if keep_id == rule_id1 else fields2
                remove_fields = fields2 if keep_id == rule_id1 else fields1
                
                similar_checks.append({
                    "keep": {
                        "rule_id": keep_id,
                        "metadata_file": f"{keep_id}.yaml",
                        "reason": f"Superset - checks {len(keep_fields)} fields vs {len(remove_fields)}",
                        "compliance_count": keep_compliance,
                        "compliance": keep_meta.get("compliance", [])
                    },
                    "remove": [{
                        "rule_id": remove_id,
                        "metadata_file": f"{remove_id}.yaml",
                        "replaced_by": keep_id,
                        "reason": f"Subset - checks only {len(remove_fields)} of {len(keep_fields)} fields",
                        "compliance_count": remove_compliance,
                        "compliance": remove_meta.get("compliance", []),
                        "confidence_percentage": 88.0,
                        "review_needed": "optional",
                        "action": "merge_compliance_to_kept_rule",
                        "compliance_merged": False
                    }]
                })
                removed_rule_ids.add(remove_id)
    
    return {
        "duplicates": duplicates,
        "similar_checks": similar_checks
    }

def analyze_cross_service(mapping_data: List[Dict], metadata: Dict[str, Dict]) -> List[Dict]:
    """Analyze cross-service placement opportunities"""
    suggestions = []
    
    for rule in mapping_data:
        rule_id = rule.get("rule_id")
        method = rule.get("python_method")
        service_from_rule = extract_service_from_rule_id(rule_id)
        
        method_service, service_count = check_method_ownership(method)
        meta = metadata.get(rule_id, {})
        
        # Check if method belongs to different service
        if method_service and method_service != "ses":
            # Cross-service suggestion
            confidence = 95.0 if service_count == 1 else 80.0
            is_common = method_service in ["iam", "s3", "kms", "cloudwatch", "cloudtrail", "acm"]
            if is_common:
                confidence = 95.0
            
            suggestions.append({
                "rule_id": rule_id,
                "metadata_file": f"{rule_id}.yaml",
                "current_service": "ses",
                "suggested_service": method_service,
                "reason": f"Uses {method_service} API method ({method})",
                "python_method": method,
                "confidence_percentage": confidence,
                "review_needed": "none" if confidence >= 90 else "optional",
                "has_compliance": len(meta.get("compliance", [])) > 0,
                "compliance_count": len(meta.get("compliance", [])),
                "compliance": meta.get("compliance", []),
                "is_common_dependency": is_common,
                "method_ambiguous": service_count > 1,
                "service_count_for_method": service_count
            })
        elif method_service == "ses" and service_count > 1:
            # Method exists in ses but also in other services (ambiguous)
            suggestions.append({
                "rule_id": rule_id,
                "metadata_file": f"{rule_id}.yaml",
                "current_service": "ses",
                "suggested_service": "ses",
                "reason": f"Method {method} exists in ses but also in {service_count-1} other service(s) - verify correct usage",
                "python_method": method,
                "confidence_percentage": 75.0,
                "review_needed": "optional",
                "has_compliance": len(meta.get("compliance", [])) > 0,
                "compliance_count": len(meta.get("compliance", [])),
                "compliance": meta.get("compliance", []),
                "is_common_dependency": False,
                "method_ambiguous": True,
                "service_count_for_method": service_count
            })
    
    return suggestions

def main():
    """Main analysis function"""
    print("Loading metadata mapping...")
    with open(METADATA_MAPPING_FILE, 'r') as f:
        mapping_data = json.load(f)["ses_metadata_mapping"]
    
    print("Loading metadata YAML files...")
    metadata = load_metadata_files()
    
    print("Analyzing consolidation opportunities...")
    consolidation = analyze_consolidation(mapping_data, metadata)
    
    print("Analyzing cross-service placements...")
    cross_service = analyze_cross_service(mapping_data, metadata)
    
    # Calculate summary
    total_rules = len(mapping_data)
    consolidation_count = len(consolidation["duplicates"]) + len(consolidation["similar_checks"])
    cross_service_count = len([s for s in cross_service if s.get("suggested_service") != "ses"])
    
    # Calculate confidence scores
    if consolidation_count > 0:
        consolidation_confidence = sum(
            [r.get("confidence_percentage", 0) for dup in consolidation["duplicates"] 
             for r in dup.get("remove", [])] +
            [r.get("confidence_percentage", 0) for sim in consolidation["similar_checks"]
             for r in sim.get("remove", [])]
        ) / sum(
            [len(dup.get("remove", [])) for dup in consolidation["duplicates"]] +
            [len(sim.get("remove", [])) for sim in consolidation["similar_checks"]]
        )
    else:
        consolidation_confidence = 0.0
    
    if cross_service_count > 0:
        cross_service_confidence = sum(
            s.get("confidence_percentage", 0) 
            for s in cross_service 
            if s.get("suggested_service") != "ses"
        ) / cross_service_count
    else:
        cross_service_confidence = 0.0
    
    # Generate recommendations
    recommendations = []
    
    if consolidation["duplicates"]:
        recommendations.append({
            "priority": "high",
            "action": "consolidate",
            "rule_ids": [
                r["rule_id"] 
                for dup in consolidation["duplicates"]
                for r in dup["remove"]
            ],
            "description": f"Merge {sum(len(dup['remove']) for dup in consolidation['duplicates'])} duplicate rules",
            "impact": "Reduces duplicate rules, improves maintainability"
        })
    
    if consolidation["similar_checks"]:
        recommendations.append({
            "priority": "medium",
            "action": "consolidate",
            "rule_ids": [
                r["rule_id"]
                for sim in consolidation["similar_checks"]
                for r in sim["remove"]
            ],
            "description": f"Merge {sum(len(sim['remove']) for sim in consolidation['similar_checks'])} similar rules with field subset relationships",
            "impact": "Consolidates overlapping checks"
        })
    
    if cross_service_count > 0:
        recommendations.append({
            "priority": "high",
            "action": "move",
            "rule_ids": [
                s["rule_id"]
                for s in cross_service
                if s.get("suggested_service") != "ses"
            ],
            "description": f"Move {cross_service_count} rule(s) to appropriate service(s)",
            "impact": "Better service organization and API method alignment"
        })
    
    # Generate final report
    report = {
        "service": "ses",
        "review_date": datetime.now().strftime("%Y-%m-%d"),
        "review_summary": {
            "total_rules": total_rules,
            "rules_reviewed": total_rules,
            "consolidation_opportunities": consolidation_count,
            "cross_service_suggestions": cross_service_count
        },
        "consolidation_suggestions": {
            "duplicates": consolidation["duplicates"],
            "similar_checks": consolidation["similar_checks"]
        },
        "cross_service_suggestions": cross_service,
        "confidence_scores": {
            "consolidation_opportunities": round(consolidation_confidence, 1),
            "cross_service_placement": round(cross_service_confidence, 1)
        },
        "recommendations": recommendations
    }
    
    # Output JSON
    output_file = SERVICE_PATH / "metadata_review_report.json"
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nReview complete! Report saved to: {output_file}")
    print(f"Summary:")
    print(f"  - Total rules: {total_rules}")
    print(f"  - Consolidation opportunities: {consolidation_count}")
    print(f"  - Cross-service suggestions: {cross_service_count}")
    
    return report

if __name__ == "__main__":
    main()






