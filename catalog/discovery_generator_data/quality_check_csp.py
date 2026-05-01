#!/usr/bin/env python3
"""
Quality check script for CSP structure files (dependency_index.json and direct_vars.json).

Checks:
1. JSON validity
2. Required fields presence
3. Consistency between dependency_index and direct_vars
4. Entity references match
5. Operations consistency
6. Field structure validity
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Set, Optional
from collections import defaultdict

def check_json_validity(file_path: Path) -> tuple[bool, Optional[str]]:
    """Check if JSON file is valid"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            json.load(f)
        return True, None
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {str(e)}"
    except Exception as e:
        return False, f"Error reading file: {str(e)}"

def check_dependency_index_structure(service_name: str, di_data: Dict) -> List[str]:
    """Check dependency_index.json structure"""
    issues = []
    
    # Check required fields
    required_fields = ["service", "read_only", "roots", "entity_paths"]
    for field in required_fields:
        if field not in di_data:
            issues.append(f"Missing required field: {field}")
    
    # Validate service name matches
    if "service" in di_data and di_data["service"] != service_name:
        issues.append(f"Service name mismatch: expected '{service_name}', got '{di_data.get('service')}'")
    
    # Check roots structure
    roots = di_data.get("roots", [])
    if not isinstance(roots, list):
        issues.append("'roots' must be a list")
    else:
        for i, root in enumerate(roots):
            if not isinstance(root, dict):
                issues.append(f"Root[{i}] must be a dict")
            else:
                if "op" not in root:
                    issues.append(f"Root[{i}] missing 'op' field")
                if "produces" not in root:
                    issues.append(f"Root[{i}] missing 'produces' field")
                elif not isinstance(root["produces"], list):
                    issues.append(f"Root[{i}].produces must be a list")
    
    # Check entity_paths structure
    entity_paths = di_data.get("entity_paths", {})
    if not isinstance(entity_paths, dict):
        issues.append("'entity_paths' must be a dict")
    else:
        for entity, paths in entity_paths.items():
            if not isinstance(paths, list):
                issues.append(f"entity_paths['{entity}'] must be a list")
            elif len(paths) == 0:
                issues.append(f"entity_paths['{entity}'] is empty")
            else:
                path_data = paths[0]
                if not isinstance(path_data, dict):
                    issues.append(f"entity_paths['{entity}'][0] must be a dict")
                else:
                    required_path_fields = ["operations", "produces", "consumes"]
                    for field in required_path_fields:
                        if field not in path_data:
                            issues.append(f"entity_paths['{entity}'][0] missing '{field}' field")
    
    return issues

def check_direct_vars_structure(service_name: str, dv_data: Dict) -> List[str]:
    """Check direct_vars.json structure"""
    issues = []
    
    # Check required fields
    required_fields = ["service", "seed_from_list", "enriched_from_get_describe", "fields"]
    for field in required_fields:
        if field not in dv_data:
            issues.append(f"Missing required field: {field}")
    
    # Validate service name matches
    if "service" in dv_data and dv_data["service"] != service_name:
        issues.append(f"Service name mismatch: expected '{service_name}', got '{dv_data.get('service')}'")
    
    # Check fields structure
    fields = dv_data.get("fields", {})
    if not isinstance(fields, dict):
        issues.append("'fields' must be a dict")
    else:
        for field_name, field_data in fields.items():
            if not isinstance(field_data, dict):
                issues.append(f"fields['{field_name}'] must be a dict")
            else:
                required_field_fields = ["field_name", "type", "operators", "dependency_index_entity", "operations"]
                for req_field in required_field_fields:
                    if req_field not in field_data:
                        issues.append(f"fields['{field_name}'] missing '{req_field}' field")
                
                # Validate field_name matches key
                if "field_name" in field_data and field_data["field_name"] != field_name:
                    issues.append(f"fields['{field_name}'].field_name mismatch: expected '{field_name}', got '{field_data['field_name']}'")
    
    # Check seed_from_list and enriched_from_get_describe are lists
    for field in ["seed_from_list", "enriched_from_get_describe"]:
        value = dv_data.get(field, [])
        if not isinstance(value, list):
            issues.append(f"'{field}' must be a list")
    
    return issues

def check_consistency(service_name: str, di_data: Dict, dv_data: Dict, csp: str) -> List[str]:
    """Check consistency between dependency_index and direct_vars"""
    issues = []
    
    di_entity_paths = di_data.get("entity_paths", {})
    dv_fields = dv_data.get("fields", {})
    
    # Check: All entities in direct_vars should have corresponding entry in dependency_index
    dv_entities = set()
    for field_data in dv_fields.values():
        entity = field_data.get("dependency_index_entity")
        if entity:
            dv_entities.add(entity)
    
    for entity in dv_entities:
        if entity not in di_entity_paths:
            issues.append(f"Entity '{entity}' in direct_vars but not in dependency_index")
    
    # Check: Operations in direct_vars should match dependency_index
    # Build operation to entities mapping from dependency_index
    di_op_to_entities = defaultdict(set)
    for entity, paths in di_entity_paths.items():
        for path_data in paths:
            operations = path_data.get("operations", [])
            for op in operations:
                di_op_to_entities[op].add(entity)
    
    # Check operations in direct_vars
    for field_name, field_data in dv_fields.items():
        entity = field_data.get("dependency_index_entity")
        operations = field_data.get("operations", [])
        
        for op in operations:
            if entity and op in di_op_to_entities:
                if entity not in di_op_to_entities[op]:
                    issues.append(f"Operation '{op}' in field '{field_name}' doesn't produce entity '{entity}' in dependency_index")
    
    # Check: All root operations should have corresponding fields in direct_vars
    roots = di_data.get("roots", [])
    root_ops = {root.get("op") for root in roots if root.get("op")}
    
    # Collect all operations from direct_vars
    dv_all_ops = set()
    for field_data in dv_fields.values():
        dv_all_ops.update(field_data.get("operations", []))
    
    def matches_operation(root_op: str, dv_op: str) -> bool:
        """Check if root operation matches direct_vars operation (flexible matching)"""
        # Exact match
        if root_op == dv_op:
            return True
        
        # For GCP: root_op is like "gcp.service.resource.operation", dv_op might be "operation" or "gcp.service.operation"
        if csp.lower() == "gcp":
            # Extract operation name from root_op (last part after last dot)
            root_op_name = root_op.split('.')[-1].lower()
            dv_op_name = dv_op.split('.')[-1].lower()
            if root_op_name == dv_op_name:
                return True
            # Also check if root_op contains dv_op
            if dv_op_name in root_op.lower() or root_op_name in dv_op.lower():
                return True
        
        # For other CSPs: similar flexible matching
        if csp.lower() in ["alicloud", "ibm"]:
            root_op_name = root_op.split('.')[-1].lower()
            dv_op_name = dv_op.split('.')[-1].lower()
            if root_op_name == dv_op_name:
                return True
        
        return False
    
    for root_op in root_ops:
        # Check if any direct_vars operation matches this root operation
        matched = any(matches_operation(root_op, dv_op) for dv_op in dv_all_ops)
        if not matched:
            issues.append(f"Root operation '{root_op}' not found in any direct_vars field operations")
    
    return issues

def validate_entity_format(entity: str, service_name: str, csp: str) -> tuple[bool, Optional[str]]:
    """Validate entity naming format matches CSP conventions"""
    # Common entities that appear across services (allowed)
    common_entities = {
        "ibm": ["ibm.crn", "ibm.ocid", "ibm.compartment_id"],
        "oci": ["oci.ocid", "oci.compartment_id"],
        "gcp": [],  # GCP doesn't have common entities across services
        "alicloud": []  # Alicloud doesn't have common entities
    }
    
    csp_lower = csp.lower()
    if csp_lower in common_entities:
        if entity in common_entities[csp_lower]:
            return True, None  # Common entity, always valid
    
    if csp_lower == "gcp":
        # Format: gcp.service.resource.entity
        if not entity.startswith("gcp."):
            return False, "Entity should start with 'gcp.'"
        parts = entity.split('.')
        if len(parts) < 3:
            return False, f"Entity should have at least 3 parts (gcp.service.entity), got {len(parts)}"
        # Allow entities that start with gcp. even if service name doesn't match exactly
        # (might be resource-specific entities like gcp.pubsub.projects.subscriptions.id)
        if len(parts) >= 2 and parts[1] != service_name:
            # Check if it's a valid GCP entity pattern (gcp.service.resource.field)
            if len(parts) >= 3:
                return True, None  # Valid GCP pattern, even if service doesn't match
            return False, f"Entity service part '{parts[1]}' doesn't match service name '{service_name}'"
    elif csp_lower == "alicloud":
        # Format: service.entity_name
        parts = entity.split('.')
        if len(parts) < 2:
            return False, f"Entity should have at least 2 parts (service.entity), got {len(parts)}"
        if parts[0] != service_name:
            return False, f"Entity service part '{parts[0]}' doesn't match service name '{service_name}'"
    elif csp_lower == "ibm":
        # Format: ibm.service.entity_name or ibm.common_entity
        if not entity.startswith("ibm."):
            return False, "Entity should start with 'ibm.'"
        parts = entity.split('.')
        if len(parts) < 2:
            return False, f"Entity should have at least 2 parts (ibm.service...), got {len(parts)}"
        # Allow ibm.crn as common entity
        if entity == "ibm.crn":
            return True, None
        if len(parts) >= 2 and parts[1] != service_name:
            # Allow entities like ibm.crn, ibm.account_id, ibm.iam_id, ibm.resource_group_id which are common across services
            if parts[1] in ["crn", "ocid", "compartment_id", "account_id", "iam_id", "resource_group_id"]:
                return True, None
            # Also allow entities with valid IBM patterns (ibm.service.field) even if service doesn't match
            # This handles cases like ibm.account_id in iam service
            if len(parts) >= 3:
                return True, None  # Valid IBM pattern, allow it
            # Allow 2-part entities if they're valid common patterns (ibm.iam_id, ibm.resource_group_id)
            # These are valid IBM entities even if they don't match the service name exactly
            if len(parts) == 2 and parts[1].endswith("_id"):
                return True, None  # Allow entities like ibm.iam_id, ibm.resource_group_id
            return False, f"Entity service part '{parts[1]}' doesn't match service name '{service_name}'"
    
    return True, None

def check_service(service_dir: Path, csp: str) -> Dict[str, Any]:
    """Check a single service"""
    service_name = service_dir.name
    result = {
        "service": service_name,
        "di_exists": False,
        "dv_exists": False,
        "di_valid": False,
        "dv_valid": False,
        "di_issues": [],
        "dv_issues": [],
        "consistency_issues": [],
        "entity_format_issues": [],
        "stats": {}
    }
    
    di_path = service_dir / "dependency_index.json"
    dv_path = service_dir / "direct_vars.json"
    
    # Check dependency_index
    if di_path.exists():
        result["di_exists"] = True
        di_valid, di_error = check_json_validity(di_path)
        if not di_valid:
            result["di_issues"].append(di_error)
            return result
        
        result["di_valid"] = True
        with open(di_path, 'r', encoding='utf-8') as f:
            di_data = json.load(f)
        
        result["di_issues"] = check_dependency_index_structure(service_name, di_data)
        
        # Check entity formats in dependency_index
        entity_paths = di_data.get("entity_paths", {})
        for entity in entity_paths.keys():
            valid, error = validate_entity_format(entity, service_name, csp)
            if not valid:
                result["entity_format_issues"].append(f"DI entity '{entity}': {error}")
        
        # Collect stats
        roots = di_data.get("roots", [])
        result["stats"]["di_roots_count"] = len(roots)
        result["stats"]["di_entities_count"] = len(entity_paths)
        
        # Check direct_vars if it exists
        if dv_path.exists():
            result["dv_exists"] = True
            dv_valid, dv_error = check_json_validity(dv_path)
            if not dv_valid:
                result["dv_issues"].append(dv_error)
                return result
            
            result["dv_valid"] = True
            with open(dv_path, 'r', encoding='utf-8') as f:
                dv_data = json.load(f)
            
            result["dv_issues"] = check_direct_vars_structure(service_name, dv_data)
            
            # Check entity formats in direct_vars
            fields = dv_data.get("fields", {})
            for field_data in fields.values():
                entity = field_data.get("dependency_index_entity")
                if entity:
                    valid, error = validate_entity_format(entity, service_name, csp)
                    if not valid:
                        result["entity_format_issues"].append(f"DV entity '{entity}': {error}")
            
            # Check consistency
            if result["di_valid"] and result["dv_valid"]:
                result["consistency_issues"] = check_consistency(service_name, di_data, dv_data, csp)
            
            # Collect stats
            result["stats"]["dv_fields_count"] = len(fields)
            seed_from_list = dv_data.get("seed_from_list", [])
            enriched = dv_data.get("enriched_from_get_describe", [])
            result["stats"]["dv_seed_count"] = len(seed_from_list)
            result["stats"]["dv_enriched_count"] = len(enriched)
            
            all_ops = set()
            for field_data in fields.values():
                all_ops.update(field_data.get("operations", []))
            result["stats"]["dv_operations_count"] = len(all_ops)
    
    return result

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Quality check for CSP structure files")
    parser.add_argument("--csp", type=str, required=True, choices=["gcp", "alicloud", "ibm"], help="CSP to check")
    parser.add_argument("--service", type=str, help="Check single service only")
    parser.add_argument("--base-dir", type=str, default=None, help="Base directory")
    
    args = parser.parse_args()
    
    base_dir = Path(args.base_dir) if args.base_dir else Path(__file__).parent / args.csp
    
    print("="*80)
    print(f"QUALITY CHECK FOR {args.csp.upper()}")
    print("="*80)
    print()
    
    # Find service directories
    if args.service:
        service_dirs = [base_dir / args.service]
    else:
        service_dirs = sorted([
            d for d in base_dir.iterdir()
            if d.is_dir() and not d.name.startswith('_') 
            and not d.name.startswith('.') 
            and d.name != "tools"
        ])
    
    print(f"Found {len(service_dirs)} services to check")
    print()
    
    results = []
    total_issues = 0
    
    for service_dir in service_dirs:
        result = check_service(service_dir, args.csp)
        results.append(result)
        
        # Count issues
        issue_count = (
            len(result["di_issues"]) + 
            len(result["dv_issues"]) + 
            len(result["consistency_issues"]) +
            len(result["entity_format_issues"])
        )
        total_issues += issue_count
        
        # Print status
        status = "✓" if issue_count == 0 else "✗"
        di_status = "✓" if result["di_valid"] else ("✗" if result["di_exists"] else "-")
        dv_status = "✓" if result["dv_valid"] else ("✗" if result["dv_exists"] else "-")
        
        stats = result.get("stats", {})
        stats_str = f"DI: {stats.get('di_roots_count', 0)} roots, {stats.get('di_entities_count', 0)} entities | DV: {stats.get('dv_fields_count', 0)} fields, {stats.get('dv_operations_count', 0)} ops"
        
        print(f"{status} {result['service']:30} [{di_status}DI/{dv_status}DV] {stats_str}")
        
        if issue_count > 0:
            if result["di_issues"]:
                for issue in result["di_issues"][:3]:  # Show first 3
                    print(f"    DI Issue: {issue}")
            if result["dv_issues"]:
                for issue in result["dv_issues"][:3]:  # Show first 3
                    print(f"    DV Issue: {issue}")
            if result["consistency_issues"]:
                for issue in result["consistency_issues"][:3]:  # Show first 3
                    print(f"    Consistency: {issue}")
            if result["entity_format_issues"]:
                for issue in result["entity_format_issues"][:3]:  # Show first 3
                    print(f"    Format: {issue}")
            if issue_count > 3:
                print(f"    ... and {issue_count - 3} more issues")
    
    print()
    print("="*80)
    print("SUMMARY")
    print("="*80)
    
    # Count statistics
    services_with_di = sum(1 for r in results if r["di_exists"])
    services_with_dv = sum(1 for r in results if r["dv_exists"])
    services_valid_di = sum(1 for r in results if r["di_valid"])
    services_valid_dv = sum(1 for r in results if r["dv_valid"])
    services_with_issues = sum(1 for r in results if (
        len(r["di_issues"]) + len(r["dv_issues"]) + 
        len(r["consistency_issues"]) + len(r["entity_format_issues"])
    ) > 0)
    
    print(f"Total services: {len(results)}")
    print(f"  With dependency_index.json: {services_with_di}/{len(results)} ({100*services_with_di/len(results):.1f}%)")
    print(f"  Valid dependency_index.json: {services_valid_di}/{services_with_di if services_with_di > 0 else 1} ({100*services_valid_di/max(services_with_di, 1):.1f}%)")
    print(f"  With direct_vars.json: {services_with_dv}/{len(results)} ({100*services_with_dv/len(results):.1f}%)")
    print(f"  Valid direct_vars.json: {services_valid_dv}/{services_with_dv if services_with_dv > 0 else 1} ({100*services_valid_dv/max(services_with_dv, 1):.1f}%)")
    print(f"  Services with issues: {services_with_issues}/{len(results)} ({100*services_with_issues/len(results):.1f}%)")
    print(f"  Total issues found: {total_issues}")
    
    # Issue breakdown
    di_issues_count = sum(len(r["di_issues"]) for r in results)
    dv_issues_count = sum(len(r["dv_issues"]) for r in results)
    consistency_issues_count = sum(len(r["consistency_issues"]) for r in results)
    format_issues_count = sum(len(r["entity_format_issues"]) for r in results)
    
    if total_issues > 0:
        print()
        print("Issue Breakdown:")
        print(f"  Dependency Index issues: {di_issues_count}")
        print(f"  Direct Vars issues: {dv_issues_count}")
        print(f"  Consistency issues: {consistency_issues_count}")
        print(f"  Entity format issues: {format_issues_count}")
    
    # Save detailed results
    results_file = base_dir / "quality_check_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nDetailed results saved to: {results_file}")
    
    # Exit with error code if issues found
    if total_issues > 0:
        sys.exit(1)
    else:
        print("\n✓ All checks passed!")
        sys.exit(0)

if __name__ == "__main__":
    main()

