"""
Deduplicate ARNs across operations with priority:
1. Independent operations (highest priority)
2. Operations in YAML discovery_id list (second priority)
3. Other operations (lowest priority)
"""

import json
import yaml
from pathlib import Path
from typing import Dict, List, Set, Optional
from collections import defaultdict

def extract_discovery_ids_from_yaml(yaml_file: Path) -> Set[str]:
    """Extract all discovery_id values from YAML file."""
    
    discovery_ids = set()
    
    if not yaml_file.exists():
        return discovery_ids
    
    try:
        with open(yaml_file, 'r') as f:
            data = yaml.safe_load(f)
        
        discovery = data.get("discovery", [])
        for disc in discovery:
            discovery_id = disc.get("discovery_id")
            if discovery_id:
                discovery_ids.add(discovery_id)
    except Exception as e:
        print(f"  ⚠️  Error reading YAML: {e}")
    
    return discovery_ids

def discovery_id_to_operation(discovery_id: str) -> str:
    """Convert discovery_id to operation name.
    
    Examples:
    - aws.accessanalyzer.list_analyzers -> ListAnalyzers
    - aws.s3.list_buckets -> ListBuckets
    - aws.ec2.describe_instances -> DescribeInstances
    """
    
    # Remove aws.{service}. prefix
    parts = discovery_id.split('.')
    if len(parts) >= 3:
        operation_part = parts[2]  # e.g., "list_analyzers"
        
        # Convert snake_case to PascalCase
        words = operation_part.split('_')
        operation = ''.join(word.capitalize() for word in words)
        
        return operation
    
    return discovery_id

def get_yaml_operations(service_name: str, services_dir: Path) -> Set[str]:
    """Get all operations from YAML discovery_id list."""
    
    service_yaml_dir = services_dir / service_name / "rules"
    yaml_file = service_yaml_dir / f"{service_name}.yaml"
    
    discovery_ids = extract_discovery_ids_from_yaml(yaml_file)
    operations = set()
    
    for disc_id in discovery_ids:
        op = discovery_id_to_operation(disc_id)
        operations.add(op)
    
    return operations

def prioritize_operations_for_arn(
    arn_entity: str,
    operations_producing_arn: List[Dict],
    root_operations: List[str],
    yaml_operations: Set[str]
) -> Optional[Dict]:
    """Select the best operation for an ARN based on priority."""
    
    if not operations_producing_arn:
        return None
    
    # Separate by priority
    independent_ops = []
    yaml_ops = []
    other_ops = []
    
    for op_info in operations_producing_arn:
        operation = op_info["operation"]
        op_data = {
            "operation": operation,
            "field_name": op_info.get("field_name", "unknown"),
            "is_primary": op_info.get("is_primary_resource", False)
        }
        
        if operation in root_operations:
            independent_ops.append(op_data)
        elif operation in yaml_operations:
            yaml_ops.append(op_data)
        else:
            other_ops.append(op_data)
    
    # Priority 1: Independent operations
    if independent_ops:
        # Prefer primary resource ARNs
        primary_ops = [op for op in independent_ops if op["is_primary"]]
        if primary_ops:
            return primary_ops[0]
        return independent_ops[0]
    
    # Priority 2: YAML operations
    if yaml_ops:
        # Prefer primary resource ARNs
        primary_ops = [op for op in yaml_ops if op["is_primary"]]
        if primary_ops:
            return primary_ops[0]
        return yaml_ops[0]
    
    # Priority 3: Other operations
    if other_ops:
        # Prefer primary resource ARNs
        primary_ops = [op for op in other_ops if op["is_primary"]]
        if primary_ops:
            return primary_ops[0]
        return other_ops[0]
    
    return None

def deduplicate_arns_in_operations(
    minimal_ops_data: Dict,
    root_operations: List[str],
    yaml_operations: Set[str]
) -> Dict:
    """Deduplicate ARNs and select best operation for each ARN."""
    
    # Build ARN to operations mapping
    arn_to_operations = defaultdict(list)
    
    for op_info in minimal_ops_data.get("minimal_operations", {}).get("selected_operations", []):
        operation = op_info["operation"]
        arns_produced = op_info.get("arns_produced", [])
        
        for arn_info in arns_produced:
            arn_entity = arn_info["arn_entity"]
            arn_to_operations[arn_entity].append({
                "operation": operation,
                "field_name": arn_info.get("field_name", "unknown"),
                "is_primary_resource": arn_info.get("is_primary_resource", False),
                "resource_type": arn_info.get("resource_type"),
                "classification": arn_info.get("classification"),
                "should_inventory": arn_info.get("should_inventory", False)
            })
    
    # Select best operation for each ARN
    arn_selections = {}
    for arn_entity, operations in arn_to_operations.items():
        selected = prioritize_operations_for_arn(
            arn_entity,
            operations,
            root_operations,
            yaml_operations
        )
        if selected:
            arn_selections[arn_entity] = selected
    
    # Update operations to only show selected ARNs
    updated_operations = []
    arn_operation_map = {}  # Track which operation was selected for each ARN
    
    for arn_entity, selected_op in arn_selections.items():
        if arn_entity not in arn_operation_map:
            arn_operation_map[arn_entity] = selected_op["operation"]
    
    # Rebuild operations list with deduplicated ARNs
    operation_arns_map = defaultdict(list)
    for arn_entity, selected_op in arn_selections.items():
        operation_arns_map[selected_op["operation"]].append({
            "arn_entity": arn_entity,
            "field_name": selected_op["field_name"],
            "is_primary_resource": any(op.get("is_primary_resource") for op in arn_to_operations[arn_entity]),
            "resource_type": next((op.get("resource_type") for op in arn_to_operations[arn_entity]), None),
            "classification": next((op.get("classification") for op in arn_to_operations[arn_entity]), None),
            "should_inventory": any(op.get("should_inventory") for op in arn_to_operations[arn_entity]),
            "selected_reason": "INDEPENDENT" if selected_op["operation"] in root_operations else 
                              "YAML_DISCOVERY" if selected_op["operation"] in yaml_operations else 
                              "OTHER"
        })
    
    # Update each operation with only its selected ARNs
    for op_info in minimal_ops_data.get("minimal_operations", {}).get("selected_operations", []):
        operation = op_info["operation"]
        updated_op = op_info.copy()
        
        # Only include ARNs that were selected for this operation
        selected_arns = operation_arns_map.get(operation, [])
        updated_op["arns_produced"] = selected_arns
        updated_op["arn_count"] = len(selected_arns)
        updated_op["primary_arn_count"] = sum(1 for a in selected_arns if a["is_primary_resource"])
        
        # Add priority info
        if operation in root_operations:
            updated_op["priority"] = "INDEPENDENT"
        elif operation in yaml_operations:
            updated_op["priority"] = "YAML_DISCOVERY"
        else:
            updated_op["priority"] = "OTHER"
        
        updated_operations.append(updated_op)
    
    # Create ARN summary with deduplication info
    total_unique_arns = len(arn_selections)
    primary_arns = sum(1 for a in arn_selections.values() if any(
        op.get("is_primary_resource") for op in arn_to_operations.get(list(arn_selections.keys())[list(arn_selections.values()).index(a)], [])
    ))
    
    # Build deduplication report
    deduplication_report = {}
    for arn_entity, operations in arn_to_operations.items():
        selected = arn_selections.get(arn_entity)
        if selected:
            deduplication_report[arn_entity] = {
                "selected_operation": selected["operation"],
                "selected_field_name": selected["field_name"],
                "priority": "INDEPENDENT" if selected["operation"] in root_operations else 
                           "YAML_DISCOVERY" if selected["operation"] in yaml_operations else 
                           "OTHER",
                "all_available_operations": [op["operation"] for op in operations],
                "operation_count": len(operations)
            }
    
    minimal_ops_data["minimal_operations"]["selected_operations"] = updated_operations
    minimal_ops_data["arn_summary"]["total_unique_arns"] = total_unique_arns
    minimal_ops_data["arn_summary"]["deduplicated"] = True
    minimal_ops_data["arn_deduplication"] = deduplication_report
    
    return minimal_ops_data

def process_service(service_name: str, aws_dir: Path, services_dir: Path) -> bool:
    """Process a single service to deduplicate ARNs."""
    
    service_dir = aws_dir / service_name
    minimal_ops_file = service_dir / "minimal_operations_list.json"
    
    if not minimal_ops_file.exists():
        print(f"  ⚠️  minimal_operations_list.json not found")
        return False
    
    try:
        with open(minimal_ops_file, 'r') as f:
            minimal_ops_data = json.load(f)
    except Exception as e:
        print(f"  ❌ Error reading file: {e}")
        return False
    
    # Get root operations
    root_operations = minimal_ops_data.get("root_operations_available", [])
    
    # Get YAML operations
    yaml_operations = get_yaml_operations(service_name, services_dir)
    
    print(f"    Root Operations: {len(root_operations)}")
    print(f"    YAML Discovery Operations: {len(yaml_operations)}")
    
    # Deduplicate
    updated_data = deduplicate_arns_in_operations(
        minimal_ops_data,
        root_operations,
        yaml_operations
    )
    
    # Save updated file
    with open(minimal_ops_file, 'w') as f:
        json.dump(updated_data, f, indent=2)
    
    # Print summary
    arn_summary = updated_data.get("arn_summary", {})
    dedup_report = updated_data.get("arn_deduplication", {})
    
    print(f"    Total Unique ARNs: {arn_summary.get('total_unique_arns', 0)}")
    print(f"    Primary Resource ARNs: {arn_summary.get('primary_resource_arns', 0)}")
    
    # Show selection breakdown
    priority_counts = defaultdict(int)
    for arn_info in dedup_report.values():
        priority_counts[arn_info["priority"]] += 1
    
    print(f"    ARN Selection by Priority:")
    for priority, count in sorted(priority_counts.items()):
        print(f"      {priority}: {count}")
    
    return True

def process_all_services(aws_dir: str, services_dir: str, services: List[str]):
    """Process all services to deduplicate ARNs."""
    
    aws_path = Path(aws_dir)
    services_path = Path(services_dir)
    
    print("=" * 80)
    print("DEDUPLICATING ARNS WITH PRIORITY")
    print("=" * 80)
    print("\nPriority Order:")
    print("  1. Independent (Root) Operations")
    print("  2. YAML Discovery Operations")
    print("  3. Other Operations")
    print("")
    
    for service_name in services:
        print(f"{'='*80}")
        print(f"Processing: {service_name.upper()}")
        print(f"{'='*80}")
        
        if process_service(service_name, aws_path, services_path):
            print(f"  ✅ Successfully deduplicated")
        else:
            print(f"  ❌ Failed to process")
    
    print(f"\n\n{'='*80}")
    print("DEDUPLICATION COMPLETE")
    print(f"{'='*80}")

if __name__ == "__main__":
    aws_dir = "/Users/apple/Desktop/threat-engine/pythonsdk-database/aws"
    services_dir = "/Users/apple/Desktop/threat-engine/configScan_engines/aws-configScan-engine/services"
    services_to_process = ["accessanalyzer", "ec2", "s3", "iam"]
    
    process_all_services(aws_dir, services_dir, services_to_process)

