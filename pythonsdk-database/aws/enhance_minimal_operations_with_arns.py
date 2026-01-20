"""
Enhance minimal_operations_list.json with ARN information:
- ARNs produced by each operation
- Whether each ARN is from a primary resource
- Actual ARN field names from boto3 operations
"""

import json
from pathlib import Path
from typing import Dict, List, Set, Optional
from collections import defaultdict

def get_arn_entities_from_operation(operation: str, dependency_index: Dict) -> List[str]:
    """Get all ARN entities produced by an operation."""
    
    arn_entities = []
    
    # Check root operations
    roots = dependency_index.get("roots", [])
    for root in roots:
        if root.get("op") == operation:
            produces = root.get("produces", [])
            arn_entities.extend([e for e in produces if "_arn" in e.lower()])
    
    # Check entity_paths
    entity_paths = dependency_index.get("entity_paths", {})
    for entity_name, paths in entity_paths.items():
        if "_arn" not in entity_name.lower():
            continue
        
        for path_data in paths:
            if operation in path_data.get("operations", []):
                produces = path_data.get("produces", {})
                if operation in produces:
                    if entity_name in produces[operation]:
                        arn_entities.append(entity_name)
                # Also check if the entity itself is produced
                if entity_name not in arn_entities:
                    arn_entities.append(entity_name)
    
    return sorted(list(set(arn_entities)))

def get_arn_field_name_from_boto3(operation: str, arn_entity: str, boto3_data: Dict) -> Optional[str]:
    """Get the actual ARN field name from boto3 operation response."""
    
    service_name = list(boto3_data.keys())[0] if boto3_data else None
    if not service_name:
        return None
    
    operations = boto3_data.get(service_name, {}).get("independent", []) + \
                 boto3_data.get(service_name, {}).get("dependent", [])
    
    for op_data in operations:
        if op_data.get("operation") == operation:
            item_fields = op_data.get("item_fields", {})
            
            # Look for ARN fields
            for field_name, field_data in item_fields.items():
                field_lower = field_name.lower()
                # Check if this field is an ARN
                if "arn" in field_lower or field_lower.endswith("arn"):
                    # Try to match with entity
                    entity_suffix = arn_entity.split(".")[-1].replace("_arn", "")
                    field_suffix = field_name.lower().replace("arn", "").replace("_", "")
                    
                    # Direct match or partial match
                    if entity_suffix in field_suffix or field_suffix in entity_suffix:
                        return field_name
            
            # If no match, return first ARN field found
            for field_name, field_data in item_fields.items():
                if "arn" in field_name.lower():
                    return field_name
    
    return None

def get_resource_info_for_arn(arn_entity: str, resource_inventory: Dict) -> Optional[Dict]:
    """Get resource information for an ARN entity."""
    
    for resource in resource_inventory.get("resources", []):
        if resource.get("arn_entity") == arn_entity:
            return {
                "resource_type": resource.get("resource_type"),
                "classification": resource.get("classification"),
                "is_primary": resource.get("classification") == "PRIMARY_RESOURCE",
                "should_inventory": resource.get("should_inventory", False)
            }
    
    return None

def enhance_operation_with_arns(
    operation_info: Dict,
    dependency_index: Dict,
    resource_inventory: Dict,
    boto3_data: Dict
) -> Dict:
    """Enhance operation info with ARN details."""
    
    operation = operation_info["operation"]
    
    # Get ARN entities produced by this operation
    arn_entities = get_arn_entities_from_operation(operation, dependency_index)
    
    arns_produced = []
    for arn_entity in arn_entities:
        # Get resource info
        resource_info = get_resource_info_for_arn(arn_entity, resource_inventory)
        
        # Get actual field name from boto3
        field_name = get_arn_field_name_from_boto3(operation, arn_entity, boto3_data)
        
        arn_info = {
            "arn_entity": arn_entity,
            "field_name": field_name or "unknown",
            "is_primary_resource": resource_info.get("is_primary", False) if resource_info else False,
            "resource_type": resource_info.get("resource_type") if resource_info else None,
            "classification": resource_info.get("classification") if resource_info else None,
            "should_inventory": resource_info.get("should_inventory", False) if resource_info else False
        }
        
        arns_produced.append(arn_info)
    
    # Add to operation info
    enhanced = operation_info.copy()
    enhanced["arns_produced"] = arns_produced
    enhanced["arn_count"] = len(arns_produced)
    enhanced["primary_arn_count"] = sum(1 for a in arns_produced if a["is_primary_resource"])
    
    return enhanced

def enhance_minimal_operations_list(service_name: str, service_dir: Path) -> bool:
    """Enhance minimal_operations_list.json with ARN information."""
    
    minimal_ops_file = service_dir / "minimal_operations_list.json"
    dependency_index_file = service_dir / "dependency_index.json"
    resource_inventory_file = service_dir / "resource_inventory_report.json"
    boto3_file = service_dir / "boto3_dependencies_with_python_names_fully_enriched.json"
    
    if not minimal_ops_file.exists():
        print(f"  ⚠️  minimal_operations_list.json not found")
        return False
    
    try:
        with open(minimal_ops_file, 'r') as f:
            minimal_ops = json.load(f)
        
        with open(dependency_index_file, 'r') as f:
            dependency_index = json.load(f)
        
        with open(resource_inventory_file, 'r') as f:
            resource_inventory = json.load(f)
        
        boto3_data = {}
        if boto3_file.exists():
            with open(boto3_file, 'r') as f:
                boto3_data = json.load(f)
    except Exception as e:
        print(f"  ❌ Error reading files: {e}")
        return False
    
    # Enhance each operation
    enhanced_operations = []
    for op_info in minimal_ops.get("minimal_operations", {}).get("selected_operations", []):
        enhanced = enhance_operation_with_arns(
            op_info,
            dependency_index,
            resource_inventory,
            boto3_data
        )
        enhanced_operations.append(enhanced)
    
    # Update the structure
    minimal_ops["minimal_operations"]["selected_operations"] = enhanced_operations
    
    # Add summary
    total_arns = sum(op["arn_count"] for op in enhanced_operations)
    total_primary_arns = sum(op["primary_arn_count"] for op in enhanced_operations)
    
    minimal_ops["arn_summary"] = {
        "total_arns_produced": total_arns,
        "primary_resource_arns": total_primary_arns,
        "other_arns": total_arns - total_primary_arns
    }
    
    # Save enhanced file
    with open(minimal_ops_file, 'w') as f:
        json.dump(minimal_ops, f, indent=2)
    
    return True

def enhance_all_services(aws_dir: str, services: List[str]):
    """Enhance minimal operations lists for all services."""
    
    aws_path = Path(aws_dir)
    
    print("=" * 80)
    print("ENHANCING MINIMAL OPERATIONS LISTS WITH ARN INFORMATION")
    print("=" * 80)
    
    for service_name in services:
        print(f"\n{'='*80}")
        print(f"Processing: {service_name.upper()}")
        print(f"{'='*80}")
        
        service_dir = aws_path / service_name
        
        if enhance_minimal_operations_list(service_name, service_dir):
            # Read back to show summary
            try:
                with open(service_dir / "minimal_operations_list.json", 'r') as f:
                    data = json.load(f)
                
                arn_summary = data.get("arn_summary", {})
                print(f"  ✅ Enhanced successfully")
                print(f"\n  ARN Summary:")
                print(f"    Total ARNs Produced: {arn_summary.get('total_arns_produced', 0)}")
                print(f"    Primary Resource ARNs: {arn_summary.get('primary_resource_arns', 0)}")
                print(f"    Other ARNs: {arn_summary.get('other_arns', 0)}")
                
                # Show sample
                ops = data.get("minimal_operations", {}).get("selected_operations", [])
                if ops:
                    first_op = ops[0]
                    print(f"\n  Sample - {first_op['operation']}:")
                    print(f"    ARNs Produced: {first_op.get('arn_count', 0)}")
                    for arn in first_op.get("arns_produced", [])[:3]:
                        primary_marker = "✅ PRIMARY" if arn["is_primary_resource"] else "❌"
                        print(f"      {primary_marker} {arn['arn_entity']} -> field: {arn['field_name']}")
            except Exception as e:
                print(f"  ⚠️  Could not read summary: {e}")
        else:
            print(f"  ❌ Failed to enhance")

if __name__ == "__main__":
    aws_dir = "/Users/apple/Desktop/threat-engine/pythonsdk-database/aws"
    services_to_enhance = ["accessanalyzer", "ec2", "s3", "iam"]
    
    enhance_all_services(aws_dir, services_to_enhance)
    
    print(f"\n\n{'='*80}")
    print("ENHANCEMENT COMPLETE")
    print(f"{'='*80}")

