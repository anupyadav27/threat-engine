#!/usr/bin/env python3
"""
Generate direct_vars.json for Kubernetes resources from k8s_dependencies_with_python_names_fully_enriched.json

This script:
1. Extracts fields from K8s SDK dependencies (read operations)
2. Maps fields to operations
3. Generates direct_vars.json matching standard structure
4. Links to dependency_index entities (if dependency_index.json exists)
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Set, Optional
from collections import defaultdict

def is_read_operation(op: Dict) -> bool:
    """Check if operation is a read operation"""
    http_method = op.get("http_method", "").upper()
    op_name = op.get("operation", "").lower()
    return http_method == "GET" or op_name in ["list", "get", "read", "watch"]

def to_snake_case(name: str) -> str:
    """Convert CamelCase to snake_case"""
    name = name.replace('-', '_')
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def generate_discovery_id(resource_name: str, operation_name: str) -> str:
    """Generate discovery ID from resource and operation name"""
    op_snake = to_snake_case(operation_name)
    return f"k8s.{resource_name}.{op_snake}"

def create_dependency_index_entity(resource_name: str, field_path: str) -> str:
    """Create dependency_index entity name from field path - ensures k8s. prefix"""
    # Field path might already be like "metadata.name" or "spec.containers"
    # Convert to entity format: k8s.resource.field_path
    entity = f"{resource_name}.{field_path}"
    # Ensure k8s. prefix
    if not entity.startswith("k8s."):
        return f"k8s.{entity}"
    return entity

def extract_field_name_from_path(field_path: str) -> str:
    """Extract simple field name from field path (e.g., 'metadata.name' -> 'name')"""
    # Take last part of path
    parts = field_path.split('.')
    # Handle array notation like "containers[].name"
    last_part = parts[-1]
    if '[]' in last_part:
        last_part = last_part.replace('[]', '')
    return last_part

def infer_field_operators(field_type: str, field_path: str) -> List[str]:
    """Infer operators based on field type and path"""
    operators = ["equals", "not_equals", "exists"]
    
    if field_type == "array":
        operators.extend(["contains", "not_empty"])
    elif field_type in ["string", "number", "integer"]:
        operators.extend(["contains", "in", "not_in"])
    elif field_type == "boolean":
        operators.extend(["is_true", "is_false"])
    
    # Add compliance-specific operators based on path
    if "security" in field_path.lower() or "privilege" in field_path.lower():
        operators.extend(["is_true", "is_false"])
    
    return operators

def extract_fields_from_operations(resource_data: Dict, resource_name: str) -> Dict[str, Dict[str, Any]]:
    """Extract all fields from read operations in K8s SDK dependencies"""
    fields = {}
    field_to_operations = defaultdict(list)
    
    # K8s structure: independent/dependent operations
    independent_ops = resource_data.get("independent", [])
    dependent_ops = resource_data.get("dependent", [])
    
    all_read_operations = []
    for op in independent_ops + dependent_ops:
        if is_read_operation(op):
            all_read_operations.append(op)
    
    # Process each read operation to extract fields
    for op in all_read_operations:
        op_name = op.get("operation", "")
        if not op_name:
            continue
        
        # Get item_fields (fields in list items)
        item_fields = op.get("item_fields", {})
        if isinstance(item_fields, dict):
            for field_path, field_data in item_fields.items():
                if not isinstance(field_data, dict):
                    continue
                
                # Extract simple field name
                field_name = extract_field_name_from_path(field_path)
                
                # Track which operation produces this field
                if op_name not in field_to_operations[field_path]:
                    field_to_operations[field_path].append(op_name)
                
                # Create or update field entry
                if field_path not in fields:
                    field_type = field_data.get("type", "string")
                    compliance_category = field_data.get("compliance_category", "general")
                    
                    field_info = {
                        "field_name": field_name,
                        "type": field_type,
                        "operators": infer_field_operators(field_type, field_path),
                        "enum": field_data.get("enum", False),
                        "possible_values": field_data.get("possible_values"),
                        "compliance_category": compliance_category,
                        "description": field_data.get("description", ""),
                        "dependency_index_entity": create_dependency_index_entity(resource_name, field_path),
                        "operations": [],
                        "main_output_field": None,  # Will be set later
                        "discovery_id": None,  # Will be set later
                        "for_each": None,
                        "consumes": [],
                        "produces": []
                    }
                    fields[field_path] = field_info
                else:
                    # Merge operators
                    existing_ops = fields[field_path].get("operators", [])
                    new_ops = infer_field_operators(fields[field_path].get("type", "string"), field_path)
                    fields[field_path]["operators"] = list(set(existing_ops + new_ops))
        
        # Get output_fields (top-level response fields)
        output_fields = op.get("output_fields", {})
        if isinstance(output_fields, dict):
            for field_name, field_data in output_fields.items():
                if not isinstance(field_data, dict):
                    continue
                
                if op_name not in field_to_operations[field_name]:
                    field_to_operations[field_name].append(op_name)
                
                if field_name not in fields:
                    field_type = field_data.get("type", "string")
                    field_info = {
                        "field_name": field_name,
                        "type": field_type,
                        "operators": infer_field_operators(field_type, field_name),
                        "enum": field_data.get("enum", False),
                        "possible_values": field_data.get("possible_values"),
                        "compliance_category": field_data.get("compliance_category", "general"),
                        "description": field_data.get("description", ""),
                        "dependency_index_entity": create_dependency_index_entity(resource_name, field_name),
                        "operations": [],
                        "main_output_field": field_name,  # Output fields are typically main
                        "discovery_id": None,
                        "for_each": None,
                        "consumes": [],
                        "produces": []
                    }
                    fields[field_name] = field_info
    
    # Update fields with operations and discovery_ids
    for field_path, field_info in fields.items():
        operations = field_to_operations.get(field_path, [])
        field_info["operations"] = sorted(set(operations))
        
        # Set discovery_id from first operation
        if operations:
            field_info["discovery_id"] = generate_discovery_id(resource_name, operations[0])
            
            # Try to determine main_output_field
            if not field_info.get("main_output_field"):
                # For list operations, common patterns
                for op_name in operations:
                    if "list" in op_name.lower():
                        # Try common list response fields
                        field_info["main_output_field"] = "items"
                        break
    
    return fields

def load_dependency_index(resource_dir: Path) -> Optional[Dict]:
    """Load dependency_index.json if it exists"""
    di_path = resource_dir / "dependency_index.json"
    if di_path.exists():
        try:
            with open(di_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"  Warning: Could not load dependency_index.json: {e}")
    return None

def link_to_dependency_index(fields: Dict, dependency_index: Dict, resource_name: str) -> Dict:
    """Link fields to dependency_index entities if available"""
    if not dependency_index:
        return fields
    
    entity_paths = dependency_index.get("entity_paths", {})
    
    for field_path, field_data in fields.items():
        entity = field_data.get("dependency_index_entity")
        
        if entity and entity in entity_paths:
            entity_info = entity_paths[entity][0] if entity_paths[entity] else None
            
            if entity_info:
                # Update operations from dependency_index
                di_operations = entity_info.get("operations", [])
                if di_operations:
                    field_data["operations"] = sorted(set(di_operations))
                
                # Update produces
                produces_map = entity_info.get("produces", {})
                if produces_map:
                    # Get produces from first operation
                    first_op = field_data["operations"][0] if field_data["operations"] else None
                    if first_op:
                        field_data["produces"] = produces_map.get(first_op, [])
    
    return fields

def generate_direct_vars(resource_name: str, resource_dir: Path) -> Optional[Dict]:
    """Generate direct_vars.json for a K8s resource"""
    sdk_file = resource_dir / "k8s_dependencies_with_python_names_fully_enriched.json"
    
    if not sdk_file.exists():
        return None
    
    # Load SDK dependencies
    try:
        with open(sdk_file, 'r', encoding='utf-8') as f:
            sdk_data = json.load(f)
    except Exception as e:
        print(f"  Error loading SDK file: {e}")
        return None
    
    # Get resource data
    resource_data = sdk_data.get(resource_name, {})
    if not resource_data:
        # Try first key if resource_name not found
        keys = list(sdk_data.keys())
        if keys:
            resource_data = sdk_data[keys[0]]
        else:
            return None
    
    # Extract fields from read operations
    fields = extract_fields_from_operations(resource_data, resource_name)
    
    if not fields:
        print(f"  Warning: No fields found for {resource_name}")
        return None
    
    # Load dependency_index if available
    dependency_index = load_dependency_index(resource_dir)
    
    # Link to dependency_index
    if dependency_index:
        fields = link_to_dependency_index(fields, dependency_index, resource_name)
    
    # Build seed_from_list and enriched_from_get_describe
    seed_from_list = []
    enriched_from_get_describe = []
    
    # Separate fields by operation type
    for field_path, field_info in fields.items():
        operations = field_info.get("operations", [])
        is_list = any("list" in op.lower() for op in operations)
        is_get = any("get" in op.lower() or "read" in op.lower() for op in operations)
        
        field_name = field_info.get("field_name", extract_field_name_from_path(field_path))
        
        if is_list and field_name not in seed_from_list:
            seed_from_list.append(field_name)
        if is_get and field_name not in enriched_from_get_describe:
            enriched_from_get_describe.append(field_name)
    
    return {
        "service": resource_name,
        "seed_from_list": sorted(seed_from_list),
        "enriched_from_get_describe": sorted(enriched_from_get_describe),
        "fields": fields
    }

def process_resource(resource_dir: Path, dry_run: bool = False) -> Dict[str, Any]:
    """Process a single K8s resource"""
    resource_name = resource_dir.name
    result = {
        "resource": resource_name,
        "status": "SKIPPED",
        "fields_count": 0,
        "operations_count": 0,
        "error": None
    }
    
    dv_path = resource_dir / "direct_vars.json"
    
    # Check if already exists
    if dv_path.exists() and not dry_run:
        result["status"] = "EXISTS"
        try:
            with open(dv_path, 'r') as f:
                existing = json.load(f)
            result["fields_count"] = len(existing.get("fields", {}))
        except:
            pass
        return result
    
    try:
        direct_vars = generate_direct_vars(resource_name, resource_dir)
        
        if not direct_vars:
            result["status"] = "NO_DATA"
            return result
        
        fields = direct_vars.get("fields", {})
        result["fields_count"] = len(fields)
        
        all_operations = set()
        for field_data in fields.values():
            all_operations.update(field_data.get("operations", []))
        result["operations_count"] = len(all_operations)
        
        if not dry_run:
            # Save direct_vars.json
            with open(dv_path, 'w', encoding='utf-8') as f:
                json.dump(direct_vars, f, indent=2, ensure_ascii=False)
            result["status"] = "SUCCESS"
        else:
            result["status"] = "DRY_RUN"
        
    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)
        import traceback
        result["traceback"] = traceback.format_exc()
    
    return result

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate direct_vars.json for K8s resources")
    parser.add_argument("--resource", type=str, help="Process single resource only")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    parser.add_argument("--base-dir", type=str, default=None, help="Base directory")
    
    args = parser.parse_args()
    
    base_dir = Path(args.base_dir) if args.base_dir else Path(__file__).parent
    
    print("="*80)
    print("GENERATING DIRECT_VARS.JSON FOR KUBERNETES RESOURCES")
    print("="*80)
    print()
    
    # Find all resource directories
    if args.resource:
        resource_dirs = [base_dir / args.resource]
    else:
        resource_dirs = sorted([
            d for d in base_dir.iterdir()
            if d.is_dir() and not d.name.startswith('_') 
            and not d.name.startswith('.') 
            and not d.name == "tools"
            and (d / "k8s_dependencies_with_python_names_fully_enriched.json").exists()
        ])
    
    print(f"Found {len(resource_dirs)} resources to process")
    if args.dry_run:
        print("DRY RUN MODE - Files will not be written")
    print()
    
    results = []
    success_count = 0
    error_count = 0
    exists_count = 0
    
    for resource_dir in resource_dirs:
        resource_name = resource_dir.name
        print(f"Processing {resource_name}...", end=" ")
        
        result = process_resource(resource_dir, dry_run=args.dry_run)
        results.append(result)
        
        if result["status"] == "SUCCESS":
            print(f"✓ Generated ({result['fields_count']} fields, {result['operations_count']} ops)")
            success_count += 1
        elif result["status"] == "DRY_RUN":
            print(f"DRY_RUN - ({result['fields_count']} fields, {result['operations_count']} ops)")
        elif result["status"] == "EXISTS":
            print(f"Already exists ({result['fields_count']} fields)")
            exists_count += 1
        elif result["status"] == "NO_DATA":
            print("No data")
        elif result["status"] == "ERROR":
            print(f"✗ Error: {result['error']}")
            error_count += 1
    
    print()
    print("="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Total resources: {len(resource_dirs)}")
    print(f"  Success: {success_count}")
    print(f"  Already exists: {exists_count}")
    print(f"  Errors: {error_count}")
    
    # Save results
    results_file = base_dir / "direct_vars_generation_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {results_file}")

if __name__ == "__main__":
    main()

