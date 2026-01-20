#!/usr/bin/env python3
"""
Generate direct_vars.json for GCP services from gcp_dependencies_with_python_names_fully_enriched.json

This script:
1. Extracts fields from GCP SDK dependencies (independent/read operations)
2. Maps fields to operations
3. Generates direct_vars.json matching AWS structure
4. Links to dependency_index entities (if dependency_index.json exists)
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Set, Optional
from collections import defaultdict

def is_read_operation(operation: Dict) -> bool:
    """Check if operation is a read operation (GET method or starts with list/get/batch)"""
    http_method = operation.get("http_method", "").upper()
    op_name = operation.get("operation", "").lower()
    
    # GET method is typically read operation
    if http_method == "GET":
        return True
    
    # POST operations that are semantically reads (batchGet, query, etc.)
    if http_method == "POST":
        read_post_patterns = ["batchget", "batchget", "query", "search", "lookup", "fetch"]
        if any(pattern in op_name for pattern in read_post_patterns):
            return True
    
    # Check operation name patterns for read operations
    read_patterns = ["list", "get", "describe", "search", "lookup", "fetch", "batchget", "batch_get"]
    if any(pattern in op_name for pattern in read_patterns):
        return True
    
    return False

def camel_to_snake(name: str) -> str:
    """Convert CamelCase to snake_case"""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def to_snake_case(name: str) -> str:
    """Convert to snake_case"""
    name = name.replace('-', '_')
    return camel_to_snake(name)

def generate_discovery_id(service_name: str, operation_name: str) -> str:
    """Generate discovery ID from service and operation name"""
    op_snake = to_snake_case(operation_name)
    return f"gcp.{service_name}.{op_snake}"

def create_dependency_index_entity(service_name: str, field_name: str) -> str:
    """Create dependency_index entity name from field - ensures gcp. prefix"""
    field_snake = to_snake_case(field_name)
    entity = f"{service_name}.{field_snake}"
    # Ensure gcp. prefix
    if not entity.startswith("gcp."):
        return f"gcp.{entity}"
    return entity

def extract_fields_from_operations(service_data: Dict, service_name: str) -> Dict[str, Dict[str, Any]]:
    """Extract all fields from read operations in GCP SDK dependencies"""
    fields = {}
    field_to_operations = defaultdict(list)
    
    # GCP structure: resources -> resourceType -> independent/dependent
    resources = service_data.get("resources", {})
    
    # Collect all read operations from all resources
    all_read_operations = []
    
    if resources:
        # Process resources structure
        for resource_type, resource_data in resources.items():
            independent_ops = resource_data.get("independent", [])
            dependent_ops = resource_data.get("dependent", [])
            
            for op in independent_ops + dependent_ops:
                if is_read_operation(op):
                    all_read_operations.append(op)
    else:
        # If no resources structure, try direct independent/dependent
        independent_ops = service_data.get("independent", [])
        dependent_ops = service_data.get("dependent", [])
        
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
            for field_name, field_data in item_fields.items():
                if not isinstance(field_data, dict):
                    continue
                
                # Track which operation produces this field
                if op_name not in field_to_operations[field_name]:
                    field_to_operations[field_name].append(op_name)
                
                # Create or update field entry
                if field_name not in fields:
                    field_info = {
                        "field_name": field_name,
                        "type": field_data.get("type", "string"),
                        "operators": field_data.get("operators", ["equals", "not_equals"]),
                        "enum": field_data.get("enum", False),
                        "possible_values": field_data.get("possible_values"),
                        "compliance_category": field_data.get("compliance_category", "general"),
                        "description": field_data.get("description", ""),
                        "dependency_index_entity": create_dependency_index_entity(service_name, field_name),
                        "operations": [],
                        "main_output_field": None,  # Will be set later
                        "discovery_id": None,  # Will be set later
                        "for_each": None,
                        "consumes": [],
                        "produces": []
                    }
                    fields[field_name] = field_info
                else:
                    # Merge operators
                    existing_ops = fields[field_name].get("operators", [])
                    new_ops = field_data.get("operators", [])
                    fields[field_name]["operators"] = list(set(existing_ops + new_ops))
        
        # Get output_fields (top-level response fields)
        output_fields = op.get("output_fields", {})
        if isinstance(output_fields, dict):
            for field_name, field_data in output_fields.items():
                if not isinstance(field_data, dict):
                    continue
                
                if op_name not in field_to_operations[field_name]:
                    field_to_operations[field_name].append(op_name)
                
                if field_name not in fields:
                    field_info = {
                        "field_name": field_name,
                        "type": field_data.get("type", "string"),
                        "operators": field_data.get("operators", ["equals", "not_equals"]),
                        "enum": field_data.get("enum", False),
                        "possible_values": field_data.get("possible_values"),
                        "compliance_category": field_data.get("compliance_category", "general"),
                        "description": field_data.get("description", ""),
                        "dependency_index_entity": create_dependency_index_entity(service_name, field_name),
                        "operations": [],
                        "main_output_field": field_name,  # Output fields are typically main
                        "discovery_id": None,
                        "for_each": None,
                        "consumes": [],
                        "produces": []
                    }
                    fields[field_name] = field_info
                else:
                    existing_ops = fields[field_name].get("operators", [])
                    new_ops = field_data.get("operators", [])
                    fields[field_name]["operators"] = list(set(existing_ops + new_ops))
    
    # Update fields with operations and discovery_ids
    for field_name, field_info in fields.items():
        operations = field_to_operations.get(field_name, [])
        field_info["operations"] = sorted(set(operations))
        
        # Set discovery_id from first operation
        if operations:
            field_info["discovery_id"] = generate_discovery_id(service_name, operations[0])
            
            # Try to determine main_output_field
            if not field_info.get("main_output_field"):
                # For list operations, common patterns
                for op_name in operations:
                    if "list" in op_name.lower():
                        # Try common list response fields
                        field_info["main_output_field"] = "items"
                        break
    
    return fields

def load_dependency_index(service_dir: Path) -> Optional[Dict]:
    """Load dependency_index.json if it exists"""
    di_path = service_dir / "dependency_index.json"
    if di_path.exists():
        try:
            with open(di_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"  Warning: Could not load dependency_index.json: {e}")
    return None

def link_to_dependency_index(fields: Dict, dependency_index: Dict, service_name: str) -> Dict:
    """Link fields to dependency_index entities if available"""
    if not dependency_index:
        return fields
    
    entity_paths = dependency_index.get("entity_paths", {})
    
    for field_name, field_info in fields.items():
        entity = field_info.get("dependency_index_entity")
        
        if entity and entity in entity_paths:
            # Get operations from dependency_index
            paths = entity_paths[entity]
            if paths and isinstance(paths, list) and len(paths) > 0:
                path = paths[0]
                di_operations = path.get("operations", [])
                
                # Update operations if dependency_index has them
                if di_operations:
                    existing_ops = set(field_info.get("operations", []))
                    field_info["operations"] = sorted(set(existing_ops | set(di_operations)))
                
                # Update produces
                produces = path.get("produces", [])
                if produces:
                    field_info["produces"] = produces
    
    return fields

def generate_direct_vars(service_name: str, service_dir: Path) -> Optional[Dict]:
    """Generate direct_vars.json for a GCP service"""
    sdk_file = service_dir / "gcp_dependencies_with_python_names_fully_enriched.json"
    
    if not sdk_file.exists():
        return None
    
    # Load SDK dependencies
    try:
        with open(sdk_file, 'r', encoding='utf-8') as f:
            sdk_data = json.load(f)
    except Exception as e:
        print(f"  Error loading SDK file: {e}")
        return None
    
    # Get service data (GCP structure has service as top key)
    service_data = sdk_data.get(service_name, {})
    if not service_data:
        # Try without service key wrapper - might be direct service data
        if "resources" in sdk_data or "independent" in sdk_data or "dependent" in sdk_data:
            service_data = sdk_data
        else:
            # Try first key if it exists
            keys = list(sdk_data.keys())
            if keys:
                service_data = sdk_data[keys[0]]
    
    # Extract fields from read operations
    fields = extract_fields_from_operations(service_data, service_name)
    
    if not fields:
        print(f"  Warning: No fields found for {service_name}")
        return None
    
    # Load dependency_index if available
    dependency_index = load_dependency_index(service_dir)
    
    # Link to dependency_index
    if dependency_index:
        fields = link_to_dependency_index(fields, dependency_index, service_name)
    
    # Build seed_from_list (fields from list operations)
    seed_from_list = []
    enriched_from_get_describe = []
    
    # Separate fields by operation type
    list_ops = set()
    get_ops = set()
    
    for field_name, field_info in fields.items():
        operations = field_info.get("operations", [])
        for op in operations:
            op_lower = op.lower()
            if "list" in op_lower:
                list_ops.add(op)
            elif "get" in op_lower or "describe" in op_lower:
                get_ops.add(op)
    
    # Categorize fields
    for field_name, field_info in fields.items():
        operations = field_info.get("operations", [])
        is_list_field = any(op in list_ops for op in operations)
        is_get_field = any(op in get_ops for op in operations)
        
        if is_list_field and field_name not in seed_from_list:
            seed_from_list.append(field_name)
        if is_get_field and field_name not in enriched_from_get_describe:
            enriched_from_get_describe.append(field_name)
    
    # Build final_union (all fields)
    final_union = sorted(set(seed_from_list + enriched_from_get_describe))
    
    # Build direct_vars structure
    direct_vars = {
        "service": service_name,
        "seed_from_list": sorted(seed_from_list),
        "enriched_from_get_describe": sorted(enriched_from_get_describe),
        "fields": fields
    }
    
    return direct_vars

def process_service(service_dir: Path, dry_run: bool = False) -> Dict[str, Any]:
    """Process a single service"""
    service_name = service_dir.name
    result = {
        "service": service_name,
        "status": "SKIPPED",
        "fields_count": 0,
        "operations_count": 0,
        "error": None
    }
    
    # Check if direct_vars already exists
    direct_vars_path = service_dir / "direct_vars.json"
    if direct_vars_path.exists() and not dry_run:
        result["status"] = "EXISTS"
        result["fields_count"] = "existing"
        return result
    
    try:
        direct_vars = generate_direct_vars(service_name, service_dir)
        
        if not direct_vars:
            result["status"] = "NO_FIELDS"
            return result
        
        # Count fields and operations
        fields = direct_vars.get("fields", {})
        result["fields_count"] = len(fields)
        
        all_operations = set()
        for field_info in fields.values():
            all_operations.update(field_info.get("operations", []))
        result["operations_count"] = len(all_operations)
        
        if not dry_run:
            # Save direct_vars.json
            with open(direct_vars_path, 'w', encoding='utf-8') as f:
                json.dump(direct_vars, f, indent=2, ensure_ascii=False)
            result["status"] = "SUCCESS"
        else:
            result["status"] = "DRY_RUN"
        
    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)
    
    return result

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate direct_vars.json for GCP services")
    parser.add_argument("--service", type=str, help="Process single service only")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode (don't write files)")
    parser.add_argument("--base-dir", type=str, default=None, help="Base directory for GCP services")
    
    args = parser.parse_args()
    
    # Determine base directory
    if args.base_dir:
        base_dir = Path(args.base_dir)
    else:
        base_dir = Path(__file__).parent
    
    print("="*80)
    print("GENERATING DIRECT_VARS.JSON FOR GCP SERVICES")
    print("="*80)
    print()
    
    # Find all service directories
    if args.service:
        service_dirs = [base_dir / args.service]
    else:
        service_dirs = sorted([
            d for d in base_dir.iterdir()
            if d.is_dir() and not d.name.startswith('_') 
            and not d.name.startswith('.') 
            and d.name != "tools"
        ])
    
    print(f"Found {len(service_dirs)} services to process")
    if args.dry_run:
        print("DRY RUN MODE - Files will not be written")
    print()
    
    results = []
    success_count = 0
    error_count = 0
    exists_count = 0
    
    for service_dir in service_dirs:
        result = process_service(service_dir, dry_run=args.dry_run)
        results.append(result)
        
        status = result["status"]
        if status == "SUCCESS":
            print(f"  ✓ {result['service']}: {result['fields_count']} fields, {result['operations_count']} operations")
            success_count += 1
        elif status == "EXISTS":
            print(f"  - {result['service']}: Already exists (skipped)")
            exists_count += 1
        elif status == "NO_FIELDS":
            print(f"  ! {result['service']}: No fields found")
        elif status == "ERROR":
            print(f"  ✗ {result['service']}: Error - {result['error']}")
            error_count += 1
        else:
            print(f"  ? {result['service']}: {status}")
    
    print()
    print("="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Total services: {len(results)}")
    print(f"  Success: {success_count}")
    print(f"  Already exists: {exists_count}")
    print(f"  Errors: {error_count}")
    print(f"  No fields: {len(results) - success_count - error_count - exists_count}")
    
    # Save results
    results_file = base_dir / "direct_vars_generation_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {results_file}")

if __name__ == "__main__":
    main()

