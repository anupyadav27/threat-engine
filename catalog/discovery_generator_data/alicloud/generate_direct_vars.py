#!/usr/bin/env python3
"""
Generate direct_vars.json for Alicloud services from operation_registry.json.

This script generates direct_vars.json from operation_registry.json for services
that have read operations defined.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Set, Optional
from collections import defaultdict

def to_snake_case(name: str) -> str:
    """Convert CamelCase to snake_case"""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def generate_discovery_id(service_name: str, operation_id: str) -> str:
    """Generate discovery ID from operation ID"""
    # Operation ID is like "DescribeAddons" - convert to snake_case
    op_snake = to_snake_case(operation_id)
    return f"alicloud.{service_name}.{op_snake}"

def extract_field_name_from_entity(entity: str, service_name: str) -> str:
    """Extract field name from entity path"""
    # Entity format: "service.entity_name" (e.g., "ack.instance_id")
    # Extract field name (entity_name part)
    parts = entity.split('.')
    
    if len(parts) >= 2 and parts[0] == service_name:
        # Remove service prefix
        field_name = '.'.join(parts[1:])
        # Convert from snake_case to camelCase for consistency with AWS
        # But actually, let's keep it as-is for now
        return field_name
    
    # Fallback: just take last part
    return entity.split('.')[-1]

def extract_field_type_from_path(path: str) -> str:
    """Infer field type from path name"""
    path_lower = path.lower()
    if 'time' in path_lower or 'date' in path_lower:
        return "string"  # date-time format
    elif 'id' in path_lower:
        return "string"
    elif 'status' in path_lower:
        return "string"
    elif 'tags' in path_lower:
        return "array"
    else:
        return "string"

def generate_direct_vars_from_registry(service_name: str, service_dir: Path) -> Optional[Dict]:
    """Generate direct_vars.json from operation_registry.json"""
    op_reg_path = service_dir / "operation_registry.json"
    di_path = service_dir / "dependency_index.json"
    
    if not op_reg_path.exists():
        return None
    
    try:
        with open(op_reg_path, 'r', encoding='utf-8') as f:
            operation_registry = json.load(f)
        
        # Load dependency_index if available for linking
        dependency_index = None
        if di_path.exists():
            try:
                with open(di_path, 'r', encoding='utf-8') as f:
                    dependency_index = json.load(f)
            except:
                pass
    except Exception as e:
        print(f"  Error loading operation_registry.json: {e}")
        return None
    
    operations = operation_registry.get("operations", {})
    if not operations:
        return None
    
    # Extract fields from read operations
    fields = {}
    entity_to_operations = defaultdict(set)
    entity_to_field_name = {}
    entity_to_path = {}
    
    # Get read operations (read_list and read_get)
    read_ops = {}
    for op_id, op_data in operations.items():
        kind = op_data.get("kind", "")
        if kind.startswith("read_"):
            read_ops[op_id] = op_data
    
    if not read_ops:
        return None
    
    # Extract entities from produces
    for op_id, op_data in read_ops.items():
        produces = op_data.get("produces", [])
        
        for produce in produces:
            if isinstance(produce, dict):
                entity = produce.get("entity", "")
                path = produce.get("path", "")
            elif isinstance(produce, str):
                entity = produce
                path = ""
            else:
                continue
            
            if not entity:
                continue
            
            # Extract field name from entity
            field_name = extract_field_name_from_entity(entity, service_name)
            
            # Store mapping
            entity_to_operations[entity].add(op_id)
            entity_to_field_name[entity] = field_name
            if path:
                entity_to_path[entity] = path
    
    # Build fields dictionary
    for entity, field_name in entity_to_field_name.items():
        operations_list = sorted(list(entity_to_operations[entity]))
        
        if not operations_list:
            continue
        
        # Get first operation for discovery_id
        first_op = operations_list[0]
        
        # Determine operation type (list vs get/describe)
        is_list = any("list" in op.lower() for op in operations_list)
        is_get = any("get" in op.lower() or "describe" in op.lower() for op in operations_list)
        
        # Get entity info from dependency_index if available
        entity_info = None
        if dependency_index:
            entity_paths = dependency_index.get("entity_paths", {})
            if entity in entity_paths and entity_paths[entity]:
                entity_info = entity_paths[entity][0]
        
        # Infer type from path/field name
        path = entity_to_path.get(entity, "")
        field_type = extract_field_type_from_path(path if path else field_name)
        
        # Build field entry
        field_entry = {
            "field_name": field_name,
            "type": field_type,
            "operators": ["equals", "not_equals", "contains", "in"],
            "enum": False,
            "possible_values": None,
            "compliance_category": "general",
            "description": f"Field from entity {entity}",
            "dependency_index_entity": entity,
            "operations": sorted(list(operations_list)),
            "main_output_field": "items" if is_list else field_name,
            "discovery_id": generate_discovery_id(service_name, first_op),
            "for_each": None,
            "consumes": [],
            "produces": [entity] if entity_info else []
        }
        
        # Enrich from entity_info if available
        if entity_info:
            entity_operations = entity_info.get("operations", [])
            if entity_operations:
                field_entry["operations"] = sorted(entity_operations)
                field_entry["consumes"] = []
                produces_map = entity_info.get("produces", {})
                if produces_map:
                    # Get produces from first operation
                    first_op_id = entity_operations[0]
                    field_entry["produces"] = produces_map.get(first_op_id, [])
        
        fields[field_name] = field_entry
    
    if not fields:
        return None
    
    # Categorize fields
    seed_from_list = []
    enriched_from_get_describe = []
    
    for field_name, field_data in fields.items():
        operations = field_data.get("operations", [])
        is_list_field = any("list" in op.lower() for op in operations)
        is_get_field = any("get" in op.lower() or "describe" in op.lower() for op in operations)
        
        if is_list_field and field_name not in seed_from_list:
            seed_from_list.append(field_name)
        if is_get_field and field_name not in enriched_from_get_describe:
            enriched_from_get_describe.append(field_name)
    
    return {
        "service": service_name,
        "seed_from_list": sorted(seed_from_list),
        "enriched_from_get_describe": sorted(enriched_from_get_describe),
        "fields": fields
    }

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
        try:
            with open(direct_vars_path, 'r') as f:
                existing = json.load(f)
            result["fields_count"] = len(existing.get("fields", {}))
        except:
            pass
        return result
    
    # Check if operation_registry exists
    op_reg_path = service_dir / "operation_registry.json"
    if not op_reg_path.exists():
        result["status"] = "NO_REGISTRY"
        return result
    
    try:
        direct_vars = generate_direct_vars_from_registry(service_name, service_dir)
        
        if not direct_vars:
            result["status"] = "NO_FIELDS"
            return result
        
        fields = direct_vars.get("fields", {})
        result["fields_count"] = len(fields)
        
        all_operations = set()
        for field_data in fields.values():
            all_operations.update(field_data.get("operations", []))
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
        import traceback
        result["traceback"] = traceback.format_exc()
    
    return result

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate direct_vars.json for Alicloud services")
    parser.add_argument("--service", type=str, help="Process single service only")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    parser.add_argument("--base-dir", type=str, default=None, help="Base directory")
    
    args = parser.parse_args()
    
    base_dir = Path(args.base_dir) if args.base_dir else Path(__file__).parent
    
    print("="*80)
    print("GENERATING DIRECT_VARS.JSON FOR ALICLOUD SERVICES")
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
            and (d / "operation_registry.json").exists()
        ])
    
    print(f"Found {len(service_dirs)} services to process")
    if args.dry_run:
        print("DRY RUN MODE - Files will not be written")
    print()
    
    results = []
    success_count = 0
    exists_count = 0
    no_fields_count = 0
    error_count = 0
    
    for service_dir in service_dirs:
        result = process_service(service_dir, dry_run=args.dry_run)
        results.append(result)
        
        status = result["status"]
        if status == "SUCCESS":
            print(f"  ✓ {result['service']}: {result['fields_count']} fields, {result['operations_count']} operations")
            success_count += 1
        elif status == "EXISTS":
            print(f"  - {result['service']}: Already exists ({result['fields_count']} fields)")
            exists_count += 1
        elif status == "NO_REGISTRY":
            print(f"  ! {result['service']}: No operation_registry.json")
        elif status == "NO_FIELDS":
            print(f"  ! {result['service']}: No read operations or fields found")
            no_fields_count += 1
        elif status == "ERROR":
            print(f"  ✗ {result['service']}: Error - {result['error']}")
            error_count += 1
        elif status == "DRY_RUN":
            print(f"  ? {result['service']}: DRY_RUN - {result['fields_count']} fields")
    
    print()
    print("="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Total services: {len(results)}")
    print(f"  Success: {success_count}")
    print(f"  Already exists: {exists_count}")
    print(f"  No fields (write-only?): {no_fields_count}")
    print(f"  Errors: {error_count}")
    
    results_file = base_dir / "direct_vars_generation_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {results_file}")

if __name__ == "__main__":
    main()

