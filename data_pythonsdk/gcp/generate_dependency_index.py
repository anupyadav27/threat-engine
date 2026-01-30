#!/usr/bin/env python3
"""
Generate dependency_index.json for GCP services.

This script can generate dependency_index.json from:
1. operation_registry.json (preferred - for all services)
2. gcp_dependencies + direct_vars.json (fallback - if operation_registry not available)

GCP dependency_index structure:
{
  "service": "servicename",
  "read_only": true,
  "roots": [
    {
      "op": "gcp.servicename.resource.operation",
      "produces": ["entity1", "entity2"]
    }
  ],
  "entity_paths": {
    "entity1": [
      {
        "operations": ["gcp.servicename.resource.operation"],
        "produces": {"op": ["entity1"]},
        "consumes": {"op": []},
        "external_inputs": []
      }
    ]
  }
}
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Set, Optional
from collections import defaultdict

def is_read_operation(kind: str) -> bool:
    """Check if operation kind is a read operation"""
    return kind.startswith('read_')

def get_read_operations_from_registry(operation_registry: Dict) -> Dict[str, Dict]:
    """Extract read operations from operation_registry.json"""
    read_ops = {}
    operations = operation_registry.get("operations", {})
    
    for op_id, op_data in operations.items():
        kind = op_data.get("kind", "")
        if is_read_operation(kind):
            read_ops[op_id] = op_data
    
    return read_ops

def normalize_gcp_entity(entity: str, service_name: str) -> str:
    """Normalize entity to have gcp. prefix if missing"""
    if not entity:
        return entity
    
    # If already has gcp. prefix, return as is
    if entity.startswith("gcp."):
        return entity
    
    # If starts with service name, add gcp. prefix
    if entity.startswith(f"{service_name}."):
        return f"gcp.{entity}"
    
    # If it's just the service name or doesn't match, add gcp.service prefix
    if "." not in entity or not entity.startswith(service_name):
        return f"gcp.{service_name}.{entity}"
    
    # Default: add gcp. prefix at the beginning
    return f"gcp.{entity}"

def build_roots_from_registry(operation_registry: Dict, service_name: str) -> List[Dict[str, Any]]:
    """Build roots (independent read operations) from operation_registry"""
    roots = []
    
    # Check if operation_registry has operations
    if not operation_registry or not isinstance(operation_registry, dict):
        return roots
    
    operations = operation_registry.get("operations", {})
    if not operations:
        return roots
    
    read_ops = get_read_operations_from_registry(operation_registry)
    
    for op_id, op_data in read_ops.items():
        consumes = op_data.get("consumes", [])
        produces = op_data.get("produces", [])
        
        # Root operations have no required consumes (independent)
        required_consumes = [c for c in consumes if c.get("required", True)]
        
        if not required_consumes:
            # This is a root operation
            produces_entities = [p.get("entity", "") for p in produces if p.get("entity")]
            produces_entities = [e for e in produces_entities if e]
            # Normalize all entities to have gcp. prefix
            produces_entities = [normalize_gcp_entity(e, service_name) for e in produces_entities]
            
            if produces_entities:
                roots.append({
                    "op": op_id,
                    "produces": produces_entities
                })
    
    return roots

def normalize_gcp_entity(entity: str, service_name: str) -> str:
    """Normalize entity to have gcp. prefix if missing"""
    if not entity:
        return entity
    
    # If already has gcp. prefix, return as is
    if entity.startswith("gcp."):
        return entity
    
    # If starts with service name, add gcp. prefix
    if entity.startswith(f"{service_name}."):
        return f"gcp.{entity}"
    
    # If it's just the service name or doesn't match, add gcp.service prefix
    if "." not in entity or not entity.startswith(service_name):
        return f"gcp.{service_name}.{entity}"
    
    # Default: add gcp. prefix at the beginning
    return f"gcp.{entity}"

def build_entity_paths_from_registry(operation_registry: Dict, service_name: str) -> Dict[str, List[Dict[str, Any]]]:
    """Build entity_paths from operation_registry"""
    entity_paths = defaultdict(lambda: {
        "operations": [],
        "produces": {},
        "consumes": {},
        "external_inputs": []
    })
    
    # Check if operation_registry has operations
    if not operation_registry or not isinstance(operation_registry, dict):
        return {}
    
    operations = operation_registry.get("operations", {})
    if not operations:
        return {}
    
    read_ops = get_read_operations_from_registry(operation_registry)
    
    # Build entity to operations mapping
    for op_id, op_data in read_ops.items():
        produces = op_data.get("produces", [])
        consumes = op_data.get("consumes", [])
        
        # Get entities produced by this operation - normalize to have gcp. prefix
        produces_entities = [p.get("entity", "") for p in produces if p.get("entity")]
        produces_entities = [e for e in produces_entities if e]
        produces_entities = [normalize_gcp_entity(e, service_name) for e in produces_entities]
        
        # Get entities consumed by this operation - normalize to have gcp. prefix
        consumes_entities = [c.get("entity", "") for c in consumes if c.get("required", True) and c.get("entity")]
        consumes_entities = [e for e in consumes_entities if e]
        consumes_entities = [normalize_gcp_entity(e, service_name) for e in consumes_entities]
        
        # Map each produced entity to this operation (entities already normalized)
        for entity in produces_entities:
            if entity not in entity_paths:
                entity_paths[entity] = {
                    "operations": [],
                    "produces": {},
                    "consumes": {},
                    "external_inputs": []
                }
            
            entity_paths[entity]["operations"].append(op_id)
            entity_paths[entity]["produces"][op_id] = produces_entities
            entity_paths[entity]["consumes"][op_id] = consumes_entities
    
    # Convert to list format matching GCP structure
    result = {}
    for entity, data in entity_paths.items():
        # Sort operations for consistency
        data["operations"] = sorted(set(data["operations"]))
        # Entity is already normalized, use as-is
        result[entity] = [data]
    
    return result

def generate_dependency_index_from_registry(service_name: str, service_dir: Path) -> Optional[Dict]:
    """Generate dependency_index.json from operation_registry.json"""
    op_reg_path = service_dir / "operation_registry.json"
    
    if not op_reg_path.exists():
        return None
    
    try:
        with open(op_reg_path, 'r', encoding='utf-8') as f:
            operation_registry = json.load(f)
    except Exception as e:
        print(f"  Error loading operation_registry.json: {e}")
        return None
    
    # Build roots and entity_paths
    roots = build_roots_from_registry(operation_registry, service_name)
    entity_paths = build_entity_paths_from_registry(operation_registry, service_name)
    
    return {
        "service": service_name,
        "read_only": True,
        "roots": roots,
        "entity_paths": entity_paths
    }

def generate_dependency_index_from_direct_vars(service_name: str, service_dir: Path) -> Optional[Dict]:
    """Generate dependency_index.json from direct_vars.json and SDK dependencies (fallback)"""
    direct_vars_path = service_dir / "direct_vars.json"
    sdk_path = service_dir / "gcp_dependencies_with_python_names_fully_enriched.json"
    
    if not direct_vars_path.exists() or not sdk_path.exists():
        return None
    
    try:
        with open(direct_vars_path, 'r', encoding='utf-8') as f:
            direct_vars = json.load(f)
    except Exception as e:
        return None
    
    try:
        with open(sdk_path, 'r', encoding='utf-8') as f:
            sdk_data = json.load(f)
    except Exception as e:
        return None
    
    if not sdk_data or not isinstance(sdk_data, dict):
        return None
    
    # Extract entities from direct_vars
    fields = direct_vars.get("fields", {})
    entity_to_operations = defaultdict(set)
    entity_to_fields = defaultdict(set)
    
    for field_name, field_data in fields.items():
        if not isinstance(field_data, dict):
            continue
        
        entity = field_data.get("dependency_index_entity")
        operations = field_data.get("operations", [])
        
        if entity and operations:
            entity_to_operations[entity].update(operations)
            entity_to_fields[entity].add(field_name)
    
    # Build roots (operations with no dependencies)
    roots = []
    all_read_operations = set()
    
    # Get service data from SDK
    service_data = sdk_data.get(service_name, {})
    if not service_data or not isinstance(service_data, dict):
        keys = list(sdk_data.keys())
        if keys:
            service_data = sdk_data.get(keys[0], {})
    
    if not service_data or not isinstance(service_data, dict):
        return None
    
    resources = service_data.get("resources", {})
    
    if resources and isinstance(resources, dict):
        # Collect independent read operations from resources
        for resource_type, resource_data in resources.items():
            if not isinstance(resource_data, dict):
                continue
                
            for op in resource_data.get("independent", []):
                if not isinstance(op, dict):
                    continue
                op_name = op.get("operation", "")
                http_method = op.get("http_method", "").upper()
                if http_method == "GET" or any(p in op_name.lower() for p in ["list", "get", "describe"]):
                    # Format operation ID like GCP format
                    op_id = f"gcp.{service_name}.{resource_type}.{op_name}"
                    all_read_operations.add(op_id)
                    
                    # Get produces from item_fields
                    item_fields = op.get("item_fields", {})
                    produces_entities = []
                    for field_name in item_fields.keys():
                        entity = f"{service_name}.{to_snake_case(field_name)}"
                        produces_entities.append(f"gcp.{entity}")
                    
                    if produces_entities:
                        roots.append({
                            "op": op_id,
                            "produces": produces_entities
                        })
    
    # Also check top-level independent/dependent if resources structure doesn't exist
    if not resources:
        independent_ops = service_data.get("independent", [])
        dependent_ops = service_data.get("dependent", [])
        
        for op in independent_ops + dependent_ops:
            if not isinstance(op, dict):
                continue
            op_name = op.get("operation", "")
            http_method = op.get("http_method", "").upper()
            if http_method == "GET" or any(p in op_name.lower() for p in ["list", "get", "describe"]):
                op_id = f"gcp.{service_name}.{to_snake_case(op_name)}"
                all_read_operations.add(op_id)
                
                item_fields = op.get("item_fields", {})
                produces_entities = []
                for field_name in item_fields.keys():
                    entity = f"{service_name}.{to_snake_case(field_name)}"
                    produces_entities.append(f"gcp.{entity}")
                
                if produces_entities:
                    roots.append({
                        "op": op_id,
                        "produces": produces_entities
                    })
    
    # Build entity_paths from direct_vars fields
    entity_paths = {}
    for field_name, field_data in fields.items():
        if not isinstance(field_data, dict):
            continue
        
        entity = field_data.get("dependency_index_entity")
        operations = field_data.get("operations", [])
        
        if not entity or not operations:
            continue
        
        # Convert operations to GCP format if needed
        gcp_operations = []
        for op in operations:
            # Try to find full operation ID from SDK
            full_op_id = None
            for op_id in all_read_operations:
                if op in op_id or op_id.endswith(f".{op}"):
                    full_op_id = op_id
                    break
            
            if not full_op_id:
                # Generate operation ID from operation name
                full_op_id = f"gcp.{service_name}.{to_snake_case(op)}"
            
            gcp_operations.append(full_op_id)
        
        # Normalize entity to have gcp. prefix
        normalized_entity = normalize_gcp_entity(entity, service_name)
        
        if gcp_operations and normalized_entity not in entity_paths:
            entity_paths[normalized_entity] = [{
                "operations": sorted(set(gcp_operations)),
                "produces": {op: [normalized_entity] for op in gcp_operations},
                "consumes": {op: [] for op in gcp_operations},
                "external_inputs": []
            }]
    
    # Ensure all entity keys have gcp. prefix
    normalized_result = {}
    for entity_key, entity_data in entity_paths.items():
        normalized_key = normalize_gcp_entity(entity_key, service_name)
        normalized_result[normalized_key] = entity_data
    
    return {
        "service": service_name,
        "read_only": True,
        "roots": roots,
        "entity_paths": normalized_result
    }

def to_snake_case(name: str) -> str:
    """Convert CamelCase to snake_case"""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def generate_dependency_index(service_name: str, service_dir: Path) -> Optional[Dict]:
    """Generate dependency_index.json for a GCP service using best available source"""
    # Try operation_registry.json first (preferred)
    op_reg_result = generate_dependency_index_from_registry(service_name, service_dir)
    
    if op_reg_result:
        roots = op_reg_result.get("roots", [])
        entity_paths = op_reg_result.get("entity_paths", {})
        if roots or entity_paths:
            return op_reg_result
    
    # Fallback to direct_vars + SDK dependencies (if operation_registry not available or empty)
    dv_result = generate_dependency_index_from_direct_vars(service_name, service_dir)
    
    if dv_result:
        roots = dv_result.get("roots", [])
        entity_paths = dv_result.get("entity_paths", {})
        if roots or entity_paths:
            return dv_result
    
    return None

def process_service(service_dir: Path, dry_run: bool = False) -> Dict[str, Any]:
    """Process a single service"""
    service_name = service_dir.name
    result = {
        "service": service_name,
        "status": "SKIPPED",
        "roots_count": 0,
        "entities_count": 0,
        "error": None
    }
    
    # Check if dependency_index already exists
    di_path = service_dir / "dependency_index.json"
    if di_path.exists() and not dry_run:
        # Check if it's empty or has content
        try:
            with open(di_path, 'r') as f:
                existing = json.load(f)
            roots = len(existing.get("roots", []))
            entities = len(existing.get("entity_paths", {}))
            
            if roots > 0 or entities > 0:
                result["status"] = "EXISTS"
                result["roots_count"] = roots
                result["entities_count"] = entities
                return result
        except:
            pass
    
    try:
        dependency_index = generate_dependency_index(service_name, service_dir)
        
        if not dependency_index:
            result["status"] = "NO_DATA"
            return result
        
        roots_count = len(dependency_index.get("roots", []))
        entities_count = len(dependency_index.get("entity_paths", {}))
        
        result["roots_count"] = roots_count
        result["entities_count"] = entities_count
        
        if roots_count == 0 and entities_count == 0:
            result["status"] = "EMPTY"
            return result
        
        # If we have entities, it's valid even without roots
        if not dry_run:
            # Save dependency_index.json
            with open(di_path, 'w', encoding='utf-8') as f:
                json.dump(dependency_index, f, indent=2, ensure_ascii=False)
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
    
    parser = argparse.ArgumentParser(description="Generate dependency_index.json for GCP services")
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
    print("GENERATING DEPENDENCY_INDEX.JSON FOR GCP SERVICES")
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
    exists_count = 0
    empty_count = 0
    error_count = 0
    no_data_count = 0
    dry_run_count = 0
    
    for service_dir in service_dirs:
        result = process_service(service_dir, dry_run=args.dry_run)
        results.append(result)
        
        status = result["status"]
        if status == "SUCCESS":
            print(f"  ✓ {result['service']}: {result['roots_count']} roots, {result['entities_count']} entities")
            success_count += 1
        elif status == "EXISTS":
            print(f"  - {result['service']}: Already exists ({result['roots_count']} roots, {result['entities_count']} entities)")
            exists_count += 1
        elif status == "EMPTY":
            print(f"  ! {result['service']}: Generated but empty")
            empty_count += 1
        elif status == "NO_DATA":
            print(f"  ? {result['service']}: No operation_registry or direct_vars")
            no_data_count += 1
        elif status == "ERROR":
            print(f"  ✗ {result['service']}: Error - {result['error']}")
            error_count += 1
        elif status == "DRY_RUN":
            print(f"  ? {result['service']}: DRY_RUN - {result['roots_count']} roots, {result['entities_count']} entities")
            dry_run_count += 1
    
    print()
    print("="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Total services: {len(results)}")
    print(f"  Success: {success_count}")
    print(f"  Already exists (with content): {exists_count}")
    print(f"  Generated but empty: {empty_count}")
    print(f"  Errors: {error_count}")
    if args.dry_run:
        print(f"  Dry run: {dry_run_count}")
    print(f"  No data: {no_data_count}")
    
    # Save results
    results_file = base_dir / "dependency_index_generation_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {results_file}")

if __name__ == "__main__":
    main()

