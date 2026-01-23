#!/usr/bin/env python3
"""
Generate dependency_index.json for IBM services from operation_registry.json.

IBM dependency_index structure (similar to Alicloud):
{
  "service": "servicename",
  "read_only": true,
  "roots": [
    {
      "op": "operation_name",
      "produces": ["entity1", "entity2"]
    }
  ],
  "entity_paths": {
    "entity1": [
      {
        "operations": ["operation_name"],
        "produces": {"operation_name": ["entity1"]},
        "consumes": {"operation_name": []},
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
        # In IBM, consumes with "source": "external" or "source": "either" are external inputs
        required_consumes = [c for c in consumes if c.get("required", True) and c.get("source") not in ["external", "either"]]
        
        if not required_consumes:
            # This is a root operation
            produces_entities = [p.get("entity", "") for p in produces if p.get("entity")]
            produces_entities = [e for e in produces_entities if e]
            
            if produces_entities:
                roots.append({
                    "op": op_id,
                    "produces": produces_entities
                })
    
    return roots

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
        
        # Get entities produced by this operation
        produces_entities = [p.get("entity", "") for p in produces if p.get("entity")]
        produces_entities = [e for e in produces_entities if e]
        
        # Get entities consumed by this operation (internal dependencies only)
        consumes_entities = [c.get("entity", "") for c in consumes if c.get("required", True) and c.get("source") not in ["external", "either"]]
        consumes_entities = [e for e in consumes_entities if e]
        
        # Get external inputs separately
        external_inputs = [c.get("entity", "") for c in consumes if c.get("source") in ["external", "either"]]
        external_inputs = [e for e in external_inputs if e]
        
        # Map each produced entity to this operation
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
            if external_inputs:
                for ext_in in external_inputs:
                    if ext_in not in entity_paths[entity]["external_inputs"]:
                        entity_paths[entity]["external_inputs"].append(ext_in)
    
    # Convert to list format matching IBM structure
    result = {}
    for entity, data in entity_paths.items():
        # Sort operations for consistency
        data["operations"] = sorted(set(data["operations"]))
        data["external_inputs"] = sorted(set(data.get("external_inputs", [])))
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

def generate_dependency_index(service_name: str, service_dir: Path) -> Optional[Dict]:
    """Generate dependency_index.json for an IBM service"""
    # Try operation_registry.json (primary source)
    result = generate_dependency_index_from_registry(service_name, service_dir)
    
    if result:
        roots = result.get("roots", [])
        entity_paths = result.get("entity_paths", {})
        if roots or entity_paths:
            return result
    
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
    
    parser = argparse.ArgumentParser(description="Generate dependency_index.json for IBM services")
    parser.add_argument("--service", type=str, help="Process single service only")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    parser.add_argument("--base-dir", type=str, default=None, help="Base directory")
    
    args = parser.parse_args()
    
    base_dir = Path(args.base_dir) if args.base_dir else Path(__file__).parent
    
    print("="*80)
    print("GENERATING DEPENDENCY_INDEX.JSON FOR IBM SERVICES")
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
            print(f"  ? {result['service']}: No operation_registry")
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

