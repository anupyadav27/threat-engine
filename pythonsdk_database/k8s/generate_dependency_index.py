#!/usr/bin/env python3
"""
Generate dependency_index.json for Kubernetes resources.

K8s dependency_index structure (similar to other CSPs):
{
  "service": "pod",  # Resource type
  "read_only": true,
  "roots": [
    {
      "op": "k8s.pod.list",
      "produces": ["k8s.pod.metadata.name", "k8s.pod.spec.containers"]
    }
  ],
  "entity_paths": {
    "k8s.pod.metadata.name": [
      {
        "operations": ["k8s.pod.list", "k8s.pod.get"],
        "produces": {"k8s.pod.list": ["k8s.pod.metadata.name"]},
        "consumes": {"k8s.pod.list": []},
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

def is_read_operation(op: Dict) -> bool:
    """Check if operation is a read operation"""
    http_method = op.get("http_method", "").upper()
    op_name = op.get("operation", "").lower()
    return http_method == "GET" or op_name in ["list", "get", "read", "watch"]

def to_snake_case(name: str) -> str:
    """Convert CamelCase to snake_case"""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def normalize_k8s_entity(field_path: str, resource_name: str) -> str:
    """Normalize entity to have k8s. prefix"""
    if not field_path:
        return field_path
    
    # Already has k8s. prefix
    if field_path.startswith("k8s."):
        return field_path
    
    # Add k8s.resource_name. prefix
    return f"k8s.{resource_name}.{field_path}"

def build_roots_from_sdk(sdk_data: Dict, resource_name: str) -> List[Dict[str, Any]]:
    """Build roots (independent read operations) from SDK data"""
    roots = []
    
    if not sdk_data or not isinstance(sdk_data, dict):
        return roots
    
    resource_data = sdk_data.get(resource_name, {})
    if not resource_data:
        return roots
    
    independent_ops = resource_data.get("independent", [])
    
    for op in independent_ops:
        if not is_read_operation(op):
            continue
        
        op_name = op.get("operation", "")
        op_id = f"k8s.{resource_name}.{to_snake_case(op_name)}"
        
        # Extract entities from item_fields
        item_fields = op.get("item_fields", {})
        produces_entities = []
        
        for field_path in item_fields.keys():
            # Normalize field path to entity
            entity = normalize_k8s_entity(field_path, resource_name)
            produces_entities.append(entity)
        
        if produces_entities:
            roots.append({
                "op": op_id,
                "produces": sorted(set(produces_entities))
            })
    
    return roots

def build_entity_paths_from_sdk(sdk_data: Dict, resource_name: str) -> Dict[str, List[Dict[str, Any]]]:
    """Build entity_paths from SDK data"""
    entity_paths = defaultdict(lambda: {
        "operations": [],
        "produces": {},
        "consumes": {},
        "external_inputs": []
    })
    
    if not sdk_data or not isinstance(sdk_data, dict):
        return {}
    
    resource_data = sdk_data.get(resource_name, {})
    if not resource_data:
        return {}
    
    # Process independent (read) operations
    independent_ops = resource_data.get("independent", [])
    dependent_ops = resource_data.get("dependent", [])
    
    all_ops = independent_ops + dependent_ops
    
    for op in all_ops:
        if not is_read_operation(op):
            continue
        
        op_name = op.get("operation", "")
        op_id = f"k8s.{resource_name}.{to_snake_case(op_name)}"
        
        # Get entities produced by this operation
        item_fields = op.get("item_fields", {})
        produces_entities = []
        
        for field_path in item_fields.keys():
            entity = normalize_k8s_entity(field_path, resource_name)
            produces_entities.append(entity)
        
        # Get entities consumed by this operation (from consumes)
        consumes_entities = []
        consumes = op.get("consumes", [])
        for consume in consumes:
            if isinstance(consume, dict):
                consume_name = consume.get("name", "")
                if consume_name:
                    # For K8s, namespace and name are typically external inputs
                    if consume.get("source") == "external":
                        entity_paths[op_id]["external_inputs"].append(consume_name)
                    else:
                        # Internal dependency
                        entity = normalize_k8s_entity(consume_name, resource_name)
                        consumes_entities.append(entity)
        
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
    
    # Convert to list format matching standard structure
    result = {}
    for entity, data in entity_paths.items():
        # Sort operations for consistency
        data["operations"] = sorted(set(data["operations"]))
        result[entity] = [data]
    
    return result

def generate_dependency_index(resource_name: str, resource_dir: Path) -> Optional[Dict]:
    """Generate dependency_index.json for a K8s resource"""
    sdk_path = resource_dir / "k8s_dependencies_with_python_names_fully_enriched.json"
    
    if not sdk_path.exists():
        return None
    
    try:
        with open(sdk_path, 'r', encoding='utf-8') as f:
            sdk_data = json.load(f)
    except Exception as e:
        print(f"  Error loading SDK file: {e}")
        return None
    
    # Build roots and entity_paths
    roots = build_roots_from_sdk(sdk_data, resource_name)
    entity_paths = build_entity_paths_from_sdk(sdk_data, resource_name)
    
    if not roots and not entity_paths:
        return None
    
    return {
        "service": resource_name,
        "read_only": True,
        "roots": roots,
        "entity_paths": entity_paths
    }

def process_resource(resource_dir: Path, dry_run: bool = False) -> Dict[str, Any]:
    """Process a single K8s resource"""
    resource_name = resource_dir.name
    result = {
        "resource": resource_name,
        "status": "SKIPPED",
        "roots_count": 0,
        "entities_count": 0,
        "error": None
    }
    
    di_path = resource_dir / "dependency_index.json"
    
    # Check if already exists
    if di_path.exists() and not dry_run:
        result["status"] = "EXISTS"
        try:
            with open(di_path, 'r') as f:
                existing = json.load(f)
            result["roots_count"] = len(existing.get("roots", []))
            result["entities_count"] = len(existing.get("entity_paths", {}))
        except:
            pass
        return result
    
    try:
        di_data = generate_dependency_index(resource_name, resource_dir)
        
        if not di_data:
            result["status"] = "NO_DATA"
            return result
        
        roots = di_data.get("roots", [])
        entity_paths = di_data.get("entity_paths", {})
        
        result["roots_count"] = len(roots)
        result["entities_count"] = len(entity_paths)
        
        if not dry_run:
            with open(di_path, 'w', encoding='utf-8') as f:
                json.dump(di_data, f, indent=2, ensure_ascii=False)
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
    
    parser = argparse.ArgumentParser(description="Generate dependency_index.json for K8s resources")
    parser.add_argument("--resource", type=str, help="Process single resource only")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    parser.add_argument("--base-dir", type=str, default=None, help="Base directory")
    
    args = parser.parse_args()
    
    base_dir = Path(args.base_dir) if args.base_dir else Path(__file__).parent
    
    print("="*80)
    print("GENERATING DEPENDENCY_INDEX.JSON FOR KUBERNETES RESOURCES")
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
            print(f"✓ Generated ({result['roots_count']} roots, {result['entities_count']} entities)")
            success_count += 1
        elif result["status"] == "DRY_RUN":
            print(f"DRY_RUN - ({result['roots_count']} roots, {result['entities_count']} entities)")
        elif result["status"] == "EXISTS":
            print(f"Already exists ({result['roots_count']} roots, {result['entities_count']} entities)")
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
    results_file = base_dir / "dependency_index_generation_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {results_file}")

if __name__ == "__main__":
    main()

