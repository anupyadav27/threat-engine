#!/usr/bin/env python3
"""
Fix GCP entity format issues by regenerating dependency_index.json and updating direct_vars.json.

This script:
1. Regenerates all dependency_index.json files with normalized entity format (gcp. prefix)
2. Updates all direct_vars.json files to ensure dependency_index_entity has gcp. prefix
3. Ensures consistency between dependency_index and direct_vars
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional

# Import normalization function
sys.path.insert(0, str(Path(__file__).parent))
from generate_dependency_index import generate_dependency_index, normalize_gcp_entity

def normalize_gcp_entity_simple(entity: str, service_name: str) -> str:
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

def fix_dependency_index(service_dir: Path, service_name: str, force: bool = False) -> Dict[str, Any]:
    """Fix dependency_index.json for a service"""
    result = {
        "service": service_name,
        "status": "SKIPPED",
        "fixed": False,
        "error": None
    }
    
    di_path = service_dir / "dependency_index.json"
    
    if not di_path.exists():
        result["status"] = "NO_FILE"
        return result
    
    try:
        # Regenerate dependency_index
        new_di = generate_dependency_index(service_name, service_dir)
        
        if not new_di:
            result["status"] = "NO_DATA"
            return result
        
        # Check if entity paths are normalized
        entity_paths = new_di.get("entity_paths", {})
        needs_fix = False
        
        for entity_key in entity_paths.keys():
            if not entity_key.startswith("gcp."):
                needs_fix = True
                break
        
        # Also check roots produces
        roots = new_di.get("roots", [])
        for root in roots:
            produces = root.get("produces", [])
            for entity in produces:
                if not entity.startswith("gcp."):
                    needs_fix = True
                    break
        
        if needs_fix or force:
            # Save fixed dependency_index
            with open(di_path, 'w', encoding='utf-8') as f:
                json.dump(new_di, f, indent=2, ensure_ascii=False)
            result["status"] = "FIXED"
            result["fixed"] = True
        else:
            result["status"] = "ALREADY_NORMALIZED"
        
    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)
        import traceback
        result["traceback"] = traceback.format_exc()
    
    return result

def fix_direct_vars(service_dir: Path, service_name: str) -> Dict[str, Any]:
    """Fix direct_vars.json to ensure all dependency_index_entity have gcp. prefix"""
    result = {
        "service": service_name,
        "status": "SKIPPED",
        "fixed": False,
        "fields_updated": 0,
        "error": None
    }
    
    dv_path = service_dir / "direct_vars.json"
    
    if not dv_path.exists():
        result["status"] = "NO_FILE"
        return result
    
    try:
        with open(dv_path, 'r', encoding='utf-8') as f:
            direct_vars = json.load(f)
        
        fields = direct_vars.get("fields", {})
        fields_updated = 0
        
        # Fix all dependency_index_entity fields
        for field_name, field_data in fields.items():
            if not isinstance(field_data, dict):
                continue
            
            entity = field_data.get("dependency_index_entity")
            if entity:
                normalized_entity = normalize_gcp_entity_simple(entity, service_name)
                if normalized_entity != entity:
                    field_data["dependency_index_entity"] = normalized_entity
                    fields_updated += 1
        
        # Also fix produces arrays
        for field_name, field_data in fields.items():
            if not isinstance(field_data, dict):
                continue
            
            produces = field_data.get("produces", [])
            if isinstance(produces, list):
                updated_produces = []
                for prod_entity in produces:
                    if isinstance(prod_entity, str):
                        normalized = normalize_gcp_entity_simple(prod_entity, service_name)
                        updated_produces.append(normalized)
                        if normalized != prod_entity:
                            fields_updated += 1
                    else:
                        updated_produces.append(prod_entity)
                field_data["produces"] = updated_produces
        
        if fields_updated > 0:
            # Save fixed direct_vars
            with open(dv_path, 'w', encoding='utf-8') as f:
                json.dump(direct_vars, f, indent=2, ensure_ascii=False)
            result["status"] = "FIXED"
            result["fixed"] = True
            result["fields_updated"] = fields_updated
        else:
            result["status"] = "ALREADY_NORMALIZED"
        
    except Exception as e:
        result["status"] = "ERROR"
        result["error"] = str(e)
        import traceback
        result["traceback"] = traceback.format_exc()
    
    return result

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Fix GCP entity format issues")
    parser.add_argument("--service", type=str, help="Fix single service only")
    parser.add_argument("--force", action="store_true", help="Force regeneration even if already normalized")
    parser.add_argument("--base-dir", type=str, default=None, help="Base directory")
    
    args = parser.parse_args()
    
    base_dir = Path(args.base_dir) if args.base_dir else Path(__file__).parent
    
    print("="*80)
    print("FIXING GCP ENTITY FORMAT ISSUES")
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
    if args.force:
        print("FORCE MODE - All files will be regenerated/updated")
    print()
    
    results = []
    di_fixed = 0
    dv_fixed = 0
    di_already_ok = 0
    dv_already_ok = 0
    errors = 0
    
    for service_dir in service_dirs:
        service_name = service_dir.name
        print(f"Processing {service_name}...")
        
        # Fix dependency_index
        di_result = fix_dependency_index(service_dir, service_name, force=args.force)
        results.append({**di_result, "type": "dependency_index"})
        
        if di_result["status"] == "FIXED":
            print(f"  ✓ Fixed dependency_index.json")
            di_fixed += 1
        elif di_result["status"] == "ALREADY_NORMALIZED":
            di_already_ok += 1
        elif di_result["status"] == "ERROR":
            print(f"  ✗ Error fixing dependency_index: {di_result['error']}")
            errors += 1
        
        # Fix direct_vars
        dv_result = fix_direct_vars(service_dir, service_name)
        results.append({**dv_result, "type": "direct_vars"})
        
        if dv_result["status"] == "FIXED":
            print(f"  ✓ Fixed direct_vars.json ({dv_result['fields_updated']} fields updated)")
            dv_fixed += 1
        elif dv_result["status"] == "ALREADY_NORMALIZED":
            dv_already_ok += 1
        elif dv_result["status"] == "ERROR":
            print(f"  ✗ Error fixing direct_vars: {dv_result['error']}")
            errors += 1
    
    print()
    print("="*80)
    print("SUMMARY")
    print("="*80)
    print(f"Total services: {len(service_dirs)}")
    print(f"  Dependency Index fixed: {di_fixed}")
    print(f"  Dependency Index already OK: {di_already_ok}")
    print(f"  Direct Vars fixed: {dv_fixed}")
    print(f"  Direct Vars already OK: {dv_already_ok}")
    print(f"  Errors: {errors}")
    
    # Save results
    results_file = base_dir / "entity_format_fix_results.json"
    with open(results_file, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nResults saved to: {results_file}")

if __name__ == "__main__":
    main()

