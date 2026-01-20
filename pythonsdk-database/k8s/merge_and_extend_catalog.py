#!/usr/bin/env python3
"""
Merge and extend K8s catalog from SDK-generated and enhanced catalogs.

This script:
1. Loads the SDK-generated catalog (has all 17 resources)
2. Enhances it with field definitions from enhanced catalog where available
3. Creates a complete catalog with all resources
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional

def merge_operation_definitions(sdk_op: Dict, enhanced_op: Optional[Dict]) -> Dict:
    """Merge SDK operation with enhanced operation (enhanced takes precedence for field details)"""
    if enhanced_op:
        # Use enhanced operation structure but keep SDK structure
        merged = {
            "operation": sdk_op.get("operation", enhanced_op.get("operation", "")),
            "http_method": sdk_op.get("http_method", enhanced_op.get("http_method", "GET")),
            "description": enhanced_op.get("description", sdk_op.get("description", "")),
            "parameters": enhanced_op.get("parameters", {}),
            "item_fields": enhanced_op.get("item_fields", sdk_op.get("item_fields", {})),
            "output_fields": enhanced_op.get("output_fields", sdk_op.get("output_fields", {}))
        }
    else:
        # Use SDK operation as-is but ensure structure matches
        merged = {
            "operation": sdk_op.get("operation", ""),
            "http_method": sdk_op.get("http_method", "GET"),
            "description": sdk_op.get("description", ""),
            "parameters": {},
            "item_fields": sdk_op.get("item_fields", {}),
            "output_fields": sdk_op.get("output_fields", {})
        }
    
    return merged

def merge_resource_catalog(sdk_resource: Dict, enhanced_resource: Optional[Dict]) -> Dict:
    """Merge SDK resource with enhanced resource"""
    resource_name = sdk_resource.get("resource", "")
    api_version = sdk_resource.get("api_version", "v1")
    kind = sdk_resource.get("kind", resource_name.title())
    
    merged_resource = {
        "resource": resource_name,
        "api_version": api_version,
        "kind": kind,
        "description": enhanced_resource.get("description", f"{kind} resource") if enhanced_resource else f"{kind} resource",
        "operations": []
    }
    
    # Get operations from SDK (has all operations)
    sdk_operations = sdk_resource.get("operations", [])
    enhanced_operations = enhanced_resource.get("operations", []) if enhanced_resource else []
    
    # Create a map of enhanced operations by operation name
    enhanced_ops_map = {}
    for op in enhanced_operations:
        op_name = op.get("operation", "")
        if op_name:
            enhanced_ops_map[op_name] = op
    
    # Merge operations
    for sdk_op in sdk_operations:
        op_name = sdk_op.get("operation", "")
        enhanced_op = enhanced_ops_map.get(op_name)
        merged_op = merge_operation_definitions(sdk_op, enhanced_op)
        merged_resource["operations"].append(merged_op)
    
    return merged_resource

def merge_catalogs(sdk_catalog_path: Path, enhanced_catalog_path: Path, output_path: Path):
    """Merge SDK catalog with enhanced catalog"""
    print(f"Loading SDK catalog from: {sdk_catalog_path}")
    
    with open(sdk_catalog_path, 'r', encoding='utf-8') as f:
        sdk_catalog = json.load(f)
    
    print(f"Found {len(sdk_catalog)} resources in SDK catalog")
    
    enhanced_catalog = {}
    if enhanced_catalog_path.exists():
        print(f"Loading enhanced catalog from: {enhanced_catalog_path}")
        with open(enhanced_catalog_path, 'r', encoding='utf-8') as f:
            enhanced_catalog = json.load(f)
        print(f"Found {len(enhanced_catalog)} resources in enhanced catalog")
    else:
        print("Enhanced catalog not found, using SDK catalog as-is")
    
    # Merge catalogs
    merged_catalog = {}
    
    for resource_name, sdk_resource in sdk_catalog.items():
        enhanced_resource = enhanced_catalog.get(resource_name)
        merged_resource = merge_resource_catalog(sdk_resource, enhanced_resource)
        merged_catalog[resource_name] = merged_resource
        print(f"  ✓ Merged {resource_name}")
    
    # Save merged catalog
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(merged_catalog, f, indent=2, ensure_ascii=False)
    
    print(f"\n✅ Saved merged catalog to: {output_path}")
    print(f"Total resources: {len(merged_catalog)}")
    print(f"\nResources in merged catalog:")
    for i, resource_name in enumerate(sorted(merged_catalog.keys()), 1):
        ops = merged_catalog[resource_name].get("operations", [])
        print(f"  {i}. {resource_name}: {len(ops)} operations")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Merge K8s SDK catalog with enhanced catalog")
    parser.add_argument(
        "--sdk-catalog",
        type=str,
        default="../../k8_engine/Agent-ruleid-rule-yaml/k8s_api_catalog_from_sdk.json",
        help="Path to SDK-generated catalog"
    )
    parser.add_argument(
        "--enhanced-catalog",
        type=str,
        default="../../k8_engine/Agent-ruleid-rule-yaml/k8s_api_catalog_enhanced.json",
        help="Path to enhanced catalog"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="k8s_api_catalog_complete.json",
        help="Output merged catalog file"
    )
    
    args = parser.parse_args()
    
    base_dir = Path(__file__).parent
    sdk_catalog_path = Path(args.sdk_catalog) if Path(args.sdk_catalog).is_absolute() else base_dir / args.sdk_catalog
    enhanced_catalog_path = Path(args.enhanced_catalog) if Path(args.enhanced_catalog).is_absolute() else base_dir / args.enhanced_catalog
    output_path = base_dir / args.output
    
    if not sdk_catalog_path.exists():
        print(f"Error: SDK catalog file not found: {sdk_catalog_path}")
        return 1
    
    merge_catalogs(sdk_catalog_path, enhanced_catalog_path, output_path)
    return 0

if __name__ == "__main__":
    exit(main())

















