#!/usr/bin/env python3
"""
Convert k8s_api_catalog_enhanced.json to k8s_dependencies_with_python_names_fully_enriched.json format.

This script converts the existing K8s API catalog into the standard SDK dependencies format
used by other CSPs.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

def to_snake_case(name: str) -> str:
    """Convert CamelCase to snake_case"""
    # Handle camelCase
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    s2 = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1)
    return s2.lower()

def flatten_nested_fields(nested_fields: Dict, prefix: str = "", result: Dict = None) -> Dict:
    """Flatten nested fields into dot-notation paths"""
    if result is None:
        result = {}
    
    for field_name, field_data in nested_fields.items():
        field_path = f"{prefix}.{field_name}" if prefix else field_name
        
        # Store field info
        result[field_path] = {
            "type": field_data.get("type", "string"),
            "description": field_data.get("description", ""),
            "compliance_category": field_data.get("compliance_category", "general"),
            "security_impact": field_data.get("security_impact"),
            "enum": field_data.get("enum", False),
            "possible_values": field_data.get("possible_values"),
        }
        
        # Recursively process nested fields
        if "nested_fields" in field_data:
            flatten_nested_fields(field_data["nested_fields"], field_path, result)
        elif "item_schema" in field_data:
            # For array items
            flatten_nested_fields(field_data["item_schema"], f"{field_path}[]", result)
    
    return result

def convert_operation(operation: Dict, resource_name: str) -> Dict:
    """Convert a single operation to SDK dependencies format"""
    op_name = operation.get("operation", "")
    http_method = operation.get("http_method", "").upper()
    
    # Determine if it's a read operation
    is_read = http_method == "GET" or op_name in ["list", "get", "read"]
    
    # Convert parameters to consumes format
    consumes = []
    parameters = operation.get("parameters", {})
    for param_name, param_data in parameters.items():
        if param_data.get("required", False):
            consumes.append({
                "name": param_name,
                "type": param_data.get("type", "string"),
                "description": param_data.get("description", ""),
                "required": True,
                "source": "external" if param_name in ["namespace", "name"] else "internal"
            })
    
    # Extract fields from item_fields
    item_fields = operation.get("item_fields", {})
    flattened_fields = flatten_nested_fields(item_fields)
    
    # Extract output_fields (top-level fields)
    output_fields = {}
    if "item_fields" in operation:
        # Top-level fields from item_fields
        for field_name, field_data in item_fields.items():
            if isinstance(field_data, dict) and "nested_fields" not in field_data:
                output_fields[field_name] = {
                    "type": field_data.get("type", "string"),
                    "description": field_data.get("description", ""),
                    "compliance_category": field_data.get("compliance_category", "general"),
                }
    
    # Build operation dict
    op_dict = {
        "operation": op_name,
        "http_method": http_method,
        "description": operation.get("description", ""),
        "item_fields": flattened_fields if flattened_fields else {},
        "output_fields": output_fields if output_fields else {},
    }
    
    if consumes:
        op_dict["consumes"] = consumes
    
    return op_dict

def convert_resource(resource_data: Dict, resource_name: str) -> Dict:
    """Convert a single resource to SDK dependencies format"""
    operations = resource_data.get("operations", [])
    
    # Separate operations into independent (read) and dependent (write)
    independent_ops = []
    dependent_ops = []
    
    for op in operations:
        op_dict = convert_operation(op, resource_name)
        http_method = op.get("http_method", "").upper()
        op_name = op.get("operation", "").lower()
        
        if http_method == "GET" or op_name in ["list", "get", "read"]:
            independent_ops.append(op_dict)
        else:
            dependent_ops.append(op_dict)
    
    return {
        "resource": resource_name,
        "api_version": resource_data.get("api_version", "v1"),
        "kind": resource_data.get("kind", resource_name.title()),
        "description": resource_data.get("description", ""),
        "independent": independent_ops,
        "dependent": dependent_ops
    }

def convert_catalog_to_sdk_dependencies(catalog_path: Path, output_path: Path, use_complete: bool = True):
    """Convert k8s API catalog to SDK dependencies format"""
    print(f"Loading catalog from: {catalog_path}")
    
    with open(catalog_path, 'r', encoding='utf-8') as f:
        catalog = json.load(f)
    
    print(f"Found {len(catalog)} resources")
    
    # If use_complete, prefer the complete catalog which has all resources
    if use_complete:
        print(f"Using complete catalog with all {len(catalog)} resources")
    
    # Convert each resource
    converted_resources = {}
    for resource_name, resource_data in catalog.items():
        print(f"Converting resource: {resource_name}")
        converted_resources[resource_name] = convert_resource(resource_data, resource_name)
    
    # Save per-resource files
    output_dir = output_path.parent
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Create per-resource directories and files
    for resource_name, resource_data in converted_resources.items():
        resource_dir = output_dir / resource_name
        resource_dir.mkdir(exist_ok=True)
        
        resource_file = resource_dir / "k8s_dependencies_with_python_names_fully_enriched.json"
        
        # Wrap in standard format
        sdk_dependencies = {
            resource_name: resource_data
        }
        
        with open(resource_file, 'w', encoding='utf-8') as f:
            json.dump(sdk_dependencies, f, indent=2, ensure_ascii=False)
        
        print(f"  ✓ Created {resource_file}")
    
    # Also create a combined file
    combined_file = output_path
    with open(combined_file, 'w', encoding='utf-8') as f:
        json.dump(converted_resources, f, indent=2, ensure_ascii=False)
    
    print(f"\n✓ Created combined file: {combined_file}")
    print(f"\nTotal resources converted: {len(converted_resources)}")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="Convert K8s API catalog to SDK dependencies format")
    parser.add_argument(
        "--catalog",
        type=str,
        default="../../k8_engine/Agent-ruleid-rule-yaml/k8s_api_catalog_enhanced.json",
        help="Path to k8s_api_catalog_enhanced.json"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="k8s_dependencies_with_python_names_fully_enriched.json",
        help="Output file path (relative to k8s directory)"
    )
    
    args = parser.parse_args()
    
    base_dir = Path(__file__).parent
    catalog_path = Path(args.catalog) if Path(args.catalog).is_absolute() else base_dir / args.catalog
    output_path = base_dir / args.output
    
    if not catalog_path.exists():
        print(f"Error: Catalog file not found: {catalog_path}")
        return 1
    
    convert_catalog_to_sdk_dependencies(catalog_path, output_path)
    return 0

if __name__ == "__main__":
    exit(main())

