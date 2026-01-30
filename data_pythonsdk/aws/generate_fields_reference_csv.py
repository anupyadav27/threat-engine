#!/usr/bin/env python3
"""
Generate CSV reference file with all services, fields, possible values, and dependency_index_entity
ONLY from read operations (List*, Get*, Describe*, Search*, Lookup*)
"""

import json
import csv
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

def is_read_operation(operation_name: str) -> bool:
    """Check if operation is a read operation"""
    read_prefixes = ['List', 'Get', 'Describe', 'Search', 'Lookup']
    return any(operation_name.startswith(prefix) for prefix in read_prefixes)

def normalize_field_name(name: str) -> str:
    """Normalize field name for matching (remove case, underscores, etc.)"""
    return name.replace("_", "").replace("-", "").lower()

def search_nested_fields(fields_dict: Dict, field_name: str, normalized_search: str) -> Optional[List[str]]:
    """Recursively search nested fields for enum values"""
    if not isinstance(fields_dict, dict):
        return None
    
    for nested_field_name, nested_field_data in fields_dict.items():
        # Check exact match
        if nested_field_name.lower() == field_name.lower():
            if isinstance(nested_field_data, dict) and nested_field_data.get("enum") and "possible_values" in nested_field_data:
                return nested_field_data["possible_values"]
        
        # Check normalized match
        normalized_nested = normalize_field_name(nested_field_name)
        if normalized_nested == normalized_search:
            if isinstance(nested_field_data, dict) and nested_field_data.get("enum") and "possible_values" in nested_field_data:
                return nested_field_data["possible_values"]
        
        # Recursively check nested_fields
        if isinstance(nested_field_data, dict) and "nested_fields" in nested_field_data:
            result = search_nested_fields(nested_field_data["nested_fields"], field_name, normalized_search)
            if result:
                return result
    
    return None

def get_possible_values_from_boto3(service_name: str, field_name: str, boto3_deps: Dict) -> Optional[List[str]]:
    """Get possible_values from boto3_dependencies if not in direct_vars
    ONLY from read operations
    """
    service_data = boto3_deps.get(service_name, {})
    
    if not service_data:
        return None
    
    # Normalize the search field name
    normalized_search = normalize_field_name(field_name)
    all_possible_values = set()
    
    # Check both independent and dependent operations, but filter to read operations only
    all_operations = service_data.get("independent", []) + service_data.get("dependent", [])
    read_operations = [op for op in all_operations if is_read_operation(op.get("operation", ""))]
    
    # Collect all matching enum values (prioritize exact matches, then normalized, then partial)
    for op in read_operations:
        item_fields = op.get("item_fields", {})
        if isinstance(item_fields, dict):
            for item_field_name, item_field_data in item_fields.items():
                normalized_item = normalize_field_name(item_field_name)
                # Exact case-insensitive match (highest priority)
                if item_field_name.lower() == field_name.lower():
                    if item_field_data.get("enum") and "possible_values" in item_field_data:
                        all_possible_values.update(item_field_data["possible_values"])
                    # Check nested fields
                    if "nested_fields" in item_field_data:
                        result = search_nested_fields(item_field_data["nested_fields"], field_name, normalized_search)
                        if result:
                            all_possible_values.update(result)
                # Normalized match (second priority)
                elif normalized_item == normalized_search:
                    if item_field_data.get("enum") and "possible_values" in item_field_data:
                        all_possible_values.update(item_field_data["possible_values"])
                    # Check nested fields
                    if "nested_fields" in item_field_data:
                        result = search_nested_fields(item_field_data["nested_fields"], field_name, normalized_search)
                        if result:
                            all_possible_values.update(result)
                # Partial match (lowest priority, only if no exact match found yet)
                elif len(normalized_search) > 2 and (normalized_search in normalized_item or normalized_item in normalized_search):
                    if item_field_data.get("enum") and "possible_values" in item_field_data:
                        all_possible_values.update(item_field_data["possible_values"])
                    # Check nested fields
                    if "nested_fields" in item_field_data:
                        result = search_nested_fields(item_field_data["nested_fields"], field_name, normalized_search)
                        if result:
                            all_possible_values.update(result)
        
        # Check output_fields
        output_fields = op.get("output_fields", {})
        if isinstance(output_fields, dict):
            for output_field_name, output_field_data in output_fields.items():
                normalized_output = normalize_field_name(output_field_name)
                # Exact case-insensitive match (highest priority)
                if output_field_name.lower() == field_name.lower():
                    if output_field_data.get("enum") and "possible_values" in output_field_data:
                        all_possible_values.update(output_field_data["possible_values"])
                    # Check nested fields
                    if "nested_fields" in output_field_data:
                        result = search_nested_fields(output_field_data["nested_fields"], field_name, normalized_search)
                        if result:
                            all_possible_values.update(result)
                # Normalized match (second priority)
                elif normalized_output == normalized_search:
                    if output_field_data.get("enum") and "possible_values" in output_field_data:
                        all_possible_values.update(output_field_data["possible_values"])
                    # Check nested fields
                    if "nested_fields" in output_field_data:
                        result = search_nested_fields(output_field_data["nested_fields"], field_name, normalized_search)
                        if result:
                            all_possible_values.update(result)
                # Partial match (lowest priority, only if no exact match found yet)
                elif len(normalized_search) > 2 and (normalized_search in normalized_output or normalized_output in normalized_search):
                    if output_field_data.get("enum") and "possible_values" in output_field_data:
                        all_possible_values.update(output_field_data["possible_values"])
                    # Check nested fields
                    if "nested_fields" in output_field_data:
                        result = search_nested_fields(output_field_data["nested_fields"], field_name, normalized_search)
                        if result:
                            all_possible_values.update(result)
    
    if all_possible_values:
        return sorted(list(all_possible_values))
    return None

def extract_all_boto3_enum_fields(service_name: str, boto3_deps: Dict) -> Dict[str, Dict[str, Any]]:
    """Extract ALL enum fields from boto3_dependencies for a service
    ONLY from read operations
    """
    service_data = boto3_deps.get(service_name, {})
    
    if not service_data or not isinstance(service_data, dict) or 'error' in service_data:
        return {}
    
    enum_fields = {}
    all_operations = service_data.get("independent", []) + service_data.get("dependent", [])
    # Filter to read operations only
    read_operations = [op for op in all_operations if is_read_operation(op.get("operation", ""))]
    
    for op in read_operations:
        operation_name = op.get("operation", "unknown")
        
        # Extract from item_fields
        item_fields = op.get("item_fields", {})
        if isinstance(item_fields, dict):
            for field_name, field_data in item_fields.items():
                if field_data.get("enum") and field_data.get("possible_values"):
                    # Use field_name as key, aggregate values from all operations
                    if field_name not in enum_fields:
                        enum_fields[field_name] = {
                            "field_name": field_name,
                            "type": field_data.get("type", "string"),
                            "is_enum": True,
                            "possible_values": set(field_data["possible_values"]),
                            "operators": field_data.get("operators", []),
                            "description": field_data.get("description", ""),
                            "source": "boto3_deps",
                            "operations": [operation_name]
                        }
                    else:
                        # Merge values from multiple operations
                        enum_fields[field_name]["possible_values"].update(field_data["possible_values"])
                        if operation_name not in enum_fields[field_name]["operations"]:
                            enum_fields[field_name]["operations"].append(operation_name)
        
        # Extract from output_fields
        output_fields = op.get("output_fields", {})
        if isinstance(output_fields, dict):
            for field_name, field_data in output_fields.items():
                if field_data.get("enum") and field_data.get("possible_values"):
                    if field_name not in enum_fields:
                        enum_fields[field_name] = {
                            "field_name": field_name,
                            "type": field_data.get("type", "string"),
                            "is_enum": True,
                            "possible_values": set(field_data["possible_values"]),
                            "operators": field_data.get("operators", []),
                            "description": field_data.get("description", ""),
                            "source": "boto3_deps",
                            "operations": [operation_name]
                        }
                    else:
                        enum_fields[field_name]["possible_values"].update(field_data["possible_values"])
                        if operation_name not in enum_fields[field_name]["operations"]:
                            enum_fields[field_name]["operations"].append(operation_name)
    
    # Convert sets to sorted lists
    for field_name in enum_fields:
        enum_fields[field_name]["possible_values"] = sorted(list(enum_fields[field_name]["possible_values"]))
    
    return enum_fields

def load_service_fields(service_dir: Path, boto3_deps: Dict) -> List[Dict[str, Any]]:
    """Load fields from direct_vars.json and enrich with boto3_dependencies
    ONLY from read operations
    """
    direct_vars_path = service_dir / "direct_vars.json"
    service_name = service_dir.name
    
    rows = []
    
    # Load direct_vars fields
    direct_vars_fields = {}
    if direct_vars_path.exists():
        try:
            with open(direct_vars_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            service_name = data.get("service", service_name)
            direct_vars_fields = data.get("fields", {})
        except Exception as e:
            print(f"Error loading {service_dir.name}/direct_vars.json: {e}")
    
    # Process direct_vars fields
    for field_name, field_data in direct_vars_fields.items():
        possible_values = field_data.get("possible_values")
        values_source = "direct_vars"
        
        if not possible_values:
            boto3_values = get_possible_values_from_boto3(service_name, field_name, boto3_deps)
            if boto3_values:
                possible_values = boto3_values
                values_source = "boto3_deps"
        
        if possible_values is None:
            possible_values_str = ""
            values_source = ""
        elif isinstance(possible_values, list):
            possible_values_str = ", ".join(str(v) for v in possible_values)
        else:
            possible_values_str = str(possible_values)
        
        rows.append({
            "service": service_name,
            "field_name": field_name,
            "type": field_data.get("type", ""),
            "is_enum": "Yes" if (field_data.get("enum") or values_source == "boto3_deps") else "No",
            "possible_values": possible_values_str,
            "values_source": values_source,
            "operators": ", ".join(field_data.get("operators", [])),
            "dependency_index_entity": field_data.get("dependency_index_entity", ""),
            "in_direct_vars": "Yes"
        })
    
    # Add ALL enum fields from boto3 read operations (even if not in direct_vars)
    boto3_enum_fields = extract_all_boto3_enum_fields(service_name, boto3_deps)
    direct_vars_field_names = set(direct_vars_fields.keys())
    
    for field_name, field_info in boto3_enum_fields.items():
        # Skip if already in direct_vars (we already processed it)
        if field_name in direct_vars_field_names:
            continue
        
        # Add as new row from boto3 only
        possible_values_str = ", ".join(str(v) for v in field_info["possible_values"])
        
        rows.append({
            "service": service_name,
            "field_name": field_name,
            "type": field_info.get("type", "string"),
            "is_enum": "Yes",
            "possible_values": possible_values_str,
            "values_source": "boto3_deps",
            "operators": ", ".join(field_info.get("operators", [])),
            "dependency_index_entity": "",
            "in_direct_vars": "No"
        })
    
    return rows

def generate_csv(base_dir: Path, output_file: Path):
    """Generate CSV file with all service fields from read operations only"""
    base_path = Path(base_dir)
    
    if not base_path.exists():
        print(f"Error: Base directory does not exist: {base_path}")
        return
    
    # Load boto3_dependencies
    boto3_deps_path = base_path / "boto3_dependencies_with_python_names_fully_enriched.json"
    boto3_deps = {}
    if boto3_deps_path.exists():
        try:
            with open(boto3_deps_path, 'r', encoding='utf-8') as f:
                boto3_deps = json.load(f)
            print(f"Loaded boto3_dependencies for enrichment (read operations only)")
        except Exception as e:
            print(f"Warning: Could not load boto3_dependencies: {e}")
    
    all_rows = []
    service_dirs = sorted([d for d in base_path.iterdir() if d.is_dir() and not d.name.startswith('_')])
    
    print(f"Processing {len(service_dirs)} services (read operations only)...")
    
    for service_dir in service_dirs:
        if service_dir.name.startswith('__') or service_dir.name.endswith('.py'):
            continue
        
        rows = load_service_fields(service_dir, boto3_deps)
        all_rows.extend(rows)
        
        if rows:
            direct_vars_count = sum(1 for r in rows if r.get("in_direct_vars") == "Yes")
            boto3_only_count = sum(1 for r in rows if r.get("in_direct_vars") == "No")
            print(f"  ✓ {service_dir.name}: {len(rows)} fields ({direct_vars_count} from direct_vars, {boto3_only_count} from boto3 read ops only)")
    
    if not all_rows:
        print("No fields found to write to CSV")
        return
    
    fieldnames = [
        "service",
        "field_name",
        "type",
        "is_enum",
        "possible_values",
        "values_source",
        "operators",
        "dependency_index_entity",
        "in_direct_vars"
    ]
    
    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)
    
    # Statistics
    total_fields = len(all_rows)
    fields_with_values = sum(1 for row in all_rows if row["possible_values"])
    fields_from_direct_vars = sum(1 for row in all_rows if row["values_source"] == "direct_vars")
    fields_from_boto3 = sum(1 for row in all_rows if row["values_source"] == "boto3_deps")
    fields_in_direct_vars = sum(1 for row in all_rows if row.get("in_direct_vars") == "Yes")
    fields_boto3_only = sum(1 for row in all_rows if row.get("in_direct_vars") == "No")
    
    print(f"\n✓ CSV file generated: {output_file}")
    print(f"  Total rows: {total_fields}")
    print(f"  Total services: {len(set(row['service'] for row in all_rows))}")
    print(f"  Fields with possible_values: {fields_with_values} ({fields_with_values/total_fields*100:.1f}%)")
    print(f"  Values from direct_vars: {fields_from_direct_vars}")
    print(f"  Values from boto3_deps (read ops): {fields_from_boto3}")
    print(f"  Fields in direct_vars: {fields_in_direct_vars}")
    print(f"  Fields from boto3 read ops only: {fields_boto3_only}")

if __name__ == "__main__":
    base_dir = Path(__file__).parent
    output_file = base_dir / "aws_fields_reference.csv"
    
    generate_csv(base_dir, output_file)
