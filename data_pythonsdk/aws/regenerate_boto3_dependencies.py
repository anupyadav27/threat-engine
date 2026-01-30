#!/usr/bin/env python3
"""
Regenerate boto3_dependencies_with_python_names_fully_enriched.json
from boto3 service models with complete enum extraction

This script:
1. Extracts all operations from boto3 service models
2. Extracts enum values directly from shape.enum
3. Extracts all fields with types, descriptions, and possible_values
4. Builds complete dependency structure
5. Enriches with metadata (compliance categories, operators, etc.)
6. Processes ALL AWS services
"""

import boto3
import json
import re
from typing import Dict, List, Any, Set, Optional
from collections import defaultdict
from pathlib import Path

def to_snake_case(name: str) -> str:
    """Convert PascalCase to snake_case"""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def extract_enum_values(shape) -> Optional[List[str]]:
    """Extract enum values from a boto3 shape"""
    if hasattr(shape, 'enum') and shape.enum:
        return list(shape.enum)
    return None

def detect_compliance_category(field_name: str) -> str:
    """Detect compliance category based on field name"""
    field_lower = field_name.lower()
    
    if any(keyword in field_lower for keyword in ['arn', 'id', 'name', 'principal', 'role', 'user', 'account']):
        return "identity"
    elif any(keyword in field_lower for keyword in ['status', 'state', 'enabled', 'public', 'encrypted', 'secure', 'policy']):
        return "security"
    elif any(keyword in field_lower for keyword in ['cost', 'price', 'billing', 'charge']):
        return "cost"
    else:
        return "general"

def get_operators_for_type(field_type: str, is_enum: bool) -> List[str]:
    """Get appropriate operators based on field type"""
    if is_enum:
        return ["equals", "not_equals", "in", "not_in"]
    elif field_type == "boolean":
        return ["equals", "not_equals"]
    elif field_type in ["integer", "long", "float", "double"]:
        return ["equals", "not_equals", "greater_than", "less_than", 
                "greater_than_or_equal", "less_than_or_equal"]
    elif field_type == "string":
        return ["equals", "not_equals", "contains", "in", "exists"]
    elif field_type == "timestamp":
        return ["equals", "not_equals", "greater_than", "less_than", 
                "greater_than_or_equal", "less_than_or_equal"]
    else:
        return ["equals", "not_equals"]

def extract_field_metadata(shape, field_name: str) -> Dict[str, Any]:
    """Extract complete metadata for a field from boto3 shape"""
    field_type = shape.type_name if hasattr(shape, 'type_name') else "unknown"
    
    metadata = {
        "type": field_type,
        "description": getattr(shape, 'documentation', '') or f"{field_name} field",
    }
    
    # Extract enum values
    enum_values = extract_enum_values(shape)
    if enum_values:
        metadata["enum"] = True
        metadata["possible_values"] = enum_values
    else:
        metadata["enum"] = False
    
    # Extract format (date-time, etc.)
    if hasattr(shape, 'serialization') and shape.serialization:
        if 'timestampFormat' in shape.serialization:
            metadata["format"] = "date-time"
    
    # Get operators
    metadata["operators"] = get_operators_for_type(field_type, bool(enum_values))
    
    # Detect compliance category
    metadata["compliance_category"] = detect_compliance_category(field_name)
    
    # Add security impact for sensitive fields
    if metadata["compliance_category"] == "security":
        if any(keyword in field_name.lower() for keyword in ['arn', 'id', 'token', 'key', 'secret']):
            metadata["security_impact"] = "high"
        else:
            metadata["security_impact"] = "medium"
    
    # Handle boolean possible_values
    if field_type == "boolean":
        metadata["possible_values"] = [True, False]
    
    return metadata

def extract_nested_fields(shape, prefix: str = "", depth: int = 0, max_depth: int = 5) -> Dict[str, Dict[str, Any]]:
    """Recursively extract nested fields from structure shapes with depth limit"""
    nested_fields = {}
    
    if not shape or not hasattr(shape, 'members') or depth >= max_depth:
        return nested_fields
    
    for nested_field_name, nested_field_shape in shape.members.items():
        full_field_name = f"{prefix}.{nested_field_name}" if prefix else nested_field_name
        nested_fields[nested_field_name] = extract_field_metadata(nested_field_shape, nested_field_name)
        
        # Recursively handle nested structures (with depth limit)
        if nested_field_shape.type_name == 'structure' and depth < max_depth:
            deeper_nested = extract_nested_fields(nested_field_shape, full_field_name, depth + 1, max_depth)
            if deeper_nested:
                nested_fields[nested_field_name]["nested_fields"] = deeper_nested
    
    return nested_fields

def extract_item_fields(shape, operation_name: str) -> Dict[str, Dict[str, Any]]:
    """Extract fields from list item structure or object structure"""
    item_fields = {}
    
    if not shape:
        return item_fields
    
    # Handle list types
    if shape.type_name == 'list' and hasattr(shape, 'member'):
        member_shape = shape.member
        if member_shape.type_name == 'structure' and hasattr(member_shape, 'members'):
            for field_name, field_shape in member_shape.members.items():
                item_fields[field_name] = extract_field_metadata(field_shape, field_name)
                
                # Handle nested structures in item fields (with depth limit)
                if field_shape.type_name == 'structure':
                    nested = extract_nested_fields(field_shape, field_name, depth=0, max_depth=3)
                    if nested:
                        item_fields[field_name]["nested_fields"] = nested
    
    # Handle structure types (for Get operations)
    elif shape.type_name == 'structure' and hasattr(shape, 'members'):
        for field_name, field_shape in shape.members.items():
            item_fields[field_name] = extract_field_metadata(field_shape, field_name)
            
            # Handle nested structures (with depth limit)
            if field_shape.type_name == 'structure':
                nested = extract_nested_fields(field_shape, field_name, depth=0, max_depth=3)
                if nested:
                    item_fields[field_name]["nested_fields"] = nested
    
    return item_fields

def extract_output_fields(op_model) -> Dict[str, Dict[str, Any]]:
    """Extract all output fields with metadata"""
    output_fields = {}
    
    if not op_model.output_shape:
        return output_fields
    
    output_shape = op_model.output_shape
    
    if output_shape.type_name == 'structure' and hasattr(output_shape, 'members'):
        for field_name, field_shape in output_shape.members.items():
            output_fields[field_name] = extract_field_metadata(field_shape, field_name)
    
    return output_fields

def find_main_output_field(op_model, operation_name: str) -> Optional[str]:
    """Find the main output field (list or structure)"""
    if not op_model.output_shape:
        return None
    
    output_shape = op_model.output_shape
    
    # Check for list fields first
    if output_shape.type_name == 'structure' and hasattr(output_shape, 'members'):
        # Prefer list fields with common patterns
        list_fields = []
        for field_name, field_shape in output_shape.members.items():
            if field_shape.type_name == 'list':
                list_fields.append((field_name, field_shape))
        
        if list_fields:
            # Check for common patterns
            for field_name, field_shape in list_fields:
                if any(keyword in field_name.lower() for keyword in 
                       ['list', 'items', 'resources', 'summary', 'analyzers', 'buckets', 
                        'keys', 'apis', 'functions', 'pools', 'groups', 'results', 'findings']):
                    return field_name
            # Return first list if no pattern match
            return list_fields[0][0]
        
        # If no list, return first structure field
        for field_name, field_shape in output_shape.members.items():
            if field_shape.type_name == 'structure':
                return field_name
        
        # Last resort: return first field
        if output_shape.members:
            return list(output_shape.members.keys())[0]
    
    return None

def analyze_service_operations(service_name: str) -> Dict[str, Any]:
    """Analyze all operations for a service with complete enum extraction"""
    try:
        client = boto3.client(service_name, region_name='us-east-1')
        service_model = client._service_model
        
        independent_ops = []
        dependent_ops = []
        
        for op_name in service_model.operation_names:
            op_model = service_model.operation_model(op_name)
            
            # INPUT PARAMETERS
            required_params = []
            optional_params = []
            
            if op_model.input_shape:
                required_params = list(op_model.input_shape.required_members)
                all_params = list(op_model.input_shape.members.keys())
                optional_params = [p for p in all_params if p not in required_params]
            
            # OUTPUT FIELDS with metadata
            output_fields = extract_output_fields(op_model)
            
            # MAIN OUTPUT FIELD
            main_output_field = find_main_output_field(op_model, op_name)
            
            # ITEM FIELDS with enum extraction
            item_fields = {}
            if op_model.output_shape and main_output_field:
                output_shape = op_model.output_shape
                if output_shape.type_name == 'structure' and hasattr(output_shape, 'members'):
                    main_field_shape = output_shape.members.get(main_output_field)
                    if main_field_shape:
                        item_fields = extract_item_fields(main_field_shape, op_name)
            
            # Convert to snake_case
            python_method = to_snake_case(op_name)
            
            op_info = {
                'operation': op_name,
                'python_method': python_method,
                'yaml_action': python_method,
                'required_params': required_params,
                'optional_params': optional_params,
                'total_optional': len(optional_params),
                'output_fields': output_fields,
                'main_output_field': main_output_field,
                'item_fields': item_fields
            }
            
            if len(required_params) == 0:
                independent_ops.append(op_info)
            else:
                dependent_ops.append(op_info)
        
        return {
            'service': service_name,
            'total_operations': len(service_model.operation_names),
            'independent': independent_ops,
            'dependent': dependent_ops,
            'independent_count': len(independent_ops),
            'dependent_count': len(dependent_ops)
        }
        
    except Exception as e:
        return {
            'service': service_name,
            'error': str(e),
            'total_operations': 0,
            'independent': [],
            'dependent': [],
            'independent_count': 0,
            'dependent_count': 0
        }

def regenerate_all_services(output_file: Path, per_service_dir: Optional[Path] = None):
    """Regenerate boto3_dependencies for all services"""
    session = boto3.Session()
    all_services = session.get_available_services()
    
    all_analysis = {}
    total_enums = 0
    services_with_errors = []
    
    print(f"Regenerating boto3_dependencies for {len(all_services)} services...")
    print("This will extract ALL enum values from boto3 shape definitions\n")
    
    for idx, service in enumerate(sorted(all_services), 1):
        print(f"[{idx}/{len(all_services)}] Processing {service}...", end='\r')
        analysis = analyze_service_operations(service)
        
        if 'error' in analysis:
            services_with_errors.append((service, analysis['error']))
            print(f"[{idx}/{len(all_services)}] ✗ {service}: Error - {analysis['error']}")
        else:
            # Count enums found
            service_enums = 0
            for op in analysis['independent'] + analysis['dependent']:
                # Count in item_fields
                for field_name, field_data in op.get('item_fields', {}).items():
                    if field_data.get('enum') and field_data.get('possible_values'):
                        service_enums += len(field_data['possible_values'])
                
                # Count in output_fields
                for field_name, field_data in op.get('output_fields', {}).items():
                    if field_data.get('enum') and field_data.get('possible_values'):
                        service_enums += len(field_data['possible_values'])
            
            if service_enums > 0:
                print(f"[{idx}/{len(all_services)}] ✓ {service}: {len(analysis['independent'])} independent, "
                      f"{len(analysis['dependent'])} dependent, {service_enums} enum values")
                total_enums += service_enums
            else:
                print(f"[{idx}/{len(all_services)}] ✓ {service}: {len(analysis['independent'])} independent, "
                      f"{len(analysis['dependent'])} dependent")
        
        all_analysis[service] = analysis
        
        # Save per-service file if directory provided
        if per_service_dir and 'error' not in analysis:
            service_dir = per_service_dir / service
            service_dir.mkdir(parents=True, exist_ok=True)
            service_file = service_dir / "boto3_dependencies_with_python_names_fully_enriched.json"
            
            service_data = {service: analysis}
            with open(service_file, 'w', encoding='utf-8') as f:
                json.dump(service_data, f, indent=2, ensure_ascii=False)
    
    print(f"\n{'='*80}")
    print("REGENERATION COMPLETE")
    print(f"{'='*80}")
    print(f"Total services: {len(all_services)}")
    print(f"Services processed: {len(all_services) - len(services_with_errors)}")
    print(f"Services with errors: {len(services_with_errors)}")
    print(f"Total enum values extracted: {total_enums}")
    
    if services_with_errors:
        print(f"\nServices with errors:")
        for service, error in services_with_errors[:10]:
            print(f"  - {service}: {error}")
        if len(services_with_errors) > 10:
            print(f"  ... and {len(services_with_errors) - 10} more")
    
    # Save main consolidated file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_analysis, f, indent=2, ensure_ascii=False)
    
    print(f"\n✓ Saved main file: {output_file}")
    print(f"  File size: {output_file.stat().st_size / 1024 / 1024:.2f} MB")
    
    if per_service_dir:
        print(f"✓ Saved per-service files to: {per_service_dir}")
    
    return all_analysis

if __name__ == '__main__':
    import sys
    
    # Default paths
    script_dir = Path(__file__).parent
    output_path = script_dir / "boto3_dependencies_with_python_names_fully_enriched.json"
    per_service_dir = script_dir  # Save per-service files in same directory
    
    if len(sys.argv) > 1:
        output_path = Path(sys.argv[1])
    
    if len(sys.argv) > 2:
        per_service_dir = Path(sys.argv[2])
    
    print("="*80)
    print("BOTO3 DEPENDENCIES REGENERATION")
    print("="*80)
    print(f"Output file: {output_path}")
    print(f"Per-service directory: {per_service_dir}")
    print("="*80)
    print()
    
    regenerate_all_services(output_path, per_service_dir)

