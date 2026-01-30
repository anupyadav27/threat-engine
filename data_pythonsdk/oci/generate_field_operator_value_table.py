#!/usr/bin/env python3
"""
Generate field_operator_value_table.csv for Oracle Cloud Infrastructure (OCI) services.
Adapted from IBM version for OCI structure.
"""

import json
import csv
from pathlib import Path
from typing import Dict, List, Any, Set
from collections import defaultdict

# Operators that don't require values
OPERATORS_NO_VALUE = {'exists', 'not_empty'}

# Operators that require values
OPERATORS_REQUIRE_VALUE = {
    'equals', 'not_equals', 'contains', 'not_contains', 
    'in', 'not_in', 'greater_than', 'less_than', 
    'greater_than_or_equal', 'less_than_or_equal',
    'gt', 'lt', 'gte', 'lte'
}

def pascal_to_snake(name: str) -> str:
    """Convert PascalCase to snake_case"""
    import re
    # Insert underscore before uppercase letters (except first)
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def normalize_field_name(field_name: str) -> str:
    """Normalize field name to snake_case for consistency"""
    # If already snake_case, return as is
    if '_' in field_name and field_name[0].islower():
        return field_name
    # If PascalCase, convert to snake_case
    if field_name and field_name[0].isupper():
        return pascal_to_snake(field_name)
    return field_name

def load_service_data(service_name: str, base_dir: Path) -> Dict[str, Any]:
    """Load all service data files"""
    service_dir = base_dir / service_name
    
    data = {
        'direct_vars': None,
        'oci_deps': None,
        'all_fields': set(),
        'field_mapping': {}  # Map normalized name to original names
    }
    
    # Load direct_vars.json
    direct_vars_path = service_dir / 'direct_vars.json'
    if direct_vars_path.exists():
        with open(direct_vars_path, 'r', encoding='utf-8') as f:
            data['direct_vars'] = json.load(f)
            # Collect all fields from direct_vars (already snake_case)
            fields = data['direct_vars'].get('fields', {})
            for field_name in fields.keys():
                normalized = normalize_field_name(field_name)
                data['all_fields'].add(normalized)
                if normalized not in data['field_mapping']:
                    data['field_mapping'][normalized] = []
                data['field_mapping'][normalized].append(('direct_vars', field_name))
    
    # Load oci_dependencies_with_python_names_fully_enriched.json
    oci_deps_path = service_dir / 'oci_dependencies_with_python_names_fully_enriched.json'
    if oci_deps_path.exists():
        with open(oci_deps_path, 'r', encoding='utf-8') as f:
            oci_data = json.load(f)
            data['oci_deps'] = oci_data.get(service_name, {})
            
            # Collect all fields from oci_deps
            # OCI has 'operations' array directly
            operations = data['oci_deps'].get('operations', [])
            for op in operations:
                item_fields = op.get('item_fields', {})
                if isinstance(item_fields, dict):
                    for field_name in item_fields.keys():
                        normalized = normalize_field_name(field_name)
                        data['all_fields'].add(normalized)
                        if normalized not in data['field_mapping']:
                            data['field_mapping'][normalized] = []
                        data['field_mapping'][normalized].append(('oci_deps', field_name))
    
    return data

def get_possible_values(field_name: str, service_data: Dict) -> tuple:
    """Get possible values for a field from multiple sources"""
    # Get all original field names for this normalized field
    field_mapping = service_data.get('field_mapping', {})
    original_names = field_mapping.get(field_name, [])
    
    # Check direct_vars first (preferred source)
    for source, orig_name in original_names:
        if source == 'direct_vars' and service_data['direct_vars']:
            fields = service_data['direct_vars'].get('fields', {})
            if orig_name in fields:
                field_data = fields[orig_name]
                if isinstance(field_data, dict):
                    possible_values = field_data.get('possible_values')
                    if possible_values:
                        if isinstance(possible_values, list):
                            return (possible_values, 'direct_vars')
                        elif isinstance(possible_values, str):
                            values = [v.strip() for v in possible_values.split(',')]
                            return (values, 'direct_vars')
    
    # Check oci_deps
    for source, orig_name in original_names:
        if source == 'oci_deps' and service_data['oci_deps']:
            operations = service_data['oci_deps'].get('operations', [])
            for op in operations:
                item_fields = op.get('item_fields', {})
                if isinstance(item_fields, dict) and orig_name in item_fields:
                    field_data = item_fields[orig_name]
                    if field_data.get('enum') and 'possible_values' in field_data:
                        return (field_data['possible_values'], 'oci_deps')
    
    return (None, None)

def get_field_type(field_name: str, service_data: Dict) -> str:
    """Get field type from multiple sources"""
    # Get all original field names for this normalized field
    field_mapping = service_data.get('field_mapping', {})
    original_names = field_mapping.get(field_name, [])
    
    # Check direct_vars first (preferred source)
    for source, orig_name in original_names:
        if source == 'direct_vars' and service_data['direct_vars']:
            fields = service_data['direct_vars'].get('fields', {})
            if orig_name in fields:
                field_data = fields[orig_name]
                if isinstance(field_data, dict):
                    return field_data.get('type', 'string')
    
    # Check oci_deps
    for source, orig_name in original_names:
        if source == 'oci_deps' and service_data['oci_deps']:
            operations = service_data['oci_deps'].get('operations', [])
            for op in operations:
                item_fields = op.get('item_fields', {})
                if isinstance(item_fields, dict) and orig_name in item_fields:
                    return item_fields[orig_name].get('type', 'string')
    
    return 'string'

def get_operators(field_name: str, service_data: Dict) -> List[str]:
    """Get available operators for a field"""
    operators = set()
    
    # Get all original field names for this normalized field
    field_mapping = service_data.get('field_mapping', {})
    original_names = field_mapping.get(field_name, [])
    
    # Check direct_vars first (preferred source)
    for source, orig_name in original_names:
        if source == 'direct_vars' and service_data['direct_vars']:
            fields = service_data['direct_vars'].get('fields', {})
            if orig_name in fields:
                field_data = fields[orig_name]
                if isinstance(field_data, dict):
                    ops = field_data.get('operators', [])
                    if ops:
                        if isinstance(ops, list):
                            operators.update(ops)
                        elif isinstance(ops, str):
                            operators.update([op.strip() for op in ops.split(',')])
    
    # Check oci_deps
    for source, orig_name in original_names:
        if source == 'oci_deps' and service_data['oci_deps']:
            operations = service_data['oci_deps'].get('operations', [])
            for op in operations:
                item_fields = op.get('item_fields', {})
                if isinstance(item_fields, dict) and orig_name in item_fields:
                    ops_list = item_fields[orig_name].get('operators', [])
                    if ops_list:
                        operators.update(ops_list)
    
    # If no operators found, return default based on type
    if not operators:
        field_type = get_field_type(field_name, service_data)
        if field_type in ['integer', 'long', 'float', 'double']:
            return ['equals', 'not_equals', 'greater_than', 'less_than', 
                   'greater_than_or_equal', 'less_than_or_equal', 'exists']
        elif field_type == 'boolean':
            return ['equals', 'not_equals', 'exists']
        elif field_type == 'timestamp':
            return ['equals', 'not_equals', 'greater_than', 'less_than', 
                   'greater_than_or_equal', 'less_than_or_equal', 'exists']
        else:
            return ['equals', 'not_equals', 'contains', 'in', 'exists']
    
    return sorted(list(operators))

def is_enum_field(field_name: str, service_data: Dict) -> bool:
    """Check if field is an enum field"""
    # Check if has possible_values
    possible_values, _ = get_possible_values(field_name, service_data)
    if possible_values:
        return True
    
    # Check oci_deps for enum flag
    field_mapping = service_data.get('field_mapping', {})
    original_names = field_mapping.get(field_name, [])
    
    for source, orig_name in original_names:
        if source == 'oci_deps' and service_data['oci_deps']:
            operations = service_data['oci_deps'].get('operations', [])
            for op in operations:
                item_fields = op.get('item_fields', {})
                if isinstance(item_fields, dict) and orig_name in item_fields:
                    if item_fields[orig_name].get('enum'):
                        return True
    
    return False

def determine_value_requirement(operator: str, has_possible_values: bool) -> str:
    """Determine value requirement for an operator"""
    if operator in OPERATORS_NO_VALUE:
        return 'Not Required'
    elif operator in OPERATORS_REQUIRE_VALUE:
        if has_possible_values:
            return 'Select from list'
        else:
            return 'Required (manual input)'
    else:
        return 'Required'

def generate_table(service_name: str, base_dir: Path) -> List[Dict[str, Any]]:
    """Generate comprehensive table for a service - one row per field"""
    service_data = load_service_data(service_name, base_dir)
    
    if not service_data['all_fields']:
        print(f"No fields found for service: {service_name}")
        return []
    
    table_rows = []
    
    for field_name in sorted(service_data['all_fields']):
        field_type = get_field_type(field_name, service_data)
        is_enum = is_enum_field(field_name, service_data)
        possible_values, values_source = get_possible_values(field_name, service_data)
        operators = get_operators(field_name, service_data)
        
        # Categorize operators by value requirement
        operators_no_value = []
        operators_select_list = []
        operators_manual_input = []
        
        for operator in sorted(operators):
            value_requirement = determine_value_requirement(operator, bool(possible_values))
            
            if value_requirement == 'Not Required':
                operators_no_value.append(operator)
            elif value_requirement == 'Select from list':
                operators_select_list.append(operator)
            else:  # Required (manual input)
                operators_manual_input.append(operator)
        
        # Determine overall value requirement type
        if operators_no_value and not operators_select_list and not operators_manual_input:
            value_req_type = 'No value required'
        elif operators_select_list and not operators_manual_input and not operators_no_value:
            value_req_type = 'Select from list only'
        elif operators_manual_input and not operators_select_list and not operators_no_value:
            value_req_type = 'Manual input only'
        elif operators_no_value and operators_select_list and not operators_manual_input:
            value_req_type = 'No value or select from list'
        elif operators_no_value and operators_manual_input and not operators_select_list:
            value_req_type = 'No value or manual input'
        elif operators_select_list and operators_manual_input and not operators_no_value:
            value_req_type = 'Select from list or manual input'
        else:
            value_req_type = 'Mixed (no value, select, or manual)'
        
        row = {
            'service': service_name,
            'field_name': field_name,
            'field_type': field_type,
            'is_enum': 'Yes' if is_enum else 'No',
            'operators': ', '.join(sorted(operators)),
            'operators_no_value': ', '.join(operators_no_value) if operators_no_value else '',
            'operators_select_list': ', '.join(operators_select_list) if operators_select_list else '',
            'operators_manual_input': ', '.join(operators_manual_input) if operators_manual_input else '',
            'possible_values': ', '.join(possible_values) if possible_values else '',
            'values_source': values_source if values_source else '',
            'num_possible_values': len(possible_values) if possible_values else 0,
            'value_requirement_type': value_req_type
        }
        
        table_rows.append(row)
    
    return table_rows

def save_to_csv(table_rows: List[Dict], output_path: Path):
    """Save table to CSV"""
    if not table_rows:
        return
    
    fieldnames = [
        'service', 'field_name', 'field_type', 'is_enum', 
        'operators', 'operators_no_value', 'operators_select_list', 
        'operators_manual_input', 'value_requirement_type',
        'possible_values', 'values_source', 'num_possible_values'
    ]
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(table_rows)
    
    print(f"✓ Saved table to: {output_path}")
    print(f"  Total rows: {len(table_rows)}")
    print(f"  Unique fields: {len(set(r['field_name'] for r in table_rows))}")

def generate_all_services(base_dir: Path):
    """Generate tables for all services"""
    print("="*80)
    print("GENERATING FIELD-OPERATOR-VALUE TABLES FOR ALL OCI SERVICES")
    print("="*80)
    
    # Get all service directories
    service_dirs = [d for d in base_dir.iterdir() 
                    if d.is_dir() and not d.name.startswith('.') 
                    and (d / 'direct_vars.json').exists()]
    
    print(f"Found {len(service_dirs)} service directories")
    
    services_processed = 0
    services_with_errors = []
    total_fields_all = 0
    
    for service_dir in sorted(service_dirs):
        service_name = service_dir.name
        try:
            table_rows = generate_table(service_name, base_dir)
            
            if table_rows:
                output_path = service_dir / 'field_operator_value_table.csv'
                save_to_csv(table_rows, output_path)
                
                total_fields_all += len(table_rows)
                services_processed += 1
                
                if services_processed % 20 == 0:
                    print(f"  Progress: {services_processed} services processed...")
            else:
                services_with_errors.append((service_name, "No fields found"))
                
        except Exception as e:
            services_with_errors.append((service_name, str(e)))
            print(f"  ✗ {service_name}: Error - {e}")
    
    print(f"\n{'='*80}")
    print("GENERATION COMPLETE")
    print(f"{'='*80}")
    print(f"Services processed: {services_processed}")
    print(f"Total fields: {total_fields_all}")
    
    if services_with_errors:
        print(f"\nServices with errors: {len(services_with_errors)}")
        for service, error in services_with_errors[:10]:
            print(f"  - {service}: {error}")

def main():
    base_dir = Path('/Users/apple/Desktop/threat-engine/pythonsdk-database/oci')
    
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--all':
        generate_all_services(base_dir)
    else:
        # Generate for single service (identity) as test
        service_name = 'identity'
        
        print(f"Generating field-operator-value table for: {service_name}")
        print("="*80)
        
        table_rows = generate_table(service_name, base_dir)
        
        if table_rows:
            output_path = base_dir / service_name / 'field_operator_value_table.csv'
            save_to_csv(table_rows, output_path)
            
            # Print sample rows
            print(f"\n{'='*80}")
            print("SAMPLE ROWS (first 5):")
            print(f"{'='*80}")
            for i, row in enumerate(table_rows[:5], 1):
                print(f"\n{i}. Field: {row['field_name']}")
                print(f"   Type: {row['field_type']}, Enum: {row['is_enum']}")
                print(f"   All Operators: {row['operators']}")
                print(f"   Value Requirement Type: {row['value_requirement_type']}")
                if row['possible_values']:
                    print(f"   Possible Values: {row['possible_values'][:100]}...")

if __name__ == '__main__':
    main()

