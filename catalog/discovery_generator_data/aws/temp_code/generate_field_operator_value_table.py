#!/usr/bin/env python3
"""
Generate a comprehensive table for fields, operators, and values for a service.
This table will help users understand:
- Field name (var)
- Field type
- Is enum
- Possible values (if enum)
- Available operators
- Whether value is required based on operator
"""

import json
import csv
from pathlib import Path
from typing import Dict, List, Any, Set
from collections import defaultdict

# Operators that don't require values (based on actual usage in data)
OPERATORS_NO_VALUE = {'exists', 'not_empty'}

# Operators that require values
OPERATORS_REQUIRE_VALUE = {
    'equals', 'not_equals', 'contains', 'not_contains', 
    'in', 'not_in', 'greater_than', 'less_than', 
    'greater_than_or_equal', 'less_than_or_equal',
    'gt', 'lt', 'gte', 'lte'
}

def load_service_data(service_name: str, base_dir: Path) -> Dict[str, Any]:
    """Load all service data files"""
    service_dir = base_dir / service_name
    
    data = {
        'direct_vars': None,
        'boto3_deps': None,
        'csv_fields': []
    }
    
    # Load direct_vars.json
    direct_vars_path = service_dir / 'direct_vars.json'
    if direct_vars_path.exists():
        with open(direct_vars_path, 'r', encoding='utf-8') as f:
            data['direct_vars'] = json.load(f)
    
    # Load boto3_dependencies
    boto3_path = service_dir / 'boto3_dependencies_with_python_names_fully_enriched.json'
    if boto3_path.exists():
        with open(boto3_path, 'r', encoding='utf-8') as f:
            boto3_data = json.load(f)
            data['boto3_deps'] = boto3_data.get(service_name, {})
    
    # Load CSV fields
    csv_path = base_dir / 'aws_fields_reference.csv'
    if csv_path.exists():
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['service'] == service_name:
                    data['csv_fields'].append(row)
    
    return data

def get_possible_values(field_name: str, service_data: Dict) -> tuple:
    """
    Get possible values for a field from multiple sources
    Returns: (possible_values_list, source)
    """
    # Check CSV first
    for csv_row in service_data['csv_fields']:
        if csv_row['field_name'] == field_name:
            possible_values_str = csv_row.get('possible_values', '').strip()
            if possible_values_str:
                values = [v.strip() for v in possible_values_str.split(',')]
                source = csv_row.get('values_source', 'unknown')
                return (values, source)
    
    # Check direct_vars
    if service_data['direct_vars']:
        fields = service_data['direct_vars'].get('fields', {})
        if field_name in fields:
            field_data = fields[field_name]
            if isinstance(field_data, dict):
                possible_values = field_data.get('possible_values')
                if possible_values:
                    if isinstance(possible_values, list):
                        return (possible_values, 'direct_vars')
                    elif isinstance(possible_values, str):
                        values = [v.strip() for v in possible_values.split(',')]
                        return (values, 'direct_vars')
    
    # Check boto3_deps
    if service_data['boto3_deps']:
        all_operations = (service_data['boto3_deps'].get('independent', []) + 
                         service_data['boto3_deps'].get('dependent', []))
        
        for op in all_operations:
            # Check item_fields
            item_fields = op.get('item_fields', {})
            if isinstance(item_fields, dict) and field_name in item_fields:
                field_data = item_fields[field_name]
                if field_data.get('enum') and 'possible_values' in field_data:
                    return (field_data['possible_values'], 'boto3_deps')
            
            # Check output_fields
            output_fields = op.get('output_fields', {})
            if isinstance(output_fields, dict) and field_name in output_fields:
                field_data = output_fields[field_name]
                if field_data.get('enum') and 'possible_values' in field_data:
                    return (field_data['possible_values'], 'boto3_deps')
    
    return (None, None)

def get_field_type(field_name: str, service_data: Dict) -> str:
    """Get field type from multiple sources"""
    # Check CSV
    for csv_row in service_data['csv_fields']:
        if csv_row['field_name'] == field_name:
            field_type = csv_row.get('type', '').strip()
            if field_type:
                return field_type
    
    # Check direct_vars
    if service_data['direct_vars']:
        fields = service_data['direct_vars'].get('fields', {})
        if field_name in fields:
            field_data = fields[field_name]
            if isinstance(field_data, dict):
                return field_data.get('type', 'string')
    
    # Check boto3_deps
    if service_data['boto3_deps']:
        all_operations = (service_data['boto3_deps'].get('independent', []) + 
                         service_data['boto3_deps'].get('dependent', []))
        
        for op in all_operations:
            item_fields = op.get('item_fields', {})
            if isinstance(item_fields, dict) and field_name in item_fields:
                return item_fields[field_name].get('type', 'string')
            
            output_fields = op.get('output_fields', {})
            if isinstance(output_fields, dict) and field_name in output_fields:
                return output_fields[field_name].get('type', 'string')
    
    return 'string'

def get_operators(field_name: str, service_data: Dict) -> List[str]:
    """Get available operators for a field"""
    operators = set()
    
    # Check CSV
    for csv_row in service_data['csv_fields']:
        if csv_row['field_name'] == field_name:
            ops_str = csv_row.get('operators', '').strip()
            if ops_str:
                ops = [op.strip() for op in ops_str.split(',')]
                operators.update(ops)
    
    # Check direct_vars
    if service_data['direct_vars']:
        fields = service_data['direct_vars'].get('fields', {})
        if field_name in fields:
            field_data = fields[field_name]
            if isinstance(field_data, dict):
                ops = field_data.get('operators', [])
                if ops:
                    if isinstance(ops, list):
                        operators.update(ops)
                    elif isinstance(ops, str):
                        operators.update([op.strip() for op in ops.split(',')])
    
    # Check boto3_deps
    if service_data['boto3_deps']:
        all_operations = (service_data['boto3_deps'].get('independent', []) + 
                         service_data['boto3_deps'].get('dependent', []))
        
        for op in all_operations:
            item_fields = op.get('item_fields', {})
            if isinstance(item_fields, dict) and field_name in item_fields:
                ops = item_fields[field_name].get('operators', [])
                if ops:
                    operators.update(ops)
            
            output_fields = op.get('output_fields', {})
            if isinstance(output_fields, dict) and field_name in output_fields:
                ops = output_fields[field_name].get('operators', [])
                if ops:
                    operators.update(ops)
    
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
    # Check CSV
    for csv_row in service_data['csv_fields']:
        if csv_row['field_name'] == field_name:
            is_enum = csv_row.get('is_enum', '').strip().lower()
            if is_enum == 'yes':
                return True
    
    # Check if has possible_values
    possible_values, _ = get_possible_values(field_name, service_data)
    if possible_values:
        return True
    
    return False

def determine_value_requirement(operator: str, has_possible_values: bool) -> str:
    """
    Determine value requirement for an operator
    Returns: 'Required', 'Optional', or 'Not Required'
    """
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
    
    if not service_data['csv_fields']:
        print(f"No fields found for service: {service_name}")
        return []
    
    table_rows = []
    
    # Get unique field names from CSV
    field_names = set()
    for csv_row in service_data['csv_fields']:
        field_names.add(csv_row['field_name'])
    
    for field_name in sorted(field_names):
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
        
        # Create single row per field
        # Determine overall value requirement type
        # Priority: Check for pure cases first, then mixed cases
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
            # All three types present
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

def _determine_overall_value_requirement(self, no_value, select_list, manual_input):
    """Determine overall value requirement type for the field"""
    if select_list and not manual_input:
        return 'Select from list only'
    elif manual_input and not select_list:
        return 'Manual input only'
    elif no_value and not select_list and not manual_input:
        return 'No value required'
    else:
        return 'Mixed'

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
    
    # Count unique operators across all fields
    all_operators = set()
    for row in table_rows:
        if row.get('operators'):
            all_operators.update([op.strip() for op in row['operators'].split(',')])
    print(f"  Unique operators: {len(all_operators)}")

def generate_all_services(base_dir: Path):
    """Generate tables for all services"""
    print("="*80)
    print("GENERATING FIELD-OPERATOR-VALUE TABLES FOR ALL SERVICES")
    print("="*80)
    
    # Get all service directories
    service_dirs = [d for d in base_dir.iterdir() 
                    if d.is_dir() and not d.name.startswith('.') 
                    and d.name != 'backup']
    
    csv_path = base_dir / 'aws_fields_reference.csv'
    if not csv_path.exists():
        print(f"✗ CSV file not found: {csv_path}")
        return
    
    # Get list of services from CSV
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        services_in_csv = set(row['service'] for row in reader)
    
    print(f"Found {len(services_in_csv)} services in CSV")
    print(f"Found {len(service_dirs)} service directories")
    
    services_processed = 0
    services_with_errors = []
    total_fields_all = 0
    
    for service_name in sorted(services_in_csv):
        try:
            table_rows = generate_table(service_name, base_dir)
            
            if table_rows:
                # Save to service directory
                service_dir = base_dir / service_name
                service_dir.mkdir(parents=True, exist_ok=True)
                output_path = service_dir / 'field_operator_value_table.csv'
                save_to_csv(table_rows, output_path)
                
                total_fields_all += len(table_rows)
                services_processed += 1
                
                if services_processed % 50 == 0:
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
    print(f"Total fields across all services: {total_fields_all}")
    print(f"Services with errors: {len(services_with_errors)}")
    
    if services_with_errors:
        print(f"\nServices with errors (first 20):")
        for service, error in services_with_errors[:20]:
            print(f"  - {service}: {error}")

def main():
    base_dir = Path('/Users/apple/Desktop/threat-engine/pythonsdk-database/aws')
    
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--all':
        # Generate for all services
        generate_all_services(base_dir)
    else:
        # Generate for single service (account) as test
        service_name = 'account'
        
        print(f"Generating field-operator-value table for: {service_name}")
        print("="*80)
        
        table_rows = generate_table(service_name, base_dir)
        
        if table_rows:
            # Save to service directory
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
                if row['operators_no_value']:
                    print(f"   No Value: {row['operators_no_value']}")
                if row['operators_select_list']:
                    print(f"   Select from List: {row['operators_select_list']}")
                if row['operators_manual_input']:
                    print(f"   Manual Input: {row['operators_manual_input']}")
                print(f"   Value Requirement Type: {row['value_requirement_type']}")
                if row['possible_values']:
                    print(f"   Possible Values: {row['possible_values'][:100]}...")
            
            # Print summary statistics
            print(f"\n{'='*80}")
            print("SUMMARY STATISTICS")
            print(f"{'='*80}")
            
            total_fields = len(table_rows)
            enum_fields = len([r for r in table_rows if r['is_enum'] == 'Yes'])
            fields_with_values = len([r for r in table_rows if r['possible_values']])
            
            # Count by value requirement type
            req_type_counts = {}
            for row in table_rows:
                req_type = row['value_requirement_type']
                req_type_counts[req_type] = req_type_counts.get(req_type, 0) + 1
            
            print(f"Total fields: {total_fields}")
            print(f"Enum fields: {enum_fields}")
            print(f"Fields with possible values: {fields_with_values}")
            print(f"\nValue Requirement Types:")
            for req_type in sorted(req_type_counts.keys()):
                print(f"  {req_type}: {req_type_counts[req_type]} fields")
            
            print(f"\n{'='*80}")
            print("Run with --all flag to generate for all services")
            print(f"{'='*80}")
        else:
            print(f"No data found for service: {service_name}")

if __name__ == '__main__':
    main()

