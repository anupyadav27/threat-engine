#!/usr/bin/env python3
"""
Extract all checks from YAML rule files and validate against enum CSV
"""

import yaml
import csv
import re
from pathlib import Path
from typing import Dict, List, Any, Set, Optional

def load_enum_csv(csv_path: Path) -> Dict[str, Dict[str, Set[str]]]:
    """
    Load enum CSV and create lookup: {service: {field_name: set(possible_values)}}
    """
    enum_lookup = {}
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            service = row['service']
            field_name = row['field_name']
            possible_values_str = row['possible_values']
            
            if not possible_values_str:
                continue
            
            # Parse comma-separated values
            possible_values = {v.strip() for v in possible_values_str.split(',')}
            
            if service not in enum_lookup:
                enum_lookup[service] = {}
            
            enum_lookup[service][field_name] = possible_values
    
    return enum_lookup

def extract_field_name(var: str) -> str:
    """Extract field name from var (e.g., 'item.status' -> 'status')"""
    if var.startswith('item.'):
        return var[5:]  # Remove 'item.' prefix
    return var

def extract_checks_from_yaml(yaml_path: Path) -> List[Dict[str, Any]]:
    """Extract all checks from a YAML file"""
    try:
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data or 'checks' not in data:
            return []
        
        service = data.get('service', '')
        checks = data.get('checks', [])
        
        extracted_checks = []
        
        for check in checks:
            rule_id = check.get('rule_id', '')
            conditions = check.get('conditions', {})
            
            # Handle single condition
            if 'var' in conditions:
                var = conditions.get('var', '')
                op = conditions.get('op', '')
                value = conditions.get('value')
                
                field_name = extract_field_name(var)
                extracted_checks.append({
                    'service': service,
                    'rule_id': rule_id,
                    'field_name': field_name,
                    'op': op,
                    'value': value,
                    'var': var
                })
            
            # Handle multiple conditions with 'all' or 'any'
            elif 'all' in conditions:
                for cond in conditions['all']:
                    var = cond.get('var', '')
                    op = cond.get('op', '')
                    value = cond.get('value')
                    
                    field_name = extract_field_name(var)
                    extracted_checks.append({
                        'service': service,
                        'rule_id': rule_id,
                        'field_name': field_name,
                        'op': op,
                        'value': value,
                        'var': var
                    })
            
            elif 'any' in conditions:
                for cond in conditions['any']:
                    var = cond.get('var', '')
                    op = cond.get('op', '')
                    value = cond.get('value')
                    
                    field_name = extract_field_name(var)
                    extracted_checks.append({
                        'service': service,
                        'rule_id': rule_id,
                        'field_name': field_name,
                        'op': op,
                        'value': value,
                        'var': var
                    })
        
        return extracted_checks
    
    except Exception as e:
        print(f"Error processing {yaml_path}: {e}")
        return []

def validate_check(check: Dict, enum_lookup: Dict) -> Dict[str, Any]:
    """Validate if check's field and value exist in enum CSV"""
    service = check['service']
    field_name = check['field_name']
    value = check['value']
    
    result = {
        **check,
        'field_exists': False,
        'value_exists': False,
        'is_valid': False,
        'possible_values': ''
    }
    
    # Check if service exists
    if service not in enum_lookup:
        return result
    
    # Check if field exists
    if field_name not in enum_lookup[service]:
        return result
    
    result['field_exists'] = True
    possible_values = enum_lookup[service][field_name]
    result['possible_values'] = ', '.join(sorted(possible_values))
    
    # Check if value exists (handle None/null)
    if value is None or value == 'null':
        # Some operators like 'exists' don't need values
        result['is_valid'] = True
        return result
    
    # Convert value to string for comparison
    value_str = str(value).strip()
    
    if value_str in possible_values:
        result['value_exists'] = True
        result['is_valid'] = True
    
    return result

def main():
    services_dir = Path('/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services')
    enum_csv_path = Path('/Users/apple/Desktop/threat-engine/pythonsdk-database/aws/aws_enum_fields_reference.csv')
    output_csv_path = Path('/Users/apple/Desktop/threat-engine/pythonsdk-database/aws/yaml_checks_validation.csv')
    
    print("Loading enum CSV...")
    enum_lookup = load_enum_csv(enum_csv_path)
    print(f"Loaded {len(enum_lookup)} services with enum fields")
    
    print("\nScanning YAML files...")
    all_checks = []
    yaml_files = list(services_dir.rglob('*.yaml'))
    
    for yaml_file in yaml_files:
        # Only process rule files (not metadata)
        if 'rules' in str(yaml_file):
            checks = extract_checks_from_yaml(yaml_file)
            all_checks.extend(checks)
            if checks:
                print(f"  ✓ {yaml_file.name}: {len(checks)} checks")
    
    print(f"\nTotal checks extracted: {len(all_checks)}")
    
    # Validate all checks
    print("\nValidating checks against enum CSV...")
    validated_checks = []
    for check in all_checks:
        validated = validate_check(check, enum_lookup)
        validated_checks.append(validated)
    
    # Statistics
    total = len(validated_checks)
    field_exists = sum(1 for c in validated_checks if c['field_exists'])
    value_exists = sum(1 for c in validated_checks if c['value_exists'] and c['value'] not in [None, 'null'])
    is_valid = sum(1 for c in validated_checks if c['is_valid'])
    
    print(f"\nValidation Results:")
    print(f"  Total checks: {total}")
    print(f"  Fields exist in enum CSV: {field_exists} ({field_exists/total*100:.1f}%)")
    print(f"  Values exist in possible_values: {value_exists} ({value_exists/total*100:.1f}%)")
    print(f"  Valid checks: {is_valid} ({is_valid/total*100:.1f}%)")
    
    # Write results to CSV
    fieldnames = [
        'service', 'rule_id', 'field_name', 'var', 'op', 'value',
        'field_exists', 'value_exists', 'is_valid', 'possible_values'
    ]
    
    with open(output_csv_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(validated_checks)
    
    print(f"\n✓ Results saved to: {output_csv_path}")
    
    # Show examples of invalid checks
    invalid_checks = [c for c in validated_checks if not c['is_valid'] and c['value'] not in [None, 'null']]
    if invalid_checks:
        print(f"\nSample invalid checks (field exists but value not in enum):")
        for check in invalid_checks[:10]:
            print(f"  {check['service']}.{check['rule_id']}: {check['field_name']} = {check['value']}")
            print(f"    Possible values: {check['possible_values'][:100]}...")

if __name__ == '__main__':
    main()

