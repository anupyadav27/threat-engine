"""
Agent 3: Field Name Validator

Takes requirements with validated functions and validates field names.
Uses boto3_dependencies_with_python_names.json to:
- Check if fields exist in the function's output
- Correct case mismatches (Status → status)
- Identify missing fields
- Mark computed/nested fields

Input: output/requirements_with_functions.json
Output: output/requirements_validated.json (FINAL)
"""

import json
import os
import sys
from typing import Dict, List, Any, Tuple, Optional


def load_boto3_catalog():
    """Load boto3 dependencies catalog"""
    with open('boto3_dependencies_with_python_names.json') as f:
        return json.load(f)


def snake_to_camel(snake_str: str) -> str:
    """
    Convert snake_case to camelCase
    
    Examples:
      logging_configuration → loggingConfiguration
      encryption_enabled → encryptionEnabled
    """
    components = snake_str.split('_')
    return components[0] + ''.join(x.capitalize() for x in components[1:])


def snake_to_pascal(snake_str: str) -> str:
    """
    Convert snake_case to PascalCase
    
    Examples:
      logging_configuration → LoggingConfiguration
      encryption_enabled → EncryptionEnabled
    """
    components = snake_str.split('_')
    return ''.join(x.capitalize() for x in components)


def find_field_with_conversion(field_name: str, available_fields: List[str]) -> Tuple[Optional[str], str]:
    """
    Find field in available_fields using multiple naming convention attempts.
    
    Returns:
        (matched_field_name, match_type) or (None, 'not_found')
    """
    available_set = set(available_fields)
    available_lower_map = {f.lower(): f for f in available_fields}
    
    # 1. Exact match
    if field_name in available_set:
        return field_name, 'exact_match'
    
    # 2. Case-insensitive match
    if field_name.lower() in available_lower_map:
        return available_lower_map[field_name.lower()], 'case_corrected'
    
    # 3. Snake to camelCase
    camel = snake_to_camel(field_name)
    if camel in available_set:
        return camel, 'snake_to_camel'
    
    # 4. Snake to PascalCase
    pascal = snake_to_pascal(field_name)
    if pascal in available_set:
        return pascal, 'snake_to_pascal'
    
    # 5. Try with common prefixes removed
    for prefix in ['get_', 'is_', 'has_', 'enable_']:
        if field_name.startswith(prefix):
            without_prefix = field_name[len(prefix):]
            # Try recursively
            result, match_type = find_field_with_conversion(without_prefix, available_fields)
            if result:
                return result, f'removed_prefix_{prefix}' + match_type
    
    return None, 'not_found'


def validate_nested_path(field_path: str, available_fields: List[str]) -> Tuple[bool, Optional[str], str]:
    """
    Validate nested field path like encryption.kms_key_id
    
    Returns:
        (is_valid, parent_field_name, validation_note)
    """
    if '.' not in field_path:
        return False, None, 'not_nested'
    
    parts = field_path.split('.')
    parent = parts[0]
    
    # Try to find parent field with conversion
    parent_field, match_type = find_field_with_conversion(parent, available_fields)
    
    if parent_field:
        return True, parent_field, f'nested_path_valid_parent_{match_type}'
    
    return False, None, 'parent_not_found'


def validate_field_names(requirements: Dict, boto3_data: Dict) -> Dict:
    """
    Validate and correct field names against boto3 catalog.
    """
    print("=" * 80)
    print("AGENT 3: Field Name Validator")
    print("=" * 80)
    print()
    
    validated = {}
    
    for service, rules in requirements.items():
        print(f"\n📦 Processing {service} ({len(rules)} rules)...")
        
        validated_rules = []
        
        for rule in rules:
            rule_id = rule['rule_id']
            ai_reqs = rule.get('ai_generated_requirements', {})
            fields_needed = ai_reqs.get('fields', [])
            validated_func = rule.get('validated_function')
            
            if not validated_func:
                print(f"   ⚠️  {rule_id}: No validated function, skipping")
                validated_rules.append(rule)
                continue
            
            print(f"   {rule_id}")
            
            available_fields = set(validated_func.get('available_fields', []))
            available_fields_lower = {f.lower(): f for f in available_fields}
            
            field_validation = {}
            all_valid = True
            
            for field_req in fields_needed:
                # Handle both old format (name) and new format (boto3_python_field)
                if 'boto3_python_field' in field_req:
                    field_name = field_req['boto3_python_field']
                elif 'name' in field_req:
                    field_name = field_req['name']
                else:
                    continue
                
                # Try field matching with conversions
                matched_field, match_type = find_field_with_conversion(
                    field_name, 
                    list(available_fields)
                )
                
                if matched_field:
                    # Field found (exact or converted)
                    field_validation[field_name] = {
                        'exists': True,
                        'correct_name': matched_field,
                        'original_name': field_name if matched_field != field_name else None,
                        'validation': match_type
                    }
                    
                    if match_type == 'exact_match':
                        print(f"      ✅ {field_name}: exact match")
                    else:
                        print(f"      🔧 {field_name} → {matched_field} ({match_type})")
                
                # Try nested path validation
                elif '.' in field_name:
                    is_valid, parent_field, note = validate_nested_path(
                        field_name,
                        list(available_fields)
                    )
                    
                    if is_valid:
                        field_validation[field_name] = {
                            'exists': True,
                            'is_nested_path': True,
                            'parent_field': parent_field,
                            'full_path': field_name,
                            'validation': note
                        }
                        print(f"      🔗 {field_name}: nested path (parent '{parent_field}' exists)")
                    else:
                        field_validation[field_name] = {
                            'exists': False,
                            'validation': 'nested_parent_not_found',
                            'note': f'Nested path but parent not found: {note}'
                        }
                        print(f"      ❌ {field_name}: nested path invalid ({note})")
                        all_valid = False
                
                # Field truly not found
                else:
                    field_validation[field_name] = {
                        'exists': False,
                        'validation': 'not_found',
                        'note': 'Field not found even after conversion attempts'
                    }
                    print(f"      ❌ {field_name}: not found (may be computed)")
                    all_valid = False
            
            # Add validation results to rule
            rule['field_validation'] = field_validation
            rule['all_fields_valid'] = all_valid
            rule['final_validation_status'] = '✅ PASS' if all_valid else '⚠️  PARTIAL'
            
            validated_rules.append(rule)
        
        validated[service] = validated_rules
    
    return validated


def main():
    # Load requirements from Agent 2
    input_file = 'output/requirements_with_functions.json'
    
    if not os.path.exists(input_file):
        print(f"❌ Error: {input_file} not found")
        print("Run Agent 2 first: python Agent-rulesid-rule-yaml/agent2_function_validator.py")
        sys.exit(1)
    
    with open(input_file) as f:
        requirements = json.load(f)
    
    # Load boto3 catalog
    boto3_data = load_boto3_catalog()
    
    # Validate fields
    validated = validate_field_names(requirements, boto3_data)
    
    # Save final output
    output_file = 'output/requirements_validated.json'
    with open(output_file, 'w') as f:
        json.dump(validated, f, indent=2)
    
    # Summary
    total_rules = sum(len(rules) for rules in validated.values())
    fully_valid = sum(1 for service in validated.values() 
                      for rule in service if rule.get('all_fields_valid'))
    partial = total_rules - fully_valid
    
    print("\n" + "=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    print(f"Total rules: {total_rules}")
    print(f"  ✅ Fully validated: {fully_valid}")
    print(f"  ⚠️  Partial (computed fields): {partial}")
    print(f"\nSaved to: {output_file}")
    print("\n🎯 This is your single source of truth!")
    print("Use it to generate YAML, Python, and documentation.")


if __name__ == '__main__':
    main()
