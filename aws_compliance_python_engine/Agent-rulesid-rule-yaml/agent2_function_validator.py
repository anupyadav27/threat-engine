"""
Agent 2: Function Name Validator

Takes requirements from Agent 1 and validates/corrects function names.
Uses boto3_dependencies_with_python_names.json to:
- Find which function can provide the required fields
- Validate function names exist
- Correct typos (list_analyser → list_analyzers)
- Determine if function is independent or dependent

Input: output/requirements_initial.json
Output: output/requirements_with_functions.json
"""

import json
import os
from typing import Dict, List, Any, Optional, Set
from difflib import SequenceMatcher


def load_boto3_catalog():
    """Load boto3 dependencies catalog"""
    with open('boto3_dependencies_with_python_names.json') as f:
        return json.load(f)


# Service name mapping: metadata name -> boto3 service name
SERVICE_NAME_MAPPING = {
    'cognito': 'cognito-idp',
    'vpc': 'ec2',
    'vpcflowlogs': 'ec2',
    'workflows': 'stepfunctions',
    'parameterstore': 'ssm',
    'elastic': 'elasticsearch',
    'eip': 'ec2',
    'edr': 'guardduty',  # EDR might be GuardDuty
    # Add more as needed
}


def get_boto3_service_name(service: str) -> str:
    """Map metadata service name to boto3 service name"""
    return SERVICE_NAME_MAPPING.get(service, service)


def snake_to_camel(snake_str: str) -> str:
    """Convert snake_case to camelCase"""
    components = snake_str.split('_')
    return components[0] + ''.join(x.capitalize() for x in components[1:])


def snake_to_pascal(snake_str: str) -> str:
    """Convert snake_case to PascalCase"""
    components = snake_str.split('_')
    return ''.join(x.capitalize() for x in components)


def generate_field_variants(field_name: str) -> List[str]:
    """
    Generate all possible naming variants for a field.
    
    Args:
        field_name: Original field name (e.g., 'key_algorithm' or 'encryption.kms_key_id')
    
    Returns:
        List of variants to try
    """
    variants = []
    
    # If nested path, extract parent
    if '.' in field_name:
        parent = field_name.split('.')[0]
        # Add parent variants
        variants.extend(generate_field_variants(parent))
        return variants
    
    # Original
    variants.append(field_name)
    
    # Lowercase
    variants.append(field_name.lower())
    
    # UPPERCASE
    variants.append(field_name.upper())
    
    # camelCase (if snake_case)
    if '_' in field_name:
        variants.append(snake_to_camel(field_name))
        variants.append(snake_to_pascal(field_name))
    
    # PascalCase to snake_case (if PascalCase)
    elif field_name[0].isupper():
        # Convert PascalCase to snake_case
        import re
        s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', field_name)
        snake = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
        variants.append(snake)
    
    return list(set(variants))  # Remove duplicates


def find_function_for_fields(service_data: Dict, required_fields: List[str]) -> Optional[Dict]:
    """
    Find which function provides the required fields (with name conversion).
    
    Args:
        service_data: boto3 data for the service
        required_fields: List of field names needed (may be snake_case or nested)
    
    Returns:
        Best matching operation or None
    """
    best_match = None
    best_score = 0
    best_field_mapping = {}
    
    # Check all operations
    for op in service_data.get('independent', []) + service_data.get('dependent', []):
        item_fields_set = set(op.get('item_fields', []))
        
        if not item_fields_set:
            continue
        
        matches = 0
        field_mapping = {}
        
        # For each required field, try to find it with conversions
        for req_field in required_fields:
            # Generate all naming variants
            variants = generate_field_variants(req_field)
            
            # Try each variant
            found = False
            for variant in variants:
                if variant in item_fields_set:
                    matches += 1
                    field_mapping[req_field] = {
                        'boto3_field': variant,
                        'matched': True
                    }
                    found = True
                    break
            
            if not found:
                field_mapping[req_field] = {
                    'boto3_field': None,
                    'matched': False
                }
        
        # Score: prioritize functions that match ALL fields
        if matches > best_score:
            best_score = matches
            best_match = op
            best_field_mapping = field_mapping
    
    # Require at least 50% match
    if best_match and best_score >= len(required_fields) * 0.5:
        best_match['field_mapping'] = best_field_mapping
        best_match['match_score'] = best_score
        best_match['match_percentage'] = (best_score / len(required_fields)) * 100
        return best_match
    
    return None


def find_similar_function_name(wrong_name: str, service_data: Dict) -> Optional[str]:
    """Find similar function name in case of typo"""
    all_functions = []
    
    for op in service_data.get('independent', []) + service_data.get('dependent', []):
        all_functions.append(op['python_method'])
    
    # Find most similar
    best_match = None
    best_ratio = 0
    
    for func in all_functions:
        ratio = SequenceMatcher(None, wrong_name, func).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
            best_match = func
    
    return best_match if best_ratio > 0.8 else None  # 80% similarity threshold


def validate_and_enrich_requirements(requirements: Dict, boto3_data: Dict) -> Dict:
    """
    Validate function names and enrich with boto3 data.
    """
    print("=" * 80)
    print("AGENT 2: Function Name Validator")
    print("=" * 80)
    print()
    
    enriched = {}
    
    for service, rules in requirements.items():
        print(f"\n📦 Processing {service} ({len(rules)} rules)...")
        
        # Map service name to boto3 service name
        boto3_service = get_boto3_service_name(service)
        service_data = boto3_data.get(boto3_service, {})
        
        if not service_data:
            print(f"   ⚠️  Service '{service}' (boto3: '{boto3_service}') not found in boto3 catalog")
            enriched[service] = rules
            continue
        
        if boto3_service != service:
            print(f"   📍 Mapped '{service}' → boto3 service '{boto3_service}'")
        
        enriched_rules = []
        
        for rule in rules:
            rule_id = rule['rule_id']
            ai_reqs = rule.get('ai_generated_requirements', {})
            # Extract field names (handle multiple formats)
            fields_needed = []
            for f in ai_reqs.get('fields', []):
                if 'boto3_python_field' in f:
                    fields_needed.append(f['boto3_python_field'])
                elif 'name' in f:
                    fields_needed.append(f['name'])
                else:
                    continue
            
            print(f"   {rule_id}")
            print(f"      Fields needed: {fields_needed}")
            
            # Find function that provides these fields
            matching_function = find_function_for_fields(service_data, fields_needed)
            
            if matching_function:
                print(f"      ✅ Found function: {matching_function['python_method']}()")
                print(f"         Type: {'INDEPENDENT' if not matching_function['required_params'] else 'DEPENDENT'}")
                
                rule['validated_function'] = {
                    'python_method': matching_function['python_method'],
                    'boto3_operation': matching_function['operation'],
                    'is_independent': len(matching_function['required_params']) == 0,
                    'required_params': matching_function['required_params'],
                    'available_fields': matching_function.get('item_fields', []),
                    'main_output_field': matching_function.get('main_output_field', '')
                }
                rule['validation_status'] = 'function_found'
            else:
                print(f"      ❌ No function found for fields: {fields_needed}")
                rule['validation_status'] = 'function_not_found'
                rule['validated_function'] = None
            
            enriched_rules.append(rule)
        
        enriched[service] = enriched_rules
    
    return enriched


def main():
    # Load requirements from Agent 1
    input_file = 'output/requirements_initial.json'
    
    if not os.path.exists(input_file):
        print(f"❌ Error: {input_file} not found")
        print("Run Agent 1 first: python Agent-rulesid-rule-yaml/agent1_requirements_generator.py")
        sys.exit(1)
    
    with open(input_file) as f:
        requirements = json.load(f)
    
    # Load boto3 catalog
    boto3_data = load_boto3_catalog()
    
    # Validate and enrich
    enriched = validate_and_enrich_requirements(requirements, boto3_data)
    
    # Save output
    output_file = 'output/requirements_with_functions.json'
    with open(output_file, 'w') as f:
        json.dump(enriched, f, indent=2)
    
    # Summary
    total_rules = sum(len(rules) for rules in enriched.values())
    found = sum(1 for service in enriched.values() 
                for rule in service if rule.get('validation_status') == 'function_found')
    not_found = total_rules - found
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total rules: {total_rules}")
    print(f"  ✅ Function found: {found}")
    print(f"  ❌ Function not found: {not_found}")
    print(f"\nSaved to: {output_file}")
    print("\nNext: Run Agent 3 to validate field names")


if __name__ == '__main__':
    main()
