"""
Agent 2: Function Name Validator (Simplified)

Takes requirements from Agent 1 (with AI suggestions) and validates them.
Uses boto3_dependencies_with_python_names.json to:
- Validate AI-suggested function exists
- Validate function type (independent/dependent) matches
- Validate parent function exists (if provided)
- Validate fields exist in suggested function
- Fallback to pattern matching if validation fails

Input: output/requirements_initial.json (with suggested_function, function_type, parent_function)
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
# Comprehensive mapping to handle all service name variations
SERVICE_NAME_MAPPING = {
    'cognito': 'cognito-idp',
    'vpc': 'ec2',
    'vpcflowlogs': 'ec2',
    'workflows': 'stepfunctions',
    'parameterstore': 'ssm',
    'elastic': 'es',
    'eip': 'ec2',
    'eventbridge': 'events',
    'fargate': 'ecs',
    'kinesisfirehose': 'firehose',
    'costexplorer': 'ce',
    'directoryservice': 'ds',
    'identitycenter': 'sso',
    'macie': 'macie2',
    'networkfirewall': 'network-firewall',
    'edr': 'guardduty',
    'kinesisvideostreams': 'kinesisvideo',  # kinesisvideo is the boto3 service name
    'qldb': 'qldb',  # Will check if exists, may need alternative
    'timestream': 'timestream-query',  # Use query for discovery operations
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


def is_discovery_function(op: Dict) -> bool:
    """
    Check if a function is suitable for discovery (not UPDATE/CREATE/DELETE).
    
    Args:
        op: Operation dictionary from boto3_dependencies
    
    Returns:
        True if function is suitable for discovery, False otherwise
    """
    python_method = op.get('python_method', '').lower()
    operation = op.get('operation', '').lower()
    
    # Filter out UPDATE/CREATE/DELETE/SET operations
    exclude_prefixes = ['update_', 'create_', 'delete_', 'remove_', 'set_', 
                       'put_', 'modify_', 'change_', 'add_', 'attach_', 
                       'detach_', 'enable_', 'disable_', 'start_', 'stop_',
                       'terminate_', 'cancel_', 'revoke_', 'grant_', 'deny_']
    
    exclude_operation_prefixes = ['update', 'create', 'delete', 'remove', 'set',
                                 'put', 'modify', 'change', 'add', 'attach',
                                 'detach', 'enable', 'disable', 'start', 'stop',
                                 'terminate', 'cancel', 'revoke', 'grant', 'deny']
    
    # Check python method name
    for prefix in exclude_prefixes:
        if python_method.startswith(prefix):
            return False
    
    # Check operation name
    for prefix in exclude_operation_prefixes:
        if operation.startswith(prefix):
            return False
    
    # Prefer LIST/GET/DESCRIBE functions
    discovery_prefixes = ['list_', 'get_', 'describe_', 'batch_get_', 'scan_',
                         'query_', 'search_', 'find_', 'fetch_', 'retrieve_']
    
    for prefix in discovery_prefixes:
        if python_method.startswith(prefix):
            return True
    
    # If operation starts with List/Get/Describe, it's good
    if operation.startswith(('list', 'get', 'describe', 'batchget', 'scan', 'query')):
        return True
    
    # If we can't determine, be conservative and exclude it
    # (better to miss a function than use a wrong one)
    return False


def find_function_for_fields(service_data: Dict, required_fields: List[str]) -> Optional[Dict]:
    """
    Find which function provides the required fields (with name conversion).
    Only considers functions suitable for discovery (LIST/GET/DESCRIBE).
    Excludes UPDATE/CREATE/DELETE operations.
    
    Args:
        service_data: boto3 data for the service
        required_fields: List of field names needed (may be snake_case or nested)
    
    Returns:
        Best matching operation or None
    """
    best_match = None
    best_score = 0
    best_field_mapping = {}
    
    # Filter to only discovery functions (LIST/GET/DESCRIBE)
    all_operations = service_data.get('independent', []) + service_data.get('dependent', [])
    discovery_operations = [op for op in all_operations if is_discovery_function(op)]
    
    if not discovery_operations:
        # No discovery functions available
        return None
    
    # Prioritize independent functions (no required params)
    # Also treat functions with only optional params (MaxResults, NextToken) as effectively independent
    optional_only_params = ['maxresults', 'nexttoken', 'paginationtoken', 'maxitems', 'limit']
    
    def is_effectively_independent(op):
        required = op.get('required_params', [])
        if not required:
            return True
        # Check if all required params are actually optional (common in boto3)
        required_lower = [p.lower() for p in required]
        return all(any(opt in p for opt in optional_only_params) for p in required_lower)
    
    independent_ops = [op for op in discovery_operations if is_effectively_independent(op)]
    dependent_ops = [op for op in discovery_operations if not is_effectively_independent(op)]
    
    # Search independent first, then dependent
    search_order = independent_ops + dependent_ops
    
    for op in search_order:
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
        # Also prioritize independent functions (higher score)
        is_independent = is_effectively_independent(op)
        score = matches * 2 if is_independent else matches  # Boost independent functions
        
        if score > best_score:
            best_score = score
            best_match = op
            best_field_mapping = field_mapping
            best_matches = matches  # Store matches for final check
    
    # Require at least 50% match
    if best_match and best_matches >= len(required_fields) * 0.5:
        best_match['field_mapping'] = best_field_mapping
        best_match['match_score'] = best_matches
        best_match['match_percentage'] = (best_matches / len(required_fields)) * 100
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


def find_function_by_name(service_data: Dict, function_name: str) -> Optional[Dict]:
    """Find function by exact name in service data"""
    all_operations = service_data.get('independent', []) + service_data.get('dependent', [])
    for op in all_operations:
        if op.get('python_method') == function_name:
            return op
    return None


def validate_ai_suggestion(ai_reqs: Dict, service_data: Dict, rule_id: str):
    # Returns: (function_dict, validation_status, used_fallback)
    """
    Validate AI suggestion from Agent 1.
    
    Returns:
        (function_dict, validation_status, used_fallback)
        validation_status: 'validated', 'validation_failed', 'used_fallback', 'needs_improvement'
    """
    suggested_func = ai_reqs.get('suggested_function')
    func_type = ai_reqs.get('function_type')
    parent_func = ai_reqs.get('parent_function')
    fields_needed = [f.get('boto3_python_field') for f in ai_reqs.get('fields', []) if f.get('boto3_python_field')]
    
    # If no AI suggestion, use fallback
    if not suggested_func:
        return None, 'used_fallback', True
    
    # Validate suggested function exists
    function_dict = find_function_by_name(service_data, suggested_func)
    if not function_dict:
        print(f"      ⚠️  AI suggested function '{suggested_func}' not found in boto3 data")
        return None, 'validation_failed', True
    
    # Validate function type
    required_params = function_dict.get('required_params', [])
    is_actually_independent = len(required_params) == 0
    
    # Check if effectively independent (only optional pagination params)
    optional_only_params = ['maxresults', 'nexttoken', 'paginationtoken', 'maxitems', 'limit']
    if required_params:
        required_lower = [p.lower() for p in required_params]
        is_effectively_independent = all(any(opt in p for opt in optional_only_params) for p in required_lower)
    else:
        is_effectively_independent = True
    
    expected_type = 'independent' if (is_actually_independent or is_effectively_independent) else 'dependent'
    
    if func_type != expected_type:
        print(f"      ⚠️  Function type mismatch: AI said '{func_type}', actual is '{expected_type}'")
        # Not a critical error, but flag for improvement
        validation_status = 'needs_improvement'
    else:
        validation_status = 'validated'
    
    # Validate parent function (if provided)
    if parent_func and parent_func != 'N/A' and parent_func is not None:
        parent_dict = find_function_by_name(service_data, parent_func)
        if not parent_dict:
            print(f"      ⚠️  AI suggested parent '{parent_func}' not found in boto3 data")
            validation_status = 'needs_improvement'
        else:
            # Verify parent is actually independent
            parent_params = parent_dict.get('required_params', [])
            if len(parent_params) > 0:
                # Check if effectively independent
                parent_lower = [p.lower() for p in parent_params]
                is_parent_independent = all(any(opt in p for opt in optional_only_params) for p in parent_lower)
                if not is_parent_independent:
                    print(f"      ⚠️  Parent function '{parent_func}' is not independent")
                    validation_status = 'needs_improvement'
    
    # Validate fields exist in function
    item_fields = set(f.lower() for f in function_dict.get('item_fields', []))
    available_fields = set(f.lower() for f in function_dict.get('available_fields', []))
    all_fields = item_fields | available_fields
    
    missing_fields = []
    for field in fields_needed:
        field_variants = generate_field_variants(field)
        if not any(f.lower() in all_fields for f in field_variants):
            missing_fields.append(field)
    
    if missing_fields:
        print(f"      ⚠️  Some fields not found in function: {missing_fields}")
        validation_status = 'needs_improvement'
    
    # If validation passed, return the function
    if validation_status == 'validated':
        return function_dict, 'validated', False
    
    # If needs improvement but function exists, still use it (Agent 3 can refine)
    if validation_status == 'needs_improvement' and function_dict:
        return function_dict, 'needs_improvement', False
    
    # Validation failed, use fallback
    return None, 'validation_failed', True


def validate_and_enrich_requirements(requirements: Dict, boto3_data: Dict) -> Dict:
    """
    Validate AI suggestions from Agent 1 and enrich with boto3 data.
    Falls back to pattern matching if validation fails.
    """
    print("=" * 80)
    print("AGENT 2: Function Validator (Simplified)")
    print("=" * 80)
    print("Validates AI suggestions from Agent 1")
    print()
    
    enriched = {}
    stats = {
        'validated': 0,
        'needs_improvement': 0,
        'used_fallback': 0,
        'validation_failed': 0
    }
    
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
            
            print(f"   {rule_id.split('.')[-1]}")
            
            # Try to validate AI suggestion first
            function_dict, validation_status, used_fallback = validate_ai_suggestion(
                ai_reqs, service_data, rule_id
            )
            
            stats[validation_status] = stats.get(validation_status, 0) + 1
            
            if function_dict and not used_fallback:
                # AI suggestion validated (or needs improvement but usable)
                print(f"      ✅ Using AI suggestion: {function_dict['python_method']}()")
                if validation_status == 'needs_improvement':
                    print(f"         ⚠️  Flagged for improvement (Agent 3 will refine)")
                
                rule['validated_function'] = {
                    'python_method': function_dict['python_method'],
                    'boto3_operation': function_dict['operation'],
                    'is_independent': len(function_dict.get('required_params', [])) == 0,
                    'required_params': function_dict.get('required_params', []),
                    'available_fields': function_dict.get('item_fields', []),
                    'main_output_field': function_dict.get('main_output_field', '')
                }
                
                # Include parent function if AI suggested it
                parent_func = ai_reqs.get('parent_function')
                if parent_func and parent_func != 'N/A' and parent_func is not None:
                    parent_dict = find_function_by_name(service_data, parent_func)
                    if parent_dict:
                        rule['validated_function']['suggested_parent_function'] = parent_func
                
                rule['validation_status'] = validation_status
                rule['used_ai_suggestion'] = True
                
            else:
                # Validation failed or no AI suggestion - use fallback pattern matching
                print(f"      🔄 Using fallback pattern matching...")
                
                # Extract field names for pattern matching
                fields_needed = []
                for f in ai_reqs.get('fields', []):
                    if 'boto3_python_field' in f:
                        fields_needed.append(f['boto3_python_field'])
                    elif 'name' in f:
                        fields_needed.append(f['name'])
                
                matching_function = find_function_for_fields(service_data, fields_needed)
                
                if matching_function:
                    print(f"      ✅ Found via pattern matching: {matching_function['python_method']}()")
                    rule['validated_function'] = {
                        'python_method': matching_function['python_method'],
                        'boto3_operation': matching_function['operation'],
                        'is_independent': len(matching_function['required_params']) == 0,
                        'required_params': matching_function['required_params'],
                        'available_fields': matching_function.get('item_fields', []),
                        'main_output_field': matching_function.get('main_output_field', '')
                    }
                    rule['validation_status'] = 'used_fallback'
                    rule['used_ai_suggestion'] = False
                else:
                    print(f"      ❌ No function found")
                    rule['validation_status'] = 'function_not_found'
                    rule['validated_function'] = None
                    rule['used_ai_suggestion'] = False
            
            enriched_rules.append(rule)
        
        enriched[service] = enriched_rules
    
    return enriched, stats


def main():
    import sys
    
    # Load requirements from Agent 1
    input_file = 'output/requirements_initial.json'
    
    if not os.path.exists(input_file):
        print(f"❌ Error: {input_file} not found")
        print("Run Agent 1 first: python3 agent1_requirements_generator.py")
        sys.exit(1)
    
    with open(input_file) as f:
        requirements = json.load(f)
    
    # Load boto3 catalog
    boto3_data = load_boto3_catalog()
    
    # Validate and enrich
    enriched, stats = validate_and_enrich_requirements(requirements, boto3_data)
    
    # Save output
    output_file = 'output/requirements_with_functions.json'
    with open(output_file, 'w') as f:
        json.dump(enriched, f, indent=2)
    
    # Summary
    total_rules = sum(len(rules) for rules in enriched.values())
    found = sum(1 for service in enriched.values() 
                for rule in service if rule.get('validated_function'))
    not_found = total_rules - found
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total rules: {total_rules}")
    print(f"  ✅ Function found: {found}")
    print(f"  ❌ Function not found: {not_found}")
    print()
    print("Validation breakdown:")
    print(f"  ✅ Validated (AI suggestion): {stats.get('validated', 0)}")
    print(f"  ⚠️  Needs improvement: {stats.get('needs_improvement', 0)}")
    print(f"  🔄 Used fallback: {stats.get('used_fallback', 0)}")
    print(f"  ❌ Validation failed: {stats.get('validation_failed', 0)}")
    print()
    print(f"Saved to: {output_file}")
    print("\nNext: Run Agent 3 to refine cases needing improvement")


if __name__ == '__main__':
    main()
