"""
Agent 3: Azure SDK Field Validator

Validates that requested fields exist in Azure SDK operation outputs.
Handles nested Azure field paths (properties.*).
"""

import json
import sys
from typing import Dict, List, Any
from azure_sdk_dependency_analyzer import load_analyzer
from agent_logger import get_logger

logger = get_logger('agent3')


def validate_field_path(analyzer, service: str, operation: str, field_path: str) -> Dict[str, Any]:
    """
    Validate a field path (including nested paths like properties.enable_soft_delete).
    
    Returns:
        {
            'exists': bool,
            'correct_name': str,
            'validation': str,
            'is_nested': bool,
            'path_parts': list
        }
    """
    # Handle nested paths
    if '.' in field_path:
        parts = field_path.split('.')
        base_field = parts[0]
        
        # Validate base field first
        validation = analyzer.validate_field(service, operation, base_field)
        
        if validation['exists']:
            return {
                'exists': True,
                'correct_name': field_path,  # Keep full path
                'validation': 'nested_field',
                'is_nested': True,
                'path_parts': parts,
                'base_field_validated': True
            }
        else:
            return {
                'exists': False,
                'correct_name': None,
                'validation': 'base_field_not_found',
                'is_nested': True,
                'path_parts': parts,
                'base_field': base_field
            }
    else:
        # Simple field
        validation = analyzer.validate_field(service, operation, field_path)
        return {
            **validation,
            'is_nested': False
        }


def validate_fields(rule: Dict[str, Any], analyzer) -> Dict[str, Any]:
    """
    Validate all fields in a rule against Azure SDK operation output.
    Uses item_fields from validated_function (set by Agent 2) instead of analyzer index.
    """
    service = rule['service']
    rule_id = rule['rule_id']
    validated_func = rule.get('validated_function', {})
    
    if validated_func.get('error'):
        logger.warning(f"Skipping field validation for {rule_id} - no function")
        return {
            **rule,
            'field_validation': {},
            'all_fields_valid': False,
            'final_validation_status': '❌ NO FUNCTION'
        }
    
    operation = validated_func.get('azure_operation')
    # Use item_fields from Agent 2's selected operation (not from analyzer index!)
    available_fields = set(validated_func.get('item_fields', []))
    
    ai_reqs = rule.get('ai_generated_requirements', {})
    fields = ai_reqs.get('fields', [])
    
    logger.info(f"Validating {len(fields)} fields for {rule_id} against {len(available_fields)} available fields")
    
    field_validations = {}
    all_valid = True
    
    for field_spec in fields:
        field_name = field_spec.get('azure_sdk_python_field', field_spec.get('name', ''))
        
        if not field_name:
            logger.warning(f"No field name in spec: {field_spec}")
            continue
        
        # Direct validation against stored item_fields
        if field_name in available_fields:
            validation = {
                'exists': True,
                'correct_name': field_name,
                'validation': 'exact_match'
            }
        else:
            # Try fuzzy match
            from difflib import get_close_matches
            matches = get_close_matches(field_name, list(available_fields), n=1, cutoff=0.8)
            if matches:
                validation = {
                    'exists': True,
                    'correct_name': matches[0],
                    'validation': 'fuzzy_match',
                    'original': field_name
                }
            else:
                validation = {
                    'exists': False,
                    'correct_name': None,
                    'validation': 'not_found',
                    'reason': f"Not in available fields: {list(available_fields)[:10]}..."
                }
        
        field_validations[field_name] = validation
        
        if not validation['exists']:
            all_valid = False
            logger.warning(f"Field '{field_name}' not found in {service}.{operation}")
    
    # Determine final status
    if all_valid and fields:
        status = '✅ PASS'
    elif not fields:
        status = '⚠️ NO FIELDS'
    else:
        status = '❌ INVALID FIELDS'
    
    logger.info(f"Field validation complete for {rule_id}: {status}")
    
    return {
        **rule,
        'field_validation': field_validations,
        'all_fields_valid': all_valid,
        'final_validation_status': status
    }


def main():
    logger.info("Agent 3 starting - Field Validator")
    print("=" * 80)
    print("AGENT 3: Azure SDK Field Validator")
    print("=" * 80)
    print("Validates field names against Azure SDK operation outputs")
    print()
    
    # Load analyzer
    logger.info("Loading Azure SDK analyzer...")
    print("Loading Azure SDK analyzer...")
    analyzer = load_analyzer()
    logger.info("Analyzer loaded")
    print("✅ Loaded")
    print()
    
    # Load requirements from Agent 2
    logger.info("Loading requirements from Agent 2...")
    print("Loading requirements_with_functions.json...")
    try:
        with open('output/requirements_with_functions.json') as f:
            requirements = json.load(f)
        logger.info(f"Loaded requirements for {len(requirements)} services")
        print(f"✅ Loaded {len(requirements)} services")
    except FileNotFoundError:
        logger.error("requirements_with_functions.json not found")
        print("❌ requirements_with_functions.json not found")
        print("Run Agent 2 first: python3 agent2_function_validator.py")
        sys.exit(1)
    
    print()
    
    # Validate fields for each service
    validated_requirements = {}
    total_rules = 0
    valid_rules = 0
    
    for service, rules in requirements.items():
        logger.info(f"Processing service: {service}")
        print(f"📦 {service}")
        
        validated_rules = []
        
        for rule in rules:
            total_rules += 1
            rule_name = rule['rule_id'].split('.')[-1]
            print(f"   {rule_name}...", end=' ')
            
            validated = validate_fields(rule, analyzer)
            
            status = validated['final_validation_status']
            print(status)
            
            if '✅' in status:
                valid_rules += 1
            
            validated_rules.append(validated)
        
        validated_requirements[service] = validated_rules
        print(f"   ✅ {len(validated_rules)} rules processed")
        print()
    
    # Save
    output_file = 'output/requirements_validated.json'
    with open(output_file, 'w') as f:
        json.dump(validated_requirements, f, indent=2)
    
    print("=" * 80)
    print(f"✅ Validated {valid_rules}/{total_rules} rules successfully")
    print(f"Saved to: {output_file}")
    print()
    print("📊 This is now the SINGLE SOURCE OF TRUTH")
    print()
    print("Next: Run Agent 4 (YAML Generator)")
    print("=" * 80)
    
    logger.info(f"Agent 3 complete: {valid_rules}/{total_rules} rules valid")
    logger.info(f"Output: {output_file}")


if __name__ == '__main__':
    main()

