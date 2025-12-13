"""
Agent 3: GCP Field Validator

Validates that fields exist in GCP API responses and corrects field names.

Input: output/requirements_with_operations.json
Output: output/requirements_validated.json
"""

import json
import os
from typing import Dict, List, Any
from agent_logger import get_logger
from shared_agent_utils import check_nested_field, normalize_item_fields

logger = get_logger('agent3')


def load_gcp_catalog():
    """Load GCP API catalog"""
    with open('gcp_api_dependencies_fully_enhanced.json') as f:
        return json.load(f)


def check_field_in_nested(field_path: str, available_fields: Dict) -> Dict:
    """
    Check if a field path exists in nested structure.
    Uses enhanced catalog with field metadata.
    
    Args:
        field_path: Field path (e.g., "iamConfiguration.publicAccessPrevention")
        available_fields: Available fields dict from enhanced catalog
    
    Returns:
        Validation result
    """
    # Handle both dict (enhanced) and list (old) formats
    if isinstance(available_fields, list):
        available_fields = {f: {} for f in available_fields}
    
    parts = field_path.split('.')
    current = available_fields
    
    for i, part in enumerate(parts):
        if part in current:
            field_meta = current[part]
            
            if i == len(parts) - 1:
                # Found the final field
                return {
                    'exists': True,
                    'correct_name': field_path,
                    'validation': 'exact_match',
                    'field_meta': field_meta if isinstance(field_meta, dict) else {}
                }
            else:
                # Go deeper into nested fields
                if isinstance(field_meta, dict):
                    nested_fields = field_meta.get('nested_fields', {})
                    if nested_fields:
                        current = nested_fields
                    else:
                        # Base field exists but no nested_fields metadata - assume valid
                        return {
                            'exists': True,
                            'correct_name': field_path,
                            'validation': 'nested_assumed_valid',
                            'note': f'Base field "{part}" exists, nested path assumed valid'
                        }
                else:
                    return {'exists': False, 'reason': f'Field {part} is not an object'}
        else:
            return {'exists': False, 'reason': f'Field {part} not found at level {i}'}
    
    return {'exists': False, 'reason': 'Unknown error'}


def validate_fields(requirement: Dict, catalog: Dict) -> Dict:
    """Validate fields for a requirement"""
    validated_op = requirement.get('validated_operation')
    
    if not validated_op:
        return requirement
    
    service_name = requirement['service']
    resource_name = validated_op.get('resource', '')
    operation_name = validated_op.get('python_method', '')
    
    # Get operation details from catalog
    service_data = catalog.get(service_name, {})
    resource_data = service_data.get('resources', {}).get(resource_name, {})
    
    # Find the operation
    operation = None
    for op in resource_data.get('independent', []) + resource_data.get('dependent', []):
        if op['python_method'] == operation_name:
            operation = op
            break
    
    if not operation:
        logger.warning(f"Operation not found: {resource_name}.{operation_name}")
        return requirement
    
    available_fields = operation.get('item_fields', {})
    
    # Normalize available fields to dict
    available_fields = normalize_item_fields(available_fields)
    
    # Validate each field
    field_validation = {}
    all_fields_valid = True
    
    for field_req in requirement.get('ai_generated_requirements', {}).get('fields', []):
        field_name = field_req.get('gcp_api_field', '')
        
        # Use shared utility for validation
        validation_result = check_nested_field(field_name, available_fields)
        field_validation[field_name] = validation_result
        
        if not validation_result.get('exists'):
            all_fields_valid = False
            logger.warning(f"Field not found: {field_name} - {validation_result.get('reason')}")
    
    requirement['field_validation'] = field_validation
    requirement['all_fields_valid'] = all_fields_valid
    requirement['final_validation_status'] = '✅ PASS' if all_fields_valid else '❌ FIELD_NOT_FOUND'
    
    return requirement


def main():
    logger.info("Agent 3: GCP Field Validator starting")
    print("=" * 80)
    print("AGENT 3: GCP Field Validator")
    print("=" * 80)
    print()
    
    # Load catalog
    print("Loading GCP API catalog...")
    catalog = load_gcp_catalog()
    print(f"✅ Loaded")
    print()
    
    # Load Agent 2 output
    print("Loading requirements from Agent 2...")
    with open('output/requirements_with_operations.json') as f:
        all_requirements = json.load(f)
    print(f"✅ Loaded")
    print()
    
    # Validate
    all_validated = {}
    total_pass = 0
    total_fail = 0
    
    for service_name, requirements in all_requirements.items():
        print(f"\n📦 {service_name}")
        logger.info(f"Validating fields for service: {service_name}")
        
        validated = [validate_fields(req, catalog) for req in requirements]
        all_validated[service_name] = validated
        
        pass_count = sum(1 for r in validated if r.get('final_validation_status') == '✅ PASS')
        fail_count = len(validated) - pass_count
        
        total_pass += pass_count
        total_fail += fail_count
        
        print(f"   ✅ {pass_count} passed, ❌ {fail_count} failed")
    
    # Save
    output_file = 'output/requirements_validated.json'
    with open(output_file, 'w') as f:
        json.dump(all_validated, f, indent=2)
    
    print("\n" + "=" * 80)
    print(f"✅ Field Validation Complete")
    print(f"   Total: {total_pass + total_fail}")
    print(f"   Passed: {total_pass} ({100*total_pass/(total_pass+total_fail):.1f}%)")
    print(f"   Failed: {total_fail}")
    print(f"   Saved to: {output_file}")
    print()
    print("Next: Run Agent 4 (YAML Generator)")
    print("=" * 80)
    
    logger.info(f"Agent 3 complete: {total_pass} passed, {total_fail} failed")
    logger.info(f"Output: {output_file}")


if __name__ == '__main__':
    main()

