"""
Agent 3: OCI Field Validator

Validates that fields exist in OCI SDK responses.
"""

import json
import os
from agent_logger import get_logger
from shared_agent_utils import check_nested_field, normalize_item_fields

logger = get_logger('agent3')


def load_oci_catalog():
    """Load OCI SDK catalog"""
    with open('oci_sdk_catalog_enhanced.json') as f:
        return json.load(f)


def validate_fields(requirement: Dict, catalog: Dict) -> Dict:
    """Validate fields for a requirement"""
    validated_op = requirement.get('validated_operation')
    
    if not validated_op:
        return requirement
    
    service_name = requirement['service']
    operation_name = validated_op.get('python_method', '')
    
    # Find operation in catalog
    service_data = catalog.get(service_name, {})
    operation = None
    
    for op in service_data.get('operations', []):
        if op['operation'] == operation_name:
            operation = op
            break
    
    if not operation:
        return requirement
    
    available_fields = operation.get('item_fields', {})
    
    # Validate each field
    field_validation = {}
    all_fields_valid = True
    
    for field_req in requirement.get('ai_generated_requirements', {}).get('fields', []):
        field_name = field_req.get('oci_sdk_field', '')
        
        if field_name in available_fields:
            field_validation[field_name] = {
                'exists': True,
                'correct_name': field_name,
                'validation': 'exact_match'
            }
        else:
            field_validation[field_name] = {
                'exists': False,
                'reason': 'Field not found'
            }
            all_fields_valid = False
    
    requirement['field_validation'] = field_validation
    requirement['all_fields_valid'] = all_fields_valid
    requirement['final_validation_status'] = '✅ PASS' if all_fields_valid else '❌ FIELD_NOT_FOUND'
    
    return requirement


def main():
    print("=" * 80)
    print("AGENT 3: OCI Field Validator")
    print("=" * 80)
    
    catalog = load_oci_catalog()
    
    with open('output/requirements_with_operations.json') as f:
        all_requirements = json.load(f)
    
    all_validated = {}
    total_pass = 0
    total_fail = 0
    
    for service_name, requirements in all_requirements.items():
        print(f"\n📦 {service_name}")
        validated = [validate_fields(req, catalog) for req in requirements]
        all_validated[service_name] = validated
        
        pass_count = sum(1 for r in validated if r.get('final_validation_status') == '✅ PASS')
        fail_count = len(validated) - pass_count
        total_pass += pass_count
        total_fail += fail_count
        
        print(f"   ✅ {pass_count} passed, ❌ {fail_count} failed")
    
    output_file = 'output/requirements_validated.json'
    with open(output_file, 'w') as f:
        json.dump(all_validated, f, indent=2)
    
    print("\n" + "=" * 80)
    print(f"✅ Complete: {total_pass} passed, {total_fail} failed")
    print("=" * 80)


if __name__ == '__main__':
    main()

