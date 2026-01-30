"""
Agent 2: OCI Operation Validator

Validates OCI SDK operations and maps fields to operations.
"""

import json
import os
from typing import Dict, List, Any, Optional
from agent_logger import get_logger
from shared_agent_utils import normalize_item_fields, calculate_field_match_score

logger = get_logger('agent2')


def load_oci_catalog():
    """Load OCI SDK catalog"""
    with open('oci_sdk_catalog_enhanced.json') as f:
        return json.load(f)


def find_best_operation(service_name: str, required_fields: List[str], catalog: Dict) -> Optional[Dict]:
    """Find the best OCI operation that provides the required fields"""
    service_data = catalog.get(service_name, {})
    
    best_match = None
    best_score = 0
    
    for op in service_data.get('operations', []):
        available_fields = op.get('item_fields', {})
        
        if not available_fields:
            continue
        
        matched_fields = sum(1 for field in required_fields if field in available_fields)
        score = matched_fields / len(required_fields) if required_fields else 0
        
        if score > best_score:
            best_score = score
            best_match = {
                'python_method': op['operation'],
                'operation': op['operation'],
                'operation_type': op.get('operation_type', 'list'),
                'available_fields': list(available_fields.keys()),
                'match_score': score
            }
    
    return best_match


def validate_service_requirements(service_name: str, requirements: List[Dict], catalog: Dict) -> List[Dict]:
    """Validate requirements for a service"""
    validated = []
    
    for req in requirements:
        rule_id = req['rule_id']
        ai_reqs = req.get('ai_generated_requirements', {})
        fields = ai_reqs.get('fields', [])
        
        if not fields:
            validated.append(req)
            continue
        
        field_names = [f.get('oci_sdk_field', '') for f in fields]
        best_op = find_best_operation(service_name, field_names, catalog)
        
        if best_op:
            req['validated_operation'] = best_op
            req['validation_status'] = '✅ PASS'
            logger.info(f"Found operation: {best_op['python_method']} (score: {best_op['match_score']:.2f})")
        else:
            req['validated_operation'] = None
            req['validation_status'] = '❌ NO_OPERATION_FOUND'
        
        validated.append(req)
    
    return validated


def main():
    print("=" * 80)
    print("AGENT 2: OCI Operation Validator")
    print("=" * 80)
    
    catalog = load_oci_catalog()
    print(f"✅ Loaded catalog")
    
    with open('output/requirements_initial.json') as f:
        all_requirements = json.load(f)
    print(f"✅ Loaded requirements")
    
    all_validated = {}
    total_pass = 0
    total_fail = 0
    
    for service_name, requirements in all_requirements.items():
        print(f"\n📦 {service_name}")
        validated = validate_service_requirements(service_name, requirements, catalog)
        all_validated[service_name] = validated
        
        pass_count = sum(1 for r in validated if r.get('validation_status') == '✅ PASS')
        fail_count = len(validated) - pass_count
        total_pass += pass_count
        total_fail += fail_count
        
        print(f"   ✅ {pass_count} passed, ❌ {fail_count} failed")
    
    output_file = 'output/requirements_with_operations.json'
    with open(output_file, 'w') as f:
        json.dump(all_validated, f, indent=2)
    
    print("\n" + "=" * 80)
    print(f"✅ Validation Complete: {total_pass} passed, {total_fail} failed")
    print(f"   Saved to: {output_file}")
    print("=" * 80)


if __name__ == '__main__':
    main()

