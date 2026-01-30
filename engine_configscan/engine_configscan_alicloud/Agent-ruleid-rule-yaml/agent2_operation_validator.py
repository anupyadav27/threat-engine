"""
Agent 2: Alibaba Operation Validator

Takes requirements from Agent 1 and validates/corrects operation names.
Uses alicloud_api_dependencies_fully_enhanced.json to:
- Find which operation can provide the required fields
- Validate operation names exist
- Correct typos
- Determine resource and operation structure

Input: output/requirements_initial.json
Output: output/requirements_with_operations.json
"""

import json
import os
from typing import Dict, List, Any, Optional
from difflib import SequenceMatcher
from agent_logger import get_logger
from shared_agent_utils import normalize_item_fields, calculate_field_match_score

logger = get_logger('agent2')


def load_alicloud_catalog():
    """Load Alibaba API catalog"""
    with open('alicloud_api_dependencies_fully_enhanced.json') as f:
        return json.load(f)


def similarity(a: str, b: str) -> float:
    """Calculate string similarity"""
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def find_best_operation(service_name: str, required_fields: List[str], catalog: Dict) -> Optional[Dict]:
    """
    Find the best Alibaba operation that provides the required fields.
    
    Args:
        service_name: Alibaba service name
        required_fields: List of field names needed
        catalog: Alibaba API catalog
    
    Returns:
        Best matching operation or None
    """
    service_data = catalog.get(service_name, {})
    
    best_match = None
    best_score = 0
    
    for resource_name, resource_data in service_data.get('resources', {}).items():
        for op in resource_data.get('independent', []) + resource_data.get('dependent', []):
            available_fields = op.get('item_fields', {})
            
            if not available_fields:
                continue
            
            # Calculate match score
            matched_fields = 0
            for req_field in required_fields:
                # Check direct match or nested match
                if req_field in available_fields:
                    matched_fields += 1
                else:
                    # Check nested fields
                    for field_name in available_fields.keys():
                        if req_field.startswith(field_name + '.'):
                            matched_fields += 0.5
            
            score = matched_fields / len(required_fields) if required_fields else 0
            
            if score > best_score:
                best_score = score
                best_match = {
                    'python_method': op['python_method'],
                    'operation': op['operation'],
                    'resource': resource_name,
                    'http_method': op.get('http_method', 'GET'),
                    'available_fields': list(available_fields.keys()),
                    'match_score': score
                }
    
    return best_match


def validate_service_requirements(service_name: str, requirements: List[Dict], catalog: Dict) -> List[Dict]:
    """Validate and enrich requirements for a service"""
    validated = []
    
    for req in requirements:
        rule_id = req['rule_id']
        logger.info(f"Validating {rule_id}")
        
        ai_reqs = req.get('ai_generated_requirements', {})
        fields = ai_reqs.get('fields', [])
        
        if not fields:
            logger.warning(f"No fields generated for {rule_id}")
            validated.append(req)
            continue
        
        # Extract field names
        field_names = [f.get('alicloud_api_field', '') for f in fields]
        
        # Find best operation
        best_op = find_best_operation(service_name, field_names, catalog)
        
        if best_op:
            req['validated_operation'] = best_op
            req['validation_status'] = '✅ PASS'
            logger.info(f"Found operation: {best_op['resource']}.{best_op['python_method']} (score: {best_op['match_score']:.2f})")
        else:
            req['validated_operation'] = None
            req['validation_status'] = '❌ NO_OPERATION_FOUND'
            logger.warning(f"No suitable operation found for {rule_id}")
        
        validated.append(req)
    
    return validated


def main():
    logger.info("Agent 2: Alibaba Operation Validator starting")
    print("=" * 80)
    print("AGENT 2: Alibaba Operation Validator")
    print("=" * 80)
    print()
    
    # Load Alibaba catalog
    print("Loading Alibaba API catalog...")
    catalog = load_alicloud_catalog()
    print(f"✅ Loaded {len(catalog)} services")
    print()
    
    # Load Agent 1 output
    print("Loading requirements from Agent 1...")
    with open('output/requirements_initial.json') as f:
        all_requirements = json.load(f)
    print(f"✅ Loaded {sum(len(reqs) for reqs in all_requirements.values())} requirements")
    print()
    
    # Validate each service
    all_validated = {}
    total_pass = 0
    total_fail = 0
    
    for service_name, requirements in all_requirements.items():
        print(f"\n📦 {service_name}")
        logger.info(f"Validating service: {service_name}")
        
        validated = validate_service_requirements(service_name, requirements, catalog)
        all_validated[service_name] = validated
        
        pass_count = sum(1 for r in validated if r.get('validation_status') == '✅ PASS')
        fail_count = len(validated) - pass_count
        
        total_pass += pass_count
        total_fail += fail_count
        
        print(f"   ✅ {pass_count} passed, ❌ {fail_count} failed")
        logger.info(f"Service {service_name}: {pass_count} passed, {fail_count} failed")
    
    # Save
    output_file = 'output/requirements_with_operations.json'
    with open(output_file, 'w') as f:
        json.dump(all_validated, f, indent=2)
    
    print("\n" + "=" * 80)
    print(f"✅ Validation Complete")
    print(f"   Total: {total_pass + total_fail} requirements")
    print(f"   Passed: {total_pass} ({100*total_pass/(total_pass+total_fail):.1f}%)")
    print(f"   Failed: {total_fail}")
    print(f"   Saved to: {output_file}")
    print()
    print("Next: Run Agent 3 (Field Validator)")
    print("=" * 80)
    
    logger.info(f"Agent 2 complete: {total_pass} passed, {total_fail} failed")
    logger.info(f"Output: {output_file}")


if __name__ == '__main__':
    main()

