"""
Agent 4: K8s YAML Generator

Generates production-ready YAML rule files from validated requirements.

Input: output/requirements_validated.json
Output: output/{resource}_generated.yaml
"""

import json
import os
import yaml
from typing import Dict, List, Any
from agent_logger import get_logger

logger = get_logger('agent4')


def generate_discovery_section(resource: str, resource: str, operation: str, validated_op: Dict) -> Dict:
    """Generate discovery section for K8s"""
    discovery_id = f"k8s.{resource}.{operation}"
    
    discovery = {
        'discovery_id': discovery_id,
        'calls': [{
            'action': operation,
            'save_as': f'{operation}_response'
        }],
        'emit': {
            'items_for': f'{{{{ {operation}_response.items }}}}',  # K8s typically uses 'items'
            'as': 'item',
            'item': {}
        }
    }
    
    # Add key fields to item
    if validated_op:
        for field in ['id', 'name', 'selfLink'][:3]:
            if field in validated_op.get('available_fields', []):
                discovery['emit']['item'][field] = f'{{{{ item.{field} }}}}'
    
    return discovery


def generate_check_section(requirement: Dict) -> Dict:
    """Generate check section for a requirement"""
    rule_id = requirement['rule_id']
    resource = requirement['resource']
    validated_op = requirement.get('validated_operation', {})
    
    if not validated_op:
        return None
    
    operation = validated_op['python_method']
    discovery_id = f"k8s.{resource}.{operation}"
    
    check = {
        'rule_id': rule_id,
        'for_each': discovery_id,
        'conditions': []
    }
    
    # Add field conditions
    ai_reqs = requirement.get('ai_generated_requirements', {})
    for field_req in ai_reqs.get('fields', []):
        k8s_field = field_req.get('k8s_api_field', '')
        operator = field_req.get('operator', 'equals')
        expected_value = field_req.get('k8s_api_field_expected_values')
        
        # Validate field exists
        field_validation = requirement.get('field_validation', {}).get(k8s_field, {})
        if not field_validation.get('exists'):
            continue
        
        condition = {
            'var': f'item.{k8s_field}',
            'op': operator
        }
        
        if expected_value is not None:
            condition['value'] = expected_value
        
        check['conditions'].append(condition)
    
    # If multiple conditions, default to AND logic
    if len(check['conditions']) > 1:
        check['logic'] = 'AND'
    elif len(check['conditions']) == 1:
        # Single condition - flatten
        check.update(check['conditions'][0])
        del check['conditions']
    
    return check if check.get('conditions') or check.get('var') else None


def generate_yaml_for_resource(resource: str, requirements: List[Dict]) -> Dict:
    """Generate complete YAML for a resource"""
    yaml_structure = {
        'version': '1.0',
        'provider': 'k8s',
        'resource': resource,
        'discovery': [],
        'checks': []
    }
    
    # Track unique discoveries
    added_discoveries = set()
    
    for req in requirements:
        if req.get('final_validation_status') != '✅ PASS':
            continue
        
        validated_op = req.get('validated_operation')
        if not validated_op:
            continue
        
        operation = validated_op['python_method']
        resource = validated_op.get('resource', '')
        
        # Add discovery if not already added
        discovery_id = f"k8s.{resource}.{operation}"
        if discovery_id not in added_discoveries:
            discovery = generate_discovery_section(resource, resource, operation, validated_op)
            yaml_structure['discovery'].append(discovery)
            added_discoveries.add(discovery_id)
        
        # Add check
        check = generate_check_section(req)
        if check:
            yaml_structure['checks'].append(check)
    
    return yaml_structure


def main():
    logger.info("Agent 4: K8s YAML Generator starting")
    print("=" * 80)
    print("AGENT 4: K8s YAML Generator")
    print("=" * 80)
    print()
    
    # Load validated requirements
    print("Loading validated requirements from Agent 3...")
    with open('output/requirements_validated.json') as f:
        all_requirements = json.load(f)
    print(f"✅ Loaded")
    print()
    
    # Generate YAMLs
    total_yamls = 0
    total_checks = 0
    
    for resource, requirements in all_requirements.items():
        print(f"\n📦 {resource}")
        logger.info(f"Generating YAML for resource: {resource}")
        
        yaml_structure = generate_yaml_for_resource(resource, requirements)
        
        if yaml_structure['checks']:
            output_file = f'output/{resource}_generated.yaml'
            with open(output_file, 'w') as f:
                yaml.dump(yaml_structure, f, default_flow_style=False, sort_keys=False)
            
            num_checks = len(yaml_structure['checks'])
            total_checks += num_checks
            total_yamls += 1
            
            print(f"   ✅ Generated {num_checks} checks")
            logger.info(f"Generated {output_file} with {num_checks} checks")
        else:
            print(f"   ⚠️  No valid checks to generate")
    
    print("\n" + "=" * 80)
    print(f"✅ YAML Generation Complete")
    print(f"   YAMLs generated: {total_yamls}")
    print(f"   Total checks: {total_checks}")
    print(f"   Output: output/{{resource}}_generated.yaml")
    print("=" * 80)
    
    logger.info(f"Agent 4 complete: {total_yamls} YAMLs, {total_checks} checks")


if __name__ == '__main__':
    main()

