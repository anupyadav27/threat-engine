"""
Agent 4: OCI YAML Generator

Generates production-ready YAML rule files from validated requirements.
"""

import json
import os
import yaml
from agent_logger import get_logger

logger = get_logger('agent4')


def generate_yaml_for_service(service: str, requirements: List[Dict]) -> Dict:
    """Generate complete YAML for a service"""
    yaml_structure = {
        'version': '1.0',
        'provider': 'oci',
        'service': service,
        'discovery': [],
        'checks': []
    }
    
    added_discoveries = set()
    
    for req in requirements:
        if req.get('final_validation_status') != '✅ PASS':
            continue
        
        validated_op = req.get('validated_operation')
        if not validated_op:
            continue
        
        operation = validated_op['python_method']
        discovery_id = f"oci.{service}.{operation}"
        
        # Add discovery
        if discovery_id not in added_discoveries:
            discovery = {
                'discovery_id': discovery_id,
                'calls': [{'action': operation, 'save_as': f'{operation}_response'}],
                'emit': {
                    'items_for': f'{{{{ {operation}_response.data }}}}',
                    'as': 'item',
                    'item': {'id': '{{ item.id }}', 'display_name': '{{ item.display_name }}'}
                }
            }
            yaml_structure['discovery'].append(discovery)
            added_discoveries.add(discovery_id)
        
        # Add check
        ai_reqs = req.get('ai_generated_requirements', {})
        check = {
            'rule_id': req['rule_id'],
            'for_each': discovery_id,
            'conditions': {'var': f"item.{ai_reqs['fields'][0].get('oci_sdk_field', 'id')}", 
                          'op': ai_reqs['fields'][0].get('operator', 'exists')}
        }
        
        expected = ai_reqs['fields'][0].get('oci_sdk_field_expected_values')
        if expected is not None:
            check['conditions']['value'] = expected
        
        yaml_structure['checks'].append(check)
    
    return yaml_structure


def main():
    print("=" * 80)
    print("AGENT 4: OCI YAML Generator")
    print("=" * 80)
    
    with open('output/requirements_validated.json') as f:
        all_requirements = json.load(f)
    
    total_yamls = 0
    total_checks = 0
    
    for service, requirements in all_requirements.items():
        print(f"\n📦 {service}")
        yaml_structure = generate_yaml_for_service(service, requirements)
        
        if yaml_structure['checks']:
            output_file = f'output/{service}_generated.yaml'
            with open(output_file, 'w') as f:
                yaml.dump(yaml_structure, f, default_flow_style=False, sort_keys=False)
            
            num_checks = len(yaml_structure['checks'])
            total_checks += num_checks
            total_yamls += 1
            print(f"   ✅ Generated {num_checks} checks")
    
    print("\n" + "=" * 80)
    print(f"✅ Generated {total_yamls} YAMLs, {total_checks} checks")
    print("=" * 80)


if __name__ == '__main__':
    main()

