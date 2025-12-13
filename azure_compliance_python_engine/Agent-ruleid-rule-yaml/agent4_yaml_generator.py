"""
Agent 4: YAML Generator

Converts validated requirements into AWS-compatible Azure YAML rules.
"""

import json
import sys
import yaml
from typing import Dict, List, Any
from agent_logger import get_logger

logger = get_logger('agent4')


def generate_yaml_for_service(service: str, rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate YAML structure for a service.
    
    Returns AWS-compatible YAML structure.
    """
    # Get unique discovery operations
    discoveries = {}
    checks = []
    
    for rule in rules:
        # Skip invalid rules
        if not rule.get('all_fields_valid'):
            logger.warning(f"Skipping invalid rule: {rule['rule_id']}")
            continue
        
        validated_func = rule.get('validated_function', {})
        discovery_id = validated_func.get('discovery_id')
        
        if not discovery_id:
            logger.warning(f"No discovery_id for {rule['rule_id']}")
            continue
        
        # Add discovery if not already added
        if discovery_id not in discoveries:
            # Get item fields for emit section
            item_fields = validated_func.get('item_fields', [])
            main_field = validated_func.get('main_output_field', 'value')
            action = validated_func.get('yaml_action', validated_func.get('python_method'))
            
            # Build emit section
            emit_item = {}
            for field in item_fields[:20]:  # Limit to first 20 fields
                emit_item[field] = f"{{{{ item.{field} }}}}"
            
            discoveries[discovery_id] = {
                'discovery_id': discovery_id,
                'calls': [
                    {
                        'action': action,
                        'save_as': f"{action}_response"
                    }
                ],
                'emit': {
                    'items_for': f"{{{{ {action}_response.{main_field} }}}}",
                    'as': 'item',
                    'item': emit_item
                }
            }
        
        # Generate check
        ai_reqs = rule.get('ai_generated_requirements', {})
        fields = ai_reqs.get('fields', [])
        
        if not fields:
            continue
        
        # For now, handle single field conditions (most common)
        field_spec = fields[0]
        field_name = field_spec.get('azure_sdk_python_field', '')
        operator = field_spec.get('operator', 'equals')
        expected_value = field_spec.get('azure_sdk_python_field_expected_values')
        
        check = {
            'rule_id': rule['rule_id'],
            'for_each': discovery_id,
            'conditions': {
                'var': f"item.{field_name}",
                'op': operator
            }
        }
        
        # Add value if not null
        if expected_value is not None:
            check['conditions']['value'] = expected_value
        
        checks.append(check)
    
    # Build final YAML structure
    yaml_structure = {
        'version': '1.0',
        'provider': 'azure',
        'service': service,
        'discovery': list(discoveries.values()),
        'checks': checks
    }
    
    return yaml_structure


def main():
    logger.info("Agent 4 starting - YAML Generator")
    print("=" * 80)
    print("AGENT 4: YAML Generator")
    print("=" * 80)
    print("Converts validated requirements to AWS-compatible YAML")
    print()
    
    # Load validated requirements
    logger.info("Loading validated requirements...")
    print("Loading requirements_validated.json...")
    try:
        with open('output/requirements_validated.json') as f:
            requirements = json.load(f)
        logger.info(f"Loaded {len(requirements)} services")
        print(f"✅ Loaded {len(requirements)} services")
    except FileNotFoundError:
        logger.error("requirements_validated.json not found")
        print("❌ requirements_validated.json not found")
        print("Run Agent 3 first: python3 agent3_field_validator.py")
        sys.exit(1)
    
    print()
    
    # Generate YAML for each service
    total_generated = 0
    
    for service, rules in requirements.items():
        logger.info(f"Generating YAML for {service}")
        print(f"📦 {service}")
        
        # Filter valid rules
        valid_rules = [r for r in rules if r.get('all_fields_valid')]
        invalid_count = len(rules) - len(valid_rules)
        
        if invalid_count > 0:
            print(f"   ⚠️  Skipping {invalid_count} invalid rules")
            logger.warning(f"Skipping {invalid_count} invalid rules for {service}")
        
        if not valid_rules:
            print(f"   ❌ No valid rules to generate")
            logger.warning(f"No valid rules for {service}")
            continue
        
        # Generate YAML
        yaml_structure = generate_yaml_for_service(service, valid_rules)
        
        # Save to file
        output_file = f"output/{service}_generated.yaml"
        with open(output_file, 'w') as f:
            yaml.dump(yaml_structure, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        print(f"   ✅ Generated {len(yaml_structure['checks'])} checks")
        print(f"      Discoveries: {len(yaml_structure['discovery'])}")
        print(f"      Output: {output_file}")
        logger.info(f"Generated YAML for {service}: {output_file}")
        
        total_generated += len(yaml_structure['checks'])
        print()
    
    print("=" * 80)
    print(f"✅ Generated {total_generated} YAML checks")
    print("Saved to: output/{{service}}_generated.yaml")
    print()
    print("Next: Test with engine")
    print("=" * 80)
    
    logger.info(f"Agent 4 complete: {total_generated} checks generated")


if __name__ == '__main__':
    main()

