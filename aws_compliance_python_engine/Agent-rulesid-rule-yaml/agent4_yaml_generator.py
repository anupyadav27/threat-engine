"""
Agent 4: YAML Generator

Takes validated requirements and generates complete YAML files.

Flow:
1. Read requirements_validated.json
2. For each rule, traverse: field → function → dependencies → emit
3. Generate complete discovery + checks YAML
4. Save to service/rules/*.yaml

Uses: boto3_dependencies_with_python_names.json for field mappings
"""

import json
import os
import sys
from typing import Dict, List, Any, Set


def load_boto3_catalog():
    """Load boto3 catalog"""
    with open('boto3_dependencies_with_python_names.json') as f:
        return json.load(f)


def load_validated_requirements():
    """Load validated requirements from Agent 3"""
    with open('output/requirements_validated.json') as f:
        return json.load(f)


def generate_discovery_for_function(service: str, function_data: Dict, discovery_id: str, is_root: bool = True) -> Dict:
    """
    Generate discovery YAML section with CORRECT emit structure.
    
    KEY LEARNING FROM S3:
    - Independent discoveries: Need items_for + as + item (defines iteration)
    - Dependent discoveries: Simple item emit (inherits 'item' from parent)
    
    Args:
        service: Service name
        function_data: Function info from validated requirements
        discovery_id: ID for this discovery
        is_root: Whether this is a root (independent) discovery
    
    Returns:
        Discovery dict ready for YAML
    """
    python_method = function_data['python_method']
    main_output = function_data['main_output_field']
    is_independent = function_data['is_independent']
    required_params = function_data.get('required_params', [])
    available_fields = function_data.get('available_fields', [])
    
    discovery = {
        'discovery_id': discovery_id,
        'calls': [
            {
                'action': python_method,
                'save_as': f'{python_method}_response'
            }
        ]
    }
    
    # Add for_each if dependent (will be filled later)
    if not is_independent:
        discovery['for_each'] = f'aws.{service}.PARENT_DISCOVERY'
    
    # Add params if dependent
    if required_params:
        discovery['calls'][0]['params'] = {}
        for param in required_params:
            discovery['calls'][0]['params'][param] = '{{ item.FIELD_NAME }}'
        discovery['calls'][0]['on_error'] = 'continue'
    
    # Generate emit section - CRITICAL DIFFERENCE
    emit = {}
    
    if is_independent:
        # INDEPENDENT: Full emit with items_for
        if main_output:
            emit['items_for'] = f'{{{{ {python_method}_response.{main_output} }}}}'
            emit['as'] = 'resource'  # Use generic name
            
            # Map fields from response
            emit['item'] = {}
            for field in available_fields[:10]:
                snake_case_name = _to_snake_case(field)
                emit['item'][snake_case_name] = f'{{{{ resource.{field} }}}}'
        else:
            # Fallback for operations without clear list output
            emit['item'] = {}
            for field in available_fields[:5]:
                snake_case_name = _to_snake_case(field)
                emit['item'][snake_case_name] = f'{{{{ {python_method}_response.{field} }}}}'
    else:
        # DEPENDENT: Simple emit - inherit 'item' from parent
        emit['item'] = {}
        
        # Pass through parent id/name (always useful)
        emit['item']['resource_id'] = '{{ item.resource_id }}'
        
        # Add NEW fields from THIS discovery's response
        if main_output and available_fields:
            # If response has a main structure, access it
            for field in available_fields[:5]:
                snake_case_name = _to_snake_case(field)
                emit['item'][snake_case_name] = f'{{{{ {python_method}_response.{main_output}.{field} }}}}'
        elif available_fields:
            # Direct fields from response
            for field in available_fields[:5]:
                snake_case_name = _to_snake_case(field)
                emit['item'][snake_case_name] = f'{{{{ {python_method}_response.{field} }}}}'
    
    discovery['emit'] = emit
    
    return discovery


def generate_check(rule: Dict, discovery_id: str) -> Dict:
    """
    Generate check YAML section.
    
    Args:
        rule: Validated rule data
        discovery_id: Which discovery to use
    
    Returns:
        Check dict ready for YAML
    """
    rule_id = rule['rule_id']
    fields = rule['ai_generated_requirements']['fields']
    condition_logic = rule['ai_generated_requirements'].get('condition_logic', 'single')
    
    check = {
        'rule_id': rule_id,
        'for_each': discovery_id
    }
    
    # Build conditions
    if condition_logic == 'single' and len(fields) == 1:
        field = fields[0]
        field_name = _to_snake_case(field['boto3_python_field'])
        
        check['conditions'] = {
            'var': f'item.{field_name}',
            'op': field['operator']
        }
        
        # ALWAYS add value (even for exists operator, for clarity)
        value = field.get('boto3_python_field_expected_values')
        if value is not None:
            check['conditions']['value'] = value
    
    elif condition_logic in ['all', 'any']:
        # Multiple conditions
        check['conditions'] = {condition_logic: []}
        
        for field in fields:
            field_name = _to_snake_case(field['boto3_python_field'])
            cond = {
                'var': f'item.{field_name}',
                'op': field['operator']
            }
            
            # ALWAYS add value if provided
            value = field.get('boto3_python_field_expected_values')
            if value is not None:
                cond['value'] = value
            elif field['operator'] == 'exists':
                # For exists operator, value can be omitted
                pass
            else:
                # Default value based on operator
                if field['operator'] == 'equals':
                    cond['value'] = None  # Will need manual review
            
            check['conditions'][condition_logic].append(cond)
    
    return check


def find_parent_discovery(service: str, required_params: List[str], all_discoveries: Dict, boto3_service_data: Dict) -> str:
    """
    Find which discovery can provide the required parameters.
    
    Args:
        service: Service name
        required_params: List of parameter names needed
        all_discoveries: Already created discoveries
        boto3_service_data: Boto3 data for this service
    
    Returns:
        Parent discovery_id or None
    """
    # Look for independent functions that can provide these params
    for discovery_id, discovery_data in all_discoveries.items():
        if discovery_data.get('for_each'):
            # This is dependent, skip
            continue
        
        # Check if this discovery's fields match the required params
        # Common pattern: analyzerArn parameter needs 'arn' field, etc.
        func_data = discovery_data.get('_function_data', {})
        available_fields = func_data.get('available_fields', [])
        
        for param in required_params:
            # Match patterns: analyzerArn → arn, bucketName → name, etc.
            for field in available_fields:
                if param.lower().endswith(field.lower()) or field.lower() in param.lower():
                    return discovery_id
    
    # Fallback: return first independent discovery
    for discovery_id, discovery_data in all_discoveries.items():
        if not discovery_data.get('for_each'):
            return discovery_id
    
    return None


def generate_yaml_for_service(service: str, rules: List[Dict], boto3_data: Dict) -> Dict:
    """
    Generate complete YAML structure for a service.
    
    Args:
        service: Service name
        rules: List of validated rules for this service
        boto3_data: Boto3 catalog
    
    Returns:
        Complete YAML structure
    """
    yaml_structure = {
        'version': '1.0',
        'provider': 'aws',
        'service': service,
        'discovery': [],
        'checks': []
    }
    
    # Track discoveries
    discoveries = {}  # discovery_id -> discovery_dict
    independent_discoveries = []
    dependent_discoveries = []
    
    # First pass: Create all discoveries
    for rule in rules:
        if not rule.get('validated_function'):
            continue
        
        func = rule['validated_function']
        python_method = func['python_method']
        discovery_id = f'aws.{service}.{python_method}'
        
        if discovery_id not in discoveries:
            discovery = generate_discovery_for_function(service, func, discovery_id)
            discovery['_function_data'] = func  # Store for parent lookup
            discoveries[discovery_id] = discovery
            
            if func['is_independent']:
                independent_discoveries.append(discovery_id)
            else:
                dependent_discoveries.append(discovery_id)
    
    # Second pass: Link dependent discoveries to parents
    for disc_id in dependent_discoveries:
        discovery = discoveries[disc_id]
        func_data = discovery['_function_data']
        required_params = func_data.get('required_params', [])
        
        # Find parent
        parent_id = find_parent_discovery(service, required_params, discoveries, boto3_data.get(service, {}))
        
        if parent_id:
            # Update for_each
            discovery['for_each'] = parent_id
            
            # Update params to reference parent fields
            if 'params' in discovery['calls'][0]:
                parent_func = discoveries[parent_id]['_function_data']
                parent_fields = parent_func.get('available_fields', [])
                
                for param in required_params:
                    # Smart matching patterns
                    matched_field = None
                    
                    # Pattern 1: Exact match (case-insensitive)
                    for field in parent_fields:
                        if field.lower() == param.lower():
                            matched_field = field
                            break
                    
                    # Pattern 2: Parameter ends with field name
                    # analyzerArn → arn, bucketName → name, Bucket → name
                    if not matched_field:
                        for field in parent_fields:
                            if param.lower().endswith(field.lower()):
                                matched_field = field
                                break
                    
                    # Pattern 3: Field name in parameter
                    if not matched_field:
                        for field in parent_fields:
                            if field.lower() in param.lower():
                                matched_field = field
                                break
                    
                    # Pattern 4: Special cases
                    if not matched_field:
                        # Bucket parameter usually maps to Name field in list_buckets
                        if param.lower() == 'bucket' and 'Name' in parent_fields:
                            matched_field = 'Name'
                        elif param.lower() == 'bucket' and 'name' in parent_fields:
                            matched_field = 'name'
                    
                    if matched_field:
                        field_snake = _to_snake_case(matched_field)
                        discovery['calls'][0]['params'][param] = f'{{{{ item.{field_snake} }}}}'
                    else:
                        # Couldn't match - leave placeholder for manual review
                        discovery['calls'][0]['params'][param] = '{{ item.id }}'
        
        # Remove helper data
        del discovery['_function_data']
    
    # Remove helper data from independent
    for disc_id in independent_discoveries:
        if '_function_data' in discoveries[disc_id]:
            del discoveries[disc_id]['_function_data']
    
    # Generate checks
    for rule in rules:
        if not rule.get('validated_function'):
            continue
        
        func = rule['validated_function']
        discovery_id = f'aws.{service}.{func['python_method']}'
        check = generate_check(rule, discovery_id)
        yaml_structure['checks'].append(check)
    
    # Add discoveries (independent first, then dependent)
    for disc_id in independent_discoveries:
        yaml_structure['discovery'].append(discoveries[disc_id])
    for disc_id in dependent_discoveries:
        yaml_structure['discovery'].append(discoveries[disc_id])
    
    return yaml_structure


def _to_snake_case(name: str) -> str:
    """Convert PascalCase/camelCase to snake_case"""
    import re
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def main():
    print("=" * 80)
    print("AGENT 4: YAML Generator")
    print("=" * 80)
    print("Generating YAML from validated requirements")
    print()
    
    # Load data
    print("Loading data...")
    boto3_data = load_boto3_catalog()
    requirements = load_validated_requirements()
    print("✅ Loaded")
    
    # Generate YAML for each service
    for service, rules in requirements.items():
        print(f"\n📦 {service}")
        
        # Count valid rules
        valid_rules = [r for r in rules if r.get('all_fields_valid')]
        print(f"   Valid rules: {len(valid_rules)}/{len(rules)}")
        
        if not valid_rules:
            print(f"   ⚠️  No valid rules, skipping")
            continue
        
        # Generate YAML
        yaml_structure = generate_yaml_for_service(service, valid_rules, boto3_data)
        
        print(f"   Discoveries: {len(yaml_structure['discovery'])}")
        print(f"   Checks: {len(yaml_structure['checks'])}")
        
        # Save YAML
        output_file = f'output/{service}_generated.yaml'
        
        # Convert to YAML format
        import yaml
        with open(output_file, 'w') as f:
            yaml.dump(yaml_structure, f, default_flow_style=False, sort_keys=False)
        
        print(f"   ✅ Saved: {output_file}")
    
    print("\n" + "=" * 80)
    print("✅ YAML GENERATION COMPLETE")
    print("=" * 80)
    print("\nGenerated YAML files:")
    print("  output/*_generated.yaml")
    print("\nNext: Review and copy to services/*/rules/*.yaml")


if __name__ == '__main__':
    main()
