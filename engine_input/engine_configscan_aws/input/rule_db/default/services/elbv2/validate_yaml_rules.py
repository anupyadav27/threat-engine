#!/usr/bin/env python3
"""
Validate ELBV2 YAML rules against metadata_mapping.json
"""
import json
import yaml
import os
from pathlib import Path

def load_yaml_file(filepath):
    with open(filepath, 'r') as f:
        return yaml.safe_load(f)

def load_json_file(filepath):
    with open(filepath, 'r') as f:
        return json.load(f)

def get_discovery_emit_structure(yaml_data, discovery_id):
    """Get the emit structure for a discovery_id"""
    for discovery in yaml_data.get('discovery', []):
        if discovery.get('discovery_id') == discovery_id:
            return discovery.get('emit', {})
    return None

def normalize_field_path(field_path, emit_structure):
    """
    Convert metadata_mapping field_path to YAML var path based on emit structure.
    
    Examples:
    - field_path: "Listeners[].SslPolicy" with emit that extracts from response.Listeners -> "item.SslPolicy"
    - field_path: "Attributes[].Key" with items_for -> "item.Key"
    """
    # Check if emit uses items_for (array iteration)
    uses_items_for = 'items_for' in emit_structure
    
    # Remove array notation
    clean_path = field_path.replace('[]', '')
    
    if uses_items_for:
        # If items_for, each item is already 'item', so remove array prefix if present
        if clean_path.startswith('Attributes.'):
            clean_path = clean_path.replace('Attributes.', '')
        return f"item.{clean_path}" if clean_path else "item"
    else:
        # If not items_for, check if emit extracts from a specific path
        # For example, if emit shows '{{ response.Listeners.SslPolicy }}', then item.SslPolicy
        # If emit shows '{{ response.LoadBalancers.LoadBalancerArn }}', then item.LoadBalancerArn
        # But if the emit structure shows item.Listeners.SslPolicy, we need to check the actual structure
        
        # Remove common prefixes
        if clean_path.startswith('Listeners.'):
            clean_path = clean_path.replace('Listeners.', '')
        elif clean_path.startswith('LoadBalancers.'):
            clean_path = clean_path.replace('LoadBalancers.', '')
        elif clean_path.startswith('TargetGroups.'):
            clean_path = clean_path.replace('TargetGroups.', '')
        elif clean_path.startswith('Attributes.'):
            clean_path = clean_path.replace('Attributes.', '')
        
        return f"item.{clean_path}" if clean_path else "item"

def validate_rule(rule, metadata_mapping, yaml_data):
    """Validate a single rule against its metadata mapping"""
    rule_id = rule.get('rule_id')
    issues = []
    
    # Find metadata mapping for this rule
    mapping = None
    for m in metadata_mapping.get('elbv2_metadata_mapping', []):
        if m.get('rule_id') == rule_id:
            mapping = m
            break
    
    if not mapping:
        return {
            'rule_id': rule_id,
            'status': 'ERROR',
            'issues': [f'No metadata mapping found for {rule_id}']
        }
    
    # Get discovery and emit structure
    discovery_id = rule.get('for_each')
    emit_structure = get_discovery_emit_structure(yaml_data, discovery_id)
    
    if not emit_structure:
        return {
            'rule_id': rule_id,
            'status': 'ERROR',
            'issues': [f'Discovery {discovery_id} not found in YAML']
        }
    
    # Check discovery method matches
    expected_method = mapping.get('python_method')
    if discovery_id and expected_method:
        # Extract method from discovery calls
        discovery = None
        for d in yaml_data.get('discovery', []):
            if d.get('discovery_id') == discovery_id:
                discovery = d
                break
        
        if discovery:
            calls = discovery.get('calls', [])
            if calls:
                actual_method = calls[0].get('action', '')
                if actual_method != expected_method:
                    issues.append(f'Discovery method mismatch: expected {expected_method}, got {actual_method}')
    
    # Check logical operator
    expected_op = mapping.get('logical_operator')
    conditions = rule.get('conditions', {})
    
    # Handle nested structure (any/all)
    if 'any' in conditions:
        if expected_op == 'all':
            issues.append('Expected "all" logical operator but found "any" wrapper')
    elif 'all' in conditions:
        if expected_op == 'any':
            issues.append('Expected "any" logical operator but found "all"')
        elif expected_op is None:
            # Single condition expected
            if len(conditions['all']) > 1:
                issues.append('Expected single condition but found multiple in "all"')
    else:
        # Single condition
        if expected_op == 'all':
            issues.append('Expected "all" logical operator but not found')
        elif expected_op == 'any':
            issues.append('Expected "any" logical operator but not found')
    
    # Get conditions list - handle nested structure
    if 'any' in conditions:
        inner_list = conditions['any']
        if isinstance(inner_list, list) and len(inner_list) > 0:
            if 'all' in inner_list[0]:
                condition_list = inner_list[0]['all']
            else:
                condition_list = inner_list
        else:
            condition_list = []
    elif 'all' in conditions:
        condition_list = conditions['all']
    else:
        condition_list = [conditions]
    
    # Validate each field check
    expected_fields = mapping.get('nested_field', [])
    
    if len(condition_list) != len(expected_fields):
        issues.append(f'Condition count mismatch: expected {len(expected_fields)}, got {len(condition_list)}')
    
    # Check each field
    for i, expected_field in enumerate(expected_fields):
        if i >= len(condition_list):
            issues.append(f'Missing condition for field: {expected_field.get("field_path")}')
            continue
        
        condition = condition_list[i]
        expected_path = expected_field.get('field_path', '')
        expected_value = expected_field.get('expected_value')
        expected_operator = expected_field.get('operator')
        
        # Normalize expected path to YAML var format
        normalized_path = normalize_field_path(expected_path, emit_structure)
        actual_path = condition.get('var', '')
        
        if actual_path != normalized_path:
            issues.append(f'Field path mismatch for {expected_path}: expected "{normalized_path}", got "{actual_path}"')
        
        # Check operator
        actual_operator = condition.get('op', '')
        if actual_operator != expected_operator:
            issues.append(f'Operator mismatch for {expected_path}: expected "{expected_operator}", got "{actual_operator}"')
        
        # Check value (handle type conversions and arrays)
        actual_value = condition.get('value')
        if expected_value is not None:
            # Handle list values (for 'in' operator)
            if isinstance(expected_value, list) and isinstance(actual_value, list):
                if set(expected_value) != set(actual_value):
                    issues.append(f'Value mismatch for {expected_path}: expected {expected_value}, got {actual_value}')
            # Convert boolean strings to boolean for comparison
            elif isinstance(expected_value, bool) and isinstance(actual_value, str):
                if str(expected_value).lower() != actual_value.lower():
                    issues.append(f'Value mismatch for {expected_path}: expected {expected_value}, got {actual_value}')
            elif expected_value != actual_value:
                # String comparison for 'true' values
                if str(expected_value) != str(actual_value):
                    issues.append(f'Value mismatch for {expected_path}: expected {expected_value}, got {actual_value}')
    
    status = 'PASS' if not issues else 'FAIL'
    return {
        'rule_id': rule_id,
        'status': status,
        'issues': issues,
        'discovery_id': discovery_id,
        'expected_method': expected_method
    }

def main():
    base_dir = Path(__file__).parent
    yaml_file = base_dir / 'rules' / 'elbv2.yaml'
    metadata_file = base_dir / 'metadata_mapping.json'
    
    print(f"Loading YAML from {yaml_file}")
    yaml_data = load_yaml_file(yaml_file)
    
    print(f"Loading metadata mapping from {metadata_file}")
    metadata_mapping = load_json_file(metadata_file)
    
    rules = yaml_data.get('checks', [])
    print(f"\nValidating {len(rules)} rules...\n")
    
    results = []
    for rule in rules:
        result = validate_rule(rule, metadata_mapping, yaml_data)
        results.append(result)
        
        if result['status'] == 'FAIL':
            print(f"❌ {result['rule_id']}")
            for issue in result['issues']:
                print(f"   - {issue}")
        elif result['status'] == 'ERROR':
            print(f"⚠️  {result['rule_id']}")
            for issue in result['issues']:
                print(f"   - {issue}")
        else:
            print(f"✅ {result['rule_id']}")
    
    # Summary
    passing = sum(1 for r in results if r['status'] == 'PASS')
    failing = sum(1 for r in results if r['status'] == 'FAIL')
    errors = sum(1 for r in results if r['status'] == 'ERROR')
    
    print(f"\n{'='*60}")
    print(f"Validation Summary:")
    print(f"  Total Rules: {len(results)}")
    print(f"  ✅ Passing: {passing}")
    print(f"  ❌ Failing: {failing}")
    print(f"  ⚠️  Errors: {errors}")
    print(f"{'='*60}\n")
    
    # Save results
    output_file = base_dir / 'validation_results.json'
    with open(output_file, 'w') as f:
        json.dump({
            'validation_date': str(Path(__file__).stat().st_mtime),
            'summary': {
                'total_rules': len(results),
                'passing': passing,
                'failing': failing,
                'errors': errors
            },
            'results': results
        }, f, indent=2)
    
    print(f"Results saved to {output_file}")
    return failing == 0 and errors == 0

if __name__ == '__main__':
    success = main()
    exit(0 if success else 1)

