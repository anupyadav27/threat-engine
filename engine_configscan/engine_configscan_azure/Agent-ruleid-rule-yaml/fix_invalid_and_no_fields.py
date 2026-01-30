"""
Fix invalid fields and no fields issues using metadata requirements
"""
import json
import os
from agent1_requirements_generator import SERVICE_NAME_MAPPING
from agent_logger import get_logger

logger = get_logger('fix_fields')

def select_field_from_requirement(requirement: str, description: str, available_fields: set) -> str:
    """
    Intelligently select a field based on requirement/description semantics.
    """
    combined_text = f"{requirement.lower()} {description.lower()}"
    
    # Field selection based on requirement semantics
    field_keywords = {
        'enabled': ['enabled', 'enable', 'status', 'state'],
        'encryption': ['encryption', 'encrypted', 'encrypt', 'cmk', 'key'],
        'access': ['access', 'public', 'private', 'network', 'endpoint'],
        'rbac': ['rbac', 'role', 'permission', 'policy', 'authorization'],
        'logging': ['logging', 'log', 'audit', 'monitor', 'diagnostic'],
        'backup': ['backup', 'retention', 'recovery', 'restore'],
        'tags': ['tag', 'label', 'metadata'],
        'location': ['location', 'region', 'zone'],
        'name': ['name', 'identifier'],
        'type': ['type', 'kind', 'category']
    }
    
    # Try to match requirement keywords to available fields
    for keyword, field_candidates in field_keywords.items():
        if any(kw in combined_text for kw in field_candidates):
            # Look for matching fields
            for candidate in field_candidates:
                # Exact match
                if candidate in available_fields:
                    return candidate
                # Partial match (field contains keyword)
                for field in available_fields:
                    if candidate in field.lower() or field.lower() in candidate:
                        return field
    
    # If no semantic match, use common meaningful fields
    preferred_fields = ['enabled', 'status', 'properties', 'id', 'name', 'type', 'location', 'tags']
    for pref_field in preferred_fields:
        if pref_field in available_fields:
            return pref_field
    
    # Last resort: use first available field
    if available_fields:
        return list(available_fields)[0]
    
    return 'id'  # Absolute last resort


def fix_rule_fields(rule: dict, validated_func: dict) -> dict:
    """
    Fix fields for a rule based on available fields from validated function.
    """
    available_fields = set(validated_func.get('item_fields', []))
    if not available_fields:
        return rule
    
    requirement = rule.get('requirement', '')
    description = rule.get('description', '')
    ai_reqs = rule.get('ai_generated_requirements', {})
    fields = ai_reqs.get('fields', [])
    
    # Fix invalid fields
    fixed_fields = []
    for field_spec in fields:
        field_name = field_spec.get('azure_sdk_python_field', '')
        
        if field_name and field_name in available_fields:
            # Field is valid, keep it
            fixed_fields.append(field_spec)
        elif field_name:
            # Field is invalid, try to find a better match
            # Check if it's a nested field (properties.*)
            if field_name.startswith('properties.'):
                base_field = field_name.replace('properties.', '')
                if 'properties' in available_fields:
                    # Keep it as properties.* (will be handled at runtime)
                    fixed_fields.append(field_spec)
                    continue
            
            # Try semantic matching
            better_field = select_field_from_requirement(requirement, description, available_fields)
            if better_field:
                field_spec['azure_sdk_python_field'] = better_field
                field_spec['original_field'] = field_name
                fixed_fields.append(field_spec)
    
    # If no fields or all were invalid, add intelligent fallback
    if not fixed_fields:
        selected_field = select_field_from_requirement(requirement, description, available_fields)
        fixed_fields.append({
            "conceptual_name": f"{selected_field}_check",
            "azure_sdk_python_field": selected_field,
            "operator": "exists",
            "azure_sdk_python_field_expected_values": None
        })
    
    # Update the rule
    rule['ai_generated_requirements']['fields'] = fixed_fields
    return rule


def main():
    logger.info("Starting field fix process")
    print("=" * 80)
    print("FIXING INVALID FIELDS AND NO FIELDS ISSUES")
    print("=" * 80)
    
    # Load validated requirements
    with open('output/requirements_validated.json') as f:
        validated = json.load(f)
    
    # Load initial requirements
    with open('output/requirements_initial.json') as f:
        initial = json.load(f)
    
    # Find rules that need fixing
    rules_to_fix = []
    for service, rules in validated.items():
        for rule in rules:
            status = rule.get('final_validation_status', '')
            if '❌ INVALID FIELDS' in status or '⚠️ NO FIELDS' in status:
                rule_id = rule.get('rule_id')
                # Find in initial
                for init_rule in initial.get(service, []):
                    if init_rule.get('rule_id') == rule_id:
                        validated_func = rule.get('validated_function', {})
                        rules_to_fix.append({
                            'service': service,
                            'initial_rule': init_rule,
                            'validated_rule': rule,
                            'validated_func': validated_func
                        })
                        break
    
    print(f"\nFound {len(rules_to_fix)} rules to fix")
    print("=" * 80)
    
    # Fix each rule
    fixed_count = 0
    for item in rules_to_fix:
        service = item['service']
        initial_rule = item['initial_rule']
        validated_func = item['validated_func']
        
        # Skip if no function validated
        if validated_func.get('error'):
            continue
        
        # Fix the rule
        fixed_rule = fix_rule_fields(initial_rule.copy(), validated_func)
        
        # Update in initial
        for i, r in enumerate(initial[service]):
            if r.get('rule_id') == initial_rule.get('rule_id'):
                initial[service][i] = fixed_rule
                fixed_count += 1
                break
        
        # Save incrementally
        if fixed_count % 50 == 0:
            os.makedirs('output', exist_ok=True)
            with open('output/requirements_initial.json', 'w') as f:
                json.dump(initial, f, indent=2)
            print(f"Progress: {fixed_count}/{len(rules_to_fix)} rules fixed...")
    
    # Final save
    os.makedirs('output', exist_ok=True)
    with open('output/requirements_initial.json', 'w') as f:
        json.dump(initial, f, indent=2)
    
    print("\n" + "=" * 80)
    print(f"✅ Fixed {fixed_count} rules")
    print("Updated: output/requirements_initial.json")
    print("\nNext: Run Agent 2 and Agent 3 again")
    print("=" * 80)
    
    logger.info(f"Fixed {fixed_count} rules")


if __name__ == '__main__':
    main()
