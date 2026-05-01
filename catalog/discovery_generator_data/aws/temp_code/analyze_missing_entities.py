#!/usr/bin/env python3
"""
Analyze why some dependency_index_entity values from direct_vars.json 
are missing from operation_registry.json.

This script identifies patterns and reasons for the mismatch.
"""

import json
from pathlib import Path
from collections import defaultdict

def analyze_service(service_name):
    """Analyze a single service to understand missing entity patterns."""
    service_dir = Path(service_name)
    
    direct_vars_path = service_dir / 'direct_vars.json'
    op_registry_path = service_dir / 'operation_registry.json'
    
    if not direct_vars_path.exists() or not op_registry_path.exists():
        return None
    
    direct_vars = json.load(open(direct_vars_path))
    op_registry = json.load(open(op_registry_path))
    
    # Get entities from direct_vars
    field_to_entity = {}
    entities_from_direct_vars = set()
    if 'fields' in direct_vars:
        for field_name, field_data in direct_vars['fields'].items():
            if 'dependency_index_entity' in field_data:
                entity = field_data['dependency_index_entity']
                entities_from_direct_vars.add(entity)
                field_to_entity[field_name] = entity
    
    # Get entities from operation_registry produces
    entities_from_registry = set()
    entity_to_operations = defaultdict(list)
    ops_dict = op_registry.get('operations', {})
    for op_name, op_data in ops_dict.items():
        if 'produces' in op_data:
            for produce_item in op_data['produces']:
                if isinstance(produce_item, dict):
                    entity = produce_item.get('entity')
                    entities_from_registry.add(entity)
                    entity_to_operations[entity].append(op_name)
    
    # Find missing entities
    missing = entities_from_direct_vars - entities_from_registry
    
    if not missing:
        return None
    
    # Analyze patterns
    patterns = {
        'duplicated_prefix': [],  # e.g., prefix_list_prefix_list_name vs prefix_list_name
        'different_parent': [],   # Different parent context
        'singular_vs_plural': [],  # singular vs plural differences
        'underscore_variations': [],  # Different underscore patterns
        'generic_suffix': [],     # Generic suffixes added
        'unknown': []
    }
    
    for missing_entity in missing:
        # Try to find similar entity in registry
        entity_parts = missing_entity.replace(f'{service_name}.', '').split('_')
        
        found_match = False
        
        # Check for duplicated prefix pattern
        if len(entity_parts) >= 3:
            # Check if first two parts are the same (e.g., prefix_list_prefix_list_name)
            if entity_parts[0] == entity_parts[1]:
                # Try finding without duplication
                candidate = f"{service_name}.{'_'.join(entity_parts[1:])}"
                if candidate in entities_from_registry:
                    patterns['duplicated_prefix'].append({
                        'missing': missing_entity,
                        'similar_in_registry': candidate,
                        'operations': entity_to_operations[candidate]
                    })
                    found_match = True
        
        if not found_match:
            # Check for similar entities (same suffix, different prefix)
            suffix = '_'.join(entity_parts[-2:])  # Last two parts
            similar = [e for e in entities_from_registry if e.endswith(suffix) and e != missing_entity]
            if similar:
                patterns['different_parent'].append({
                    'missing': missing_entity,
                    'similar_in_registry': similar[:3]
                })
                found_match = True
        
        if not found_match:
            patterns['unknown'].append(missing_entity)
    
    return {
        'service': service_name,
        'total_missing': len(missing),
        'patterns': {k: len(v) for k, v in patterns.items()},
        'pattern_examples': {k: v[:5] for k, v in patterns.items() if v}
    }

def main():
    base_dir = Path('.')
    
    # Analyze a few services
    services_to_analyze = ['ec2', 'sagemaker', 'ssm']
    
    print("Analyzing missing entity patterns...")
    print("=" * 80)
    
    for service_name in services_to_analyze:
        result = analyze_service(service_name)
        if result:
            print(f"\n{service_name}:")
            print(f"  Total missing entities: {result['total_missing']}")
            print(f"  Pattern breakdown:")
            for pattern, count in result['patterns'].items():
                if count > 0:
                    print(f"    {pattern}: {count}")
            
            if 'pattern_examples' in result and 'duplicated_prefix' in result['pattern_examples']:
                print(f"\n  Examples of duplicated_prefix pattern:")
                for example in result['pattern_examples']['duplicated_prefix'][:3]:
                    print(f"    Missing: {example['missing']}")
                    print(f"    Found in registry as: {example['similar_in_registry']}")
                    print(f"    Operations: {example['similar_in_registry']}")
                    print()

if __name__ == '__main__':
    main()

