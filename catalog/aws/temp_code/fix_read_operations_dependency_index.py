#!/usr/bin/env python3
"""
Fix script for READ OPERATIONS ONLY.

Adds missing dependency_index entries for entities produced by READ operations.
Read operations are identified by: kind.startswith('read_')
"""

import json
import sys
from pathlib import Path
from collections import defaultdict

def load_json_file(filepath):
    """Load and parse a JSON file."""
    try:
        if not filepath.exists():
            return None
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        return None

def save_json_file(filepath, data):
    """Save data to a JSON file."""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)

def is_read_operation(op_data):
    """Check if an operation is a read operation."""
    kind = op_data.get('kind', '')
    return kind.startswith('read_')

def find_read_operations_for_entity(entity_name, operation_registry):
    """Find which READ operations produce a given entity."""
    operations = []
    if not operation_registry:
        return operations
    
    ops_dict = operation_registry.get('operations', {})
    entity_aliases = operation_registry.get('entity_aliases', {})
    
    # Resolve entity name through aliases
    actual_entity_name = entity_aliases.get(entity_name, entity_name)
    
    for op_name, op_data in ops_dict.items():
        if op_name in ['service', 'version', 'kind_rules', 'entity_aliases', 'overrides']:
            continue
        
        if not isinstance(op_data, dict):
            continue
        
        # Only consider READ operations
        if not is_read_operation(op_data):
            continue
        
        if 'produces' in op_data:
            for produce_item in op_data['produces']:
                if isinstance(produce_item, dict):
                    produced_entity = produce_item.get('entity')
                    # Check both the entity name and its alias
                    if produced_entity == entity_name or produced_entity == actual_entity_name:
                        operations.append({
                            'name': op_name,
                            'consumes': op_data.get('consumes', []),
                            'produces': produce_item
                        })
    
    return operations

def create_dependency_index_entry(operations):
    """Create a dependency_index entry for an entity from its producing operations."""
    if not operations:
        return None
    
    entry = {
        'operations': [op['name'] for op in operations],
        'produces': {},
        'consumes': {},
        'external_inputs': []
    }
    
    # Build produces and consumes for each operation
    for op in operations:
        op_name = op['name']
        produces_item = op['produces']
        
        entry['produces'][op_name] = [produces_item.get('entity')]
        
        # Build consumes for this operation
        consumes_list = []
        for consume_item in op['consumes']:
            if isinstance(consume_item, dict):
                source = consume_item.get('source', 'external')
                if source == 'external':
                    consumes_list.append(consume_item.get('entity'))
        
        entry['consumes'][op_name] = consumes_list
    
    return entry

def fix_service(service_dir):
    """Fix dependency_index.json for a service by adding missing read operation entities."""
    service_path = Path(service_dir)
    service_name = service_path.name
    
    direct_vars_path = service_path / 'direct_vars.json'
    dependency_index_path = service_path / 'dependency_index.json'
    operation_registry_path = service_path / 'operation_registry.json'
    
    if not direct_vars_path.exists() or not dependency_index_path.exists() or not operation_registry_path.exists():
        return {'service': service_name, 'added': 0, 'skipped': 0, 'errors': ['Missing required files']}
    
    direct_vars = load_json_file(direct_vars_path)
    dependency_index = load_json_file(dependency_index_path)
    operation_registry = load_json_file(operation_registry_path)
    
    if not direct_vars or not dependency_index or not operation_registry:
        return {'service': service_name, 'added': 0, 'skipped': 0, 'errors': ['Cannot parse JSON files']}
    
    # Extract entities from direct_vars.json that come from read operations
    direct_vars_entities = set()
    if 'fields' in direct_vars:
        for field_data in direct_vars['fields'].values():
            if isinstance(field_data, dict) and 'dependency_index_entity' in field_data:
                entity = field_data['dependency_index_entity']
                if entity:
                    direct_vars_entities.add(entity)
    
    if 'field_mappings' in direct_vars:
        for mapping_data in direct_vars['field_mappings'].values():
            if isinstance(mapping_data, dict) and 'dependency_index_entity' in mapping_data:
                entity = mapping_data['dependency_index_entity']
                if entity:
                    direct_vars_entities.add(entity)
    
    # Get existing entities from dependency_index.json
    existing_entities = set()
    if 'entity_paths' in dependency_index:
        existing_entities = set(dependency_index['entity_paths'].keys())
    
    # Find missing entities
    missing_entities = direct_vars_entities - existing_entities
    
    # Extract entities from READ operations only
    read_operation_entities = set()
    entity_aliases = operation_registry.get('entity_aliases', {})
    ops_dict = operation_registry.get('operations', {})
    
    for op_data in ops_dict.values():
        if isinstance(op_data, dict) and is_read_operation(op_data):
            for produce_item in op_data.get('produces', []):
                if isinstance(produce_item, dict):
                    entity = produce_item.get('entity')
                    if entity:
                        read_operation_entities.add(entity)
                        # Also add aliases
                        for alias, canonical in entity_aliases.items():
                            if canonical == entity:
                                read_operation_entities.add(alias)
    
    # Filter missing entities to only those from read operations
    missing_read_entities = missing_entities & read_operation_entities
    
    added_count = 0
    skipped_count = 0
    errors = []
    
    # Ensure entity_paths exists
    if 'entity_paths' not in dependency_index:
        dependency_index['entity_paths'] = {}
    
    # Add missing entities
    for entity_name in sorted(missing_read_entities):
        # Find read operations that produce this entity
        operations = find_read_operations_for_entity(entity_name, operation_registry)
        
        if operations:
            entry = create_dependency_index_entry(operations)
            if entry:
                dependency_index['entity_paths'][entity_name] = [entry]
                added_count += 1
            else:
                skipped_count += 1
                errors.append(f"Could not create entry for {entity_name}")
        else:
            skipped_count += 1
    
    # Save updated dependency_index.json
    if added_count > 0:
        save_json_file(dependency_index_path, dependency_index)
    
    return {
        'service': service_name,
        'added': added_count,
        'skipped': skipped_count,
        'errors': errors
    }

def main():
    base_dir = Path(__file__).parent
    services_dir = base_dir
    
    print("=" * 80)
    print("FIX READ OPERATIONS DEPENDENCY INDEX")
    print("=" * 80)
    
    # Get all service directories
    service_dirs = [d for d in services_dir.iterdir() 
                   if d.is_dir() and not d.name.startswith('.') and not d.name.startswith('_')
                   and (d / 'direct_vars.json').exists() 
                   and (d / 'dependency_index.json').exists()
                   and (d / 'operation_registry.json').exists()]
    
    service_dirs.sort()
    
    print(f"\nProcessing {len(service_dirs)} services...")
    print("-" * 80)
    
    results = []
    for service_dir in service_dirs:
        result = fix_service(service_dir)
        results.append(result)
        
        if result['added'] > 0:
            print(f"{result['service']}: {result['added']} entities ADDED")
        elif result['skipped'] > 0:
            print(f"{result['service']}: {result['skipped']} entities skipped (no read operations found)")
    
    # Summary
    total_added = sum(r['added'] for r in results)
    total_skipped = sum(r['skipped'] for r in results)
    services_fixed = sum(1 for r in results if r['added'] > 0)
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Services processed: {len(results)}")
    print(f"Services with entities added: {services_fixed}")
    print(f"Total entities added: {total_added}")
    print(f"Total entities skipped: {total_skipped}")
    
    return results

if __name__ == '__main__':
    main()

