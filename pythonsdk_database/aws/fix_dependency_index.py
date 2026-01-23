#!/usr/bin/env python3
"""
Script to automatically add missing dependency_index entries.
Finds operations that produce missing entities from operation_registry.json
and adds them to dependency_index.json in the correct alphabetical order.
"""

import json
import os
import sys
from pathlib import Path
from collections import defaultdict

def load_json_file(filepath):
    """Load and parse a JSON file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return None

def save_json_file(filepath, data):
    """Save data to a JSON file with proper formatting."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving {filepath}: {e}")
        return False

def find_operations_for_entity(entity_name, operation_registry):
    """Find which operations produce a given entity."""
    operations = []
    if not operation_registry:
        return operations
    
    # Get the operations dict (might be top-level or under 'operations' key)
    ops_dict = operation_registry
    if 'operations' in operation_registry:
        ops_dict = operation_registry['operations']
    
    # Check entity_aliases first
    entity_aliases = operation_registry.get('entity_aliases', {})
    actual_entity_name = entity_aliases.get(entity_name, entity_name)
    
    for op_name, op_data in ops_dict.items():
        # Skip metadata keys
        if op_name in ['service', 'version', 'kind_rules', 'entity_aliases', 'overrides']:
            continue
        
        if not isinstance(op_data, dict):
            continue
            
        if 'produces' in op_data:
            for produce_item in op_data['produces']:
                if isinstance(produce_item, dict):
                    produced_entity = produce_item.get('entity')
                    # Check exact match or alias match
                    if produced_entity == entity_name or produced_entity == actual_entity_name:
                        operations.append({
                            'name': op_name,
                            'consumes': op_data.get('consumes', []),
                            'produces': produce_item
                        })
    
    return operations

def create_entity_entry(operations_info):
    """Create a dependency_index entity_paths entry from operations info."""
    if not operations_info:
        return None
    
    # Group by operation name
    ops_by_name = defaultdict(lambda: {'produces': [], 'consumes': []})
    
    for op_info in operations_info:
        op_name = op_info['name']
        entity_name = op_info['produces']['entity']
        
        ops_by_name[op_name]['produces'].append(entity_name)
        # Get consumes for this operation
        consumes = op_info.get('consumes', [])
        if isinstance(consumes, list):
            # Extract entity names from consumes
            consume_entities = []
            for consume in consumes:
                if isinstance(consume, dict):
                    consume_entities.append(consume.get('entity'))
                elif isinstance(consume, str):
                    consume_entities.append(consume)
            ops_by_name[op_name]['consumes'] = consume_entities
    
    # Build the entry structure
    entry = {
        'operations': sorted(ops_by_name.keys()),
        'produces': {},
        'consumes': {},
        'external_inputs': []
    }
    
    for op_name in sorted(ops_by_name.keys()):
        entry['produces'][op_name] = ops_by_name[op_name]['produces']
        entry['consumes'][op_name] = ops_by_name[op_name]['consumes']
    
    # Determine external inputs - operations that have required params with source=external
    # For now, we'll leave this empty as it requires deeper analysis
    # The pattern from cloudfront shows empty external_inputs for Get operations
    
    return entry

def find_insertion_point(entity_name, entity_paths):
    """Find where to insert an entity alphabetically."""
    entity_keys = sorted(entity_paths.keys())
    
    # Binary search for insertion point
    left, right = 0, len(entity_keys)
    while left < right:
        mid = (left + right) // 2
        if entity_keys[mid] < entity_name:
            left = mid + 1
        else:
            right = mid
    
    return left

def add_missing_entities_to_dependency_index(service_dir, missing_entities, operation_registry):
    """Add missing entities to dependency_index.json."""
    dependency_index_path = service_dir / 'dependency_index.json'
    dependency_index = load_json_file(dependency_index_path)
    
    if not dependency_index:
        print(f"  Could not load dependency_index.json for {service_dir.name}")
        return 0
    
    if 'entity_paths' not in dependency_index:
        dependency_index['entity_paths'] = {}
    
    entity_paths = dependency_index['entity_paths']
    initial_count = len(entity_paths)
    added_count = 0
    skipped_no_ops = 0
    
    for entity_name in missing_entities:
        if entity_name in entity_paths:
            continue  # Already exists (shouldn't happen, but check anyway)
        
        # Find operations that produce this entity
        operations_info = find_operations_for_entity(entity_name, operation_registry)
        
        if not operations_info:
            skipped_no_ops += 1
            continue
        
        # Create the entry
        entry = create_entity_entry(operations_info)
        if not entry:
            skipped_no_ops += 1
            continue
        
        # Add to entity_paths (will sort later)
        entity_paths[entity_name] = [entry]
        added_count += 1
    
    # Sort entity_paths alphabetically
    dependency_index['entity_paths'] = dict(sorted(entity_paths.items()))
    
    # Validate JSON before saving
    try:
        json.dumps(dependency_index)
    except Exception as e:
        print(f"  ERROR: Generated invalid JSON for {service_dir.name}: {e}")
        return 0
    
    # Save the updated file
    if save_json_file(dependency_index_path, dependency_index):
        final_count = len(dependency_index['entity_paths'])
        if final_count != initial_count + added_count:
            print(f"  WARNING: Count mismatch for {service_dir.name}: {initial_count} -> {final_count} (expected +{added_count})")
        if skipped_no_ops > 0:
            print(f"  INFO: Skipped {skipped_no_ops} entities with no operations found")
        return added_count
    else:
        return 0

def fix_service(service_dir, dry_run=False):
    """Fix missing entities for a single service."""
    service_path = Path(service_dir)
    service_name = service_path.name
    
    direct_vars_path = service_path / 'direct_vars.json'
    dependency_index_path = service_path / 'dependency_index.json'
    operation_registry_path = service_path / 'operation_registry.json'
    
    if not direct_vars_path.exists() or not dependency_index_path.exists():
        return None
    
    direct_vars = load_json_file(direct_vars_path)
    dependency_index = load_json_file(dependency_index_path)
    operation_registry = load_json_file(operation_registry_path)
    
    if not direct_vars or not dependency_index:
        return None
    
    # Extract entities
    direct_vars_entities = set()
    if 'fields' in direct_vars:
        for field_data in direct_vars['fields'].values():
            if 'dependency_index_entity' in field_data:
                direct_vars_entities.add(field_data['dependency_index_entity'])
    if 'field_mappings' in direct_vars:
        for mapping_data in direct_vars['field_mappings'].values():
            if 'dependency_index_entity' in mapping_data:
                direct_vars_entities.add(mapping_data['dependency_index_entity'])
    
    dependency_index_entities = set(dependency_index.get('entity_paths', {}).keys())
    missing = sorted(direct_vars_entities - dependency_index_entities)
    
    if not missing:
        return {'service': service_name, 'added': 0, 'missing': 0}
    
    if dry_run:
        return {'service': service_name, 'added': 0, 'missing': len(missing)}
    
    # Add missing entities
    added = add_missing_entities_to_dependency_index(service_path, missing, operation_registry)
    
    return {'service': service_name, 'added': added, 'missing': len(missing)}

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Fix missing dependency_index entries')
    parser.add_argument('--service', help='Fix a specific service only')
    parser.add_argument('--dry-run', action='store_true', help='Dry run (don\'t modify files)')
    parser.add_argument('--limit', type=int, help='Limit number of services to process')
    args = parser.parse_args()
    
    base_dir = Path(__file__).parent
    services_dir = base_dir
    
    # Get service directories
    service_dirs = [d for d in services_dir.iterdir() 
                   if d.is_dir() and (d / 'direct_vars.json').exists() 
                   and (d / 'dependency_index.json').exists()]
    
    if args.service:
        service_dirs = [d for d in service_dirs if d.name == args.service]
        if not service_dirs:
            print(f"Service '{args.service}' not found")
            return
    
    service_dirs.sort()
    
    if args.limit:
        service_dirs = service_dirs[:args.limit]
    
    print(f"Processing {len(service_dirs)} services...")
    print("=" * 80)
    
    results = []
    for service_dir in service_dirs:
        result = fix_service(service_dir, dry_run=args.dry_run)
        if result:
            results.append(result)
            if result['missing'] > 0:
                status = "DRY RUN" if args.dry_run else "FIXED"
                print(f"{result['service']}: {result['added']}/{result['missing']} entities {status}")
    
    print("=" * 80)
    total_added = sum(r['added'] for r in results)
    total_missing = sum(r['missing'] for r in results)
    print(f"\nSummary:")
    print(f"Services processed: {len(results)}")
    print(f"Total missing: {total_missing}")
    if not args.dry_run:
        print(f"Total added: {total_added}")

if __name__ == '__main__':
    main()

