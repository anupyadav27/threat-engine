#!/usr/bin/env python3
"""
Validation script focusing on READ OPERATIONS ONLY.

This script validates that:
1. All entities produced by READ operations in operation_registry.json are in dependency_index.json
2. All dependency_index_entity values from direct_vars.json that come from READ operations are in dependency_index.json

Read operations are identified by: kind.startswith('read_') (e.g., read_get, read_list)
"""

import json
import os
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

def is_read_operation(op_data):
    """Check if an operation is a read operation."""
    kind = op_data.get('kind', '')
    return kind.startswith('read_')

def extract_read_operation_entities(operation_registry):
    """Extract all entities produced by READ operations only."""
    entities_from_read_ops = set()
    entity_to_read_operations = defaultdict(list)
    
    if not operation_registry:
        return entities_from_read_ops, entity_to_read_operations
    
    ops_dict = operation_registry.get('operations', {})
    entity_aliases = operation_registry.get('entity_aliases', {})
    
    for op_name, op_data in ops_dict.items():
        # Skip non-operations
        if op_name in ['service', 'version', 'kind_rules', 'entity_aliases', 'overrides']:
            continue
        
        if not isinstance(op_data, dict):
            continue
        
        # Only process READ operations
        if not is_read_operation(op_data):
            continue
        
        # Get all entities produced by this read operation
        for produce_item in op_data.get('produces', []):
            if isinstance(produce_item, dict):
                entity = produce_item.get('entity')
                if entity:
                    entities_from_read_ops.add(entity)
                    entity_to_read_operations[entity].append(op_name)
                    
                    # Also add alias if it exists
                    for alias, canonical in entity_aliases.items():
                        if canonical == entity:
                            entities_from_read_ops.add(alias)
                            entity_to_read_operations[alias].append(op_name)
    
    return entities_from_read_ops, entity_to_read_operations

def extract_entities_from_direct_vars(direct_vars):
    """Extract all dependency_index_entity values from direct_vars.json."""
    entities = set()
    
    # Check fields section
    if 'fields' in direct_vars:
        for field_name, field_data in direct_vars['fields'].items():
            if isinstance(field_data, dict) and 'dependency_index_entity' in field_data:
                entity = field_data['dependency_index_entity']
                if entity:  # Skip empty strings
                    entities.add(entity)
    
    # Check field_mappings section
    if 'field_mappings' in direct_vars:
        for field_name, mapping_data in direct_vars['field_mappings'].items():
            if isinstance(mapping_data, dict) and 'dependency_index_entity' in mapping_data:
                entity = mapping_data['dependency_index_entity']
                if entity:  # Skip empty strings
                    entities.add(entity)
    
    return entities

def extract_entities_from_dependency_index(dependency_index):
    """Extract all entity keys from dependency_index.json entity_paths."""
    entities = set()
    if 'entity_paths' in dependency_index:
        entities = set(dependency_index['entity_paths'].keys())
    return entities

def validate_read_operations_for_service(service_dir):
    """Validate read operations dependency index coverage for a service."""
    service_path = Path(service_dir)
    service_name = service_path.name
    
    direct_vars_path = service_path / 'direct_vars.json'
    dependency_index_path = service_path / 'dependency_index.json'
    operation_registry_path = service_path / 'operation_registry.json'
    
    result = {
        'service': service_name,
        'has_direct_vars': False,
        'has_dependency_index': False,
        'has_operation_registry': False,
        'read_operations_count': 0,
        'total_read_operation_entities': 0,
        'read_entities_in_dependency_index': 0,
        'read_entities_missing_from_dependency_index': [],
        'direct_vars_read_entities': 0,
        'direct_vars_read_entities_missing': [],
        'missing_count': 0,
        'status': 'FAIL',
        'issues': []
    }
    
    # Check if required files exist
    if not direct_vars_path.exists():
        result['issues'].append('Missing direct_vars.json')
        return result
    
    if not dependency_index_path.exists():
        result['issues'].append('Missing dependency_index.json')
        return result
    
    if not operation_registry_path.exists():
        result['issues'].append('Missing operation_registry.json')
        return result
    
    result['has_direct_vars'] = True
    result['has_dependency_index'] = True
    result['has_operation_registry'] = True
    
    direct_vars = load_json_file(direct_vars_path)
    dependency_index = load_json_file(dependency_index_path)
    operation_registry = load_json_file(operation_registry_path)
    
    if not direct_vars or not dependency_index or not operation_registry:
        result['issues'].append('Cannot parse one or more JSON files')
        return result
    
    # Extract entities from READ operations only
    read_operation_entities, entity_to_read_ops = extract_read_operation_entities(operation_registry)
    result['total_read_operation_entities'] = len(read_operation_entities)
    
    # Count read operations
    ops_dict = operation_registry.get('operations', {})
    read_ops_count = sum(1 for op_data in ops_dict.values() 
                         if isinstance(op_data, dict) and is_read_operation(op_data))
    result['read_operations_count'] = read_ops_count
    
    # Extract entities from dependency_index.json
    dependency_index_entities = extract_entities_from_dependency_index(dependency_index)
    
    # Check which read operation entities are in dependency_index.json
    read_entities_in_di = read_operation_entities & dependency_index_entities
    read_entities_missing = read_operation_entities - dependency_index_entities
    result['read_entities_in_dependency_index'] = len(read_entities_in_di)
    result['read_entities_missing_from_dependency_index'] = sorted(read_entities_missing)
    
    # Extract entities from direct_vars.json
    direct_vars_entities = extract_entities_from_direct_vars(direct_vars)
    
    # Filter to only entities that come from read operations (or their aliases)
    entity_aliases = operation_registry.get('entity_aliases', {})
    direct_vars_read_entities = set()
    
    for entity in direct_vars_entities:
        # Check if entity or its canonical form is produced by a read operation
        canonical = entity_aliases.get(entity, entity)
        if entity in read_operation_entities or canonical in read_operation_entities:
            direct_vars_read_entities.add(entity)
    
    result['direct_vars_read_entities'] = len(direct_vars_read_entities)
    
    # Check which direct_vars read entities are missing from dependency_index.json
    direct_vars_read_missing = direct_vars_read_entities - dependency_index_entities
    result['direct_vars_read_entities_missing'] = sorted(direct_vars_read_missing)
    result['missing_count'] = len(direct_vars_read_missing)
    
    # Determine status
    if result['missing_count'] == 0 and len(read_entities_missing) == 0:
        result['status'] = 'PASS'
    elif result['missing_count'] > 0:
        result['status'] = 'FAIL'
        result['issues'].append(f"{result['missing_count']} read operation entities missing from dependency_index.json")
    else:
        result['status'] = 'PASS'
    
    return result

def main():
    base_dir = Path(__file__).parent
    services_dir = base_dir
    
    print("=" * 80)
    print("READ OPERATIONS ONLY - Dependency Index Validation")
    print("=" * 80)
    
    # Get all service directories
    service_dirs = [d for d in services_dir.iterdir() 
                   if d.is_dir() and not d.name.startswith('.') and not d.name.startswith('_')
                   and (d / 'direct_vars.json').exists()]
    
    service_dirs.sort()
    
    print(f"\nFound {len(service_dirs)} service directories")
    print("\nValidating read operations dependency index coverage...")
    print("-" * 80)
    
    results = []
    services_with_issues = []
    
    for service_dir in service_dirs:
        result = validate_read_operations_for_service(service_dir)
        results.append(result)
        
        if result['status'] != 'PASS':
            services_with_issues.append(result)
            print(f"{result['service']}: {result['status']} - {result['missing_count']} missing entities")
    
    # Generate summary
    pass_count = sum(1 for r in results if r['status'] == 'PASS')
    fail_count = sum(1 for r in results if r['status'] == 'FAIL')
    total_missing = sum(r['missing_count'] for r in results)
    total_read_ops = sum(r['read_operations_count'] for r in results)
    total_read_entities = sum(r['total_read_operation_entities'] for r in results)
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"\nTotal Services: {len(results)}")
    print(f"  PASS: {pass_count}")
    print(f"  FAIL: {fail_count}")
    print(f"\nTotal Read Operations: {total_read_ops}")
    print(f"Total Read Operation Entities: {total_read_entities}")
    print(f"Total Missing Entities: {total_missing}")
    
    if services_with_issues:
        print(f"\nServices with missing entities ({len(services_with_issues)}):")
        sorted_issues = sorted(services_with_issues, key=lambda x: x['missing_count'], reverse=True)
        for r in sorted_issues[:30]:
            print(f"  {r['service']:40} {r['missing_count']:>6} missing")
        if len(services_with_issues) > 30:
            print(f"  ... and {len(services_with_issues) - 30} more")
    
    # Write detailed report
    report_path = base_dir / 'read_operations_validation_report.json'
    with open(report_path, 'w') as f:
        json.dump({
            'summary': {
                'total_services': len(results),
                'pass': pass_count,
                'fail': fail_count,
                'total_read_operations': total_read_ops,
                'total_read_operation_entities': total_read_entities,
                'total_missing_entities': total_missing
            },
            'services': {
                r['service']: {
                    'status': r['status'],
                    'read_operations_count': r['read_operations_count'],
                    'total_read_operation_entities': r['total_read_operation_entities'],
                    'read_entities_in_dependency_index': r['read_entities_in_dependency_index'],
                    'read_entities_missing_from_dependency_index_count': len(r['read_entities_missing_from_dependency_index']),
                    'direct_vars_read_entities': r['direct_vars_read_entities'],
                    'missing_count': r['missing_count'],
                    'missing_entities': r['direct_vars_read_entities_missing'],
                    'issues': r['issues']
                }
                for r in results
            }
        }, f, indent=2)
    
    print(f"\nDetailed report written to: {report_path}")
    
    return results

if __name__ == '__main__':
    main()

