#!/usr/bin/env python3
"""
Validate that all fields in direct_vars.json can trace back to read operations
through dependency_index.json.

For each field in direct_vars.json:
1. Check if it has a dependency_index_entity
2. Check if that entity exists in dependency_index.json
3. Check if that entity has read operations defined
4. Check if those read operations are independent (have no consumes or only external consumes)
"""

import json
import sys
from pathlib import Path
from collections import defaultdict, deque

def load_json_file(filepath):
    """Load and parse a JSON file."""
    try:
        if not filepath.exists():
            return None
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        return None

def is_read_operation(op_name, operation_registry):
    """Check if an operation is a read operation."""
    ops_dict = operation_registry.get('operations', {})
    op_data = ops_dict.get(op_name)
    if not op_data:
        return False
    kind = op_data.get('kind', '')
    return kind.startswith('read_')

def is_independent_operation(op_name, dependency_index, operation_registry):
    """
    Check if an operation is independent (can be called without dependencies).
    An operation is independent if it has no consumes or only external consumes.
    """
    entity_paths = dependency_index.get('entity_paths', {})
    
    # Check all entities produced by this operation
    ops_dict = operation_registry.get('operations', {})
    op_data = ops_dict.get(op_name)
    if not op_data:
        return False
    
    # Get all entities this operation produces
    produced_entities = set()
    for produce_item in op_data.get('produces', []):
        if isinstance(produce_item, dict):
            entity = produce_item.get('entity')
            if entity:
                produced_entities.add(entity)
    
    # Check if any of these entities are in dependency_index
    for entity in produced_entities:
        if entity in entity_paths:
            entries = entity_paths[entity]
            for entry in entries:
                if op_name in entry.get('operations', []):
                    consumes = entry.get('consumes', {}).get(op_name, [])
                    # If no consumes or only external entities, it's independent
                    if len(consumes) == 0:
                        return True
    
    return False

def find_root_operations(entity_name, dependency_index, operation_registry, visited=None):
    """
    Find root (independent) operations for an entity by traversing the dependency graph.
    """
    if visited is None:
        visited = set()
    
    entity_paths = dependency_index.get('entity_paths', {})
    
    if entity_name not in entity_paths:
        return []
    
    root_ops = []
    entries = entity_paths[entity_name]
    
    for entry in entries:
        operations = entry.get('operations', [])
        for op_name in operations:
            if op_name in visited:
                continue
            
            # Check if this operation is independent
            consumes = entry.get('consumes', {}).get(op_name, [])
            if len(consumes) == 0:
                # Independent operation - add it
                if is_read_operation(op_name, operation_registry):
                    root_ops.append(op_name)
            else:
                # Has dependencies - check if all dependencies are external
                all_external = True
                for consume_entity in consumes:
                    # Check if consume_entity is in external_inputs or is external
                    external_inputs = entry.get('external_inputs', [])
                    if consume_entity not in external_inputs:
                        all_external = False
                        break
                
                if all_external and is_read_operation(op_name, operation_registry):
                    root_ops.append(op_name)
    
    return root_ops

def validate_service(service_dir):
    """Validate that all fields in direct_vars.json can trace to read operations."""
    service_path = Path(service_dir)
    service_name = service_path.name
    
    direct_vars_path = service_path / 'direct_vars.json'
    dependency_index_path = service_path / 'dependency_index.json'
    operation_registry_path = service_path / 'operation_registry.json'
    
    result = {
        'service': service_name,
        'total_fields': 0,
        'fields_with_dependency_index_entity': 0,
        'fields_with_valid_entity': 0,
        'fields_with_read_operations': 0,
        'fields_with_root_operations': 0,
        'fields_missing_entity': [],
        'fields_missing_in_dependency_index': [],
        'fields_without_read_operations': [],
        'fields_without_root_operations': [],
        'status': 'PASS',
        'issues': []
    }
    
    # Check if required files exist
    if not direct_vars_path.exists():
        result['status'] = 'FAIL'
        result['issues'].append('Missing direct_vars.json')
        return result
    
    if not dependency_index_path.exists():
        result['status'] = 'FAIL'
        result['issues'].append('Missing dependency_index.json')
        return result
    
    if not operation_registry_path.exists():
        result['status'] = 'FAIL'
        result['issues'].append('Missing operation_registry.json')
        return result
    
    direct_vars = load_json_file(direct_vars_path)
    dependency_index = load_json_file(dependency_index_path)
    operation_registry = load_json_file(operation_registry_path)
    
    if not direct_vars or not dependency_index or not operation_registry:
        result['status'] = 'FAIL'
        result['issues'].append('Cannot parse JSON files')
        return result
    
    # Extract fields from direct_vars.json
    fields_data = {}
    if 'fields' in direct_vars:
        fields_data.update(direct_vars['fields'])
    if 'field_mappings' in direct_vars:
        fields_data.update(direct_vars['field_mappings'])
    
    result['total_fields'] = len(fields_data)
    
    entity_paths = dependency_index.get('entity_paths', {})
    entity_aliases = operation_registry.get('entity_aliases', {})
    
    # Validate each field
    for field_name, field_data in fields_data.items():
        if not isinstance(field_data, dict):
            continue
        
        dependency_index_entity = field_data.get('dependency_index_entity')
        
        if not dependency_index_entity:
            result['fields_missing_entity'].append(field_name)
            continue
        
        result['fields_with_dependency_index_entity'] += 1
        
        # Resolve entity through aliases
        actual_entity = entity_aliases.get(dependency_index_entity, dependency_index_entity)
        
        # Check if entity exists in dependency_index
        if actual_entity not in entity_paths and dependency_index_entity not in entity_paths:
            result['fields_missing_in_dependency_index'].append({
                'field': field_name,
                'entity': dependency_index_entity,
                'canonical': actual_entity
            })
            continue
        
        result['fields_with_valid_entity'] += 1
        
        # Get entity from dependency_index (try canonical first, then original)
        entity_entry = None
        if actual_entity in entity_paths:
            entity_entry = entity_paths[actual_entity]
        elif dependency_index_entity in entity_paths:
            entity_entry = entity_paths[dependency_index_entity]
        
        if not entity_entry:
            continue
        
        # Check if entity has read operations
        has_read_ops = False
        read_operations = []
        
        for entry in entity_entry:
            operations = entry.get('operations', [])
            for op_name in operations:
                if is_read_operation(op_name, operation_registry):
                    has_read_ops = True
                    read_operations.append(op_name)
        
        if not has_read_ops:
            result['fields_without_read_operations'].append({
                'field': field_name,
                'entity': dependency_index_entity
            })
            continue
        
        result['fields_with_read_operations'] += 1
        
        # Check if entity has root (independent) read operations
        root_ops = find_root_operations(actual_entity, dependency_index, operation_registry)
        if not root_ops and dependency_index_entity != actual_entity:
            root_ops = find_root_operations(dependency_index_entity, dependency_index, operation_registry)
        
        if not root_ops:
            result['fields_without_root_operations'].append({
                'field': field_name,
                'entity': dependency_index_entity,
                'read_operations': read_operations
            })
            continue
        
        result['fields_with_root_operations'] += 1
    
    # Determine status
    if result['fields_missing_entity'] or result['fields_missing_in_dependency_index']:
        result['status'] = 'FAIL'
    elif result['fields_without_read_operations'] or result['fields_without_root_operations']:
        result['status'] = 'WARN'
    else:
        result['status'] = 'PASS'
    
    return result

def main():
    base_dir = Path(__file__).parent
    services_dir = base_dir
    
    print("=" * 80)
    print("VALIDATE DIRECT_VARS TRACEABILITY TO READ OPERATIONS")
    print("=" * 80)
    
    # Get all service directories
    service_dirs = [d for d in services_dir.iterdir() 
                   if d.is_dir() and not d.name.startswith('.') and not d.name.startswith('_')
                   and (d / 'direct_vars.json').exists()]
    
    service_dirs.sort()
    
    print(f"\nFound {len(service_dirs)} service directories")
    print("Validating traceability...")
    print("-" * 80)
    
    results = []
    services_with_issues = []
    
    for service_dir in service_dirs:
        result = validate_service(service_dir)
        results.append(result)
        
        if result['status'] != 'PASS':
            services_with_issues.append(result)
            issue_summary = []
            if result['fields_missing_entity']:
                issue_summary.append(f"{len(result['fields_missing_entity'])} missing entity")
            if result['fields_missing_in_dependency_index']:
                issue_summary.append(f"{len(result['fields_missing_in_dependency_index'])} not in DI")
            if result['fields_without_read_operations']:
                issue_summary.append(f"{len(result['fields_without_read_operations'])} no read ops")
            if result['fields_without_root_operations']:
                issue_summary.append(f"{len(result['fields_without_root_operations'])} no root ops")
            
            print(f"{result['service']}: {result['status']} - {', '.join(issue_summary)}")
    
    # Summary
    pass_count = sum(1 for r in results if r['status'] == 'PASS')
    warn_count = sum(1 for r in results if r['status'] == 'WARN')
    fail_count = sum(1 for r in results if r['status'] == 'FAIL')
    
    total_fields = sum(r['total_fields'] for r in results)
    total_with_entity = sum(r['fields_with_dependency_index_entity'] for r in results)
    total_with_valid_entity = sum(r['fields_with_valid_entity'] for r in results)
    total_with_read_ops = sum(r['fields_with_read_operations'] for r in results)
    total_with_root_ops = sum(r['fields_with_root_operations'] for r in results)
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"\nTotal Services: {len(results)}")
    print(f"  PASS: {pass_count}")
    print(f"  WARN: {warn_count}")
    print(f"  FAIL: {fail_count}")
    
    print(f"\nField Coverage:")
    print(f"  Total fields: {total_fields}")
    print(f"  Fields with dependency_index_entity: {total_with_entity} ({total_with_entity/total_fields*100:.1f}%)")
    print(f"  Fields with valid entity in dependency_index: {total_with_valid_entity} ({total_with_valid_entity/total_fields*100:.1f}%)")
    print(f"  Fields with read operations: {total_with_read_ops} ({total_with_read_ops/total_fields*100:.1f}%)")
    print(f"  Fields with root operations: {total_with_root_ops} ({total_with_root_ops/total_fields*100:.1f}%)")
    
    # Write detailed report
    report_path = base_dir / 'direct_vars_traceability_report.json'
    with open(report_path, 'w') as f:
        json.dump({
            'summary': {
                'total_services': len(results),
                'pass': pass_count,
                'warn': warn_count,
                'fail': fail_count,
                'total_fields': total_fields,
                'fields_with_dependency_index_entity': total_with_entity,
                'fields_with_valid_entity': total_with_valid_entity,
                'fields_with_read_operations': total_with_read_ops,
                'fields_with_root_operations': total_with_root_ops
            },
            'services': {
                r['service']: {
                    'status': r['status'],
                    'total_fields': r['total_fields'],
                    'fields_with_dependency_index_entity': r['fields_with_dependency_index_entity'],
                    'fields_with_valid_entity': r['fields_with_valid_entity'],
                    'fields_with_read_operations': r['fields_with_read_operations'],
                    'fields_with_root_operations': r['fields_with_root_operations'],
                    'fields_missing_entity_count': len(r['fields_missing_entity']),
                    'fields_missing_in_dependency_index_count': len(r['fields_missing_in_dependency_index']),
                    'fields_without_read_operations_count': len(r['fields_without_read_operations']),
                    'fields_without_root_operations_count': len(r['fields_without_root_operations']),
                    'issues': r['issues']
                }
                for r in results
            }
        }, f, indent=2)
    
    print(f"\nDetailed report written to: {report_path}")
    
    return results

if __name__ == '__main__':
    main()

