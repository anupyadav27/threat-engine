#!/usr/bin/env python3
"""
Analyze fields in direct_vars.json that have no operations listed.
Determine if they should be kept (from read ops) or removed (from write ops).
"""

import json
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

def is_read_operation(op_name, operation_registry):
    """Check if an operation is a read operation."""
    ops_dict = operation_registry.get('operations', {})
    op_data = ops_dict.get(op_name)
    if not op_data:
        return None  # Unknown operation
    kind = op_data.get('kind', '')
    return kind.startswith('read_')

def get_operations_for_entity(entity_name, dependency_index, operation_registry):
    """Get all operations that produce an entity."""
    entity_paths = dependency_index.get('entity_paths', {})
    entity_aliases = operation_registry.get('entity_aliases', {})
    
    # Resolve entity through aliases
    actual_entity = entity_aliases.get(entity_name, entity_name)
    
    operations = []
    if actual_entity in entity_paths:
        entries = entity_paths[actual_entity]
        for entry in entries:
            operations.extend(entry.get('operations', []))
    
    # Also check original entity name
    if entity_name != actual_entity and entity_name in entity_paths:
        entries = entity_paths[entity_name]
        for entry in entries:
            operations.extend(entry.get('operations', []))
    
    return list(set(operations))

def analyze_service(service_dir):
    """Analyze fields without operations for a service."""
    service_path = Path(service_dir)
    service_name = service_path.name
    
    direct_vars_path = service_path / 'direct_vars.json'
    dependency_index_path = service_path / 'dependency_index.json'
    operation_registry_path = service_path / 'operation_registry.json'
    
    result = {
        'service': service_name,
        'fields_without_operations': [],
        'fields_in_dependency_index': [],
        'fields_not_in_dependency_index': [],
        'fields_from_read_ops': [],
        'fields_from_write_ops': [],
        'fields_from_unknown_ops': []
    }
    
    if not direct_vars_path.exists():
        return result
    
    direct_vars = load_json_file(direct_vars_path)
    dependency_index = load_json_file(dependency_index_path)
    operation_registry = load_json_file(operation_registry_path)
    
    if not direct_vars:
        return result
    
    if not dependency_index or not operation_registry:
        # Can't determine - mark as unknown
        return result
    
    # Extract fields
    fields_data = {}
    if 'fields' in direct_vars:
        fields_data.update(direct_vars['fields'])
    if 'field_mappings' in direct_vars:
        fields_data.update(direct_vars['field_mappings'])
    
    # Analyze each field without operations
    for field_name, field_data in fields_data.items():
        if not isinstance(field_data, dict):
            continue
        
        operations = field_data.get('operations', [])
        if operations:  # Skip fields that have operations
            continue
        
        dependency_index_entity = field_data.get('dependency_index_entity')
        
        field_info = {
            'field_name': field_name,
            'dependency_index_entity': dependency_index_entity,
            'has_operators': bool(field_data.get('operators')),
            'type': field_data.get('type')
        }
        
        result['fields_without_operations'].append(field_info)
        
        if not dependency_index_entity:
            result['fields_not_in_dependency_index'].append(field_info)
            continue
        
        # Check if entity exists in dependency_index
        entity_paths = dependency_index.get('entity_paths', {})
        if dependency_index_entity not in entity_paths:
            result['fields_not_in_dependency_index'].append(field_info)
            continue
        
        result['fields_in_dependency_index'].append(field_info)
        
        # Get operations that produce this entity
        entity_operations = get_operations_for_entity(
            dependency_index_entity, dependency_index, operation_registry
        )
        
        if not entity_operations:
            result['fields_from_unknown_ops'].append(field_info)
            continue
        
        # Check if operations are read or write
        read_ops = []
        write_ops = []
        unknown_ops = []
        
        for op_name in entity_operations:
            is_read = is_read_operation(op_name, operation_registry)
            if is_read is True:
                read_ops.append(op_name)
            elif is_read is False:
                write_ops.append(op_name)
            else:
                unknown_ops.append(op_name)
        
        field_info['operations'] = entity_operations
        field_info['read_operations'] = read_ops
        field_info['write_operations'] = write_ops
        
        if read_ops:
            result['fields_from_read_ops'].append(field_info)
        elif write_ops:
            result['fields_from_write_ops'].append(field_info)
        else:
            result['fields_from_unknown_ops'].append(field_info)
    
    return result

def main():
    base_dir = Path(__file__).parent
    services_dir = base_dir
    
    print("=" * 80)
    print("ANALYZE FIELDS WITHOUT OPERATIONS")
    print("=" * 80)
    
    service_dirs = [d for d in services_dir.iterdir() 
                   if d.is_dir() and not d.name.startswith('.') and not d.name.startswith('_')
                   and (d / 'direct_vars.json').exists()]
    
    service_dirs.sort()
    
    print(f"\nAnalyzing {len(service_dirs)} services...")
    print("-" * 80)
    
    all_results = []
    for service_dir in service_dirs:
        result = analyze_service(service_dir)
        all_results.append(result)
    
    # Calculate totals
    total_without_ops = sum(len(r['fields_without_operations']) for r in all_results)
    total_in_di = sum(len(r['fields_in_dependency_index']) for r in all_results)
    total_not_in_di = sum(len(r['fields_not_in_dependency_index']) for r in all_results)
    total_from_read = sum(len(r['fields_from_read_ops']) for r in all_results)
    total_from_write = sum(len(r['fields_from_write_ops']) for r in all_results)
    total_unknown = sum(len(r['fields_from_unknown_ops']) for r in all_results)
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"\nTotal fields without operations: {total_without_ops:,}")
    print(f"  In dependency_index.json: {total_in_di:,} ({total_in_di/total_without_ops*100:.1f}%)")
    print(f"  NOT in dependency_index.json: {total_not_in_di:,} ({total_not_in_di/total_without_ops*100:.1f}%)")
    print()
    print(f"Of fields IN dependency_index.json:")
    print(f"  From READ operations: {total_from_read:,} ({total_from_read/total_in_di*100:.1f}%) ✅ KEEP")
    print(f"  From WRITE operations: {total_from_write:,} ({total_from_write/total_in_di*100:.1f}%) ❌ REMOVE")
    print(f"  Unknown operations: {total_unknown:,} ({total_unknown/total_in_di*100:.1f}%) ⚠️ REVIEW")
    
    # Recommendations
    print("\n" + "=" * 80)
    print("RECOMMENDATIONS")
    print("=" * 80)
    print(f"\n✅ KEEP: {total_from_read:,} fields (from read operations)")
    print(f"   - These fields are produced by read operations")
    print(f"   - They should have operations added to their definitions")
    print()
    print(f"❌ REMOVE: {total_from_write:,} fields (from write operations)")
    print(f"   - These fields are produced by write operations")
    print(f"   - Not needed for CSPM read-only use cases")
    print()
    print(f"⚠️  REVIEW: {total_not_in_di + total_unknown:,} fields")
    print(f"   - {total_not_in_di:,} not in dependency_index.json")
    print(f"   - {total_unknown:,} unknown operations")
    
    # Services with most write operation fields
    write_heavy = [(r['service'], len(r['fields_from_write_ops'])) 
                   for r in all_results if r['fields_from_write_ops']]
    write_heavy.sort(key=lambda x: x[1], reverse=True)
    
    if write_heavy:
        print(f"\nTop 20 services with fields from WRITE operations (should be removed):")
        print("-" * 80)
        for service, count in write_heavy[:20]:
            print(f"  {service:40} {count:>6} fields")
    
    # Services with most read operation fields (missing operations list)
    read_heavy = [(r['service'], len(r['fields_from_read_ops'])) 
                  for r in all_results if r['fields_from_read_ops']]
    read_heavy.sort(key=lambda x: x[1], reverse=True)
    
    if read_heavy:
        print(f"\nTop 20 services with fields from READ operations (should keep, add operations):")
        print("-" * 80)
        for service, count in read_heavy[:20]:
            print(f"  {service:40} {count:>6} fields")
    
    # Sample fields from read ops
    print(f"\n" + "=" * 80)
    print("SAMPLE FIELDS FROM READ OPERATIONS (Should Keep)")
    print("=" * 80)
    sample_count = 0
    for result in all_results:
        if result['fields_from_read_ops'] and sample_count < 10:
            for field in result['fields_from_read_ops'][:2]:
                print(f"\nService: {result['service']}")
                print(f"  Field: {field['field_name']}")
                print(f"  Entity: {field['dependency_index_entity']}")
                print(f"  Read Operations: {', '.join(field['read_operations'][:3])}")
                sample_count += 1
                if sample_count >= 10:
                    break
    
    # Sample fields from write ops
    print(f"\n" + "=" * 80)
    print("SAMPLE FIELDS FROM WRITE OPERATIONS (Should Remove)")
    print("=" * 80)
    sample_count = 0
    for result in all_results:
        if result['fields_from_write_ops'] and sample_count < 10:
            for field in result['fields_from_write_ops'][:2]:
                print(f"\nService: {result['service']}")
                print(f"  Field: {field['field_name']}")
                print(f"  Entity: {field['dependency_index_entity']}")
                print(f"  Write Operations: {', '.join(field['write_operations'][:3])}")
                sample_count += 1
                if sample_count >= 10:
                    break
    
    # Save detailed report
    report_path = base_dir / 'fields_without_operations_analysis.json'
    with open(report_path, 'w') as f:
        json.dump({
            'summary': {
                'total_without_operations': total_without_ops,
                'in_dependency_index': total_in_di,
                'not_in_dependency_index': total_not_in_di,
                'from_read_operations': total_from_read,
                'from_write_operations': total_from_write,
                'unknown_operations': total_unknown
            },
            'services': {
                r['service']: {
                    'total_without_operations': len(r['fields_without_operations']),
                    'in_dependency_index': len(r['fields_in_dependency_index']),
                    'from_read_operations': len(r['fields_from_read_ops']),
                    'from_write_operations': len(r['fields_from_write_ops']),
                    'fields_from_read_ops': [
                        {
                            'field_name': f['field_name'],
                            'dependency_index_entity': f['dependency_index_entity'],
                            'read_operations': f['read_operations']
                        }
                        for f in r['fields_from_read_ops']
                    ],
                    'fields_from_write_ops': [
                        {
                            'field_name': f['field_name'],
                            'dependency_index_entity': f['dependency_index_entity'],
                            'write_operations': f['write_operations']
                        }
                        for f in r['fields_from_write_ops']
                    ]
                }
                for r in all_results
            }
        }, f, indent=2)
    
    print(f"\nDetailed report written to: {report_path}")
    
    return all_results

if __name__ == '__main__':
    main()

