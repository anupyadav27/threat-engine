#!/usr/bin/env python3
"""
Analyze direct_vars.json to determine which fields come from read vs write operations.
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

def analyze_service(service_dir):
    """Analyze fields by operation type for a service."""
    service_path = Path(service_dir)
    service_name = service_path.name
    
    direct_vars_path = service_path / 'direct_vars.json'
    operation_registry_path = service_path / 'operation_registry.json'
    
    result = {
        'service': service_name,
        'total_fields': 0,
        'fields_from_read_ops': 0,
        'fields_from_write_ops': 0,
        'fields_from_unknown_ops': 0,
        'fields_with_no_operations': 0,
        'read_operations': set(),
        'write_operations': set(),
        'unknown_operations': set()
    }
    
    if not direct_vars_path.exists() or not operation_registry_path.exists():
        return result
    
    direct_vars = load_json_file(direct_vars_path)
    operation_registry = load_json_file(operation_registry_path)
    
    if not direct_vars or not operation_registry:
        return result
    
    # Extract fields
    fields_data = {}
    if 'fields' in direct_vars:
        fields_data.update(direct_vars['fields'])
    if 'field_mappings' in direct_vars:
        fields_data.update(direct_vars['field_mappings'])
    
    result['total_fields'] = len(fields_data)
    
    # Analyze each field
    for field_name, field_data in fields_data.items():
        if not isinstance(field_data, dict):
            continue
        
        operations = field_data.get('operations', [])
        if not operations:
            result['fields_with_no_operations'] += 1
            continue
        
        # Check if operations are read or write
        has_read = False
        has_write = False
        
        for op_name in operations:
            is_read = is_read_operation(op_name, operation_registry)
            
            if is_read is True:
                has_read = True
                result['read_operations'].add(op_name)
            elif is_read is False:
                has_write = True
                result['write_operations'].add(op_name)
            else:
                result['unknown_operations'].add(op_name)
        
        if has_read:
            result['fields_from_read_ops'] += 1
        elif has_write:
            result['fields_from_write_ops'] += 1
        else:
            result['fields_from_unknown_ops'] += 1
    
    # Convert sets to lists for JSON serialization
    result['read_operations'] = sorted(list(result['read_operations']))
    result['write_operations'] = sorted(list(result['write_operations']))
    result['unknown_operations'] = sorted(list(result['unknown_operations']))
    
    return result

def main():
    base_dir = Path(__file__).parent
    services_dir = base_dir
    
    print("=" * 80)
    print("ANALYZE DIRECT_VARS OPERATION TYPES")
    print("=" * 80)
    
    service_dirs = [d for d in services_dir.iterdir() 
                   if d.is_dir() and not d.name.startswith('.') and not d.name.startswith('_')
                   and (d / 'direct_vars.json').exists()]
    
    service_dirs.sort()
    
    print(f"\nAnalyzing {len(service_dirs)} services...")
    print("-" * 80)
    
    results = []
    for service_dir in service_dirs:
        result = analyze_service(service_dir)
        results.append(result)
    
    # Calculate totals
    total_fields = sum(r['total_fields'] for r in results)
    total_from_read = sum(r['fields_from_read_ops'] for r in results)
    total_from_write = sum(r['fields_from_write_ops'] for r in results)
    total_from_unknown = sum(r['fields_from_unknown_ops'] for r in results)
    total_no_ops = sum(r['fields_with_no_operations'] for r in results)
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"\nTotal Fields: {total_fields:,}")
    print(f"  From Read Operations: {total_from_read:,} ({total_from_read/total_fields*100:.1f}%)")
    print(f"  From Write Operations: {total_from_write:,} ({total_from_write/total_fields*100:.1f}%)")
    print(f"  From Unknown Operations: {total_from_unknown:,} ({total_from_unknown/total_fields*100:.1f}%)")
    print(f"  No Operations Listed: {total_no_ops:,} ({total_no_ops/total_fields*100:.1f}%)")
    
    # Services with most write operation fields
    write_heavy = [(r['service'], r['fields_from_write_ops'], r['total_fields']) 
                   for r in results if r['fields_from_write_ops'] > 0]
    write_heavy.sort(key=lambda x: x[1], reverse=True)
    
    print(f"\nTop 20 services with most write operation fields:")
    print("-" * 80)
    for service, write_count, total in write_heavy[:20]:
        pct = write_count / total * 100 if total > 0 else 0
        print(f"  {service:40} {write_count:>6} / {total:>6} ({pct:>5.1f}%)")
    
    # Save detailed report
    report_path = base_dir / 'direct_vars_operation_types_report.json'
    with open(report_path, 'w') as f:
        json.dump({
            'summary': {
                'total_fields': total_fields,
                'fields_from_read_ops': total_from_read,
                'fields_from_write_ops': total_from_write,
                'fields_from_unknown_ops': total_from_unknown,
                'fields_with_no_operations': total_no_ops
            },
            'services': {
                r['service']: {
                    'total_fields': r['total_fields'],
                    'fields_from_read_ops': r['fields_from_read_ops'],
                    'fields_from_write_ops': r['fields_from_write_ops'],
                    'fields_from_unknown_ops': r['fields_from_unknown_ops'],
                    'fields_with_no_operations': r['fields_with_no_operations'],
                    'read_operations': r['read_operations'],
                    'write_operations': r['write_operations']
                }
                for r in results
            }
        }, f, indent=2)
    
    print(f"\nDetailed report written to: {report_path}")
    
    return results

if __name__ == '__main__':
    main()

