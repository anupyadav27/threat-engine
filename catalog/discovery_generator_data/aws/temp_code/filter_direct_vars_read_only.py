#!/usr/bin/env python3
"""
Filter direct_vars.json to only include fields from READ operations.

For CSPM use cases, we only need read-only operations.
This script creates filtered versions of direct_vars.json files.
"""

import json
import shutil
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

def is_read_operation(op_name, operation_registry):
    """Check if an operation is a read operation."""
    ops_dict = operation_registry.get('operations', {})
    op_data = ops_dict.get(op_name)
    if not op_data:
        return None  # Unknown operation
    kind = op_data.get('kind', '')
    return kind.startswith('read_')

def filter_direct_vars_to_read_only(service_dir, backup=True):
    """Filter direct_vars.json to only include fields from read operations."""
    service_path = Path(service_dir)
    service_name = service_path.name
    
    direct_vars_path = service_path / 'direct_vars.json'
    operation_registry_path = service_path / 'operation_registry.json'
    dependency_index_path = service_path / 'dependency_index.json'
    
    result = {
        'service': service_name,
        'original_fields': 0,
        'filtered_fields': 0,
        'removed_fields': 0,
        'status': 'SKIPPED',
        'errors': []
    }
    
    if not direct_vars_path.exists():
        result['errors'].append('Missing direct_vars.json')
        return result
    
    if not operation_registry_path.exists():
        result['errors'].append('Missing operation_registry.json')
        return result
    
    direct_vars = load_json_file(direct_vars_path)
    operation_registry = load_json_file(operation_registry_path)
    dependency_index = load_json_file(dependency_index_path)  # Optional - for fields without operations
    
    if not direct_vars:
        result['errors'].append('Cannot parse direct_vars.json')
        return result
    
    if not operation_registry:
        result['errors'].append('Cannot parse operation_registry.json')
        return result
    
    # dependency_index is optional - use empty dict if not available
    if not dependency_index:
        dependency_index = {}
    
    # Create backup if requested
    if backup:
        backup_path = service_path / 'direct_vars.json.backup'
        if not backup_path.exists():
            shutil.copy2(direct_vars_path, backup_path)
    
    # Create filtered copy
    filtered_direct_vars = {
        'service': direct_vars.get('service'),
        'seed_from_list': direct_vars.get('seed_from_list', []),
        'enriched_from_get_describe': direct_vars.get('enriched_from_get_describe', []),
        'fields': {},
        'field_mappings': {}
    }
    
    # Copy source if it exists
    if 'source' in direct_vars:
        filtered_direct_vars['source'] = direct_vars['source']
    
    # Filter fields
    original_fields = {}
    if 'fields' in direct_vars:
        original_fields.update(direct_vars['fields'])
    if 'field_mappings' in direct_vars:
        original_fields.update(direct_vars['field_mappings'])
    
    result['original_fields'] = len(original_fields)
    
    # Keep only fields from read operations
    for field_name, field_data in original_fields.items():
        if not isinstance(field_data, dict):
            # Keep non-dict fields (like arrays, strings)
            if 'fields' in direct_vars and field_name in direct_vars['fields']:
                filtered_direct_vars['fields'][field_name] = field_data
            elif 'field_mappings' in direct_vars and field_name in direct_vars['field_mappings']:
                filtered_direct_vars['field_mappings'][field_name] = field_data
            result['filtered_fields'] += 1
            continue
        
        operations = field_data.get('operations', [])
        
        # If no operations listed, check dependency_index.json to see if it's from read operations
        if not operations:
            dependency_index_entity = field_data.get('dependency_index_entity')
            
            if dependency_index_entity:
                # Check if entity exists in dependency_index.json
                entity_paths = dependency_index.get('entity_paths', {})
                entity_aliases = operation_registry.get('entity_aliases', {})
                
                # Resolve entity through aliases
                actual_entity = entity_aliases.get(dependency_index_entity, dependency_index_entity)
                
                # Get operations that produce this entity
                entity_operations = []
                if actual_entity in entity_paths:
                    entries = entity_paths[actual_entity]
                    for entry in entries:
                        entity_operations.extend(entry.get('operations', []))
                
                # Check if any operations are read operations
                has_read_op = False
                for op_name in entity_operations:
                    if is_read_operation(op_name, operation_registry):
                        has_read_op = True
                        break
                
                # Keep only if from read operations
                if has_read_op:
                    if 'fields' in direct_vars and field_name in direct_vars['fields']:
                        filtered_direct_vars['fields'][field_name] = field_data
                    elif 'field_mappings' in direct_vars and field_name in direct_vars['field_mappings']:
                        filtered_direct_vars['field_mappings'][field_name] = field_data
                    result['filtered_fields'] += 1
                else:
                    result['removed_fields'] += 1
            else:
                # No dependency_index_entity - keep it (assume it's valid)
                if 'fields' in direct_vars and field_name in direct_vars['fields']:
                    filtered_direct_vars['fields'][field_name] = field_data
                elif 'field_mappings' in direct_vars and field_name in direct_vars['field_mappings']:
                    filtered_direct_vars['field_mappings'][field_name] = field_data
                result['filtered_fields'] += 1
            continue
        
        # Check if all operations are read operations
        all_read = True
        has_read = False
        
        for op_name in operations:
            is_read = is_read_operation(op_name, operation_registry)
            if is_read is True:
                has_read = True
            elif is_read is False:
                all_read = False
                break
        
        # Keep field if it has at least one read operation
        if has_read and all_read:
            if 'fields' in direct_vars and field_name in direct_vars['fields']:
                filtered_direct_vars['fields'][field_name] = field_data
            elif 'field_mappings' in direct_vars and field_name in direct_vars['field_mappings']:
                filtered_direct_vars['field_mappings'][field_name] = field_data
            result['filtered_fields'] += 1
        else:
            result['removed_fields'] += 1
    
    # Save filtered version
    save_json_file(direct_vars_path, filtered_direct_vars)
    
    result['status'] = 'SUCCESS'
    
    return result

def main():
    import sys
    
    base_dir = Path(__file__).parent
    services_dir = base_dir
    
    # Check for --dry-run flag
    dry_run = '--dry-run' in sys.argv
    no_backup = '--no-backup' in sys.argv
    
    print("=" * 80)
    print("FILTER DIRECT_VARS TO READ-ONLY OPERATIONS")
    print("=" * 80)
    
    if dry_run:
        print("\n🔍 DRY RUN MODE - No files will be modified")
    else:
        if not no_backup:
            print("\n📦 Backups will be created (.backup files)")
        else:
            print("\n⚠️  NO BACKUP MODE - Backups will NOT be created")
    
    # Get all service directories
    service_dirs = [d for d in services_dir.iterdir() 
                   if d.is_dir() and not d.name.startswith('.') and not d.name.startswith('_')
                   and (d / 'direct_vars.json').exists()]
    
    service_dirs.sort()
    
    print(f"\nFound {len(service_dirs)} service directories")
    
    if dry_run:
        print("Dry run - analyzing what would be filtered...")
        print("-" * 80)
    else:
        print("Filtering direct_vars.json files...")
        print("-" * 80)
    
    results = []
    for service_dir in service_dirs:
        if dry_run:
            # In dry-run, just analyze
            result = filter_direct_vars_to_read_only(service_dir, backup=False)
            result['status'] = 'DRY_RUN'
        else:
            result = filter_direct_vars_to_read_only(service_dir, backup=not no_backup)
        
        results.append(result)
        
        if result['status'] == 'SUCCESS' or result['status'] == 'DRY_RUN':
            removed = result['removed_fields']
            if removed > 0:
                pct = removed / result['original_fields'] * 100 if result['original_fields'] > 0 else 0
                print(f"{result['service']}: Removed {removed} fields ({pct:.1f}%)")
        elif result['errors']:
            print(f"{result['service']}: ERROR - {', '.join(result['errors'])}")
    
    # Summary
    total_original = sum(r['original_fields'] for r in results)
    total_filtered = sum(r['filtered_fields'] for r in results)
    total_removed = sum(r['removed_fields'] for r in results)
    services_modified = sum(1 for r in results if r['status'] == 'SUCCESS')
    services_with_errors = sum(1 for r in results if r['errors'])
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"\nTotal Fields:")
    print(f"  Original: {total_original:,}")
    print(f"  Filtered: {total_filtered:,} ({total_filtered/total_original*100:.1f}%)")
    print(f"  Removed: {total_removed:,} ({total_removed/total_original*100:.1f}%)")
    
    if not dry_run:
        print(f"\nServices modified: {services_modified}")
    print(f"Services with errors: {services_with_errors}")
    
    if dry_run:
        print("\n💡 Run without --dry-run to apply changes")
        if not no_backup:
            print("💡 Use --no-backup to skip creating backup files")
    else:
        print("\n✅ Filtering complete!")
        if not no_backup:
            print("💡 Backups saved as direct_vars.json.backup")
    
    return results

if __name__ == '__main__':
    main()

