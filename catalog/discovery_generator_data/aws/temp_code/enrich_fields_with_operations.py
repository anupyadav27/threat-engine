#!/usr/bin/env python3
"""
Enrich fields in direct_vars.json that don't have operations listed.
Adds operations, discovery_id, and other fields based on dependency_index.json and operation_registry.json.
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
        return None
    kind = op_data.get('kind', '')
    return kind.startswith('read_')

def get_read_operations_for_entity(entity_name, dependency_index, operation_registry):
    """Get all READ operations that produce an entity."""
    entity_paths = dependency_index.get('entity_paths', {})
    entity_aliases = operation_registry.get('entity_aliases', {})
    
    # Resolve entity through aliases
    actual_entity = entity_aliases.get(entity_name, entity_name)
    
    read_operations = []
    operation_details = {}
    
    # Check both actual entity and original entity name
    entities_to_check = [actual_entity]
    if entity_name != actual_entity:
        entities_to_check.append(entity_name)
    
    for check_entity in entities_to_check:
        if check_entity in entity_paths:
            entries = entity_paths[check_entity]
            for entry in entries:
                operations = entry.get('operations', [])
                for op_name in operations:
                    if is_read_operation(op_name, operation_registry):
                        if op_name not in read_operations:
                            read_operations.append(op_name)
                            # Get operation details
                            ops_dict = operation_registry.get('operations', {})
                            op_data = ops_dict.get(op_name, {})
                            operation_details[op_name] = {
                                'sdk': op_data.get('sdk', {}),
                                'produces': op_data.get('produces', [])
                            }
    
    return read_operations, operation_details

def generate_discovery_id(service, operation_name):
    """Generate discovery_id from operation name."""
    # Convert operation name to snake_case
    import re
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', operation_name)
    discovery_name = re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()
    return f"aws.{service}.{discovery_name}"

def find_main_output_field(operation_name, operation_details):
    """Try to find main_output_field from operation produces."""
    if operation_name not in operation_details:
        return None
    
    produces = operation_details[operation_name].get('produces', [])
    for produce_item in produces:
        if isinstance(produce_item, dict):
            source = produce_item.get('source')
            path = produce_item.get('path', '')
            # If source is 'output', this is likely the main output field
            if source == 'output' and path:
                # For list operations, remove []
                return path.replace('[]', '')
    
    return None

def enrich_service(service_dir, backup=True):
    """Enrich fields without operations for a service."""
    service_path = Path(service_dir)
    service_name = service_path.name
    
    direct_vars_path = service_path / 'direct_vars.json'
    dependency_index_path = service_path / 'dependency_index.json'
    operation_registry_path = service_path / 'operation_registry.json'
    
    result = {
        'service': service_name,
        'fields_enriched': 0,
        'fields_skipped': 0,
        'operations_added': 0,
        'discovery_ids_added': 0,
        'main_output_fields_added': 0,
        'status': 'SKIPPED',
        'errors': []
    }
    
    if not direct_vars_path.exists():
        result['errors'].append('Missing direct_vars.json')
        return result
    
    if not dependency_index_path.exists() or not operation_registry_path.exists():
        result['errors'].append('Missing dependency_index.json or operation_registry.json')
        return result
    
    direct_vars = load_json_file(direct_vars_path)
    dependency_index = load_json_file(dependency_index_path)
    operation_registry = load_json_file(operation_registry_path)
    
    if not direct_vars or not dependency_index or not operation_registry:
        result['errors'].append('Cannot parse JSON files')
        return result
    
    # Create backup if requested
    if backup:
        backup_path = service_path / 'direct_vars.json.enrich_backup'
        if not backup_path.exists():
            shutil.copy2(direct_vars_path, backup_path)
    
    # Track changes
    changes_made = False
    
    # Process fields
    if 'fields' in direct_vars:
        for field_name, field_data in direct_vars['fields'].items():
            if not isinstance(field_data, dict):
                continue
            
            operations = field_data.get('operations', [])
            if operations:  # Skip fields that already have operations
                continue
            
            dependency_index_entity = field_data.get('dependency_index_entity')
            if not dependency_index_entity:
                result['fields_skipped'] += 1
                continue
            
            # Get read operations for this entity
            read_ops, op_details = get_read_operations_for_entity(
                dependency_index_entity, dependency_index, operation_registry
            )
            
            if not read_ops:
                result['fields_skipped'] += 1
                continue
            
            # Add operations
            field_data['operations'] = read_ops
            result['operations_added'] += len(read_ops)
            changes_made = True
            
            # Add discovery_id if missing (use first operation)
            if 'discovery_id' not in field_data and read_ops:
                first_op = read_ops[0]
                field_data['discovery_id'] = generate_discovery_id(service_name, first_op)
                result['discovery_ids_added'] += 1
            
            # Try to add main_output_field if missing
            if 'main_output_field' not in field_data and read_ops:
                first_op = read_ops[0]
                main_output = find_main_output_field(first_op, op_details)
                if main_output:
                    field_data['main_output_field'] = main_output
                    result['main_output_fields_added'] += 1
            
            result['fields_enriched'] += 1
    
    # Process field_mappings
    if 'field_mappings' in direct_vars:
        for field_name, field_data in direct_vars['field_mappings'].items():
            if not isinstance(field_data, dict):
                continue
            
            operations = field_data.get('operations', [])
            if operations:  # Skip fields that already have operations
                continue
            
            dependency_index_entity = field_data.get('dependency_index_entity')
            if not dependency_index_entity:
                result['fields_skipped'] += 1
                continue
            
            # Get read operations for this entity
            read_ops, op_details = get_read_operations_for_entity(
                dependency_index_entity, dependency_index, operation_registry
            )
            
            if not read_ops:
                result['fields_skipped'] += 1
                continue
            
            # Add operations
            field_data['operations'] = read_ops
            result['operations_added'] += len(read_ops)
            changes_made = True
            
            # Add discovery_id if missing (use first operation)
            if 'discovery_id' not in field_data and read_ops:
                first_op = read_ops[0]
                field_data['discovery_id'] = generate_discovery_id(service_name, first_op)
                result['discovery_ids_added'] += 1
            
            # Try to add main_output_field if missing
            if 'main_output_field' not in field_data and read_ops:
                first_op = read_ops[0]
                main_output = find_main_output_field(first_op, op_details)
                if main_output:
                    field_data['main_output_field'] = main_output
                    result['main_output_fields_added'] += 1
            
            result['fields_enriched'] += 1
    
    # Save if changes were made
    if changes_made:
        save_json_file(direct_vars_path, direct_vars)
        result['status'] = 'SUCCESS'
    else:
        result['status'] = 'NO_CHANGES'
    
    return result

def main():
    import sys
    
    base_dir = Path(__file__).parent
    services_dir = base_dir
    
    # Check for --dry-run flag
    dry_run = '--dry-run' in sys.argv
    no_backup = '--no-backup' in sys.argv
    
    print("=" * 80)
    print("ENRICH FIELDS WITH OPERATIONS")
    print("=" * 80)
    
    if dry_run:
        print("\n🔍 DRY RUN MODE - No files will be modified")
    else:
        if not no_backup:
            print("\n📦 Backups will be created (.enrich_backup files)")
        else:
            print("\n⚠️  NO BACKUP MODE - Backups will NOT be created")
    
    # Get all service directories
    service_dirs = [d for d in services_dir.iterdir() 
                   if d.is_dir() and not d.name.startswith('.') and not d.name.startswith('_')
                   and (d / 'direct_vars.json').exists()]
    
    service_dirs.sort()
    
    print(f"\nFound {len(service_dirs)} service directories")
    
    if dry_run:
        print("Dry run - analyzing what would be enriched...")
        print("-" * 80)
    else:
        print("Enriching fields with operations...")
        print("-" * 80)
    
    results = []
    for service_dir in service_dirs:
        if dry_run:
            result = enrich_service(service_dir, backup=False)
            result['status'] = 'DRY_RUN'
        else:
            result = enrich_service(service_dir, backup=not no_backup)
        
        results.append(result)
        
        if result['fields_enriched'] > 0:
            print(f"{result['service']}: {result['fields_enriched']} fields enriched, {result['operations_added']} operations added")
    
    # Summary
    total_enriched = sum(r['fields_enriched'] for r in results)
    total_operations = sum(r['operations_added'] for r in results)
    total_discovery_ids = sum(r['discovery_ids_added'] for r in results)
    total_main_outputs = sum(r['main_output_fields_added'] for r in results)
    services_modified = sum(1 for r in results if r['status'] == 'SUCCESS')
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"\nFields enriched: {total_enriched}")
    print(f"Operations added: {total_operations}")
    print(f"Discovery IDs added: {total_discovery_ids}")
    print(f"Main output fields added: {total_main_outputs}")
    
    if not dry_run:
        print(f"\nServices modified: {services_modified}")
        if not no_backup:
            print("💡 Backups saved as direct_vars.json.enrich_backup")
    else:
        print("\n💡 Run without --dry-run to apply changes")
        if not no_backup:
            print("💡 Use --no-backup to skip creating backup files")
    
    return results

if __name__ == '__main__':
    main()

