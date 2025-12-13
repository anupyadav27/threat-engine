"""
Simplify Discovery Section

This script removes redundant fields from discovery sections:
1. Removes 'client' field when it matches service name
2. Removes 'save_as' field (engine auto-generates)
3. Removes 'on_error: continue' (now default)
4. Simplifies 'as' in emit to standard 'item'

Before:
  calls:
  - client: s3
    action: list_buckets
    save_as: bucket_list
    on_error: continue
  emit:
    items_for: bucket_list.Buckets[]
    as: bucket

After:
  calls:
  - action: list_buckets
  emit:
    items_for: list_buckets_response.Buckets[]

Usage:
    python3 simplify_discovery.py
    
Options:
    --dry-run: Preview changes
    --service: Process specific service only
"""

import os
import yaml
import re
import argparse
from pathlib import Path


def simplify_discovery_calls(discovery, service_name):
    """
    Simplify calls in a discovery block
    
    Returns: (updated_discovery, changes_made)
    """
    if 'calls' not in discovery:
        return discovery, False
    
    changes_made = False
    updated_calls = []
    
    for call in discovery['calls']:
        updated_call = dict(call)
        
        # Remove 'client' if it matches service name
        if 'client' in updated_call:
            if updated_call['client'] == service_name or updated_call['client'] == 'unknown':
                del updated_call['client']
                changes_made = True
        
        # Remove 'on_error: continue' (it's now the default)
        if 'on_error' in updated_call and updated_call['on_error'] == 'continue':
            del updated_call['on_error']
            changes_made = True
        
        # Track save_as for emit section updates
        old_save_as = call.get('save_as')
        action = call.get('action')
        
        # Remove 'save_as' (engine auto-generates as {action}_response)
        if 'save_as' in updated_call and action:
            # Store for emit section updates
            new_save_as = f'{action}_response'
            updated_call['_old_save_as'] = old_save_as
            updated_call['_new_save_as'] = new_save_as
            del updated_call['save_as']
            changes_made = True
        
        updated_calls.append(updated_call)
    
    discovery['calls'] = updated_calls
    return discovery, changes_made


def update_emit_references(emit, calls):
    """
    Update emit section to reference new save_as names
    
    Example: bucket_list[] → list_buckets_response[]
    """
    if not emit:
        return emit, False
    
    changes_made = False
    
    # Build mapping of old_save_as → new_save_as
    save_as_mapping = {}
    for call in calls:
        if '_old_save_as' in call and '_new_save_as' in call:
            save_as_mapping[call['_old_save_as']] = call['_new_save_as']
    
    if not save_as_mapping:
        return emit, False
    
    # Update items_for references
    if 'items_for' in emit:
        items_for = emit['items_for']
        for old_name, new_name in save_as_mapping.items():
            if old_name in items_for:
                emit['items_for'] = items_for.replace(old_name, new_name)
                changes_made = True
    
    # Update item template references
    if 'item' in emit and isinstance(emit['item'], dict):
        for field_name, template in emit['item'].items():
            if isinstance(template, str):
                for old_name, new_name in save_as_mapping.items():
                    if old_name in template:
                        emit['item'][field_name] = template.replace(old_name, new_name)
                        changes_made = True
    
    # Remove 'as' field (standardize to 'item')
    if 'as' in emit:
        del emit['as']
        changes_made = True
    
    return emit, changes_made


def simplify_yaml_file(yaml_path, dry_run=False):
    """Simplify discovery sections in a YAML file"""
    
    print(f"\nProcessing: {yaml_path}")
    
    # Load YAML
    try:
        with open(yaml_path, 'r') as f:
            rules = yaml.safe_load(f)
    except Exception as e:
        print(f"  ❌ Error loading: {e}")
        return False, False
    
    if not rules or 'discovery' not in rules:
        print(f"  ℹ️  No discovery section")
        return True, False
    
    service_name = rules.get('service', 'unknown')
    total_changes = 0
    
    # Process each discovery
    updated_discoveries = []
    
    for discovery in rules['discovery']:
        discovery_id = discovery.get('discovery_id', 'unknown')
        
        # Simplify calls
        updated_discovery, calls_changed = simplify_discovery_calls(discovery, service_name)
        
        # Update emit references
        if 'emit' in updated_discovery:
            updated_discovery['emit'], emit_changed = update_emit_references(
                updated_discovery['emit'],
                updated_discovery['calls']
            )
        else:
            emit_changed = False
        
        # Clean up temporary fields
        for call in updated_discovery['calls']:
            call.pop('_old_save_as', None)
            call.pop('_new_save_as', None)
        
        if calls_changed or emit_changed:
            total_changes += 1
            print(f"  ✓ Simplified: {discovery_id}")
            if calls_changed:
                print(f"    - Removed redundant fields from calls")
            if emit_changed:
                print(f"    - Updated emit section")
        
        updated_discoveries.append(updated_discovery)
    
    rules['discovery'] = updated_discoveries
    
    if total_changes == 0:
        print(f"  ℹ️  No changes needed")
        return True, False
    
    print(f"  📝 Total discoveries updated: {total_changes}")
    
    if dry_run:
        print(f"  [DRY RUN] Would save changes")
        return True, True
    
    # Write updated YAML
    try:
        with open(yaml_path, 'w') as f:
            f.write(f'# {service_name.upper()} Service - Logic Only\n')
            f.write(f'# Metadata (titles, severity, descriptions) in: metadata/checks/{service_name}_metadata.yaml\n\n')
            yaml.dump(rules, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        print(f"  ✅ Saved: {yaml_path}")
        return True, True
        
    except Exception as e:
        print(f"  ❌ Error writing: {e}")
        return False, False


def find_all_yaml_files(services_dir):
    """Find all YAML rule files"""
    yaml_files = []
    
    for service_dir in Path(services_dir).iterdir():
        if not service_dir.is_dir():
            continue
        
        rules_dir = service_dir / 'rules'
        if not rules_dir.exists():
            continue
        
        # Find YAML files
        for yaml_file in rules_dir.glob('*.yaml'):
            if '.old' not in yaml_file.name:
                yaml_files.append(str(yaml_file))
    
    return sorted(yaml_files)


def main():
    parser = argparse.ArgumentParser(description='Simplify discovery sections in YAML files')
    parser.add_argument('--dry-run', action='store_true',
                       help='Preview changes without modifying files')
    parser.add_argument('--service', type=str,
                       help='Process only specific service')
    parser.add_argument('--services-dir', type=str, default='services',
                       help='Path to services directory')
    
    args = parser.parse_args()
    
    services_dir = args.services_dir
    if not os.path.exists(services_dir):
        print(f"❌ Services directory not found: {services_dir}")
        return 1
    
    yaml_files = find_all_yaml_files(services_dir)
    
    if not yaml_files:
        print(f"❌ No YAML files found")
        return 1
    
    # Filter by service
    if args.service:
        yaml_files = [f for f in yaml_files if args.service in f]
        if not yaml_files:
            print(f"❌ No files found for service: {args.service}")
            return 1
    
    print("="*80)
    print("SIMPLIFY DISCOVERY SECTIONS")
    print("="*80)
    print(f"\nFound {len(yaml_files)} YAML files")
    
    if args.dry_run:
        print("\n⚠️  DRY RUN MODE - No changes will be made")
    
    print("\nRemoving:")
    print("  - 'client' field (when same as service)")
    print("  - 'save_as' field (auto-generated)")
    print("  - 'on_error: continue' (now default)")
    print("  - 'as' in emit (standardized to 'item')")
    
    # Process files
    results = {'success': 0, 'no_changes': 0, 'failed': 0, 'errors': []}
    
    for yaml_file in yaml_files:
        success, changes_made = simplify_yaml_file(yaml_file, args.dry_run)
        
        if success:
            if changes_made:
                results['success'] += 1
            else:
                results['no_changes'] += 1
        else:
            results['failed'] += 1
            results['errors'].append(yaml_file)
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    print(f"\n✅ Successfully updated: {results['success']}")
    print(f"ℹ️  No changes needed: {results['no_changes']}")
    
    if results['failed'] > 0:
        print(f"\n❌ Failed: {results['failed']}")
        for error in results['errors']:
            print(f"  - {error}")
    
    print(f"\n📊 Total: {len(yaml_files)} files")
    print(f"   Updated: {results['success']}")
    print(f"   No changes: {results['no_changes']}")
    print(f"   Failed: {results['failed']}")
    
    if not args.dry_run and results['success'] > 0:
        print(f"\n✅ All discovery sections simplified!")
        print(f"\nChanges made:")
        print(f"  - Removed redundant 'client' fields")
        print(f"  - Removed manual 'save_as' names (auto-generated)")
        print(f"  - Removed 'on_error: continue' (now default)")
        print(f"  - Standardized emit variable names")
    
    return 0 if results['failed'] == 0 else 1


if __name__ == '__main__':
    try:
        exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Interrupted by user")
        exit(1)
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
