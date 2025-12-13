"""
Standardize for_each Syntax

This script updates ALL YAML files to use simplified for_each syntax:
- Removes redundant 'as' and 'item' fields
- Converts to simple string format
- Updates all condition variables to use 'item'

Before:
  for_each:
    discovery: aws.s3.buckets
    as: bucket
    item: bucket
  conditions:
    var: bucket.encryption

After:
  for_each: aws.s3.buckets
  conditions:
    var: item.encryption

Usage:
    python3 standardize_for_each.py
    
Options:
    --dry-run: Preview changes without modifying files
    --service: Process only specific service
"""

import os
import yaml
import re
import argparse
from pathlib import Path


def update_for_each_in_check(check):
    """
    Update for_each syntax in a check
    
    Returns: (updated_check, old_var_name, changes_made)
    """
    changes_made = False
    old_var_name = 'item'
    
    for_each = check.get('for_each')
    
    if for_each and isinstance(for_each, dict):
        # Extract discovery ID
        discovery_id = for_each.get('discovery')
        old_var_name = for_each.get('as', 'item')
        
        if discovery_id:
            # Simplify to just the discovery ID string
            check['for_each'] = discovery_id
            changes_made = True
    
    return check, old_var_name, changes_made


def update_condition_variables(condition, old_var_name, new_var_name='item'):
    """
    Recursively update variable names in conditions
    
    Example: bucket.encryption → item.encryption
    """
    if not condition:
        return condition, False
    
    changes_made = False
    
    if isinstance(condition, dict):
        # Handle 'all' and 'any'
        if 'all' in condition:
            updated_all = []
            for sub_cond in condition['all']:
                updated, changed = update_condition_variables(sub_cond, old_var_name, new_var_name)
                updated_all.append(updated)
                changes_made = changes_made or changed
            condition['all'] = updated_all
        
        elif 'any' in condition:
            updated_any = []
            for sub_cond in condition['any']:
                updated, changed = update_condition_variables(sub_cond, old_var_name, new_var_name)
                updated_any.append(updated)
                changes_made = changes_made or changed
            condition['any'] = updated_any
        
        else:
            # Single condition with 'var'
            var = condition.get('var')
            if var and isinstance(var, str):
                # Check if it starts with old variable name
                if var.startswith(f'{old_var_name}.'):
                    # Replace old var name with new var name
                    new_var = var.replace(f'{old_var_name}.', f'{new_var_name}.', 1)
                    condition['var'] = new_var
                    changes_made = True
    
    return condition, changes_made


def standardize_yaml_file(yaml_path, dry_run=False):
    """
    Standardize for_each syntax in a YAML file
    
    Returns: (success, changes_made)
    """
    print(f"\nProcessing: {yaml_path}")
    
    # Load YAML
    try:
        with open(yaml_path, 'r') as f:
            content = f.read()
            rules = yaml.safe_load(content)
    except Exception as e:
        print(f"  ❌ Error loading YAML: {e}")
        return False, False
    
    if not rules or 'checks' not in rules:
        print(f"  ⚠️  No checks found, skipping")
        return True, False
    
    service_name = rules.get('service', 'unknown')
    total_changes = 0
    
    # Process each check
    updated_checks = []
    
    for check in rules['checks']:
        rule_id = check.get('rule_id', 'unknown')
        
        # Update for_each
        updated_check, old_var_name, for_each_changed = update_for_each_in_check(check)
        
        # Update conditions to use 'item' instead of old variable name
        conditions_changed = False
        if 'conditions' in updated_check and old_var_name != 'item':
            updated_check['conditions'], conditions_changed = update_condition_variables(
                updated_check['conditions'],
                old_var_name,
                'item'
            )
        
        if for_each_changed or conditions_changed:
            total_changes += 1
            print(f"  ✓ Updated: {rule_id}")
            if for_each_changed:
                print(f"    - Simplified for_each")
            if conditions_changed:
                print(f"    - Changed '{old_var_name}.*' → 'item.*' in conditions")
        
        updated_checks.append(updated_check)
    
    rules['checks'] = updated_checks
    
    if total_changes == 0:
        print(f"  ℹ️  No changes needed")
        return True, False
    
    print(f"  📝 Total checks updated: {total_changes}")
    
    if dry_run:
        print(f"  [DRY RUN] Would save changes")
        return True, True
    
    # Write updated YAML
    try:
        with open(yaml_path, 'w') as f:
            # Write header comment
            f.write(f'# {service_name.upper()} Service - Logic Only\n')
            f.write(f'# Metadata (titles, severity, descriptions) in: metadata/checks/{service_name}_metadata.yaml\n\n')
            yaml.dump(rules, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        print(f"  ✅ Saved: {yaml_path}")
        return True, True
        
    except Exception as e:
        print(f"  ❌ Error writing YAML: {e}")
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
        
        # Find main YAML files (not backup or corrected files)
        for yaml_file in rules_dir.glob('*.yaml'):
            # Skip backup and temporary files
            if any(skip in yaml_file.name for skip in ['_corrected', '_manual', '_generated', '.old', '_backup']):
                continue
            yaml_files.append(str(yaml_file))
    
    return sorted(yaml_files)


def main():
    parser = argparse.ArgumentParser(description='Standardize for_each syntax in all YAML files')
    parser.add_argument('--dry-run', action='store_true',
                       help='Preview changes without modifying files')
    parser.add_argument('--service', type=str,
                       help='Process only specific service (e.g., s3, ec2)')
    parser.add_argument('--services-dir', type=str, default='services',
                       help='Path to services directory')
    
    args = parser.parse_args()
    
    services_dir = args.services_dir
    if not os.path.exists(services_dir):
        print(f"❌ Services directory not found: {services_dir}")
        return 1
    
    # Find all YAML files
    yaml_files = find_all_yaml_files(services_dir)
    
    if not yaml_files:
        print(f"❌ No YAML files found in {services_dir}")
        return 1
    
    # Filter by service if specified
    if args.service:
        yaml_files = [f for f in yaml_files if args.service in f]
        if not yaml_files:
            print(f"❌ No YAML files found for service: {args.service}")
            return 1
    
    print("="*80)
    print("STANDARDIZE FOR_EACH SYNTAX")
    print("="*80)
    print(f"\nFound {len(yaml_files)} YAML files to process")
    
    if args.dry_run:
        print("\n⚠️  DRY RUN MODE - No files will be modified")
    
    # Process each file
    results = {
        'success': 0,
        'failed': 0,
        'no_changes': 0,
        'errors': []
    }
    
    for yaml_file in yaml_files:
        success, changes_made = standardize_yaml_file(yaml_file, args.dry_run)
        
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
        print(f"\n✅ All for_each syntax standardized!")
        print(f"\nChanges made:")
        print(f"  - Simplified 'for_each' to string format")
        print(f"  - Removed redundant 'as' and 'item' fields")
        print(f"  - Updated all condition variables to use 'item'")
    
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

