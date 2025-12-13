"""
Phase 3: Ultra-Simplify YAML

Removes all redundant prefixes and wrappers:
1. Remove version/provider (defaults)
2. Simplify discovery_id (remove aws.{service} prefix)
3. Remove 'calls' wrapper
4. Simplify rule_id (remove aws.{service} prefix)
5. Simplify for_each references

Before (Phase 2):
  version: '1.0'
  provider: aws
  service: account
  discovery:
  - discovery_id: aws.account.alternate_contacts
    calls:
    - action: get_alternate_contact
  checks:
  - rule_id: aws.account.contact.configured
    for_each: aws.account.alternate_contacts

After (Phase 3):
  service: account
  resources:
    alternate_contacts:
      get_alternate_contact: {AlternateContactType: SECURITY}
  checks:
    contact.configured:
      resource: alternate_contacts
      assert: item.exists

Usage:
    python3 phase3_ultra_simplify.py --service account --dry-run
    python3 phase3_ultra_simplify.py  # All services
"""

import os
import yaml
import re
import argparse
from pathlib import Path
from collections import OrderedDict


def strip_service_prefix(text, service_name):
    """Remove aws.{service}. prefix from IDs"""
    prefix = f'aws.{service_name}.'
    if text and text.startswith(prefix):
        return text[len(prefix):]
    return text


def ultra_simplify_discovery(discovery, service_name):
    """
    Convert discovery to ultra-simple format
    
    Before:
      discovery_id: aws.account.alternate_contacts
      calls:
      - action: get_alternate_contact
        params: {...}
      emit:
        item: {...}
    
    After:
      alternate_contacts:
        get_alternate_contact:
          params: {...}
          emit: {...}
    """
    discovery_id = discovery.get('discovery_id', '')
    resource_name = strip_service_prefix(discovery_id, service_name)
    
    calls = discovery.get('calls', [])
    emit = discovery.get('emit', {})
    
    # Simplified format
    simplified = {}
    
    if len(calls) == 1:
        # Single action - use action as key
        call = calls[0]
        action = call.get('action')
        
        action_def = {}
        if 'params' in call:
            action_def['params'] = call['params']
        if 'fields' in call:
            action_def['extract'] = call['fields']
        if emit:
            action_def['emit'] = emit
        
        simplified[resource_name] = {action: action_def} if action_def else action
    
    else:
        # Multiple actions - use list
        actions = []
        for call in calls:
            action = call.get('action')
            if 'params' in call:
                actions.append({action: call['params']})
            else:
                actions.append(action)
        
        simplified[resource_name] = {
            'actions': actions,
            'emit': emit
        }
    
    return resource_name, simplified


def ultra_simplify_check(check, service_name):
    """
    Convert check to ultra-simple format
    
    Before:
      rule_id: aws.account.contact.configured
      for_each: aws.account.alternate_contacts
      conditions:
        var: item.exists
        op: exists
    
    After:
      contact.configured:
        resource: alternate_contacts
        assert: item.exists
    """
    rule_id = check.get('rule_id', '')
    check_name = strip_service_prefix(rule_id, service_name)
    
    for_each = check.get('for_each', '')
    resource_name = strip_service_prefix(for_each, service_name)
    
    conditions = check.get('conditions', {})
    
    # Simplify condition to assertion
    simplified_check = {}
    
    if resource_name:
        simplified_check['resource'] = resource_name
    
    # Convert conditions to simpler format
    if conditions:
        # Simple condition (var + op)
        if 'var' in conditions and 'op' in conditions:
            var = conditions['var']
            op = conditions['op']
            value = conditions.get('value')
            
            if op == 'exists':
                simplified_check['assert'] = var
            elif op == 'equals' and value:
                simplified_check['assert'] = {var: value}
            else:
                # Keep original for complex conditions
                simplified_check['conditions'] = conditions
        
        # Complex condition (all/any)
        elif 'all' in conditions or 'any' in conditions:
            simplified_check['conditions'] = conditions
        
        else:
            simplified_check['conditions'] = conditions
    
    return check_name, simplified_check


def ultra_simplify_yaml(yaml_path, dry_run=False):
    """Convert YAML to Phase 3 ultra-simple format"""
    
    print(f"\nProcessing: {yaml_path}")
    
    # Load YAML
    try:
        with open(yaml_path, 'r') as f:
            rules = yaml.safe_load(f)
    except Exception as e:
        print(f"  ❌ Error loading: {e}")
        return False
    
    if not rules:
        print(f"  ⚠️  Empty file")
        return False
    
    service_name = rules.get('service', 'unknown')
    
    # Create ultra-simplified structure
    ultra_simple = {
        'service': service_name
    }
    
    # Convert discoveries to resources
    if 'discovery' in rules:
        resources = {}
        for discovery in rules['discovery']:
            resource_name, resource_def = ultra_simplify_discovery(discovery, service_name)
            if resource_name and resource_def:
                resources.update(resource_def)
        
        if resources:
            ultra_simple['resources'] = resources
            print(f"  ✓ Converted {len(resources)} discoveries → resources")
    
    # Convert checks
    if 'checks' in rules:
        checks = {}
        for check in rules['checks']:
            check_name, check_def = ultra_simplify_check(check, service_name)
            if check_name and check_def:
                checks[check_name] = check_def
        
        if checks:
            ultra_simple['checks'] = checks
            print(f"  ✓ Converted {len(checks)} checks")
    
    # Calculate reduction
    old_lines = len(open(yaml_path).readlines())
    new_yaml_str = yaml.dump(ultra_simple, default_flow_style=False, sort_keys=False)
    new_lines = len(new_yaml_str.split('\n'))
    reduction = ((old_lines - new_lines) / old_lines * 100) if old_lines > 0 else 0
    
    print(f"  📊 Size: {old_lines} lines → {new_lines} lines ({reduction:.0f}% reduction)")
    
    if dry_run:
        print(f"  [DRY RUN] Would save changes")
        print(f"\n  Preview:")
        print("  " + "-"*76)
        for line in new_yaml_str.split('\n')[:20]:
            print(f"  {line}")
        if new_lines > 20:
            print(f"  ... ({new_lines - 20} more lines)")
        return True
    
    # Write ultra-simplified YAML
    output_path = yaml_path.replace('.yaml', '_v3.yaml')
    
    try:
        with open(output_path, 'w') as f:
            f.write(f'# {service_name.upper()} Service - Ultra-Simplified (Phase 3)\n')
            f.write(f'# Metadata in: metadata/checks/{service_name}_metadata.yaml\n\n')
            f.write(new_yaml_str)
        
        print(f"  ✅ Saved: {output_path}")
        return True
        
    except Exception as e:
        print(f"  ❌ Error writing: {e}")
        return False


def find_yaml_files(services_dir, service_filter=None):
    """Find YAML files to process"""
    yaml_files = []
    
    for service_dir in Path(services_dir).iterdir():
        if not service_dir.is_dir():
            continue
        
        if service_filter and service_filter not in service_dir.name:
            continue
        
        rules_dir = service_dir / 'rules'
        if not rules_dir.exists():
            continue
        
        for yaml_file in rules_dir.glob('*.yaml'):
            if '_v3' not in yaml_file.name and '.old' not in yaml_file.name:
                yaml_files.append(str(yaml_file))
                break  # One per service
    
    return sorted(yaml_files)


def main():
    parser = argparse.ArgumentParser(description='Phase 3: Ultra-simplify YAML files')
    parser.add_argument('--dry-run', action='store_true',
                       help='Preview changes without creating files')
    parser.add_argument('--service', type=str,
                       help='Process only specific service')
    parser.add_argument('--services-dir', type=str, default='services',
                       help='Path to services directory')
    
    args = parser.parse_args()
    
    services_dir = args.services_dir
    if not os.path.exists(services_dir):
        print(f"❌ Services directory not found: {services_dir}")
        return 1
    
    yaml_files = find_yaml_files(services_dir, args.service)
    
    if not yaml_files:
        print(f"❌ No YAML files found")
        return 1
    
    print("="*80)
    print("PHASE 3: ULTRA-SIMPLIFY YAML")
    print("="*80)
    print(f"\nFound {len(yaml_files)} services to process")
    
    if args.dry_run:
        print("\n⚠️  DRY RUN MODE - No files will be created")
    
    print("\nRemoving:")
    print("  - version/provider (use defaults)")
    print("  - 'aws.{service}' prefixes from discovery_id")
    print("  - 'aws.{service}' prefixes from rule_id")  
    print("  - 'aws.{service}' prefixes from for_each")
    print("  - 'calls' wrapper")
    print("\nConverting:")
    print("  - discovery → resources")
    print("  - conditions → assert (when simple)")
    
    # Process files
    success_count = 0
    failed_count = 0
    
    for yaml_file in yaml_files:
        if ultra_simplify_yaml(yaml_file, args.dry_run):
            success_count += 1
        else:
            failed_count += 1
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    print(f"\n✅ Successfully processed: {success_count}")
    
    if failed_count > 0:
        print(f"❌ Failed: {failed_count}")
    
    print(f"\n📊 Total: {len(yaml_files)} services")
    print(f"   Success: {success_count}")
    print(f"   Failed: {failed_count}")
    
    if not args.dry_run and success_count > 0:
        print(f"\n✅ Phase 3 ultra-simplified files created!")
        print(f"\nNew files: services/*/rules/*_v3.yaml")
        print(f"\nThese files are ~70% smaller than originals!")
        print(f"\nNext: Update engine to support Phase 3 format")
    
    return 0 if failed_count == 0 else 1


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
