"""
Simplify All YAML Files

This script processes ALL service YAML files and:
1. Extracts metadata (title, severity, description)
2. Creates simplified YAML (logic only)
3. Creates metadata YAML files

Usage:
    python3 simplify_all_yamls.py
    
    Options:
    --dry-run: Show what would be done without creating files
    --service: Process only specific service (e.g., --service s3)
"""

import os
import yaml
import argparse
from pathlib import Path


def extract_metadata_from_check(check):
    """Extract metadata fields from a check"""
    metadata = {}
    
    # Extract metadata fields
    if 'title' in check:
        metadata['title'] = check['title']
    if 'description' in check:
        metadata['description'] = check['description']
    if 'severity' in check:
        metadata['severity'] = check['severity']
    if 'category' in check:
        metadata['category'] = check['category']
    if 'frameworks' in check:
        metadata['frameworks'] = check['frameworks']
    if 'remediation' in check:
        metadata['remediation'] = check['remediation']
    if 'references' in check:
        metadata['references'] = check['references']
    if 'tags' in check:
        metadata['tags'] = check['tags']
    
    return metadata


def create_logic_only_check(check):
    """Create logic-only check (remove metadata)"""
    logic_check = {}
    
    # Keep only logic fields
    if 'rule_id' in check:
        logic_check['rule_id'] = check['rule_id']
    if 'for_each' in check:
        logic_check['for_each'] = check['for_each']
    if 'params' in check:
        logic_check['params'] = check['params']
    if 'conditions' in check:
        logic_check['conditions'] = check['conditions']
    if 'assertion_id' in check:
        logic_check['assertion_id'] = check['assertion_id']
    
    return logic_check


def simplify_yaml_file(yaml_path, dry_run=False):
    """
    Simplify a single YAML file
    
    Args:
        yaml_path: Path to original YAML file
        dry_run: If True, don't write files, just show what would be done
    
    Returns:
        Tuple of (simplified_yaml_path, metadata_yaml_path, success)
    """
    print(f"\nProcessing: {yaml_path}")
    
    # Load original YAML
    try:
        with open(yaml_path, 'r') as f:
            rules = yaml.safe_load(f)
    except Exception as e:
        print(f"  ❌ Error loading YAML: {e}")
        return None, None, False
    
    if not rules:
        print(f"  ⚠️  Empty YAML file")
        return None, None, False
    
    service_name = rules.get('service')
    if not service_name:
        print(f"  ⚠️  No service name found")
        return None, None, False
    
    # Extract metadata from checks
    all_metadata = {}
    simplified_checks = []
    
    if 'checks' in rules:
        print(f"  Found {len(rules['checks'])} checks")
        
        for check in rules['checks']:
            rule_id = check.get('rule_id')
            
            if not rule_id:
                print(f"  ⚠️  Check without rule_id, skipping")
                continue
            
            # Extract metadata
            metadata = extract_metadata_from_check(check)
            if metadata:
                all_metadata[rule_id] = metadata
            
            # Create logic-only check
            logic_check = create_logic_only_check(check)
            simplified_checks.append(logic_check)
    
    # Create simplified YAML (logic only)
    simplified_rules = {
        'version': rules.get('version', '1.0'),
        'provider': rules.get('provider', 'aws'),
        'service': service_name
    }
    
    if 'discovery' in rules:
        simplified_rules['discovery'] = rules['discovery']
    
    if simplified_checks:
        simplified_rules['checks'] = simplified_checks
    
    # Create metadata YAML
    metadata_yaml = {
        'version': '1.0',
        'service': service_name,
        'checks': all_metadata
    }
    
    # Determine output paths
    yaml_dir = os.path.dirname(yaml_path)
    simplified_yaml_path = os.path.join(yaml_dir, f'{service_name}_simplified.yaml')
    
    metadata_dir = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(yaml_path))),
        'metadata', 'checks'
    )
    os.makedirs(metadata_dir, exist_ok=True)
    metadata_yaml_path = os.path.join(metadata_dir, f'{service_name}_metadata.yaml')
    
    # Show summary
    print(f"  Checks with metadata: {len(all_metadata)}")
    print(f"  Simplified YAML: {simplified_yaml_path}")
    print(f"  Metadata YAML: {metadata_yaml_path}")
    
    if dry_run:
        print(f"  [DRY RUN] Would create files")
        return simplified_yaml_path, metadata_yaml_path, True
    
    # Write files
    try:
        # Write simplified YAML
        with open(simplified_yaml_path, 'w') as f:
            f.write(f'# {service_name.upper()} Service - Logic Only\n')
            f.write(f'# Metadata (titles, severity, descriptions) in: metadata/checks/{service_name}_metadata.yaml\n\n')
            yaml.dump(simplified_rules, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        
        print(f"  ✅ Created: {simplified_yaml_path}")
        
        # Write metadata YAML
        if all_metadata:
            with open(metadata_yaml_path, 'w') as f:
                f.write(f'# {service_name.upper()} Service - Check Metadata\n')
                f.write(f'# This file contains titles, descriptions, and severity for all checks\n')
                f.write(f'# The main YAML file only contains the logic\n\n')
                yaml.dump(metadata_yaml, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            
            print(f"  ✅ Created: {metadata_yaml_path}")
        else:
            print(f"  ⚠️  No metadata found, skipping metadata file")
        
        return simplified_yaml_path, metadata_yaml_path, True
        
    except Exception as e:
        print(f"  ❌ Error writing files: {e}")
        return None, None, False


def find_all_yaml_files(services_dir):
    """Find all YAML rule files"""
    yaml_files = []
    
    for service_dir in Path(services_dir).iterdir():
        if not service_dir.is_dir():
            continue
        
        rules_dir = service_dir / 'rules'
        if not rules_dir.exists():
            continue
        
        # Find YAML files (not simplified ones)
        for yaml_file in rules_dir.glob('*.yaml'):
            if '_simplified' not in yaml_file.name and '_metadata' not in yaml_file.name:
                yaml_files.append(str(yaml_file))
    
    return sorted(yaml_files)


def main():
    parser = argparse.ArgumentParser(description='Simplify all service YAML files')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Show what would be done without creating files')
    parser.add_argument('--service', type=str,
                       help='Process only specific service (e.g., s3, ec2)')
    parser.add_argument('--services-dir', type=str,
                       default='services',
                       help='Path to services directory')
    
    args = parser.parse_args()
    
    # Find all YAML files
    services_dir = args.services_dir
    if not os.path.exists(services_dir):
        print(f"❌ Services directory not found: {services_dir}")
        return 1
    
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
    print("YAML SIMPLIFICATION TOOL")
    print("="*80)
    print(f"\nFound {len(yaml_files)} YAML files to process")
    
    if args.dry_run:
        print("\n⚠️  DRY RUN MODE - No files will be created")
    
    # Process each file
    results = {
        'success': [],
        'failed': [],
        'skipped': []
    }
    
    for yaml_file in yaml_files:
        simplified_path, metadata_path, success = simplify_yaml_file(yaml_file, args.dry_run)
        
        if success:
            results['success'].append({
                'original': yaml_file,
                'simplified': simplified_path,
                'metadata': metadata_path
            })
        elif simplified_path is None:
            results['skipped'].append(yaml_file)
        else:
            results['failed'].append(yaml_file)
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    print(f"\n✅ Successfully processed: {len(results['success'])}")
    for item in results['success']:
        service = os.path.basename(os.path.dirname(os.path.dirname(item['original'])))
        print(f"  - {service}")
    
    if results['failed']:
        print(f"\n❌ Failed: {len(results['failed'])}")
        for item in results['failed']:
            print(f"  - {item}")
    
    if results['skipped']:
        print(f"\n⚠️  Skipped: {len(results['skipped'])}")
        for item in results['skipped']:
            print(f"  - {item}")
    
    print(f"\n📊 Total: {len(yaml_files)} files")
    print(f"   Success: {len(results['success'])}")
    print(f"   Failed: {len(results['failed'])}")
    print(f"   Skipped: {len(results['skipped'])}")
    
    if not args.dry_run:
        print(f"\n✅ Files created:")
        print(f"   - Simplified YAMLs in: services/*/rules/*_simplified.yaml")
        print(f"   - Metadata YAMLs in: metadata/checks/*_metadata.yaml")
    
    return 0 if not results['failed'] else 1


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
