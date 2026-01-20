#!/usr/bin/env python3
"""
Fix PARENT_DISCOVERY and FIELD_NAME Placeholders

This script fixes unresolved placeholders in YAML rule files:
- PARENT_DISCOVERY → actual parent discovery ID
- FIELD_NAME → actual field name from parent discovery

Usage:
    python fix_placeholders.py [--dry-run] [--service SERVICE_NAME]
"""

import os
import sys
import yaml
import re
import json
from typing import Dict, List, Optional, Tuple
from pathlib import Path


# Map services to their parent discovery and field name
# Format: {service: (parent_discovery_id, field_name)}
SERVICE_PARENT_MAPPING = {
    's3': ('aws.s3.list_buckets', 'name'),
    'apigatewayv2': ('aws.apigatewayv2.get_apis', 'api_id'),
    'budgets': ('aws.budgets.describe_budgets', 'budget_name'),
    'codeartifact': ('aws.codeartifact.list_repositories', 'repository'),
    'ebs': ('aws.ebs.describe_volumes', 'volume_id'),
    'firehose': ('aws.firehose.list_delivery_streams', 'delivery_stream_name'),
    'glacier': ('aws.glacier.list_vaults', 'vault_name'),
    'guardduty': ('aws.guardduty.list_detectors', 'detector_id'),
    'opensearch': ('aws.opensearch.list_domain_names', 'domain_name'),
    'quicksight': ('aws.quicksight.list_data_sets', 'data_set_id'),
    'sqs': ('aws.sqs.list_queues', 'queue_url'),
    'stepfunctions': ('aws.stepfunctions.list_state_machines', 'state_machine_arn'),
    'transfer': ('aws.transfer.list_servers', 'server_id'),
    'workflows': ('aws.stepfunctions.list_state_machines', 'state_machine_arn'),
}


def find_parent_discovery(yaml_data: Dict, service: str) -> Optional[Tuple[str, str]]:
    """
    Find the parent discovery and identifier field from YAML.
    
    Returns:
        (parent_discovery_id, field_name) or None
    """
    discoveries = yaml_data.get('discovery', [])
    
    # Look for independent discoveries (root discoveries - no for_each)
    independent_discoveries = [d for d in discoveries if 'for_each' not in d]
    
    if not independent_discoveries:
        return None
    
    # Use the first independent discovery as parent
    parent_disc = independent_discoveries[0]
    disc_id = parent_disc.get('discovery_id', '')
    
    # Extract field name from emit
    emit = parent_disc.get('emit', {})
    item = emit.get('item', {})
    
    # Try to extract field name from template (e.g., "{{ resource.Name }}" -> "name")
    identifier_field = None
    
    # Priority 1: Look for common identifier fields in item keys
    identifier_field_names = ['name', 'id', 'resource_id', 'arn', 'api_id', 
                              'bucket_name', 'volume_id', 'detector_id', 
                              'queue_url', 'state_machine_arn', 'server_id',
                              'domain_name', 'data_set_id', 'delivery_stream_name',
                              'vault_name', 'budget_name', 'repository']
    
    for field in identifier_field_names:
        if field in item:
            identifier_field = field
            break
    
    # Priority 2: Extract from template (e.g., "{{ resource.Name }}" -> "name")
    if not identifier_field and item:
        for field_name, template in item.items():
            if isinstance(template, str):
                # Match patterns like "{{ resource.Name }}" or "{{ item.name }}"
                match = re.search(r'(?:resource|item)\.(\w+)', template)
                if match:
                    extracted_field = match.group(1).lower()
                    # Prefer name/id fields
                    if extracted_field in ['name', 'id', 'resource_id']:
                        identifier_field = extracted_field
                        break
    
    # Priority 3: Use first field name from item
    if not identifier_field and item:
        first_field = list(item.keys())[0]
        # Extract from template if it's a template
        if isinstance(item[first_field], str) and '{{' in item[first_field]:
            match = re.search(r'(?:resource|item)\.(\w+)', item[first_field])
            if match:
                identifier_field = match.group(1).lower()
            else:
                identifier_field = first_field
        else:
            identifier_field = first_field
    
    if identifier_field:
        return (disc_id, identifier_field)
    
    return None


def fix_yaml_file(yaml_path: Path, service: str, dry_run: bool = False) -> Dict[str, int]:
    """
    Fix placeholders in a YAML file.
    
    Returns:
        Dict with counts of fixes made
    """
    fixes = {
        'parent_discovery': 0,
        'field_name': 0,
        'total': 0
    }
    
    try:
        with open(yaml_path, 'r') as f:
            content = f.read()
            yaml_data = yaml.safe_load(content)
    except Exception as e:
        print(f"  ❌ Error loading {yaml_path}: {e}")
        return fixes
    
    # Get parent discovery info
    parent_info = SERVICE_PARENT_MAPPING.get(service)
    if not parent_info:
        # Try to find it from YAML
        parent_info = find_parent_discovery(yaml_data, service)
    
    if not parent_info:
        print(f"  ⚠️  Could not determine parent discovery for {service}")
        return fixes
    
    parent_discovery_id, field_name = parent_info
    
    # Fix PARENT_DISCOVERY
    parent_pattern = f'aws\\.{service}\\.PARENT_DISCOVERY'
    if re.search(parent_pattern, content):
        new_content = re.sub(parent_pattern, parent_discovery_id, content)
        fixes['parent_discovery'] = len(re.findall(parent_pattern, content))
        content = new_content
    
    # Fix FIELD_NAME
    field_pattern = r'\{\{\s*item\.FIELD_NAME\s*\}\}'
    if re.search(field_pattern, content):
        replacement = f'{{{{ item.{field_name} }}}}'
        new_content = re.sub(field_pattern, replacement, content)
        fixes['field_name'] = len(re.findall(field_pattern, content))
        content = new_content
    
    fixes['total'] = fixes['parent_discovery'] + fixes['field_name']
    
    if fixes['total'] > 0:
        if not dry_run:
            # Write back
            with open(yaml_path, 'w') as f:
                f.write(content)
            print(f"  ✅ Fixed {fixes['total']} placeholders ({fixes['parent_discovery']} PARENT_DISCOVERY, {fixes['field_name']} FIELD_NAME)")
        else:
            print(f"  🔍 Would fix {fixes['total']} placeholders ({fixes['parent_discovery']} PARENT_DISCOVERY, {fixes['field_name']} FIELD_NAME)")
    
    return fixes


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Fix PARENT_DISCOVERY and FIELD_NAME placeholders')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be fixed without making changes')
    parser.add_argument('--service', type=str, help='Fix only this service')
    parser.add_argument('--services-dir', type=str, default='../services', help='Services directory path')
    
    args = parser.parse_args()
    
    services_dir = Path(args.services_dir)
    if not services_dir.exists():
        print(f"❌ Services directory not found: {services_dir}")
        sys.exit(1)
    
    # Find all services with placeholders
    services_to_fix = []
    
    if args.service:
        service_path = services_dir / args.service / 'rules' / f'{args.service}.yaml'
        if service_path.exists():
            services_to_fix.append(args.service)
        else:
            print(f"❌ Service YAML not found: {service_path}")
            sys.exit(1)
    else:
        # Find all services with placeholders
        for service_dir in services_dir.iterdir():
            if service_dir.is_dir():
                yaml_file = service_dir / 'rules' / f'{service_dir.name}.yaml'
                if yaml_file.exists():
                    with open(yaml_file, 'r') as f:
                        content = f.read()
                        if 'PARENT_DISCOVERY' in content or 'FIELD_NAME' in content:
                            services_to_fix.append(service_dir.name)
    
    if not services_to_fix:
        print("✅ No services with placeholders found!")
        return
    
    print(f"Found {len(services_to_fix)} services with placeholders:")
    print("=" * 80)
    
    total_fixes = {'parent_discovery': 0, 'field_name': 0, 'total': 0}
    
    for service in sorted(services_to_fix):
        print(f"\n📦 {service}")
        yaml_path = services_dir / service / 'rules' / f'{service}.yaml'
        
        if not yaml_path.exists():
            print(f"  ⚠️  YAML file not found: {yaml_path}")
            continue
        
        fixes = fix_yaml_file(yaml_path, service, dry_run=args.dry_run)
        
        for key in total_fixes:
            total_fixes[key] += fixes[key]
    
    print("\n" + "=" * 80)
    print(f"Summary:")
    print(f"  Services processed: {len(services_to_fix)}")
    print(f"  PARENT_DISCOVERY fixes: {total_fixes['parent_discovery']}")
    print(f"  FIELD_NAME fixes: {total_fixes['field_name']}")
    print(f"  Total fixes: {total_fixes['total']}")
    
    if args.dry_run:
        print("\n🔍 DRY RUN - No files were modified")
    else:
        print("\n✅ All fixes applied!")


if __name__ == '__main__':
    main()


