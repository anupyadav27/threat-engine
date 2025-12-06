#!/usr/bin/env python3
"""
Regenerate services folder structure from rule_ids.yaml

This script:
1. Parses rule_ids.yaml to extract all rules
2. Groups rules by service
3. Creates service directories with metadata and rules files
4. Generates placeholder rule YAML files for each service
"""

import os
import yaml
from collections import defaultdict
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).parent
RULE_IDS_FILE = BASE_DIR / "rule_ids.yaml"
SERVICES_DIR = BASE_DIR / "services"


def load_rules():
    """Load all rules from rule_ids.yaml"""
    print(f"Loading rules from {RULE_IDS_FILE}...")
    with open(RULE_IDS_FILE, 'r') as f:
        data = yaml.safe_load(f)
    rules = data.get('rules', [])
    print(f"Loaded {len(rules)} rules")
    return rules


def group_by_service(rules):
    """Group rules by service name"""
    print("\nGrouping rules by service...")
    services = defaultdict(list)
    for rule in rules:
        service = rule.get('service', 'unknown')
        services[service].append(rule)
    
    print(f"Found {len(services)} services:")
    for service, rule_list in sorted(services.items(), key=lambda x: -len(x[1])):
        print(f"  - {service}: {len(rule_list)} rules")
    
    return dict(services)


def create_metadata_file(service_dir, rule):
    """Create individual metadata YAML file for a rule"""
    import hashlib
    
    metadata_dir = service_dir / "metadata"
    metadata_dir.mkdir(parents=True, exist_ok=True)
    
    rule_id = rule.get('rule_id', 'unknown')
    
    # Handle long filenames (max 255 chars on most filesystems)
    filename = f"{rule_id}.yaml"
    if len(filename) > 200:  # Leave some margin
        # Use first part of rule_id + hash of full rule_id
        hash_suffix = hashlib.md5(rule_id.encode()).hexdigest()[:8]
        short_id = rule_id[:150]  # Keep first 150 chars
        filename = f"{short_id}_{hash_suffix}.yaml"
    
    filepath = metadata_dir / filename
    
    # Extract metadata fields
    metadata = {
        'rule_id': rule_id,
        'service': rule.get('service'),
        'resource': rule.get('resource'),
        'requirement': rule.get('requirement'),
        'scope': rule.get('scope'),
        'domain': rule.get('domain'),
        'subcategory': rule.get('subcategory'),
        'severity': rule.get('severity'),
        'title': rule.get('title'),
        'rationale': rule.get('rationale'),
        'description': rule.get('description'),
        'references': rule.get('references', [])
    }
    
    # Add compliance if exists
    if 'compliance' in rule:
        metadata['compliance'] = rule['compliance']
    
    # Remove None values
    metadata = {k: v for k, v in metadata.items() if v is not None}
    
    with open(filepath, 'w') as f:
        yaml.dump(metadata, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    return filepath


def create_service_rules_file(service_dir, service_name, rules):
    """Create service rules YAML file with discovery and checks structure"""
    rules_dir = service_dir / "rules"
    rules_dir.mkdir(parents=True, exist_ok=True)
    
    filepath = rules_dir / f"{service_name}.yaml"
    
    # Create basic structure
    # Group rules by resource type for discovery
    resources = defaultdict(list)
    for rule in rules:
        resource = rule.get('resource', 'unknown')
        resources[resource].append(rule)
    
    # Build discovery section (placeholder)
    discovery = []
    for resource in sorted(resources.keys()):
        discovery.append({
            'discovery_id': f"alicloud.{service_name}.{resource}",
            'calls': [{
                'product': service_name.upper() if service_name not in ['ecs', 'oss', 'rds', 'vpc'] else service_name.capitalize(),
                'version': '2014-05-26',  # Placeholder version
                'action': f'Describe{resource.replace("_", " ").title().replace(" ", "")}s',
                'params': {},
                'save_as': f'{resource}_list'
            }],
            'emit': {
                'items_for': f'{{ {resource}_list }}',
                'as': 'r',
                'item': {
                    'id': '{{ r.id }}',
                    'name': '{{ r.name }}',
                    'resource_type': resource
                }
            }
        })
    
    # Build checks section (placeholder)
    checks = []
    for rule in rules:
        rule_id = rule.get('rule_id')
        resource = rule.get('resource', 'unknown')
        
        checks.append({
            'rule_id': rule_id,
            'title': rule.get('title', ''),
            'severity': rule.get('severity', 'medium'),
            'assertion_id': rule.get('compliance', [''])[0] if rule.get('compliance') else '',
            'for_each': f"alicloud.{service_name}.{resource}",
            'params': {},
            'conditions': {
                'all': [
                    {
                        'var': 'item.id',
                        'op': 'exists',
                        'value': None
                    }
                ]
            }
        })
    
    # Create the YAML structure
    service_yaml = {
        'version': '1.0',
        'provider': 'alicloud',
        'service': service_name,
        'discovery': discovery,
        'checks': checks
    }
    
    with open(filepath, 'w') as f:
        yaml.dump(service_yaml, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    return filepath


def regenerate_services():
    """Main function to regenerate services folder"""
    print("="*80)
    print("ALICLOUD SERVICES REGENERATION")
    print("="*80)
    
    # Load rules
    rules = load_rules()
    
    # Group by service
    services = group_by_service(rules)
    
    # Create backup of existing services
    if SERVICES_DIR.exists():
        backup_dir = BASE_DIR / "services_backup_old"
        if backup_dir.exists():
            import shutil
            shutil.rmtree(backup_dir)
        print(f"\nBacking up existing services to {backup_dir}...")
        import shutil
        shutil.copytree(SERVICES_DIR, backup_dir)
    
    # Recreate services directory
    print(f"\nRecreating {SERVICES_DIR}...")
    if SERVICES_DIR.exists():
        import shutil
        shutil.rmtree(SERVICES_DIR)
    SERVICES_DIR.mkdir(parents=True, exist_ok=True)
    
    # Process each service
    print("\nGenerating service files...")
    total_metadata = 0
    total_services = 0
    
    for service_name, service_rules in sorted(services.items()):
        print(f"\n  Processing {service_name}...")
        service_dir = SERVICES_DIR / service_name
        service_dir.mkdir(parents=True, exist_ok=True)
        
        # Create metadata files
        print(f"    Creating {len(service_rules)} metadata files...")
        for rule in service_rules:
            create_metadata_file(service_dir, rule)
            total_metadata += 1
        
        # Create service rules file
        print(f"    Creating rules file...")
        create_service_rules_file(service_dir, service_name, service_rules)
        total_services += 1
    
    print("\n" + "="*80)
    print("REGENERATION COMPLETE")
    print("="*80)
    print(f"  Services created: {total_services}")
    print(f"  Metadata files created: {total_metadata}")
    print(f"  Location: {SERVICES_DIR}")
    print("="*80)


if __name__ == "__main__":
    regenerate_services()

