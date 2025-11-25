#!/usr/bin/env python3
"""
Create organized folder structure for AWS compliance rules:
- For each service: create service folder
- Inside each service: create 'metadata' and 'checks' subfolders
- In metadata: create separate YAML file for each rule_id with all its fields
- In checks: create service_checks.yaml (empty for now, to be populated later)
"""

import yaml
import os
from pathlib import Path
from collections import defaultdict

def create_service_structure(rule_ids_file: str, base_path: str):
    print("="*80)
    print("CREATING SERVICE FOLDER STRUCTURE")
    print("="*80)
    
    # Load rules
    print(f"\n[1/4] Loading rules from {rule_ids_file}...")
    with open(rule_ids_file, 'r') as f:
        data = yaml.safe_load(f)
    
    rules = data.get('rule_ids', [])
    print(f"  ✓ Loaded {len(rules)} rules")
    
    # Group rules by service
    print(f"\n[2/4] Grouping rules by service...")
    service_rules = defaultdict(list)
    
    for rule in rules:
        rule_id = rule.get('rule_id', '')
        # Extract service from rule_id (second part)
        # e.g., aws.s3.bucket.encryption_enabled → s3
        parts = rule_id.split('.')
        if len(parts) >= 2:
            service = parts[1]
            service_rules[service].append(rule)
    
    print(f"  ✓ Found {len(service_rules)} services")
    
    # Create folder structure
    print(f"\n[3/4] Creating folder structure and metadata files...")
    
    base_dir = Path(base_path)
    stats = {
        'services': 0,
        'metadata_files': 0,
        'check_files': 0,
    }
    
    for service, rules_list in sorted(service_rules.items()):
        # Create service folder
        service_dir = base_dir / service
        service_dir.mkdir(parents=True, exist_ok=True)
        
        # Create metadata subfolder
        metadata_dir = service_dir / 'metadata'
        metadata_dir.mkdir(exist_ok=True)
        
        # Create checks subfolder
        checks_dir = service_dir / 'checks'
        checks_dir.mkdir(exist_ok=True)
        
        # Create metadata YAML file for each rule_id
        for rule in rules_list:
            rule_id = rule.get('rule_id', '')
            
            # Use rule_id as filename (replace dots with underscores for filesystem safety)
            filename = f"{rule_id}.yaml"
            filepath = metadata_dir / filename
            
            # Write rule metadata to YAML
            with open(filepath, 'w') as f:
                yaml.dump(rule, f, default_flow_style=False, sort_keys=False, 
                         width=120, allow_unicode=True)
            
            stats['metadata_files'] += 1
        
        # Create service_checks.yaml in checks folder
        checks_file = checks_dir / f"{service}_checks.yaml"
        
        # Create empty checks file with structure placeholder
        checks_content = {
            'service': service,
            'description': f'Security checks for AWS {service.upper()} service',
            'checks': []  # To be populated in next phase
        }
        
        with open(checks_file, 'w') as f:
            yaml.dump(checks_content, f, default_flow_style=False, sort_keys=False,
                     width=120, allow_unicode=True)
        
        stats['check_files'] += 1
        stats['services'] += 1
        
        if stats['services'] % 20 == 0:
            print(f"    Processed {stats['services']} services...")
    
    print(f"  ✓ Created {stats['services']} service folders")
    print(f"  ✓ Created {stats['metadata_files']} metadata files")
    print(f"  ✓ Created {stats['check_files']} check files")
    
    # Create index file
    print(f"\n[4/4] Creating service index...")
    index_file = base_dir / 'SERVICE_INDEX.yaml'
    
    service_index = {
        'metadata': {
            'total_services': len(service_rules),
            'total_rules': len(rules),
            'structure': {
                'service_folder': {
                    'metadata': 'Individual YAML files for each rule_id',
                    'checks': 'service_checks.yaml with security checks (to be populated)'
                }
            }
        },
        'services': {}
    }
    
    for service, rules_list in sorted(service_rules.items()):
        service_index['services'][service] = {
            'rule_count': len(rules_list),
            'metadata_path': f'{service}/metadata/',
            'checks_path': f'{service}/checks/{service}_checks.yaml'
        }
    
    with open(index_file, 'w') as f:
        yaml.dump(service_index, f, default_flow_style=False, sort_keys=False,
                 width=120, allow_unicode=True)
    
    print(f"  ✓ Created SERVICE_INDEX.yaml")
    
    # Summary
    print("\n" + "="*80)
    print("FOLDER STRUCTURE CREATED")
    print("="*80)
    
    print(f"\n📊 Statistics:")
    print(f"  Services: {stats['services']}")
    print(f"  Metadata Files: {stats['metadata_files']}")
    print(f"  Check Files: {stats['check_files']}")
    
    print(f"\n📁 Structure:")
    print(f"  Base Path: {base_path}")
    print(f"  Format:")
    print(f"    services/")
    print(f"      {{service}}/")
    print(f"        metadata/")
    print(f"          aws.{{service}}.{{resource}}.{{requirement}}.yaml")
    print(f"        checks/")
    print(f"          {{service}}_checks.yaml")
    
    print(f"\n✅ Sample Services:")
    sample_services = list(service_rules.keys())[:5]
    for service in sample_services:
        count = len(service_rules[service])
        print(f"  • {service:20s} - {count:3d} rules")
    
    print("\n" + "="*80)
    print("✅ STRUCTURE CREATION COMPLETE!")
    print("="*80)

def main():
    create_service_structure(
        rule_ids_file='/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml',
        base_path='/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services'
    )

if __name__ == '__main__':
    main()

