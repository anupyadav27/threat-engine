#!/usr/bin/env python3
"""
Consolidate services that share the same boto3 client into single YAML files.

For example:
- eip, vpc, vpcflowlogs → merge into ec2.yaml (all use ec2 client)
- fargate → merge into ecs.yaml
- kinesisfirehose → merge into firehose.yaml
- parameterstore → merge into ssm.yaml
- workflows → merge into stepfunctions.yaml
"""

import yaml
import os
import shutil
from pathlib import Path

# Services to consolidate: sub-service -> main service
CONSOLIDATION_MAP = {
    'eip': 'ec2',
    'vpc': 'ec2',
    'vpcflowlogs': 'ec2',
    'fargate': 'ecs',
    'kinesisfirehose': 'firehose',
    'parameterstore': 'ssm',
    'workflows': 'stepfunctions',
}

BASE_DIR = Path(__file__).parent
SERVICES_DIR = BASE_DIR / 'services'


def load_yaml(file_path):
    """Load YAML file"""
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)


def save_yaml(file_path, data):
    """Save YAML file with proper formatting"""
    with open(file_path, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=120)


def merge_yamls(main_yaml_path, sub_yaml_path, sub_service_name):
    """Merge sub-service YAML into main service YAML"""
    main_data = load_yaml(main_yaml_path)
    sub_data = load_yaml(sub_yaml_path)
    
    # Merge discoveries (keep service names distinct)
    if 'discovery' not in main_data:
        main_data['discovery'] = []
    if 'discovery' in sub_data:
        main_data['discovery'].extend(sub_data['discovery'])
    
    # Merge checks (keep service names distinct)
    if 'checks' not in main_data:
        main_data['checks'] = []
    if 'checks' in sub_data:
        main_data['checks'].extend(sub_data['checks'])
    
    return main_data


def consolidate_services():
    """Consolidate all services according to CONSOLIDATION_MAP"""
    print("Consolidating services that share boto3 clients...")
    print("=" * 80)
    
    # Group by main service
    main_services = {}
    for sub_svc, main_svc in CONSOLIDATION_MAP.items():
        if main_svc not in main_services:
            main_services[main_svc] = []
        main_services[main_svc].append(sub_svc)
    
    for main_svc, sub_services in main_services.items():
        print(f"\n📦 Consolidating into {main_svc}:")
        main_yaml_path = SERVICES_DIR / main_svc / 'rules' / f'{main_svc}.yaml'
        
        if not main_yaml_path.exists():
            print(f"  ⚠️  Main service YAML not found: {main_yaml_path}")
            continue
        
        # Load main YAML
        main_data = load_yaml(main_yaml_path)
        original_discoveries = len(main_data.get('discovery', []))
        original_checks = len(main_data.get('checks', []))
        
        # Merge each sub-service
        for sub_svc in sub_services:
            sub_yaml_path = SERVICES_DIR / sub_svc / 'rules' / f'{sub_svc}.yaml'
            
            if not sub_yaml_path.exists():
                print(f"  ⚠️  Sub-service YAML not found: {sub_yaml_path}")
                continue
            
            sub_data = load_yaml(sub_yaml_path)
            sub_discoveries = len(sub_data.get('discovery', []))
            sub_checks = len(sub_data.get('checks', []))
            
            # Merge
            if 'discovery' not in main_data:
                main_data['discovery'] = []
            if 'discovery' in sub_data:
                main_data['discovery'].extend(sub_data['discovery'])
            
            if 'checks' not in main_data:
                main_data['checks'] = []
            if 'checks' in sub_data:
                main_data['checks'].extend(sub_data['checks'])
            
            print(f"  ✅ Merged {sub_svc}: {sub_discoveries} discoveries, {sub_checks} checks")
        
        # Save consolidated YAML
        save_yaml(main_yaml_path, main_data)
        
        new_discoveries = len(main_data.get('discovery', []))
        new_checks = len(main_data.get('checks', []))
        
        print(f"  📊 {main_svc}.yaml: {original_discoveries} → {new_discoveries} discoveries, {original_checks} → {new_checks} checks")
    
    print("\n" + "=" * 80)
    print("✅ Consolidation complete!")
    print("\nNext steps:")
    print("1. Update config/service_list.json to point sub-services to main service YAML")
    print("2. Update engine/service_scanner.py load_service_rules() to handle consolidated services")
    print("3. Test the consolidated YAML files")


if __name__ == '__main__':
    consolidate_services()
