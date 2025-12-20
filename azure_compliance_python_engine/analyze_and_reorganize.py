#!/usr/bin/env python3
"""
Analyze and plan service reorganization:
1. Identify duplicate rule files (main/ vs rules/)
2. Find unique SDK clients and services that need merging
3. Generate reorganization plan
"""

import os
import json
import glob
import re
from collections import defaultdict

def load_sdk_mappings():
    """Load SDK client mappings from agent2"""
    agent2_path = "Agent-ruleid-rule-yaml/agent2_function_validator.py"
    service_mapping = {}
    
    with open(agent2_path) as f:
        content = f.read()
        match = re.search(r'SERVICE_NAME_MAPPING\s*=\s*\{([^}]+)\}', content, re.DOTALL)
        if match:
            dict_content = match.group(1)
            for line in dict_content.split('\n'):
                line = line.strip()
                if ':' in line and not line.startswith('#'):
                    parts = line.split(':')
                    if len(parts) >= 2:
                        key = parts[0].strip().strip("'\"")
                        value = parts[1].split(',')[0].strip().strip("'\"")
                        if key and value:
                            service_mapping[key] = value
    
    # Add services from config
    with open("config/service_list.json") as f:
        config = json.load(f)
        all_services = [s['name'] for s in config['services'] if s.get('enabled')]
    
    for svc in all_services:
        if svc not in service_mapping:
            service_mapping[svc] = svc
    
    return service_mapping

def find_duplicate_rules():
    """Find services with duplicate rule files"""
    rule_files_main = glob.glob("services/*/*.yaml")
    rule_files_rules = glob.glob("services/*/rules/*.yaml")
    
    services_with_rules = defaultdict(lambda: {'main': [], 'rules': []})
    
    for f in rule_files_main:
        parts = f.split('/')
        if len(parts) >= 3:
            service = parts[1]
            filename = parts[2]
            # Skip metadata files
            if 'metadata' not in f and filename.endswith('.yaml'):
                services_with_rules[service]['main'].append(filename)
    
    for f in rule_files_rules:
        parts = f.split('/')
        if len(parts) >= 4:
            service = parts[1]
            filename = parts[3]
            if filename.endswith('.yaml'):
                services_with_rules[service]['rules'].append(filename)
    
    duplicates = []
    for service, files in services_with_rules.items():
        main_yamls = [f for f in files['main'] if f.endswith('.yaml')]
        rules_yamls = [f for f in files['rules'] if f.endswith('.yaml')]
        
        # Check for service.yaml in rules/ and service_rules.yaml in main/
        has_rules_yaml = f"{service}.yaml" in rules_yamls
        has_main_rules = f"{service}_rules.yaml" in main_yamls or f"{service}.yaml" in main_yamls
        
        if has_rules_yaml and has_main_rules:
            duplicates.append({
                'service': service,
                'main_files': main_yamls,
                'rules_files': rules_yamls
            })
    
    return duplicates

def find_merge_groups():
    """Find services that should be merged by SDK client"""
    service_mapping = load_sdk_mappings()
    
    # Group services by SDK client
    sdk_to_services = defaultdict(list)
    for service, sdk_client in service_mapping.items():
        sdk_to_services[sdk_client].append(service)
    
    # Find groups with multiple services
    merge_groups = []
    for sdk_client, services in sdk_to_services.items():
        if len(services) > 1:
            merge_groups.append({
                'sdk_client': sdk_client,
                'services': sorted(services),
                'target_folder': sdk_client
            })
    
    return merge_groups

def main():
    print("=" * 80)
    print("SERVICE REORGANIZATION ANALYSIS")
    print("=" * 80)
    print()
    
    # 1. Find duplicate rule files
    print("1. DUPLICATE RULE FILES")
    print("-" * 80)
    duplicates = find_duplicate_rules()
    print(f"Found {len(duplicates)} services with duplicate rule files")
    print()
    
    print("Services with duplicates (keep rules/ folder, remove main/ folder):")
    for dup in duplicates[:10]:  # Show first 10
        print(f"  • {dup['service']}")
        print(f"    Main: {dup['main_files']}")
        print(f"    Rules: {dup['rules_files']}")
        print(f"    → Keep: services/{dup['service']}/rules/{dup['service']}.yaml")
        print(f"    → Remove: services/{dup['service']}/{dup['service']}_rules.yaml")
        print()
    
    if len(duplicates) > 10:
        print(f"  ... and {len(duplicates) - 10} more")
    
    print()
    
    # 2. Find merge groups
    print("2. SDK CLIENT MERGE GROUPS")
    print("-" * 80)
    merge_groups = find_merge_groups()
    print(f"Found {len(merge_groups)} SDK clients with multiple services")
    print()
    
    for group in merge_groups:
        print(f"📦 SDK Client: {group['sdk_client']}")
        print(f"   Target folder: services/{group['target_folder']}/")
        print(f"   Services to merge ({len(group['services'])}):")
        for svc in group['services']:
            print(f"     • {svc}")
        print()
    
    # 3. Generate action plan
    print("=" * 80)
    print("3. ACTION PLAN")
    print("=" * 80)
    print()
    
    print("STEP 1: Remove duplicate rule files from main/ folders")
    print(f"  • {len(duplicates)} services need cleanup")
    print("  • Keep: services/{service}/rules/{service}.yaml")
    print("  • Remove: services/{service}/{service}_rules.yaml")
    print()
    
    print("STEP 2: Merge services by SDK client")
    print(f"  • {len(merge_groups)} SDK client groups to create")
    print("  • Merge metadata from all services in group")
    print("  • Merge rules from all services in group")
    print("  • Update service_list.json to use SDK client names")
    print()
    
    # Save plan to JSON
    plan = {
        'duplicates': duplicates,
        'merge_groups': merge_groups,
        'summary': {
            'total_duplicates': len(duplicates),
            'total_merge_groups': len(merge_groups),
            'total_services_to_merge': sum(len(g['services']) for g in merge_groups)
        }
    }
    
    with open('reorganization_plan.json', 'w') as f:
        json.dump(plan, f, indent=2)
    
    print("✅ Plan saved to: reorganization_plan.json")
    print()
    print("Next: Review plan and run reorganization script")

if __name__ == '__main__':
    main()
