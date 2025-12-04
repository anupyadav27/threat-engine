#!/usr/bin/env python3
"""
Redistribute rules from generic services to specific services
Based on the analysis from analyze_needs_review.py
"""

import yaml
import json
import shutil
from pathlib import Path
from collections import defaultdict
from datetime import datetime

def load_redistribution_plan(detailed_file):
    """Load the detailed redistribution plan"""
    with open(detailed_file, 'r') as f:
        return json.load(f)


def move_rule(rule_info, services_dir, dry_run=True):
    """Move a rule from current service to suggested service"""
    current_service = rule_info['current_service']
    target_service = rule_info['suggested_service']
    rule_file = rule_info['file']
    
    source_file = services_dir / current_service / 'metadata' / rule_file
    target_dir = services_dir / target_service / 'metadata'
    target_file = target_dir / rule_file
    
    if not source_file.exists():
        return False, "Source file not found"
    
    # Create target directory if it doesn't exist
    if not dry_run:
        target_dir.mkdir(parents=True, exist_ok=True)
    
    # Check if target file already exists
    if target_file.exists():
        return False, "Target file already exists"
    
    if dry_run:
        return True, "Would move"
    else:
        # Move the file
        shutil.move(str(source_file), str(target_file))
        return True, "Moved"


def update_service_rules_yaml(service_name, services_dir, service_mapping):
    """Update the rules YAML file for a service after redistribution"""
    service_dir = services_dir / service_name
    rules_file = service_dir / 'rules' / f'{service_name}.yaml'
    metadata_dir = service_dir / 'metadata'
    
    if not metadata_dir.exists():
        return
    
    # Count rules
    rule_count = len(list(metadata_dir.glob('*.yaml')))
    
    # Load or create rules YAML
    if rules_file.exists():
        with open(rules_file, 'r') as f:
            rules_yaml = yaml.safe_load(f)
    else:
        rules_yaml = {
            'version': '1.0',
            'provider': 'azure',
            'service': service_name
        }
    
    # Update rule count
    rules_yaml['total_rules'] = rule_count
    rules_yaml['last_updated'] = datetime.now().isoformat()
    
    # Add mapping info if available
    if service_name in service_mapping:
        mapping = service_mapping[service_name]
        rules_yaml['package'] = mapping['package']
        rules_yaml['client_class'] = mapping['client']
        rules_yaml['group'] = mapping['group']
    
    # Save
    rules_file.parent.mkdir(parents=True, exist_ok=True)
    with open(rules_file, 'w') as f:
        yaml.dump(rules_yaml, f, default_flow_style=False, sort_keys=False)


def main():
    import sys
    
    dry_run = '--execute' not in sys.argv
    
    print("=" * 80)
    if dry_run:
        print(" REDISTRIBUTION DRY RUN (use --execute to actually move files)")
    else:
        print(" EXECUTING REDISTRIBUTION")
    print("=" * 80)
    
    script_dir = Path(__file__).parent
    services_dir = script_dir / 'services'
    detailed_file = script_dir / 'redistribution_detailed.json'
    
    if not detailed_file.exists():
        print("❌ Error: redistribution_detailed.json not found")
        print("Run analyze_needs_review.py first")
        return 1
    
    # Load redistribution plan
    redistribution = load_redistribution_plan(detailed_file)
    
    # Group by target service
    by_target = defaultdict(list)
    for rule in redistribution:
        target = rule['suggested_service']
        if target:
            by_target[target].append(rule)
    
    # Service mapping (static, from our planning)
    service_mapping = {
        'network': {'package': 'azure-mgmt-network', 'client': 'NetworkManagementClient', 'group': 'networking'},
        'monitor': {'package': 'azure-mgmt-monitor', 'client': 'MonitorManagementClient', 'group': 'monitoring'},
        'storage': {'package': 'azure-mgmt-storage', 'client': 'StorageManagementClient', 'group': 'storage'},
        'backup': {'package': 'azure-mgmt-recoveryservices', 'client': 'RecoveryServicesClient', 'group': 'backup'},
        'security': {'package': 'azure-mgmt-security', 'client': 'SecurityCenter', 'group': 'security'},
        'keyvault': {'package': 'azure-mgmt-keyvault', 'client': 'KeyVaultManagementClient', 'group': 'keyvault'},
        'api': {'package': 'azure-mgmt-apimanagement', 'client': 'ApiManagementClient', 'group': 'web_services'},
        'rbac': {'package': 'azure-mgmt-authorization', 'client': 'AuthorizationManagementClient', 'group': 'identity'},
        'policy': {'package': 'azure-mgmt-resource', 'client': 'PolicyClient', 'group': 'core_management'},
        'function': {'package': 'azure-mgmt-web', 'client': 'WebSiteManagementClient', 'group': 'web_services'},
        'compute': {'package': 'azure-mgmt-compute', 'client': 'ComputeManagementClient', 'group': 'compute'},
        'sql': {'package': 'azure-mgmt-sql', 'client': 'SqlManagementClient', 'group': 'databases'},
        'aad': {'package': 'msgraph-sdk', 'client': 'GraphServiceClient', 'group': 'identity'},
    }
    
    stats = {
        'total_rules': len(redistribution),
        'moved': 0,
        'failed': 0,
        'by_target': defaultdict(int),
        'by_source': defaultdict(int)
    }
    
    errors = []
    
    print(f"\n📦 Processing {len(redistribution)} rules...")
    print(f"   Target services: {len(by_target)}")
    
    for target_service, rules in sorted(by_target.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"\n→ {target_service:20s} ({len(rules)} rules)")
        
        moved_count = 0
        for rule in rules:
            success, message = move_rule(rule, services_dir, dry_run)
            
            if success:
                moved_count += 1
                stats['moved'] += 1
                stats['by_target'][target_service] += 1
                stats['by_source'][rule['current_service']] += 1
            else:
                stats['failed'] += 1
                errors.append({
                    'rule': rule['rule_id'],
                    'error': message
                })
        
        action = "Would move" if dry_run else "Moved"
        print(f"   {action}: {moved_count}/{len(rules)} rules")
        
        # Update service rules YAML
        if not dry_run:
            update_service_rules_yaml(target_service, services_dir, service_mapping)
    
    # Clean up empty source services
    if not dry_run:
        print(f"\n🧹 Cleaning up source services...")
        for source_service in ['azure', 'active', 'managed']:
            metadata_dir = services_dir / source_service / 'metadata'
            if metadata_dir.exists():
                remaining = list(metadata_dir.glob('*.yaml'))
                if len(remaining) == 0:
                    print(f"   Removing empty service: {source_service}")
                    shutil.rmtree(services_dir / source_service)
                else:
                    print(f"   ⚠️  {source_service} still has {len(remaining)} rules")
    
    # Generate report
    print("\n" + "=" * 80)
    print(" SUMMARY")
    print("=" * 80)
    print(f"Total rules:              {stats['total_rules']}")
    print(f"Successfully processed:   {stats['moved']}")
    print(f"Failed:                   {stats['failed']}")
    
    if stats['failed'] > 0:
        print(f"\n⚠️  {stats['failed']} errors occurred:")
        for error in errors[:10]:
            print(f"  - {error['rule'][:60]}... : {error['error']}")
        if len(errors) > 10:
            print(f"  ... and {len(errors) - 10} more")
    
    print(f"\n📊 Rules moved by target service:")
    for service, count in sorted(stats['by_target'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {service:20s}: {count:3d} rules")
    
    print(f"\n📊 Rules moved by source service:")
    for service, count in sorted(stats['by_source'].items(), key=lambda x: x[1], reverse=True):
        print(f"  {service:20s}: {count:3d} rules")
    
    # Save execution report
    report = {
        'timestamp': datetime.now().isoformat(),
        'dry_run': dry_run,
        'stats': dict(stats),
        'errors': errors
    }
    
    report_file = script_dir / 'redistribution_execution_report.json'
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\n📄 Report saved: {report_file}")
    
    if dry_run:
        print("\n" + "=" * 80)
        print(" DRY RUN COMPLETE - No files were moved")
        print(" Run with --execute to perform actual redistribution")
        print("=" * 80)
    else:
        print("\n" + "=" * 80)
        print(" ✅ REDISTRIBUTION COMPLETE")
        print("=" * 80)
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())

