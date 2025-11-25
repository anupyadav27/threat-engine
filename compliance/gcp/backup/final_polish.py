#!/usr/bin/env python3
"""
Final Polish: Fix remaining generic 'resource' names with proper context-aware resource names
"""

import yaml
from datetime import datetime
import shutil

# Comprehensive resource name mapping based on service context
RESOURCE_MAPPINGS = {
    'appengine': {
        'resource': 'application',
    },
    'artifactregistry': {
        'resource': 'repository',
    },
    'backupdr': {
        'resource': 'backup_vault',
    },
    'bigquery': {
        'resource': 'dataset',
    },
    'bigtable': {
        'resource': 'instance',
    },
    'certificatemanager': {
        'resource': 'certificate',
    },
    'config': {
        'resource': 'configuration',
    },
    'dataproc': {
        'resource': 'cluster',
    },
    'dns': {
        'resource': 'managed_zone',
    },
    'filestore': {
        'resource': 'instance',
    },
    'firestore': {
        'resource': 'database',
    },
    'gcr': {
        'resource': 'repository',
    },
    'iam': {
        'resource': 'policy',
    },
    'kms': {
        'resource': 'key',
    },
    'logging': {
        'resource': 'log_sink',
    },
    'secret': {
        'resource': 'secret',
    },
    'security': {
        'resource': 'finding',
    },
    'securitycenter': {
        'resource': 'finding',
    },
    'securitycommandcenter': {
        'resource': 'finding',
    },
    'spanner': {
        'resource': 'instance',
    },
}

# Service name corrections for unknown services
SERVICE_MAPPINGS = {
    'config': 'resourcemanager',  # Cloud Config is part of Resource Manager
    'gcr': 'artifactregistry',  # GCR is now part of Artifact Registry
    'secret': 'secretmanager',  # Normalize secret to secretmanager
    'security': 'securitycenter',  # Normalize security to securitycenter
    'securitycommandcenter': 'securitycenter',  # Normalize to securitycenter
}

def fix_generic_resource(rule_id: str) -> str:
    """Fix generic 'resource' names based on service context."""
    parts = rule_id.split('.')
    
    if len(parts) != 4:
        return rule_id
    
    csp, service, resource, assertion = parts
    
    # Fix service name if needed
    if service in SERVICE_MAPPINGS:
        service = SERVICE_MAPPINGS[service]
    
    # Fix generic resource name
    if resource == 'resource' and service in RESOURCE_MAPPINGS:
        resource = RESOURCE_MAPPINGS[service]['resource']
    
    return f"{csp}.{service}.{resource}.{assertion}"

def process_rules_final_polish(rule_ids: list) -> tuple:
    """Final polish to fix generic resource names."""
    polished_rules = []
    changes = 0
    
    for rule_id in rule_ids:
        fixed_rule = fix_generic_resource(rule_id)
        polished_rules.append(fixed_rule)
        
        if fixed_rule != rule_id:
            changes += 1
            print(f"  {rule_id}")
            print(f"  → {fixed_rule}")
            print()
    
    return polished_rules, changes

def main():
    """Main function."""
    print("=" * 80)
    print("Final Polish: Fixing Generic Resource Names")
    print("=" * 80)
    print()
    
    # Paths
    rule_file = '/Users/apple/Desktop/threat-engine/compliance/gcp/rule_ids.yaml'
    backup_file = f'/Users/apple/Desktop/threat-engine/compliance/gcp/rule_ids_BACKUP_POLISH_{datetime.now().strftime("%Y%m%d_%H%M%S")}.yaml'
    
    # Backup
    print(f"Creating backup: {backup_file}")
    shutil.copy(rule_file, backup_file)
    print("✓ Backup created")
    print()
    
    # Read
    print(f"Reading rules from: {rule_file}")
    with open(rule_file, 'r') as f:
        data = yaml.safe_load(f)
    
    original_rules = data.get('rule_ids', [])
    print(f"Total rules: {len(original_rules)}")
    print()
    
    # Process
    print("Fixing generic resource names...")
    print()
    polished_rules, changes = process_rules_final_polish(original_rules)
    print(f"✓ Fixed {changes} rules")
    print()
    
    # Update metadata
    data['rule_ids'] = polished_rules
    data['metadata']['formatted_date'] = datetime.now().isoformat()
    data['metadata']['last_polished'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Write
    print(f"Writing polished rules to: {rule_file}")
    with open(rule_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    print("✓ File written")
    print()
    
    print("=" * 80)
    print("✓ FINAL POLISH COMPLETE")
    print("=" * 80)
    print(f"Changes made:  {changes}")
    print(f"Total rules:   {len(polished_rules)}")
    print(f"Backup saved:  {backup_file}")
    print()

if __name__ == "__main__":
    main()

