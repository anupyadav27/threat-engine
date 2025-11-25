#!/usr/bin/env python3
"""
Fix malformed OCI rules that don't follow the 4-part format.
These are usually AWS-style rules that need resource injection.
"""

import yaml
from datetime import datetime
from oci_python_sdk_mappings import get_official_service_name, get_official_resource_name

# Service to default resource mapping
AWS_TO_OCI_RESOURCE_MAPPING = {
    "aks": "cluster",
    "cloudfront": "distribution",
    "dynamodb": "table",
    "ec2": "instance",
    "ecs": "container_instance",
    "eks": "cluster",
    "elasticache": "cluster",
    "elb": "load_balancer",
    "kms": "key",
    "lambda": "function",
    "rds": "db_system",
    "redshift": "cluster",
    "s3": "bucket",
    "sns": "topic",
}

def fix_malformed_rule(rule: str) -> tuple:
    """
    Fix rules that don't follow 4-part format.
    Returns: (fixed_rule, was_changed)
    """
    parts = rule.split('.')
    
    # Already 4+ parts, good
    if len(parts) >= 4:
        return rule, False
    
    # Only 3 parts: oci.service.assertion
    if len(parts) == 3:
        csp, service, assertion = parts
        
        # Map AWS service to OCI service
        oci_service = get_official_service_name(service)
        
        # Get appropriate resource
        if service in AWS_TO_OCI_RESOURCE_MAPPING:
            resource = AWS_TO_OCI_RESOURCE_MAPPING[service]
        else:
            resource = get_official_resource_name(oci_service, "resource")
        
        # Reconstruct
        new_rule = f"{csp}.{oci_service}.{resource}.{assertion}"
        return new_rule, True
    
    # Malformed in other ways
    return rule, False

def main():
    print("=" * 80)
    print("FIXING MALFORMED OCI RULES (3-part → 4-part)")
    print("=" * 80)
    print()
    
    # Read
    print("📖 Reading rule_ids.yaml...")
    with open('rule_ids.yaml', 'r') as f:
        data = yaml.safe_load(f)
    
    rules = data['rule_ids']
    print(f"   Loaded: {len(rules)} rules")
    
    # Backup
    backup_file = f"rule_ids_BACKUP_MALFORMED_FIX_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
    print(f"💾 Creating backup: {backup_file}")
    with open(backup_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    print()
    
    # Fix malformed rules
    print("🔧 Fixing malformed rules...")
    fixed_rules = []
    changes = []
    malformed_count = 0
    
    for rule in rules:
        fixed_rule, was_changed = fix_malformed_rule(rule)
        fixed_rules.append(fixed_rule)
        if was_changed:
            malformed_count += 1
            changes.append((rule, fixed_rule))
    
    print()
    print("=" * 80)
    print("📊 STATISTICS")
    print("=" * 80)
    print(f"Total Rules:        {len(rules)}")
    print(f"Malformed Fixed:    {malformed_count}")
    print(f"Already Good:       {len(rules) - malformed_count}")
    print()
    
    if malformed_count > 0:
        print("=" * 80)
        print(f"FIXED RULES ({malformed_count} total)")
        print("=" * 80)
        for old, new in changes[:20]:  # Show first 20
            print(f"  OLD: {old}")
            print(f"  NEW: {new}")
            print()
        if len(changes) > 20:
            print(f"  ... and {len(changes) - 20} more")
        print()
    
    # Update and save
    data['rule_ids'] = fixed_rules
    data['metadata']['total_rules'] = len(fixed_rules)
    data['metadata']['last_malformed_fix'] = datetime.now().isoformat()
    
    print("💾 Writing fixed rules...")
    with open('rule_ids.yaml', 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    
    print()
    print("=" * 80)
    print("✅ COMPLETE!")
    print("=" * 80)
    print(f"Fixed: {malformed_count} malformed rules")
    print(f"Backup: {backup_file}")
    print("=" * 80)

if __name__ == "__main__":
    main()

