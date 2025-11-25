#!/usr/bin/env python3
"""
OCI CSPM - AWS to OCI Service Mapping Fix

Replaces all AWS service names with their OCI equivalents
Affects 162 rules across 45 AWS-like services
"""

import yaml
from datetime import datetime
from collections import defaultdict

# Comprehensive AWS → OCI mapping
AWS_TO_OCI_SERVICE_MAPPING = {
    # Compute
    'ec2': 'compute',
    'awslambda': 'functions',
    'lambda': 'functions',
    'ecs': 'container_instances',
    'eks': 'container_engine',
    'aks': 'container_engine',  # Azure Kubernetes → OKE
    'emr': 'bds',  # EMR → Big Data Service
    'sagemaker': 'data_science',
    
    # Storage
    's3': 'object_storage',
    'ebs': 'block_storage',
    'efs': 'file_storage',
    'glacier': 'object_storage',
    
    # Database
    'rds': 'database',
    'dynamodb': 'nosql',
    'redshift': 'database',
    'elasticache': 'redis',
    
    # Networking
    'vpc': 'virtual_network',
    'elb': 'load_balancer',
    'elbv2': 'load_balancer',
    'cloudfront': 'cdn',
    'ipsec_vpn_tls_certificates_service_vault_kms': 'ipsec_vpn',
    
    # Security & KMS variants
    'kms': 'key_management',
    'oci_kms': 'key_management',
    'oci_vault_kms_object_storage_encryption': 'key_management',
    'oci_vault_secrets': 'vault',
    'acm': 'certificates',
    'guardduty': 'cloud_guard',
    
    # WAF variants (consolidate all)
    'waf': 'waf',
    'oci_web_application_firewall_waf': 'waf',
    'oci_waf_address_lists': 'waf',
    'oci_waf_policy_rule_groups': 'waf',
    'oci_waf_regex_filters': 'waf',
    'oci_waf_rule': 'waf',
    'waf_address_lists': 'waf',
    'waf_edge': 'waf',
    
    # Monitoring & Logging
    'cloudwatch': 'monitoring',
    'cloudtrail': 'audit',
    'oci_observability_management_dashboards': 'monitoring',
    
    # Messaging
    'sns': 'ons',  # Oracle Notification Service
    'sqs': 'queue',
    'kinesis': 'streaming',
    
    # Other
    'cloudformation': 'resource_manager',
    'oci_dns_records': 'dns',
}

# Resource mappings for specific service transitions
RESOURCE_MAPPINGS = {
    # sagemaker → data_science
    'data_science': {
        'notebook_instance': 'notebook_session',
        'endpoint': 'model_deployment',
    },
    # dynamodb → nosql
    'nosql': {
        'accelerator': 'table',  # DAX accelerator
    },
    # redshift → database
    # elasticache → redis
    'redis': {
        'replication_group': 'cluster',
    },
    # elb/elbv2 → load_balancer
    'load_balancer': {
        'target_group': 'backend_set',
    },
}

def fix_aws_to_oci_rule(rule: str) -> tuple:
    """
    Fix AWS service names to OCI equivalents
    Returns: (fixed_rule, was_changed, change_description)
    """
    original = rule
    parts = rule.split('.')
    
    if len(parts) < 4:
        return rule, False, "malformed"
    
    csp = parts[0]
    service = parts[1]
    resource = parts[2]
    assertion = '.'.join(parts[3:])
    
    changes = []
    
    # Check if service is AWS
    if service in AWS_TO_OCI_SERVICE_MAPPING:
        new_service = AWS_TO_OCI_SERVICE_MAPPING[service]
        changes.append(f"service:{service}→{new_service}")
        
        # Update resource if needed for this service
        if new_service in RESOURCE_MAPPINGS and resource in RESOURCE_MAPPINGS[new_service]:
            new_resource = RESOURCE_MAPPINGS[new_service][resource]
            changes.append(f"resource:{resource}→{new_resource}")
            resource = new_resource
        
        service = new_service
    
    if changes:
        new_rule = f"{csp}.{service}.{resource}.{assertion}"
        return new_rule, True, " | ".join(changes)
    
    return rule, False, "no_change"

def main():
    print("=" * 80)
    print("OCI CSPM - AWS TO OCI SERVICE MAPPING FIX")
    print("=" * 80)
    print()
    
    # Read rules
    print("📖 Reading rule_ids.yaml...")
    with open('rule_ids.yaml', 'r') as f:
        data = yaml.safe_load(f)
    
    rules = data['rule_ids']
    print(f"   Current: {len(rules)} rules")
    print()
    
    # Backup
    backup_file = f"rule_ids_BACKUP_AWS_TO_OCI_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
    print(f"💾 Creating backup: {backup_file}")
    with open(backup_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    print()
    
    # Process
    print("🔧 Mapping AWS services to OCI equivalents...")
    improved_rules = []
    changes_log = defaultdict(list)
    stats = {
        'total': len(rules),
        'changed': 0,
        'service_fixes': 0,
        'resource_fixes': 0,
    }
    
    for i, rule in enumerate(rules):
        if (i + 1) % 500 == 0:
            print(f"  Progress: {i+1}/{len(rules)}")
        
        new_rule, was_changed, change_desc = fix_aws_to_oci_rule(rule)
        improved_rules.append(new_rule)
        
        if was_changed:
            stats['changed'] += 1
            changes_log[change_desc].append((rule, new_rule))
            
            if 'service:' in change_desc:
                stats['service_fixes'] += 1
            if 'resource:' in change_desc:
                stats['resource_fixes'] += 1
    
    # Remove duplicates
    original_count = len(improved_rules)
    improved_rules = list(dict.fromkeys(improved_rules))
    stats['duplicates_removed'] = original_count - len(improved_rules)
    
    print()
    print("=" * 80)
    print("📊 AWS → OCI MAPPING STATISTICS")
    print("=" * 80)
    print(f"Total Rules:             {stats['total']}")
    print(f"  ✅ AWS Services Fixed:  {stats['changed']} rules")
    if stats['duplicates_removed'] > 0:
        print(f"  🔍 Duplicates Removed:  {stats['duplicates_removed']} rules")
    print()
    print(f"Fix Breakdown:")
    print(f"  🏢 AWS → OCI Services:  {stats['service_fixes']} fixes")
    print(f"  📦 Resource Updates:    {stats['resource_fixes']} fixes")
    print()
    
    # Show top changes
    print("Top Service Mappings Applied:")
    print("-" * 80)
    service_counts = defaultdict(int)
    for change_desc, rule_pairs in changes_log.items():
        if 'service:' in change_desc:
            service_counts[change_desc] += len(rule_pairs)
    
    for change, count in sorted(service_counts.items(), key=lambda x: -x[1])[:15]:
        print(f"  {change:50s} {count:3d} rules")
    
    print()
    
    # Update and save
    data['metadata']['total_rules'] = len(improved_rules)
    data['metadata']['last_aws_to_oci_fix'] = datetime.now().isoformat()
    data['rule_ids'] = improved_rules
    
    print("💾 Writing OCI-native rules...")
    with open('rule_ids.yaml', 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    
    # Generate report
    with open('OCI_AWS_TO_OCI_MAPPING_REPORT.txt', 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("OCI CSPM - AWS TO OCI SERVICE MAPPING REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("STATISTICS:\n")
        f.write(f"  Total Rules:              {stats['total']}\n")
        f.write(f"  AWS Services Mapped:      {stats['changed']}\n")
        f.write(f"  Service Name Changes:     {stats['service_fixes']}\n")
        f.write(f"  Resource Name Changes:    {stats['resource_fixes']}\n")
        if stats['duplicates_removed'] > 0:
            f.write(f"  Duplicates Removed:       {stats['duplicates_removed']}\n")
        f.write("\n")
        
        f.write("=" * 80 + "\n")
        f.write("DETAILED CHANGES\n")
        f.write("=" * 80 + "\n\n")
        
        for change_desc, rule_pairs in sorted(changes_log.items(), key=lambda x: -len(x[1])):
            f.write(f"\n{change_desc} ({len(rule_pairs)} rules)\n")
            f.write("-" * 80 + "\n")
            for old, new in rule_pairs[:10]:
                f.write(f"  OLD: {old}\n")
                f.write(f"  NEW: {new}\n\n")
            if len(rule_pairs) > 10:
                f.write(f"  ... and {len(rule_pairs) - 10} more\n\n")
    
    print()
    print("=" * 80)
    print("✅ AWS → OCI MAPPING COMPLETE!")
    print("=" * 80)
    print(f"Final rule count: {len(improved_rules)}")
    print(f"AWS services converted: {stats['changed']}")
    if stats['duplicates_removed'] > 0:
        print(f"Duplicates removed: {stats['duplicates_removed']}")
    print()
    print(f"Backup: {backup_file}")
    print(f"Report: OCI_AWS_TO_OCI_MAPPING_REPORT.txt")
    print("=" * 80)

if __name__ == "__main__":
    main()

