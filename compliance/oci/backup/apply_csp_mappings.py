#!/usr/bin/env python3
"""
Phase 1: Apply CSP Service Mappings (AWS/Azure/GCP → OCI)
Fixes 157 rules (7.4%) that use non-OCI service names
"""

import yaml
from datetime import datetime
from collections import Counter

# CSP → OCI Service Mappings
CSP_TO_OCI_MAPPINGS = {
    # AWS/Azure/GCP → OCI
    'object': 'object_storage',
    'defender': 'cloud_guard',
    'opensearch': 'analytics',
    'codebuild': 'devops',
    'api': 'apigateway',
    'sagemaker': 'data_science',
    'load': 'load_balancer',
    'efs': 'file_storage',
    'neptune': 'database',
    'app': 'functions',
    'ssm': 'compute',
    'dms': 'database',
    'cloudwatch': 'monitoring',
    'autoscaling': 'compute',
    'emr': 'bds',
    'mq': 'streaming',
    'networkfirewall': 'network_firewall',
    'kafka': 'streaming',
    'ebs': 'block_storage',
    'guardduty': 'cloud_guard',
    'kinesis': 'streaming',
    'config': 'cloud_guard',
    'directconnect': 'virtual_network',
    'sqs': 'queue',
    'organizations': 'identity',
    'os': 'compute',
    'wafv2': 'waf',
    'acm': 'certificates',
    'apigatewayv2': 'apigateway',
    'appsync': 'apigateway',
    'eventbridge': 'events',
    'no': 'identity',
    'route53': 'dns',
    'secretsmanager': 'vault',
    'securityhub': 'cloud_guard',
    'servicecatalog': 'resource_manager',
    'stepfunctions': 'data_integration',
    'storagegateway': 'object_storage',
    'transfer': 'object_storage',
    'workspaces': 'compute',
}

print("=" * 80)
print("PHASE 1: CSP SERVICE MAPPING (AWS/Azure/GCP → OCI)")
print("=" * 80)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")

# Backup
backup_file = f"rule_ids_BACKUP_CSP_MAPPING_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"Creating backup: {backup_file}")
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

# Apply mappings
updated_rules = []
changes = {}
services_changed = Counter()

for rule in rules:
    parts = rule.split('.')
    
    if len(parts) >= 4:
        csp = parts[0]
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:])
        
        if service in CSP_TO_OCI_MAPPINGS:
            new_service = CSP_TO_OCI_MAPPINGS[service]
            new_rule = f"{csp}.{new_service}.{resource}.{assertion}"
            updated_rules.append(new_rule)
            
            services_changed[service] += 1
            
            if service not in changes:
                changes[service] = {
                    'target': new_service,
                    'examples': []
                }
            
            if len(changes[service]['examples']) < 3:
                changes[service]['examples'].append({
                    'old': rule,
                    'new': new_rule
                })
        else:
            updated_rules.append(rule)
    else:
        updated_rules.append(rule)

# Display changes
print(f"\n{'=' * 80}")
print("CHANGES APPLIED")
print(f"{'=' * 80}")

total_rules_changed = sum(services_changed.values())
print(f"\nServices Mapped: {len(services_changed)}")
print(f"Rules Changed: {total_rules_changed} ({total_rules_changed/len(rules)*100:.1f}%)")

print(f"\n{'=' * 80}")
print("SERVICE MAPPINGS")
print(f"{'=' * 80}")

for service in sorted(services_changed.keys()):
    count = services_changed[service]
    target = changes[service]['target']
    print(f"\n{service} → {target} ({count} rules)")
    print("-" * 80)
    
    for example in changes[service]['examples']:
        print(f"  OLD: {example['old']}")
        print(f"  NEW: {example['new']}")
        print()

# Update metadata
data['rule_ids'] = updated_rules
data['metadata']['total_rules'] = len(updated_rules)
data['metadata']['last_csp_mapping'] = datetime.now().isoformat()
data['metadata']['csp_mapping_phase'] = 'phase_1_complete'

# Save
print(f"{'=' * 80}")
print("SAVING UPDATED RULES")
print(f"{'=' * 80}")

with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print(f"\n✅ Phase 1 Complete!")
print(f"✅ Mapped {len(services_changed)} services")
print(f"✅ Updated {total_rules_changed} rules")
print(f"✅ Backup: {backup_file}")
print(f"\n{'=' * 80}")

