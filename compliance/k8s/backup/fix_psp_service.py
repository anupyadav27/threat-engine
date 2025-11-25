#!/usr/bin/env python3
"""
Fix podsecuritypolicy service misalignment
podsecuritypolicy should be a RESOURCE, not a SERVICE
"""

import yaml
from datetime import datetime

with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']

# Backup
backup_file = f"rule_ids_BACKUP_PSP_FIX_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print(f"Backup created: {backup_file}")

# Fix mappings
fixes = {
    'k8s.podsecuritypolicy.apiserver.forensic_data_collection_enabled': 
        'k8s.monitoring.deployment.forensic_data_collection_enabled',
    
    'k8s.podsecuritypolicy.apiserver.incident_forensics_enabled': 
        'k8s.monitoring.deployment.incident_forensics_enabled',
    
    'k8s.podsecuritypolicy.deployment.playbooks_automated_enabled': 
        'k8s.monitoring.deployment.playbooks_automated_enabled',
    
    'k8s.podsecuritypolicy.deployment.proactive_hunting_enabled': 
        'k8s.monitoring.deployment.proactive_hunting_enabled',
    
    'k8s.podsecuritypolicy.event.automated_containment_enabled': 
        'k8s.monitoring.deployment.automated_containment_enabled',
    
    'k8s.podsecuritypolicy.networkpolicy.micro_segmentation_enabled_enforced': 
        'k8s.networkpolicy.networkpolicy.micro_segmentation_enabled_enforced',
    
    'k8s.podsecuritypolicy.networkpolicy.network_policies_enforced': 
        'k8s.networkpolicy.networkpolicy.network_policies_enforced',
    
    'k8s.podsecuritypolicy.podsecuritypolicy.identity_verification_enabled': 
        'k8s.policy.podsecuritypolicy.identity_verification_enabled',
    
    'k8s.podsecuritypolicy.service.mtls_enforced': 
        'k8s.networkpolicy.service.mtls_enforced',
}

# Apply fixes
updated_rules = []
fixed_count = 0

for rule in rules:
    if rule in fixes:
        new_rule = fixes[rule]
        print(f"✓ FIXED:")
        print(f"  OLD: {rule}")
        print(f"  NEW: {new_rule}\n")
        updated_rules.append(new_rule)
        fixed_count += 1
    else:
        updated_rules.append(rule)

# Update and save
data['rule_ids'] = updated_rules
data['metadata']['total_rules'] = len(updated_rules)
data['metadata']['last_psp_service_fix'] = datetime.now().isoformat()
data['metadata']['psp_service_fixes'] = fixed_count

with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print(f"=" * 100)
print(f"✅ PSP Service Fix Complete!")
print(f"✅ Rules fixed: {fixed_count}")
print(f"✅ Total rules: {len(updated_rules)}")
print(f"=" * 100)

