#!/usr/bin/env python3
"""
Apply IBM Cloud Service Mappings
Transform all service names to IBM Cloud SDK standards
"""

import yaml
from datetime import datetime
from collections import Counter
from ibm_cloud_service_mappings import IBM_CLOUD_SERVICE_MAPPINGS

print("=" * 100)
print("APPLYING IBM CLOUD SERVICE NORMALIZATION")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")
print(f"Total Service Mappings Available: {len(IBM_CLOUD_SERVICE_MAPPINGS)}")

# Backup
backup_file = f"rule_ids_BACKUP_SERVICE_MAPPING_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"Creating backup: {backup_file}")
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

# Apply mappings
updated_rules = []
changes = Counter()
service_changes = {}

for rule in rules:
    parts = rule.split('.')
    
    if len(parts) >= 3:
        csp = parts[0]
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:]) if len(parts) > 3 else ''
        
        if service in IBM_CLOUD_SERVICE_MAPPINGS:
            new_service = IBM_CLOUD_SERVICE_MAPPINGS[service]
            
            # Build new rule
            if assertion:
                new_rule = f"{csp}.{new_service}.{resource}.{assertion}"
            else:
                new_rule = f"{csp}.{new_service}.{resource}"
            
            updated_rules.append(new_rule)
            
            if service != new_service:  # Only count if actually changed
                changes[f"{service} → {new_service}"] += 1
                
                if service not in service_changes:
                    service_changes[service] = {
                        'target': new_service,
                        'count': 0,
                        'example': rule
                    }
                service_changes[service]['count'] += 1
        else:
            updated_rules.append(rule)
    else:
        updated_rules.append(rule)

# Display results
print(f"\n{'=' * 100}")
print("TRANSFORMATION RESULTS")
print(f"{'=' * 100}")

rules_changed = sum(service_changes[s]['count'] for s in service_changes)
services_mapped = len(service_changes)

print(f"\nServices Mapped: {services_mapped}")
print(f"Rules Changed: {rules_changed} ({rules_changed/len(rules)*100:.1f}%)")
print(f"Rules Unchanged: {len(rules) - rules_changed} ({(len(rules) - rules_changed)/len(rules)*100:.1f}%)")

# Top 30 service changes
print(f"\n{'=' * 100}")
print("TOP 30 SERVICE TRANSFORMATIONS")
print(f"{'=' * 100}")

sorted_services = sorted(service_changes.items(), key=lambda x: x[1]['count'], reverse=True)
for service, details in sorted_services[:30]:
    print(f"{service:60s} → {details['target']:30s} {details['count']:4d} rules")
    if details['count'] <= 3:  # Show example for smaller counts
        print(f"  Example: {details['example']}")

# Update metadata
data['rule_ids'] = updated_rules
data['metadata']['total_rules'] = len(updated_rules)
data['metadata']['last_service_mapping'] = datetime.now().isoformat()
data['metadata']['service_mapping_phase'] = 'ibm_cloud_sdk_complete'
data['metadata']['services_mapped'] = services_mapped
data['metadata']['rules_transformed'] = rules_changed

# Save
print(f"\n{'=' * 100}")
print("SAVING UPDATED RULES")
print(f"{'=' * 100}")

with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print(f"\n✅ Service Mapping Complete!")
print(f"✅ Services Mapped: {services_mapped}")
print(f"✅ Rules Transformed: {rules_changed}")
print(f"✅ Backup: {backup_file}")
print(f"\n{'=' * 100}")

