#!/usr/bin/env python3
"""
Apply IBM Cloud Resource Normalization
Transform resource names to IBM SDK standards
"""

import yaml
from datetime import datetime
from collections import Counter
from ibm_resource_mappings import get_resource_name

print("=" * 100)
print("APPLYING IBM CLOUD RESOURCE NORMALIZATION")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")

# Backup
backup_file = f"rule_ids_BACKUP_RESOURCE_NORM_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"Creating backup: {backup_file}")
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

# Apply resource normalization
updated_rules = []
changes = Counter()
resource_changes = {}

for rule in rules:
    parts = rule.split('.')
    
    if len(parts) >= 3:
        csp = parts[0]
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:]) if len(parts) > 3 else ''
        
        # Get normalized resource name
        new_resource = get_resource_name(service, resource)
        
        # Build new rule
        if assertion:
            new_rule = f"{csp}.{service}.{new_resource}.{assertion}"
        else:
            new_rule = f"{csp}.{service}.{new_resource}"
        
        updated_rules.append(new_rule)
        
        if resource != new_resource:  # Only count if actually changed
            change_key = f"{resource} → {new_resource}"
            changes[change_key] += 1
            
            if resource not in resource_changes:
                resource_changes[resource] = {
                    'target': new_resource,
                    'count': 0,
                    'services': Counter(),
                    'example': rule
                }
            resource_changes[resource]['count'] += 1
            resource_changes[resource]['services'][service] += 1
    else:
        updated_rules.append(rule)

# Display results
print(f"\n{'=' * 100}")
print("TRANSFORMATION RESULTS")
print(f"{'=' * 100}")

rules_changed = sum(resource_changes[r]['count'] for r in resource_changes)
resources_mapped = len(resource_changes)

print(f"\nResources Mapped: {resources_mapped}")
print(f"Rules Changed: {rules_changed} ({rules_changed/len(rules)*100:.1f}%)")
print(f"Rules Unchanged: {len(rules) - rules_changed} ({(len(rules) - rules_changed)/len(rules)*100:.1f}%)")

# Top resource changes
print(f"\n{'=' * 100}")
print("TOP 30 RESOURCE TRANSFORMATIONS")
print(f"{'=' * 100}")

sorted_resources = sorted(resource_changes.items(), key=lambda x: x[1]['count'], reverse=True)
for resource, details in sorted_resources[:30]:
    print(f"{resource:60s} → {details['target']:30s} {details['count']:4d} rules")
    top_services = ', '.join([f"{svc}({cnt})" for svc, cnt in details['services'].most_common(3)])
    print(f"  Services: {top_services}")

# Generic 'resource' replacements
generic_fixed = resource_changes.get('resource', {}).get('count', 0)
if generic_fixed > 0:
    print(f"\n{'=' * 100}")
    print("GENERIC 'resource' REPLACEMENTS")
    print(f"{'=' * 100}")
    print(f"Generic 'resource' entries fixed: {generic_fixed}")
    print(f"\nBreakdown by service:")
    for service, count in resource_changes['resource']['services'].most_common(20):
        print(f"  {service:40s} {count:4d} rules")

# Update metadata
data['rule_ids'] = updated_rules
data['metadata']['total_rules'] = len(updated_rules)
data['metadata']['last_resource_normalization'] = datetime.now().isoformat()
data['metadata']['resource_normalization_phase'] = 'ibm_sdk_complete'
data['metadata']['resources_normalized'] = resources_mapped
data['metadata']['rules_resource_transformed'] = rules_changed

# Save
print(f"\n{'=' * 100}")
print("SAVING UPDATED RULES")
print(f"{'=' * 100}")

with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print(f"\n✅ Resource Normalization Complete!")
print(f"✅ Resources Mapped: {resources_mapped}")
print(f"✅ Rules Transformed: {rules_changed}")
print(f"✅ Backup: {backup_file}")
print(f"\n{'=' * 100}")

