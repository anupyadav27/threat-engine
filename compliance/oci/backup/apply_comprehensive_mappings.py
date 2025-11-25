#!/usr/bin/env python3
"""
Apply Comprehensive OCI Service Mappings (Phase 1 + Phase 2)
Final transformation of all service names to OCI SDK standards
"""

import yaml
from datetime import datetime
from collections import Counter
from comprehensive_oci_mappings import COMPREHENSIVE_OCI_SERVICE_MAPPINGS

print("=" * 100)
print("APPLYING COMPREHENSIVE OCI SERVICE MAPPINGS")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")
print(f"Total Service Mappings Available: {len(COMPREHENSIVE_OCI_SERVICE_MAPPINGS)}")

# Backup
backup_file = f"rule_ids_BACKUP_COMPREHENSIVE_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"Creating backup: {backup_file}")
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

# Apply mappings
updated_rules = []
changes = Counter()
service_changes = {}

for rule in rules:
    parts = rule.split('.')
    
    if len(parts) >= 4:
        csp = parts[0]
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:])
        
        if service in COMPREHENSIVE_OCI_SERVICE_MAPPINGS:
            new_service = COMPREHENSIVE_OCI_SERVICE_MAPPINGS[service]
            new_rule = f"{csp}.{new_service}.{resource}.{assertion}"
            updated_rules.append(new_rule)
            
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

# Top 20 service changes
print(f"\n{'=' * 100}")
print("TOP 20 SERVICE TRANSFORMATIONS")
print(f"{'=' * 100}")

sorted_services = sorted(service_changes.items(), key=lambda x: x[1]['count'], reverse=True)
for service, details in sorted_services[:20]:
    print(f"{service:60s} → {details['target']:25s} {details['count']:4d} rules")
    print(f"  Example: {details['example']}")
    print()

# Update metadata
data['rule_ids'] = updated_rules
data['metadata']['total_rules'] = len(updated_rules)
data['metadata']['last_comprehensive_mapping'] = datetime.now().isoformat()
data['metadata']['comprehensive_mapping_phase'] = 'complete'
data['metadata']['services_mapped'] = services_mapped
data['metadata']['rules_transformed'] = rules_changed

# Save
print(f"{'=' * 100}")
print("SAVING UPDATED RULES")
print(f"{'=' * 100}")

with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

# Generate detailed report
report = []
report.append("=" * 100)
report.append("COMPREHENSIVE OCI SERVICE MAPPING REPORT")
report.append("=" * 100)
report.append(f"\nGenerated: {datetime.now().isoformat()}")
report.append(f"\nTotal Rules: {len(rules)}")
report.append(f"Services Mapped: {services_mapped}")
report.append(f"Rules Transformed: {rules_changed} ({rules_changed/len(rules)*100:.1f}%)")
report.append(f"Rules Unchanged: {len(rules) - rules_changed} ({(len(rules) - rules_changed)/len(rules)*100:.1f}%)")
report.append("\n" + "=" * 100)
report.append("ALL SERVICE TRANSFORMATIONS")
report.append("=" * 100)

for service, details in sorted_services:
    report.append(f"\n{service} → {details['target']} ({details['count']} rules)")
    report.append(f"  Example: {details['example']}")

report_text = '\n'.join(report)
with open('COMPREHENSIVE_MAPPING_REPORT.txt', 'w') as f:
    f.write(report_text)

print(f"\n✅ Comprehensive Mapping Complete!")
print(f"✅ Services Mapped: {services_mapped}")
print(f"✅ Rules Transformed: {rules_changed}")
print(f"✅ Backup: {backup_file}")
print(f"✅ Report: COMPREHENSIVE_MAPPING_REPORT.txt")
print(f"\n{'=' * 100}")

