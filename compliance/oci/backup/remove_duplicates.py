#!/usr/bin/env python3
"""
Identify and Remove Duplicate Rules
After normalization, many rules may have become identical
"""

import yaml
from datetime import datetime
from collections import Counter

print("=" * 100)
print("DUPLICATE RULE ANALYSIS & REMOVAL")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules (Before): {len(rules)}")

# Find duplicates
rule_counts = Counter(rules)
duplicates = {rule: count for rule, count in rule_counts.items() if count > 1}

print(f"Unique Rules: {len(rule_counts)}")
print(f"Duplicate Rules Found: {len(duplicates)}")
print(f"Total Duplicate Instances: {sum(count - 1 for count in duplicates.values())}")

# Show duplicate examples
print(f"\n{'=' * 100}")
print("TOP 20 MOST DUPLICATED RULES")
print(f"{'=' * 100}")

for rule, count in sorted(duplicates.items(), key=lambda x: x[1], reverse=True)[:20]:
    parts = rule.split('.')
    if len(parts) >= 4:
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:])
        print(f"\n{count}x duplicates:")
        print(f"  Service:   {service}")
        print(f"  Resource:  {resource}")
        print(f"  Assertion: {assertion[:80]}")
        print(f"  Full:      {rule}")

# Backup
backup_file = f"rule_ids_BACKUP_DEDUP_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"\n{'=' * 100}")
print(f"Creating backup: {backup_file}")
print(f"{'=' * 100}")

with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

# Remove duplicates (keep first occurrence)
unique_rules = []
seen = set()

for rule in rules:
    if rule not in seen:
        unique_rules.append(rule)
        seen.add(rule)

# Statistics by service
print(f"\n{'=' * 100}")
print("DUPLICATES BY SERVICE")
print(f"{'=' * 100}")

service_duplicates = {}
for rule, count in duplicates.items():
    parts = rule.split('.')
    if len(parts) >= 2:
        service = parts[1]
        if service not in service_duplicates:
            service_duplicates[service] = []
        service_duplicates[service].append((rule, count))

for service in sorted(service_duplicates.keys(), 
                     key=lambda s: sum(count - 1 for _, count in service_duplicates[s]), 
                     reverse=True):
    total_removed = sum(count - 1 for _, count in service_duplicates[service])
    print(f"{service:30s} {len(service_duplicates[service]):3d} duplicate rules, {total_removed:3d} instances removed")

# Update data
data['rule_ids'] = unique_rules
data['metadata']['total_rules'] = len(unique_rules)
data['metadata']['last_deduplication'] = datetime.now().isoformat()
data['metadata']['deduplication_phase'] = 'complete'
data['metadata']['duplicates_removed'] = len(rules) - len(unique_rules)

# Save
print(f"\n{'=' * 100}")
print("SAVING DEDUPLICATED RULES")
print(f"{'=' * 100}")

with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print(f"\n{'=' * 100}")
print("DEDUPLICATION COMPLETE")
print(f"{'=' * 100}")
print(f"Total Rules (Before):     {len(rules)}")
print(f"Unique Rules (After):     {len(unique_rules)}")
print(f"Duplicates Removed:       {len(rules) - len(unique_rules)}")
print(f"Reduction:                {(len(rules) - len(unique_rules))/len(rules)*100:.1f}%")
print(f"\n✅ Backup: {backup_file}")
print(f"✅ Updated: rule_ids.yaml")
print(f"\n{'=' * 100}")

