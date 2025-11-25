#!/usr/bin/env python3
"""
Remove Duplicate Rules from IBM Cloud CSPM
Identify and remove identical rule entries
"""

import yaml
from datetime import datetime
from collections import Counter

print("=" * 100)
print("IBM CLOUD RULE DEDUPLICATION")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules (before): {len(rules)}")

# Backup
backup_file = f"rule_ids_BACKUP_DEDUP_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"Creating backup: {backup_file}")
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

# Find duplicates
rule_counts = Counter(rules)
duplicates = {rule: count for rule, count in rule_counts.items() if count > 1}

print(f"\n{'=' * 100}")
print("DUPLICATE ANALYSIS")
print(f"{'=' * 100}")

print(f"\nUnique Rules: {len(rule_counts)}")
print(f"Duplicate Rules: {len(duplicates)}")
print(f"Total Duplicate Instances: {sum(count - 1 for count in duplicates.values())}")

if duplicates:
    print(f"\n{'=' * 100}")
    print("TOP 20 MOST DUPLICATED RULES")
    print(f"{'=' * 100}")
    
    for rule, count in sorted(duplicates.items(), key=lambda x: x[1], reverse=True)[:20]:
        print(f"{count:3d} instances: {rule[:90]}")
    
    # Remove duplicates (keep first occurrence)
    unique_rules = []
    seen = set()
    duplicates_removed = 0
    
    for rule in rules:
        if rule not in seen:
            unique_rules.append(rule)
            seen.add(rule)
        else:
            duplicates_removed += 1
    
    # Update data
    data['rule_ids'] = unique_rules
    data['metadata']['total_rules'] = len(unique_rules)
    data['metadata']['last_deduplication'] = datetime.now().isoformat()
    data['metadata']['duplicates_removed'] = duplicates_removed
    data['metadata']['duplicate_reduction_percent'] = round(duplicates_removed / len(rules) * 100, 2)
    
    # Save
    print(f"\n{'=' * 100}")
    print("DEDUPLICATION RESULTS")
    print(f"{'=' * 100}")
    
    print(f"\nRules before:          {len(rules)}")
    print(f"Rules after:           {len(unique_rules)}")
    print(f"Duplicates removed:    {duplicates_removed} ({duplicates_removed/len(rules)*100:.1f}%)")
    
    print(f"\n{'=' * 100}")
    print("SAVING DEDUPLICATED RULES")
    print(f"{'=' * 100}")
    
    with open('rule_ids.yaml', 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    
    print(f"\n✅ Deduplication Complete!")
    print(f"✅ Unique Rules: {len(unique_rules)}")
    print(f"✅ Duplicates Removed: {duplicates_removed}")
    print(f"✅ Backup: {backup_file}")
else:
    print("\n✅ No duplicates found! All rules are unique.")

print(f"\n{'=' * 100}")

