#!/usr/bin/env python3
"""
Kubernetes - FINAL Ultra-Aggressive Deduplication
Remove ALL remaining semantic duplicates with maximum normalization
"""

import yaml
import re
from datetime import datetime
from collections import defaultdict

print("=" * 100)
print("KUBERNETES - FINAL ULTRA-AGGRESSIVE DEDUPLICATION")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nInitial rules: {len(rules)}")

# Backup
backup_file = f"rule_ids_BACKUP_ULTRA_DEDUP_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"Creating backup: {backup_file}")
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

def ultra_normalize(rule):
    """
    Most aggressive normalization - extract the absolute core concept
    Handles plurals, validation suffixes, complex patterns
    """
    parts = rule.split('.')
    if len(parts) < 4 or parts[0] != 'k8s':
        return (rule, None, 999, rule)
    
    csp, service, resource = parts[0], parts[1], parts[2]
    assertion = '.'.join(parts[3:])
    
    # Status scores (higher = better)
    status_scores = {
        'enforced': 100,
        'enabled': 80,
        'configured': 60,
        'required': 60,
        'restricted': 60,
        'disabled': 60,
        'prohibited': 60,
        'validated': 40,
        'audited': 20,
    }
    
    # Detect status
    detected_status = None
    for status in status_scores.keys():
        if assertion.endswith(f'_{status}'):
            detected_status = status
            break
    
    # Ultra normalization - remove EVERYTHING except core concept
    base = assertion
    
    # Remove all validation patterns (any_words_status at end)
    base = re.sub(r'_[a-z_]+_(validated|enforced|enabled|configured|audited|restricted|required)$', '', base)
    
    # Remove status suffixes
    for status in status_scores.keys():
        base = re.sub(f'_{status}$', '', base)
    
    # Normalize plurals (e.g., "pv_access_modes" → "pv_access_mode")
    base = re.sub(r'_modes(_|$)', r'_mode\1', base)
    base = re.sub(r'_policies(_|$)', r'_policy\1', base)
    base = re.sub(r'_rules(_|$)', r'_rule\1', base)
    base = re.sub(r'_alerts(_|$)', r'_alert\1', base)
    base = re.sub(r'_events(_|$)', r'_event\1', base)
    base = re.sub(r'_bindings(_|$)', r'_binding\1', base)
    
    # Remove duplicate words
    words = base.split('_')
    seen = {}
    cleaned = []
    for i, word in enumerate(words):
        # Keep word if not seen, or if it's far from last occurrence
        if word not in seen or (i - seen[word] > 2):
            cleaned.append(word)
            seen[word] = i
        # Skip if it's a repeat
    
    base = '_'.join(cleaned)
    
    # Clean up
    base = re.sub(r'_+', '_', base)
    base = base.strip('_')
    
    ultra_base = f"{csp}.{service}.{resource}.{base}"
    
    # Complexity score (lower = simpler = better)
    complexity = len(assertion) - status_scores.get(detected_status, 0)
    
    return (ultra_base, detected_status, complexity, rule)

# Group by ultra base
groups = defaultdict(list)

for rule in rules:
    base, status, complexity, original = ultra_normalize(rule)
    groups[base].append((status, complexity, original))

# For each group, keep ONLY the best one
status_priority = {
    'enforced': 100,
    'enabled': 80,
    'configured': 60,
    'required': 60,
    'restricted': 60,
    'disabled': 60,
    'prohibited': 60,
    'validated': 40,
    'audited': 20,
    None: 0
}

deduplicated_rules = []
removed_count = 0
removal_details = []

for base, variants in sorted(groups.items()):
    if len(variants) == 1:
        deduplicated_rules.append(variants[0][2])
    else:
        # Sort by: 1) status priority (higher), 2) complexity (lower), 3) length (shorter)
        sorted_variants = sorted(variants, 
                                key=lambda x: (-status_priority.get(x[0], 0), x[1], len(x[2])))
        
        best_rule = sorted_variants[0][2]
        deduplicated_rules.append(best_rule)
        
        # Log removals
        for status, complexity, rule in sorted_variants[1:]:
            removed_count += 1
            removal_details.append((base, rule, best_rule))

# Results
print(f"\n{'=' * 100}")
print("ULTRA-AGGRESSIVE DEDUPLICATION RESULTS")
print(f"{'=' * 100}")

print(f"\nInitial rules:     {len(rules)}")
print(f"Final rules:       {len(deduplicated_rules)}")
print(f"Rules removed:     {removed_count}")
print(f"Reduction:         {removed_count/len(rules)*100:.1f}%")

if removal_details:
    print(f"\n{'=' * 100}")
    print(f"ALL REMOVED DUPLICATES ({len(removal_details)} total)")
    print(f"{'=' * 100}\n")
    
    for i, (base, removed, kept) in enumerate(removal_details, 1):
        print(f"{i}. REMOVED: {removed}")
        print(f"   KEPT:    {kept}")
        print(f"   BASE:    {base}\n")

# Update metadata
data['rule_ids'] = deduplicated_rules
data['metadata']['total_rules'] = len(deduplicated_rules)
data['metadata']['last_ultra_deduplication'] = datetime.now().isoformat()
data['metadata']['ultra_duplicates_removed'] = removed_count

# Save
print(f"{'=' * 100}")
print("SAVING ULTRA-DEDUPLICATED RULES")
print(f"{'=' * 100}")

with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print(f"\n✅ Ultra-Aggressive Deduplication Complete!")
print(f"✅ Rules removed: {removed_count}")
print(f"✅ Final rules: {len(deduplicated_rules)}")
print(f"✅ Backup: {backup_file}")
print(f"\n{'=' * 100}")

