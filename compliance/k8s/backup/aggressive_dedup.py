#!/usr/bin/env python3
"""
Kubernetes - Aggressive Semantic Deduplication
Remove ALL semantic duplicates including complex validation patterns
Strategy: Keep only the BEST rule per unique security check
"""

import yaml
import re
from datetime import datetime
from collections import defaultdict

print("=" * 100)
print("KUBERNETES - AGGRESSIVE SEMANTIC DEDUPLICATION")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nInitial rules: {len(rules)}")

# Backup
backup_file = f"rule_ids_BACKUP_AGGRESSIVE_DEDUP_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"Creating backup: {backup_file}")
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

def normalize_to_base(rule):
    """
    Normalize a rule to its base form by removing ALL validation/status suffixes
    Returns: (base_rule, detected_status, complexity_score, original_rule)
    
    Complexity score: lower = simpler/better to keep
    """
    parts = rule.split('.')
    if len(parts) < 4 or parts[0] != 'k8s':
        return (rule, None, 999, rule)
    
    csp = parts[0]
    service = parts[1]
    resource = parts[2]
    assertion = '.'.join(parts[3:])
    
    # Status hierarchy (higher score = better to keep)
    status_scores = {
        'enforced': 100,
        'enabled': 80,
        'configured': 60,
        'required': 60,
        'validated': 40,
        'audited': 20,
    }
    
    # Remove ALL status/validation suffixes to find the true base
    base_assertion = assertion
    detected_status = None
    
    # Remove simple status suffixes
    for status in status_scores.keys():
        if base_assertion.endswith(f'_{status}'):
            detected_status = status
            base_assertion = base_assertion[:-len(f'_{status}')]
            break
    
    # Remove complex validation patterns like "_X_validated", "_X_enabled_validated", etc.
    # Pattern: "_anything_status" at the end
    if not detected_status:
        match = re.search(r'_([a-z_]+)_(validated|audited|enforced|enabled|configured|required)$', base_assertion)
        if match:
            detected_status = match.group(2)
            # Remove the entire validation suffix
            base_assertion = re.sub(r'_[a-z_]+_(validated|audited|enforced|enabled|configured|required)$', '', base_assertion)
    
    # Further normalization: remove duplicate parts
    # e.g., "mfa_enforced_mfa_enabled" → "mfa"
    parts_list = base_assertion.split('_')
    
    # Remove repeating words
    seen = set()
    cleaned = []
    for part in parts_list:
        if part not in seen or part in ['enabled', 'enforced', 'configured', 'required', 'validated', 'audited']:
            cleaned.append(part)
            seen.add(part)
    
    base_assertion = '_'.join(cleaned)
    
    # Remove remaining status words that might be embedded
    for status in ['enforced', 'enabled', 'configured', 'required', 'validated', 'audited']:
        base_assertion = base_assertion.replace(f'_{status}', '')
        base_assertion = base_assertion.replace(f'{status}_', '')
    
    # Clean up multiple underscores and trailing/leading underscores
    base_assertion = re.sub(r'_+', '_', base_assertion)
    base_assertion = base_assertion.strip('_')
    
    # Create normalized base rule
    base_rule = f"{csp}.{service}.{resource}.{base_assertion}"
    
    # Complexity score (lower = simpler = better)
    # Prefer shorter assertions and higher status
    complexity = len(assertion) - status_scores.get(detected_status, 0)
    
    return (base_rule, detected_status, complexity, rule)

# Group rules by their normalized base
groups = defaultdict(list)

for rule in rules:
    base, status, complexity, original = normalize_to_base(rule)
    groups[base].append((status, complexity, original))

# For each group, keep ONLY the best rule
deduplicated_rules = []
removed_count = 0
removal_details = []

status_priority = {
    'enforced': 5,
    'enabled': 4,
    'configured': 3,
    'required': 3,
    'validated': 2,
    'audited': 1,
    None: 0
}

for base, variants in sorted(groups.items()):
    if len(variants) == 1:
        # No duplicates
        deduplicated_rules.append(variants[0][2])
    else:
        # Multiple variants - keep the BEST one
        # Sort by: 1) status priority (higher better), 2) complexity (lower better)
        sorted_variants = sorted(variants, 
                                key=lambda x: (-status_priority.get(x[0], 0), x[1]))
        
        best_rule = sorted_variants[0][2]
        deduplicated_rules.append(best_rule)
        
        # Log all removed rules
        for status, complexity, rule in sorted_variants[1:]:
            removed_count += 1
            removal_details.append((base, rule, best_rule))

# Results
print(f"\n{'=' * 100}")
print("AGGRESSIVE DEDUPLICATION RESULTS")
print(f"{'=' * 100}")

print(f"\nInitial rules:     {len(rules)}")
print(f"Final rules:       {len(deduplicated_rules)}")
print(f"Rules removed:     {removed_count}")
print(f"Reduction:         {removed_count/len(rules)*100:.1f}%")

# Show samples of removed rules by category
print(f"\n{'=' * 100}")
print("SAMPLE REMOVED DUPLICATES (30 examples)")
print(f"{'=' * 100}\n")

for i, (base, removed, kept) in enumerate(removal_details[:30], 1):
    print(f"{i}. REMOVED: {removed}")
    print(f"   KEPT:    {kept}")
    print()

# Show duplicate group statistics
duplicate_groups = {k: v for k, v in groups.items() if len(v) > 1}
print(f"{'=' * 100}")
print(f"DUPLICATE GROUP STATISTICS")
print(f"{'=' * 100}")

group_sizes = defaultdict(int)
for base, variants in duplicate_groups.items():
    group_sizes[len(variants)] += 1

print(f"\nTotal duplicate groups: {len(duplicate_groups)}")
for size in sorted(group_sizes.keys(), reverse=True):
    count = group_sizes[size]
    print(f"  {size} variants per group: {count} groups")

# Update metadata
data['rule_ids'] = deduplicated_rules
data['metadata']['total_rules'] = len(deduplicated_rules)
data['metadata']['last_aggressive_deduplication'] = datetime.now().isoformat()
data['metadata']['aggressive_duplicates_removed'] = removed_count

# Save
print(f"\n{'=' * 100}")
print("SAVING DEDUPLICATED RULES")
print(f"{'=' * 100}")

with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print(f"\n✅ Aggressive Semantic Deduplication Complete!")
print(f"✅ Rules removed: {removed_count}")
print(f"✅ Final rules: {len(deduplicated_rules)}")
print(f"✅ Reduction: {removed_count/len(rules)*100:.1f}%")
print(f"✅ Backup: {backup_file}")
print(f"\n{'=' * 100}")

