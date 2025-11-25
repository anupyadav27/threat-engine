#!/usr/bin/env python3
"""
Standardize IBM Cloud Rule Assertions
Convert to enterprise-grade snake_case format: [parameter]_[desired_status]
"""

import yaml
import re
from datetime import datetime
from collections import Counter

print("=" * 100)
print("IBM CLOUD ASSERTION STANDARDIZATION")
print("=" * 100)

# Load rules
with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")

# Backup
backup_file = f"rule_ids_BACKUP_ASSERTION_STD_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"Creating backup: {backup_file}")
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

def standardize_assertion(assertion):
    """
    Standardize assertion to enterprise-grade format
    Rules:
    1. Remove redundant prefixes (security_, check_, policy_, etc.)
    2. Remove duplicate words
    3. Ensure snake_case
    4. Keep it concise and clear
    5. Format: [parameter]_[desired_status]
    """
    if not assertion:
        return assertion
    
    original = assertion
    
    # Remove common redundant prefixes (only at the start)
    prefixes_to_remove = [
        'security_', 'check_', 'policy_', 'ensure_', 'verify_',
        'validate_', 'should_', 'must_', 'requires_'
    ]
    for prefix in prefixes_to_remove:
        if assertion.startswith(prefix):
            assertion = assertion[len(prefix):]
            break  # Only remove one prefix
    
    # Split into words
    words = assertion.split('_')
    
    # Remove duplicate consecutive words
    unique_words = []
    prev = None
    for word in words:
        if word != prev:
            unique_words.append(word)
        prev = word
    
    # Rejoin
    assertion = '_'.join(unique_words)
    
    # If assertion is too long (> 80 chars), try to shorten
    if len(assertion) > 80:
        # This is likely a very long descriptive assertion
        # Keep the last part which usually has the status
        parts = assertion.split('_')
        if len(parts) > 10:
            # Take first 3-4 words and last 2-3 words
            assertion = '_'.join(parts[:4] + ['...'] + parts[-3:])
    
    return assertion

# Apply assertion standardization
updated_rules = []
changes = Counter()
improved_count = 0

for rule in rules:
    parts = rule.split('.')
    
    if len(parts) >= 4:
        csp = parts[0]
        service = parts[1]
        resource = parts[2]
        assertion = '.'.join(parts[3:])
        
        # Standardize assertion
        new_assertion = standardize_assertion(assertion)
        
        # Build new rule
        new_rule = f"{csp}.{service}.{resource}.{new_assertion}"
        updated_rules.append(new_rule)
        
        if assertion != new_assertion:
            improved_count += 1
            changes[f"{len(assertion)} → {len(new_assertion)} chars"] += 1
    else:
        updated_rules.append(rule)

# Display results
print(f"\n{'=' * 100}")
print("TRANSFORMATION RESULTS")
print(f"{'=' * 100}")

print(f"\nRules with Assertions: {sum(1 for r in rules if len(r.split('.')) >= 4)}")
print(f"Assertions Improved: {improved_count} ({improved_count/len(rules)*100:.1f}%)")
print(f"Rules Unchanged: {len(rules) - improved_count} ({(len(rules) - improved_count)/len(rules)*100:.1f}%)")

# Calculate average assertion length before and after
before_lengths = []
after_lengths = []
for rule in rules:
    parts = rule.split('.')
    if len(parts) >= 4:
        before_lengths.append(len('.'.join(parts[3:])))

for rule in updated_rules:
    parts = rule.split('.')
    if len(parts) >= 4:
        after_lengths.append(len('.'.join(parts[3:])))

if before_lengths and after_lengths:
    avg_before = sum(before_lengths) / len(before_lengths)
    avg_after = sum(after_lengths) / len(after_lengths)
    print(f"\nAverage Assertion Length:")
    print(f"  Before: {avg_before:.1f} chars")
    print(f"  After:  {avg_after:.1f} chars")
    print(f"  Reduction: {avg_before - avg_after:.1f} chars ({(avg_before - avg_after)/avg_before*100:.1f}%)")

# Show examples
print(f"\n{'=' * 100}")
print("EXAMPLE TRANSFORMATIONS (First 20)")
print(f"{'=' * 100}")

example_count = 0
for old_rule, new_rule in zip(rules, updated_rules):
    if old_rule != new_rule and example_count < 20:
        old_parts = old_rule.split('.')
        new_parts = new_rule.split('.')
        if len(old_parts) >= 4 and len(new_parts) >= 4:
            old_assertion = '.'.join(old_parts[3:])
            new_assertion = '.'.join(new_parts[3:])
            print(f"\nBEFORE: {old_assertion}")
            print(f"AFTER:  {new_assertion}")
            example_count += 1

# Update metadata
data['rule_ids'] = updated_rules
data['metadata']['total_rules'] = len(updated_rules)
data['metadata']['last_assertion_standardization'] = datetime.now().isoformat()
data['metadata']['assertion_standardization_phase'] = 'enterprise_grade_complete'
data['metadata']['assertions_improved'] = improved_count

# Save
print(f"\n{'=' * 100}")
print("SAVING UPDATED RULES")
print(f"{'=' * 100}")

with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print(f"\n✅ Assertion Standardization Complete!")
print(f"✅ Assertions Improved: {improved_count}")
print(f"✅ Backup: {backup_file}")
print(f"\n{'=' * 100}")

