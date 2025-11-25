#!/usr/bin/env python3
"""
Fix OCI rules to ensure proper 4-part format: oci.service.resource.assertion
Consolidates rules with 5+ parts by merging extra parts into the assertion
"""

import yaml
from datetime import datetime

# Load rules
print("=" * 80)
print("FIXING OCI RULE FORMAT")
print("=" * 80)

with open('rule_ids.yaml', 'r') as f:
    data = yaml.safe_load(f)

rules = data['rule_ids']
print(f"\nTotal Rules: {len(rules)}")

# Backup
backup_file = f"rule_ids_BACKUP_FORMAT_FIX_{datetime.now().strftime('%Y%m%d_%H%M%S')}.yaml"
print(f"Creating backup: {backup_file}")
with open(backup_file, 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

# Fix rules
fixed_rules = []
fixed_count = 0

for rule in rules:
    parts = rule.split('.')
    
    if len(parts) == 4:
        # Already correct format
        fixed_rules.append(rule)
    elif len(parts) > 4:
        # Too many parts - consolidate into 4
        # Format: oci.service.resource.assertion1.assertion2.assertion3...
        # Keep: oci.service.resource.assertion1_assertion2_assertion3
        
        csp = parts[0]  # oci
        service = parts[1]
        resource = parts[2]
        assertion = '_'.join(parts[3:])  # Join remaining parts with underscore
        
        new_rule = f"{csp}.{service}.{resource}.{assertion}"
        fixed_rules.append(new_rule)
        fixed_count += 1
        
        print(f"\n  Fixed:")
        print(f"    OLD: {rule}")
        print(f"    NEW: {new_rule}")
    else:
        # Less than 4 parts - shouldn't happen but keep as is
        fixed_rules.append(rule)

# Update metadata
data['rule_ids'] = fixed_rules
data['metadata']['total_rules'] = len(fixed_rules)
data['metadata']['last_format_fix'] = datetime.now().isoformat()

# Save fixed rules
print(f"\n{'='*80}")
print("SAVING FIXED RULES")
print(f"{'='*80}")

with open('rule_ids.yaml', 'w') as f:
    yaml.dump(data, f, default_flow_style=False, sort_keys=False)

print(f"\n✅ Fixed: {fixed_count} rules")
print(f"✅ Total: {len(fixed_rules)} rules")
print(f"✅ All rules now in format: oci.service.resource.assertion")
print(f"\n{'='*80}")

