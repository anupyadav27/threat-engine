#!/usr/bin/env python3
"""Extract verified rules and their URLs from the log"""

import re
import json

log_file = "alicloud_intelligent.log"
output_file = "alicloud/final/VERIFIED_URLS_SO_FAR.json"

verified_rules = []

with open(log_file, 'r') as f:
    content = f.read()

# Find all processed rules and their outcomes
pattern = r'🔍 (alicloud\.[^:]+):.*?(?=🔍 alicloud\.|$)'
matches = re.findall(pattern, content, re.DOTALL)

for match in matches:
    rule_id = match.strip()
    
    # Find the section for this rule
    rule_section = content[content.find(f"🔍 {rule_id}"):content.find(f"🔍 {rule_id}") + 2000]
    
    # Check outcome
    if "✅ MATCH!" in rule_section:
        # Extract the matched URL
        url_match = re.search(r'🧪 Testing: (https://[^\s]+)', rule_section)
        if url_match:
            verified_rules.append({
                'rule_id': rule_id,
                'status': 'MATCHED',
                'url': url_match.group(1),
                'method': 'search_found'
            })
    elif "📚 Using fallback:" in rule_section:
        # Extract fallback URL
        fallback_match = re.search(r'📚 Using fallback: (https://[^\s]+)', rule_section)
        if fallback_match:
            verified_rules.append({
                'rule_id': rule_id,
                'status': 'FALLBACK',
                'url': fallback_match.group(1),
                'method': 'verified_fallback'
            })

# Save
report = {
    'timestamp': 'in_progress',
    'total_processed': len(verified_rules),
    'matched': sum(1 for r in verified_rules if r['status'] == 'MATCHED'),
    'fallback': sum(1 for r in verified_rules if r['status'] == 'FALLBACK'),
    'rules': verified_rules
}

with open(output_file, 'w') as f:
    json.dump(report, f, indent=2)

print(f"✅ Extracted {len(verified_rules)} verified rules")
print(f"📁 Saved to: {output_file}")
print(f"\nBreakdown:")
print(f"  Matched (search found): {report['matched']}")
print(f"  Fallback (verified):    {report['fallback']}")

# Show sample
print(f"\n📋 Sample (last 5):")
for rule in verified_rules[-5:]:
    print(f"  {rule['rule_id'][:60]}")
    print(f"    → {rule['url'][:70]}")
    print(f"    → Status: {rule['status']}")
    print()

