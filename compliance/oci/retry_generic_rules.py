#!/usr/bin/env python3
"""
Find and retry rules that still have generic/template content
"""

import yaml
import json
from openai import OpenAI
import time

OPENAI_API_KEY = "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"
INPUT_FILE = "rule_ids_ENRICHED_AI_ENHANCED.yaml"
OUTPUT_FILE = "rule_ids_ENRICHED_AI_ENHANCED.yaml"
MODEL = "gpt-4o"

client = OpenAI(api_key=OPENAI_API_KEY)

def load_yaml(filename):
    with open(filename, 'r') as f:
        return yaml.safe_load(f)

def save_yaml(data, filename):
    with open(filename, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=1000)

def is_generic_content(rule):
    """Check if rule has generic/template content"""
    title = rule.get('title', '')
    rationale = rule.get('rationale', '')
    description = rule.get('description', '')
    
    # Check for generic patterns
    generic_patterns = [
        'properly configured for security compliance',
        'configured according to security best practices',
        'OCI CONTAINER_ENGINE',
        'OCI RESOURCE_MANAGER',
        'OCI DATABASE',
        'OCI COMPUTE',
        'This control is essential'
    ]
    
    for pattern in generic_patterns:
        if pattern in title or pattern in rationale or pattern in description:
            return True
    return False

def enhance_rule(rule):
    """Enhance a single rule using GPT-4o"""
    prompt = f"""You are a Cloud Security Posture Management (CSPM) expert specializing in Oracle Cloud Infrastructure (OCI) security.

Enhance this OCI security rule with high-quality, specific, and actionable content:

**Rule ID**: {rule['rule_id']}
**Service**: {rule['service']}
**Resource**: {rule['resource']}
**Requirement**: {rule['requirement']}
**Severity**: {rule['severity']}
**Domain**: {rule['domain']}

Provide enhanced content in JSON format:
{{
  "title": "Clear, concise title (max 80 chars, no 'OCI SERVICE Resource:' prefix)",
  "rationale": "WHY this matters - business impact, security risks, compliance (2-4 sentences)",
  "description": "WHAT this checks - technical details, verification, remediation (3-5 sentences)",
  "references": [
    "Specific OCI documentation URLs",
    "CIS OCI Benchmark references if applicable",
    "Compliance frameworks (NIST, PCI-DSS, HIPAA, SOC2, ISO 27001)",
    "Security best practice resources (max 6 total)"
  ]
}}

Make it specific to OCI. For AWS-style terms (fargate, workgroup), interpret them as generic cloud concepts or OCI equivalents.

Respond with ONLY the JSON object."""

    try:
        response = client.chat.completions.create(
            model=MODEL,
            messages=[
                {"role": "system", "content": "You are an OCI security expert. Respond only with valid JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,
            max_tokens=1500,
            response_format={"type": "json_object"}
        )
        
        result = json.loads(response.choices[0].message.content)
        
        if all(key in result for key in ['title', 'rationale', 'description', 'references']):
            return result
    except Exception as e:
        print(f"  ❌ Error: {str(e)}")
    
    return None

print("="*80)
print("OCI CSPM - RETRY GENERIC/FAILED RULES")
print("="*80)

data = load_yaml(INPUT_FILE)
rules = data['rules']

print(f"\nScanning {len(rules)} rules for generic content...")

generic_rules = []
for idx, rule in enumerate(rules):
    if is_generic_content(rule):
        generic_rules.append((idx, rule))

print(f"Found {len(generic_rules)} rules with generic content to enhance")

if len(generic_rules) == 0:
    print("\n✅ No generic rules found! All rules are properly enhanced.")
    exit(0)

print(f"\nStarting enhancement...")

enhanced_count = 0
failed_count = 0

for i, (idx, rule) in enumerate(generic_rules):
    rule_id = rule['rule_id']
    print(f"\n[{i+1}/{len(generic_rules)}] Enhancing: {rule_id}")
    
    enhanced = enhance_rule(rule)
    
    if enhanced:
        rules[idx]['title'] = enhanced['title']
        rules[idx]['rationale'] = enhanced['rationale']
        rules[idx]['description'] = enhanced['description']
        rules[idx]['references'] = enhanced['references']
        enhanced_count += 1
        print(f"  ✓ Enhanced")
    else:
        failed_count += 1
        print(f"  ✗ Failed")
    
    # Save every 10 rules
    if (i + 1) % 10 == 0:
        data['rules'] = rules
        data['statistics']['enhanced'] = data['statistics'].get('enhanced', 0) + enhanced_count
        save_yaml(data, OUTPUT_FILE)
        print(f"\n  💾 Progress saved: {enhanced_count} enhanced, {failed_count} failed")
    
    time.sleep(0.5)

# Final save
data['rules'] = rules
original_enhanced = data['statistics'].get('enhanced', 0)
data['statistics']['enhanced'] = original_enhanced + enhanced_count
data['statistics']['failed'] = failed_count

save_yaml(data, OUTPUT_FILE)

print(f"\n{'='*80}")
print("RETRY COMPLETE!")
print(f"{'='*80}")
print(f"Rules processed: {len(generic_rules)}")
print(f"Successfully enhanced: {enhanced_count}")
print(f"Failed: {failed_count}")
print(f"Success rate: {(enhanced_count/len(generic_rules))*100:.1f}%")
print(f"\nOutput saved to: {OUTPUT_FILE}")











