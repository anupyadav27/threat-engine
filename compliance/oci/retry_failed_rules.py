#!/usr/bin/env python3
"""
OCI CSPM Rule Enhancement - Retry Failed Rules using GPT-4o
"""

import yaml
import os
import sys
import json
import time
from datetime import datetime
from openai import OpenAI

# Configuration
OPENAI_API_KEY = "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"
INPUT_FILE = "rule_ids_ENRICHED_AI_ENHANCED.yaml"
OUTPUT_FILE = "rule_ids_ENRICHED_AI_ENHANCED.yaml"
FAILED_RULES_FILE = "enhancement_progress_oci.json"
BATCH_SIZE = 5
MODEL = "gpt-4o"

# Initialize OpenAI client
client = OpenAI(api_key=OPENAI_API_KEY)

def load_yaml(filename):
    """Load YAML file"""
    print(f"Loading {filename}...")
    with open(filename, 'r') as f:
        return yaml.safe_load(f)

def save_yaml(data, filename):
    """Save YAML file"""
    print(f"Saving to {filename}...")
    with open(filename, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True, width=1000)

def load_failed_rules():
    """Load list of failed rule IDs"""
    if os.path.exists(FAILED_RULES_FILE):
        with open(FAILED_RULES_FILE, 'r') as f:
            data = json.load(f)
            return data.get('failed_rules', [])
    return []

def enhance_rule_with_gpt4o(rule, retry_count=3):
    """Enhance a single rule using GPT-4o"""
    
    prompt = f"""You are a Cloud Security Posture Management (CSPM) expert specializing in Oracle Cloud Infrastructure (OCI) security.

Enhance this OCI security rule with high-quality, specific, and actionable content:

**Rule ID**: {rule['rule_id']}
**Service**: {rule['service']}
**Resource**: {rule['resource']}
**Requirement**: {rule['requirement']}
**Severity**: {rule['severity']}
**Domain**: {rule['domain']}
**Subcategory**: {rule['subcategory']}
**Scope**: {rule['scope']}

Provide enhanced content in the following JSON format:
{{
  "title": "Concise, clear title (max 80 chars)",
  "rationale": "WHY this matters - explain business impact, security risks, threat scenarios, and compliance requirements (2-4 sentences)",
  "description": "WHAT this checks - technical details, specific configuration settings, how to verify, and remediation guidance (3-5 sentences)",
  "references": [
    "Specific OCI documentation URL",
    "Relevant CIS OCI Benchmark reference (if applicable)",
    "Compliance framework (NIST, PCI-DSS, HIPAA, SOC2, ISO 27001 as applicable)",
    "Additional security best practice resources (max 6 total)"
  ]
}}

Requirements:
- Title: Short, professional, no redundant "OCI SERVICE Resource:" prefix
- Rationale: Focus on business value, risk scenarios, regulatory impact
- Description: Technical specifics, configuration details, actionable guidance
- References: Real, relevant URLs and standards (no fake links)
- Make content specific to the OCI service, resource, and requirement
- For unusual or AWS-style terminology (like fargate, workgroup, cdn), interpret it in OCI context or use generic cloud security best practices
- Avoid generic statements like "ensures security compliance"
- Use proper security terminology

Respond with ONLY the JSON object, no markdown formatting or extra text."""

    for attempt in range(retry_count):
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
            
            # Validate response structure
            required_keys = ['title', 'rationale', 'description', 'references']
            if all(key in result for key in required_keys):
                return result
            else:
                print(f"  ⚠️  Missing keys in response, retrying... (attempt {attempt + 1})")
                
        except Exception as e:
            print(f"  ❌ Error on attempt {attempt + 1}: {str(e)}")
            if attempt < retry_count - 1:
                time.sleep(2 ** attempt)
            else:
                return None
    
    return None

def main():
    print("=" * 80)
    print("OCI CSPM Rule Enhancement - RETRY FAILED RULES - GPT-4o")
    print("=" * 80)
    
    # Load data
    data = load_yaml(INPUT_FILE)
    rules = data['rules']
    
    # Load failed rule IDs
    failed_rule_ids = load_failed_rules()
    
    if not failed_rule_ids:
        print("\n✅ No failed rules to retry!")
        return
    
    print(f"\nTotal failed rules to retry: {len(failed_rule_ids)}")
    
    # Find failed rules in the rules list
    failed_rules = []
    rule_id_to_index = {}
    
    for idx, rule in enumerate(rules):
        if rule['rule_id'] in failed_rule_ids:
            failed_rules.append(rule)
            rule_id_to_index[rule['rule_id']] = idx
    
    print(f"Found {len(failed_rules)} failed rules in the YAML file")
    
    total_enhanced = 0
    total_failed = 0
    still_failed = []
    
    print(f"\nStarting retry process...")
    print(f"Model: {MODEL}")
    print(f"Batch size: {BATCH_SIZE}")
    
    start_time = time.time()
    
    # Process failed rules
    for i, rule in enumerate(failed_rules):
        rule_id = rule['rule_id']
        
        print(f"\n[{i+1}/{len(failed_rules)}] Retrying: {rule_id}")
        
        enhanced = enhance_rule_with_gpt4o(rule)
        
        if enhanced:
            # Update rule with enhanced content
            idx = rule_id_to_index[rule_id]
            rules[idx]['title'] = enhanced['title']
            rules[idx]['rationale'] = enhanced['rationale']
            rules[idx]['description'] = enhanced['description']
            rules[idx]['references'] = enhanced['references']
            
            total_enhanced += 1
            print(f"  ✓ Enhanced successfully")
        else:
            total_failed += 1
            still_failed.append(rule_id)
            print(f"  ✗ Still failed")
        
        # Save progress every 10 rules
        if (i + 1) % 10 == 0:
            data['rules'] = rules
            data['statistics']['enhanced'] = data['statistics']['enhanced'] + total_enhanced
            data['statistics']['failed'] = len(still_failed)
            save_yaml(data, OUTPUT_FILE)
            print(f"\n  💾 Progress saved: {total_enhanced} recovered, {total_failed} still failed")
        
        # Small delay to respect rate limits
        time.sleep(0.5)
    
    # Final save
    elapsed_time = time.time() - start_time
    
    data['rules'] = rules
    original_enhanced = data['statistics'].get('enhanced', 0)
    data['statistics']['enhanced'] = original_enhanced + total_enhanced
    data['statistics']['failed'] = len(still_failed)
    data['metadata']['enhancement_date'] = datetime.now().strftime('%Y-%m-%d')
    
    save_yaml(data, OUTPUT_FILE)
    
    print(f"\n{'='*80}")
    print("RETRY COMPLETE!")
    print(f"{'='*80}")
    print(f"Original failures: {len(failed_rule_ids)}")
    print(f"Successfully recovered: {total_enhanced}")
    print(f"Still failed: {total_failed}")
    print(f"Success rate: {(total_enhanced/len(failed_rule_ids))*100:.1f}%")
    print(f"Time elapsed: {elapsed_time/60:.1f} minutes")
    print(f"\nOutput saved to: {OUTPUT_FILE}")
    
    # Update progress file
    if os.path.exists(FAILED_RULES_FILE):
        with open(FAILED_RULES_FILE, 'r') as f:
            progress = json.load(f)
        progress['failed_rules'] = still_failed
        with open(FAILED_RULES_FILE, 'w') as f:
            json.dump(progress, f, indent=2)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Process interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

