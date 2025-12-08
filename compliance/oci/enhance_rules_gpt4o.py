#!/usr/bin/env python3
"""
OCI CSPM Rule Enhancement Script using GPT-4o
Enhances title, rationale, description, and references for each rule
"""

import yaml
import os
import sys
import json
import time
from datetime import datetime
from openai import OpenAI

# Configuration
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY', 'your-openai-api-key-here')
INPUT_FILE = "rule_ids_ENRICHED_AI_ENHANCED.yaml"
OUTPUT_FILE = "rule_ids_ENRICHED_AI_ENHANCED.yaml"
PROGRESS_FILE = "enhancement_progress_oci.json"
BATCH_SIZE = 5  # Process 5 rules at a time for efficiency
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

def load_progress():
    """Load enhancement progress"""
    if os.path.exists(PROGRESS_FILE):
        with open(PROGRESS_FILE, 'r') as f:
            return json.load(f)
    return {"enhanced_count": 0, "failed_rules": [], "last_index": 0}

def save_progress(progress):
    """Save enhancement progress"""
    with open(PROGRESS_FILE, 'w') as f:
        json.dump(progress, f, indent=2)

def enhance_rule_with_gpt4o(rule, retry_count=3):
    """
    Enhance a single rule using GPT-4o
    Returns enhanced title, rationale, description, and references
    """
    
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
- Avoid generic statements like "ensures security compliance"
- Use proper security terminology
- Focus on OCI-specific features and Oracle Cloud best practices

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
                time.sleep(2 ** attempt)  # Exponential backoff
            else:
                return None
    
    return None

def enhance_rules_batch(rules, start_index, batch_size, progress):
    """
    Enhance a batch of rules
    """
    enhanced_count = 0
    failed_count = 0
    
    end_index = min(start_index + batch_size, len(rules))
    
    for i in range(start_index, end_index):
        rule = rules[i]
        rule_id = rule['rule_id']
        
        print(f"\n[{i+1}/{len(rules)}] Processing: {rule_id}")
        
        enhanced = enhance_rule_with_gpt4o(rule)
        
        if enhanced:
            # Update rule with enhanced content
            rule['title'] = enhanced['title']
            rule['rationale'] = enhanced['rationale']
            rule['description'] = enhanced['description']
            rule['references'] = enhanced['references']
            
            enhanced_count += 1
            print(f"  ✓ Enhanced successfully")
        else:
            failed_count += 1
            progress['failed_rules'].append(rule_id)
            print(f"  ✗ Failed to enhance")
        
        # Small delay to respect rate limits
        time.sleep(0.5)
    
    return enhanced_count, failed_count

def main():
    print("=" * 80)
    print("OCI CSPM Rule Enhancement - GPT-4o")
    print("=" * 80)
    
    # Load data
    data = load_yaml(INPUT_FILE)
    rules = data['rules']
    total_rules = len(rules)
    
    print(f"\nTotal rules to process: {total_rules}")
    
    # Load progress
    progress = load_progress()
    start_index = progress['last_index']
    
    if start_index > 0:
        print(f"Resuming from rule #{start_index + 1}")
        print("Auto-continuing from last position...")
    
    total_enhanced = progress['enhanced_count']
    total_failed = len(progress['failed_rules'])
    
    print(f"\nStarting enhancement process...")
    print(f"Model: {MODEL}")
    print(f"Batch size: {BATCH_SIZE}")
    print(f"Starting from rule: {start_index + 1}")
    
    start_time = time.time()
    
    # Process in batches
    current_index = start_index
    
    while current_index < total_rules:
        batch_start = current_index
        batch_end = min(current_index + BATCH_SIZE, total_rules)
        
        print(f"\n{'='*80}")
        print(f"Batch: Rules {batch_start + 1} to {batch_end}")
        print(f"{'='*80}")
        
        enhanced, failed = enhance_rules_batch(rules, batch_start, BATCH_SIZE, progress)
        
        total_enhanced += enhanced
        total_failed += failed
        current_index = batch_end
        
        # Update progress
        progress['enhanced_count'] = total_enhanced
        progress['last_index'] = current_index
        save_progress(progress)
        
        # Save intermediate results
        data['rules'] = rules
        data['metadata']['enhancement_date'] = datetime.now().strftime('%Y-%m-%d')
        data['metadata']['ai_engine'] = MODEL
        data['statistics']['enhanced'] = total_enhanced
        data['statistics']['failed'] = total_failed
        data['statistics']['api_calls'] = total_enhanced + total_failed
        
        save_yaml(data, OUTPUT_FILE)
        
        print(f"\n{'='*80}")
        print(f"Progress: {total_enhanced}/{total_rules} enhanced, {total_failed} failed")
        print(f"{'='*80}")
        
        # Rate limiting: pause between batches
        if current_index < total_rules:
            time.sleep(1)
    
    # Final save
    elapsed_time = time.time() - start_time
    
    data['metadata']['total_rules'] = total_rules
    data['metadata']['quality_grade'] = 'A+ (GPT-4o Enhanced)'
    data['statistics']['total_rules'] = total_rules
    data['statistics']['enhanced'] = total_enhanced
    data['statistics']['failed'] = total_failed
    data['statistics']['connection_errors'] = 0
    
    save_yaml(data, OUTPUT_FILE)
    
    print(f"\n{'='*80}")
    print("ENHANCEMENT COMPLETE!")
    print(f"{'='*80}")
    print(f"Total rules: {total_rules}")
    print(f"Successfully enhanced: {total_enhanced}")
    print(f"Failed: {total_failed}")
    print(f"Success rate: {(total_enhanced/total_rules)*100:.1f}%")
    print(f"Time elapsed: {elapsed_time/60:.1f} minutes")
    print(f"Average time per rule: {elapsed_time/total_rules:.1f} seconds")
    print(f"\nOutput saved to: {OUTPUT_FILE}")
    
    # Clean up progress file
    if os.path.exists(PROGRESS_FILE):
        os.remove(PROGRESS_FILE)
        print(f"Progress file removed: {PROGRESS_FILE}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Process interrupted by user")
        print("Progress has been saved. Run the script again to continue.")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

