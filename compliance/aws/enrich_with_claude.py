#!/usr/bin/env python3
"""
Use Anthropic Claude API for enterprise-grade descriptions and AWS references.
Claude is excellent for technical documentation and may have better connectivity.
"""

import yaml
import json
import os
import time
from anthropic import Anthropic

client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

SYSTEM_PROMPT = """You are an AWS security expert creating control descriptions and documentation references for an enterprise CSPM platform (like Wiz, Prowler, or Prisma Cloud).

Generate professional descriptions and AWS documentation references.

DESCRIPTION Guidelines (150-300 characters):
- First sentence: What the control checks (specific AWS resource/configuration)
- Second sentence: Security risk/impact if not implemented
- Use clear, professional, actionable language
- Be concrete and specific

REFERENCES Guidelines:
- Provide 2-3 relevant AWS documentation URLs
- Use actual AWS docs format: https://docs.aws.amazon.com/[service]/latest/[guide]/[topic].html
- Include service best practices and security-specific documentation

Return ONLY valid JSON in this exact format:
{
  "rules": [
    {
      "rule_id": "aws.s3.bucket.encryption_enabled",
      "description": "Verifies S3 buckets have server-side encryption enabled using AWS KMS or AES-256. Unencrypted data is vulnerable to unauthorized access if storage or credentials are compromised.",
      "references": [
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html",
        "https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html"
      ]
    }
  ]
}"""

def enrich_with_claude(input_file: str, output_file: str, batch_size: int = 10):
    """Enrich using Claude API"""
    
    print("="*80)
    print("ENRICHING WITH ANTHROPIC CLAUDE")
    print("="*80)
    
    with open(input_file, 'r') as f:
        data = yaml.safe_load(f)
    
    rules = data.get('rule_ids', [])
    print(f"\n✓ Loaded {len(rules)} rules")
    print(f"✓ Using Claude 3.5 Sonnet model")
    print(f"✓ Batch size: {batch_size} rules\n")
    
    enriched_map = {}
    total = len(rules)
    
    for i in range(0, total, batch_size):
        batch = rules[i:i + batch_size]
        batch_num = (i // batch_size) + 1
        total_batches = (total + batch_size - 1) // batch_size
        
        print(f"[{batch_num}/{total_batches}] Processing {len(batch)} rules...", end=' ')
        
        # Prepare batch data
        rules_info = []
        for rule in batch:
            rules_info.append({
                'rule_id': rule.get('rule_id'),
                'service': rule.get('service'),
                'resource': rule.get('resource'),
                'requirement': rule.get('requirement'),
                'title': rule.get('title'),
                'domain': rule.get('domain'),
                'severity': rule.get('severity'),
            })
        
        prompt = f"""Generate enterprise-grade description and AWS documentation references for these security rules:

{json.dumps(rules_info, indent=2)}

Return valid JSON only."""
        
        try:
            message = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=4000,
                temperature=0.3,
                system=SYSTEM_PROMPT,
                messages=[{
                    "role": "user",
                    "content": prompt
                }]
            )
            
            # Parse response
            response_text = message.content[0].text
            result = json.loads(response_text)
            
            # Map results
            for generated_rule in result.get('rules', []):
                rule_id = generated_rule.get('rule_id')
                if rule_id:
                    enriched_map[rule_id] = {
                        'description': generated_rule.get('description'),
                        'references': generated_rule.get('references', [])
                    }
            
            print(f"✓ ({len(enriched_map)}/{total} total)")
            
            # Save progress every 10 batches
            if batch_num % 10 == 0:
                print(f"    💾 Saving checkpoint...")
                save_checkpoint(data, rules, enriched_map, output_file)
            
            # Rate limiting
            time.sleep(1)
            
        except Exception as e:
            print(f"✗ Error: {str(e)[:60]}")
    
    # Apply enrichment
    print(f"\n✓ Applying enrichment to all rules...")
    enriched_rules = []
    
    for rule in rules:
        enriched_rule = rule.copy()
        rule_id = rule.get('rule_id')
        
        if rule_id in enriched_map:
            enriched_rule['description'] = enriched_map[rule_id]['description']
            enriched_rule['references'] = enriched_map[rule_id]['references']
        
        enriched_rules.append(enriched_rule)
    
    # Update metadata
    data['rule_ids'] = enriched_rules
    data['metadata']['version'] = '12.0'
    data['metadata']['description'] = 'AWS Security Rules - Enterprise CSPM with AI-Generated Content'
    
    if 'fields' not in data['metadata']:
        data['metadata']['fields'] = []
    if 'references' not in data['metadata']['fields']:
        data['metadata']['fields'].append('references')
    
    data['metadata']['ai_enrichment'] = {
        'model': 'claude-3-5-sonnet-20241022',
        'provider': 'anthropic',
        'date': '2024-11-24',
        'enriched_count': len(enriched_map),
    }
    
    # Save final
    print(f"✓ Saving final file...")
    with open(output_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, width=120, allow_unicode=True)
    
    print("\n" + "="*80)
    print("✅ ENRICHMENT COMPLETE!")
    print("="*80)
    print(f"\n📊 Enriched: {len(enriched_map)}/{total} rules ({len(enriched_map)/total*100:.1f}%)")

def save_checkpoint(data, rules, enriched_map, output_file):
    """Save progress"""
    enriched_rules = []
    for rule in rules:
        enriched_rule = rule.copy()
        rule_id = rule.get('rule_id')
        if rule_id in enriched_map:
            enriched_rule['description'] = enriched_map[rule_id]['description']
            enriched_rule['references'] = enriched_map[rule_id]['references']
        enriched_rules.append(enriched_rule)
    
    data['rule_ids'] = enriched_rules
    with open(output_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, width=120, allow_unicode=True)

def main():
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("❌ ERROR: ANTHROPIC_API_KEY not set!")
        print("\nSet with: export ANTHROPIC_API_KEY='your-key'")
        return
    
    print("\n🤖 Using Anthropic Claude 3.5 Sonnet")
    print("⏱️  Estimated time: ~8-10 minutes\n")
    
    enrich_with_claude(
        input_file='/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml',
        output_file='/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml',
        batch_size=10
    )

if __name__ == '__main__':
    main()

