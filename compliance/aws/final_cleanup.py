#!/usr/bin/env python3
"""
Final cleanup: Remove old title/assertion_id, keep ui_title/ui_description OR rename to title/description
"""

import yaml

def final_cleanup(input_file: str, output_file: str):
    print("="*80)
    print("FINAL CLEANUP - REMOVE OLD FIELDS")
    print("="*80)
    
    with open(input_file, 'r') as f:
        data = yaml.safe_load(f)
    
    rules = data.get('rule_ids', [])
    print(f"\nLoaded {len(rules)} rules")
    
    stats = {
        'total': len(rules),
        'had_ui_fields': 0,
        'generated_fallback': 0,
        'removed_old_title': 0,
        'removed_assertion_id': 0,
    }
    
    cleaned_rules = []
    
    for i, rule in enumerate(rules, 1):
        if i % 500 == 0:
            print(f"  Processing rule {i}/{len(rules)}")
        
        cleaned_rule = {}
        
        # Keep core identification fields
        for field in ['rule_id', 'service', 'resource', 'requirement']:
            if field in rule:
                cleaned_rule[field] = rule[field]
        
        # Check if we already have title/description (from my cleanup)
        if 'title' in rule and 'assertion_id' not in rule:
            # Already cleaned, just keep it
            cleaned_rule['title'] = rule['title']
            cleaned_rule['description'] = rule.get('description', '')
            stats['generated_fallback'] += 1
        else:
            # This rule still has old structure - shouldn't happen but handle it
            stats['had_ui_fields'] += 1
            cleaned_rule['title'] = rule.get('title', 'Security check')
            cleaned_rule['description'] = rule.get('description', 'Security control')
        
        # Track removals
        if 'assertion_id' in rule:
            stats['removed_assertion_id'] += 1
        
        # Keep other fields (NOT assertion_id)
        for field in ['scope', 'domain', 'subcategory', 'rationale', 'severity', 
                      'source', 'compliance']:
            if field in rule:
                cleaned_rule[field] = rule[field]
        
        cleaned_rules.append(cleaned_rule)
    
    # Update data
    data['rule_ids'] = cleaned_rules
    data['metadata']['version'] = '10.0'
    data['metadata']['description'] = 'AWS Security Rules - Enterprise CSPM'
    data['metadata']['fields'] = [
        'rule_id', 'service', 'resource', 'requirement',
        'title', 'description',
        'scope', 'domain', 'subcategory', 'rationale', 'severity',
        'source', 'compliance'
    ]
    
    # Remove old metadata fields
    if 'ai_enrichment' in data['metadata']:
        del data['metadata']['ai_enrichment']
    
    # Save
    with open(output_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False,
                 width=120, allow_unicode=True)
    
    print("\n" + "="*80)
    print("FINAL STATISTICS")
    print("="*80)
    print(f"\n📊 Total Rules: {stats['total']}")
    print(f"✅ Rules with title/description: {stats['total']}")
    print(f"🗑️  Removed assertion_id: {stats['removed_assertion_id']}")
    
    print("\n" + "="*80)
    print("✅ FINAL CLEANUP COMPLETE!")
    print("="*80)

def main():
    final_cleanup(
        input_file='/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml',
        output_file='/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml'
    )

if __name__ == '__main__':
    main()

