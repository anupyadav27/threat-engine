#!/usr/bin/env python3
"""
Cleanup and finalize rule_ids.yaml:
1. Remove old title and assertion_id fields
2. Rename ui_title -> title, ui_description -> description
3. Enrich any missing title/description with simple fallbacks
"""

import yaml
from typing import Dict

def humanize_requirement(req: str) -> str:
    """Turn requirement into readable phrase"""
    r = req.replace('.', '_')
    
    if r.endswith('_enabled'):
        return r[:-8].replace('_', ' ') + ' enabled'
    if r.endswith('_disabled'):
        return r[:-9].replace('_', ' ') + ' disabled'
    if r.endswith('_configured'):
        return r[:-11].replace('_', ' ') + ' configured'
    if r.endswith('_enforced'):
        return r[:-9].replace('_', ' ') + ' enforced'
    if r.endswith('_required'):
        return r[:-9].replace('_', ' ') + ' required'
    
    return r.replace('_', ' ')

def nice_service(service: str) -> str:
    """Convert service to display name"""
    service_map = {
        's3': 'Amazon S3',
        'ec2': 'Amazon EC2', 
        'iam': 'AWS IAM',
        'rds': 'Amazon RDS',
        'lambda': 'AWS Lambda',
        'cloudtrail': 'AWS CloudTrail',
        'cloudwatch': 'Amazon CloudWatch',
        'kms': 'AWS KMS',
        'acm': 'AWS Certificate Manager',
        'apigateway': 'Amazon API Gateway',
        'elb': 'Elastic Load Balancing',
        'elbv2': 'Elastic Load Balancing v2',
    }
    return service_map.get(service, f"AWS {service.upper()}")

def cleanup_and_finalize(input_file: str, output_file: str):
    print("="*80)
    print("CLEANUP AND FINALIZE RULE_IDS.YAML")
    print("="*80)
    
    with open(input_file, 'r') as f:
        data = yaml.safe_load(f)
    
    rules = data.get('rule_ids', [])
    print(f"\nLoaded {len(rules)} rules")
    
    stats = {
        'total': len(rules),
        'had_ui_title': 0,
        'had_ui_description': 0,
        'missing_ui_title': 0,
        'missing_ui_description': 0,
        'removed_old_title': 0,
        'removed_assertion_id': 0,
    }
    
    cleaned_rules = []
    
    for i, rule in enumerate(rules, 1):
        if i % 500 == 0:
            print(f"  Processing rule {i}/{len(rules)}")
        
        cleaned_rule = {}
        
        # Keep core fields first
        for field in ['rule_id', 'service', 'resource', 'requirement']:
            if field in rule:
                cleaned_rule[field] = rule[field]
        
        # Handle title: ui_title -> title (remove old title)
        if 'ui_title' in rule and rule['ui_title']:
            cleaned_rule['title'] = rule['ui_title']
            stats['had_ui_title'] += 1
        else:
            # Fallback: generate simple title
            service = nice_service(rule.get('service', ''))
            resource = rule.get('resource', '').replace('_', ' ').title()
            req = humanize_requirement(rule.get('requirement', ''))
            cleaned_rule['title'] = f"{service} {resource}: {req.capitalize()}"
            stats['missing_ui_title'] += 1
        
        # Handle description: ui_description -> description (remove old if exists)
        if 'ui_description' in rule and rule['ui_description']:
            cleaned_rule['description'] = rule['ui_description']
            stats['had_ui_description'] += 1
        else:
            # Fallback: generate simple description
            service = nice_service(rule.get('service', ''))
            resource = rule.get('resource', '').replace('_', ' ')
            req = humanize_requirement(rule.get('requirement', ''))
            severity = rule.get('severity', 'medium')
            
            cleaned_rule['description'] = (
                f"This {severity}-severity control ensures {service} {resource} has {req}. "
                f"Proper configuration reduces security risks and maintains compliance."
            )
            stats['missing_ui_description'] += 1
        
        # Track removals
        if 'title' in rule and 'ui_title' in rule:
            stats['removed_old_title'] += 1
        if 'assertion_id' in rule:
            stats['removed_assertion_id'] += 1
        
        # Keep other important fields (NOT title or assertion_id)
        for field in ['scope', 'domain', 'subcategory', 'rationale', 'severity', 
                      'source', 'compliance']:
            if field in rule:
                cleaned_rule[field] = rule[field]
        
        cleaned_rules.append(cleaned_rule)
    
    # Update metadata
    data['rule_ids'] = cleaned_rules
    data['metadata']['version'] = '10.0'
    data['metadata']['description'] = 'AWS Security Rules - Enterprise CSPM with AI-Generated Content'
    data['metadata']['fields'] = [
        'rule_id', 'service', 'resource', 'requirement',
        'title', 'description',
        'scope', 'domain', 'subcategory', 'rationale', 'severity',
        'source', 'compliance'
    ]
    
    # Save
    with open(output_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False,
                 width=120, allow_unicode=True)
    
    print("\n" + "="*80)
    print("CLEANUP STATISTICS")
    print("="*80)
    print(f"\n📊 Total Rules: {stats['total']}")
    print(f"\n✅ Had ui_title: {stats['had_ui_title']} ({stats['had_ui_title']/stats['total']*100:.1f}%)")
    print(f"✅ Had ui_description: {stats['had_ui_description']} ({stats['had_ui_description']/stats['total']*100:.1f}%)")
    print(f"\n🔧 Generated title fallback: {stats['missing_ui_title']}")
    print(f"🔧 Generated description fallback: {stats['missing_ui_description']}")
    print(f"\n🗑️  Removed old 'title' field: {stats['removed_old_title']}")
    print(f"🗑️  Removed 'assertion_id' field: {stats['removed_assertion_id']}")
    
    print("\n" + "="*80)
    print("✅ CLEANUP COMPLETE!")
    print("="*80)
    print(f"\n📁 Saved to: {output_file}")
    print("\n🎯 FINAL STRUCTURE:")
    print("  - title: Enterprise-grade UI title")
    print("  - description: Clear, actionable description")
    print("  - Removed: old title, assertion_id")
    print("  - Kept: All other fields (scope, domain, compliance, etc.)")

def main():
    cleanup_and_finalize(
        input_file='/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml',
        output_file='/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml'
    )

if __name__ == '__main__':
    main()

