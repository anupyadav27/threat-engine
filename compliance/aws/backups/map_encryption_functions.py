#!/usr/bin/env python3
"""
Map encryption-related functions to rule_ids
"""

import yaml
import json

def load_files():
    """Load necessary files"""
    with open('/Users/apple/Desktop/threat-engine/compliance/aws/rule_ids.yaml', 'r') as f:
        rule_data = yaml.safe_load(f)
        rule_ids = rule_data['rule_ids']
    
    with open('/Users/apple/Desktop/threat-engine/compliance/aws/aws_function_to_compliance_mapping.json', 'r') as f:
        main_mapping = json.load(f)
    
    return rule_ids, main_mapping

def create_encryption_mappings(rule_ids):
    """Create proper encryption function mappings"""
    
    # User's suggested encryption checks with proper improved names
    encryption_checks = {
        "aws_ebs_encryption_by_default_enabled_check": {
            "improved_function": "aws.ec2.ebs.encryption_by_default_enabled",
            "search_patterns": ["aws.ec2.resource.ebs_encryption_by_default_enabled", "aws.ec2.ebs.default_encryption"]
        },
        "aws_s3_bucket_default_encryption_enabled_check": {
            "improved_function": "aws.s3.bucket.default_encryption_enabled",
            "search_patterns": ["aws.s3.bucket.encryption", "aws.s3.bucket.default_encryption"]
        },
        "aws_rds_encryption_enabled_check": {
            "improved_function": "aws.rds.instance.encryption_at_rest_enabled",
            "search_patterns": ["aws.rds.instance.encryption", "aws.rds.db.encryption"]
        },
        "aws_efs_encryption_enabled_check": {
            "improved_function": "aws.efs.filesystem.encryption_at_rest_enabled",
            "search_patterns": ["aws.efs.filesystem.encryption", "aws.efs.resource.encryption"]
        }
    }
    
    # Find matching rule_ids
    mappings = {}
    
    for original, data in encryption_checks.items():
        improved = data['improved_function']
        matched_rule = None
        
        # Try exact patterns first
        for pattern in data['search_patterns']:
            matching_rules = [r for r in rule_ids if pattern in r]
            if matching_rules:
                matched_rule = matching_rules[0]
                break
        
        mappings[original] = {
            'improved_function': improved,
            'matched_rule_id': matched_rule,
            'confidence': 'high' if matched_rule else None,
            'notes': f'Encryption at rest enabled for {improved.split(".")[1]}'
        }
    
    return mappings

def print_analysis(mappings, rule_ids):
    """Print analysis"""
    
    print("\n" + "="*80)
    print("ENCRYPTION FUNCTIONS - IMPROVED NAMES & MAPPINGS")
    print("="*80)
    
    print(f"\n{'USER SUGGESTED ENCRYPTION CHECKS':-^80}")
    
    for original, mapping in mappings.items():
        print(f"\n  {original}")
        print(f"    Improved: {mapping['improved_function']}")
        if mapping['matched_rule_id']:
            print(f"    ✓ Mapped to: {mapping['matched_rule_id']}")
            print(f"    Confidence: {mapping['confidence']}")
        else:
            print(f"    ✗ No matching rule found - searching...")
    
    # Search for EBS encryption rules
    print(f"\n{'SEARCHING RULE_IDS FOR ENCRYPTION RULES':-^80}")
    
    print(f"\n  EBS Encryption Rules:")
    ebs_rules = [r for r in rule_ids if 'ebs' in r.lower() and 'encrypt' in r.lower()]
    for rule in sorted(ebs_rules)[:5]:
        print(f"    • {rule}")
    
    print(f"\n  S3 Encryption Rules:")
    s3_rules = [r for r in rule_ids if 'aws.s3' in r and 'encrypt' in r.lower()]
    for rule in sorted(s3_rules)[:5]:
        print(f"    • {rule}")
    
    print(f"\n  RDS Encryption Rules:")
    rds_rules = [r for r in rule_ids if 'aws.rds' in r and 'encrypt' in r.lower()]
    for rule in sorted(rds_rules)[:5]:
        print(f"    • {rule}")
    
    print(f"\n  EFS Encryption Rules:")
    efs_rules = [r for r in rule_ids if 'aws.efs' in r and 'encrypt' in r.lower()]
    for rule in sorted(efs_rules)[:5]:
        print(f"    • {rule}")
    
    print("\n" + "="*80)
    print()

def create_corrected_mappings(rule_ids):
    """Create corrected mappings based on actual rule_ids"""
    
    mappings = {
        "aws_ebs_encryption_by_default_enabled_check": {
            "improved_function": "aws.ec2.ebs.encryption_by_default_enabled",
            "matched_rule_id": "aws.ec2.resource.ebs_encryption_by_default_enabled",
            "confidence": "high",
            "notes": "EBS encryption by default enabled"
        },
        "aws_s3_bucket_default_encryption_enabled_check": {
            "improved_function": "aws.s3.bucket.default_encryption_enabled",
            "matched_rule_id": "aws.s3.bucket.default_encryption_server_side_s3_or_kms",
            "confidence": "high",
            "notes": "S3 bucket default encryption enabled (SSE-S3 or KMS)"
        },
        "aws_rds_encryption_enabled_check": {
            "improved_function": "aws.rds.instance.encryption_at_rest_enabled",
            "matched_rule_id": "aws.rds.instance.encryption_at_rest_configured",
            "confidence": "high",
            "notes": "RDS instance encryption at rest enabled"
        },
        "aws_efs_encryption_enabled_check": {
            "improved_function": "aws.efs.filesystem.encryption_at_rest_enabled",
            "matched_rule_id": "aws.efs.resource.filesystems_encrypted",
            "confidence": "high",
            "notes": "EFS filesystem encryption at rest enabled"
        }
    }
    
    # Verify all rule_ids exist
    for original, mapping in mappings.items():
        if mapping['matched_rule_id'] not in rule_ids:
            mapping['matched_rule_id'] = None
            mapping['confidence'] = None
            mapping['notes'] += " - RULE NOT FOUND"
    
    return mappings

def print_final_mappings(mappings):
    """Print final corrected mappings"""
    
    print("\n" + "="*80)
    print("FINAL CORRECTED ENCRYPTION MAPPINGS")
    print("="*80)
    
    mapped_count = sum(1 for m in mappings.values() if m['matched_rule_id'])
    
    print(f"\n  Total encryption checks:        {len(mappings)}")
    print(f"  Successfully mapped:            {mapped_count}")
    print(f"  Not found:                      {len(mappings) - mapped_count}")
    
    print(f"\n{'MAPPINGS':-^80}")
    
    for i, (original, mapping) in enumerate(mappings.items(), 1):
        print(f"\n{i}. {original}")
        print(f"   Improved: {mapping['improved_function']}")
        if mapping['matched_rule_id']:
            print(f"   ✓ Mapped to: {mapping['matched_rule_id']}")
            print(f"   Confidence: {mapping['confidence']}")
            print(f"   Notes: {mapping['notes']}")
        else:
            print(f"   ✗ Rule not found in rule_ids.yaml")
            print(f"   Notes: {mapping['notes']}")
    
    print("\n" + "="*80)
    print()

def main():
    print("Loading files...")
    rule_ids, main_mapping = load_files()
    print(f"  ✓ Loaded {len(rule_ids)} rule_ids")
    
    print("\nCreating encryption mappings...")
    mappings = create_encryption_mappings(rule_ids)
    
    print_analysis(mappings, rule_ids)
    
    print("\nCreating corrected mappings based on actual rules...")
    final_mappings = create_corrected_mappings(rule_ids)
    
    print_final_mappings(final_mappings)

if __name__ == "__main__":
    main()

