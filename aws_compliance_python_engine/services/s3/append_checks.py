#!/usr/bin/env python3
"""
Append all remaining S3 checks to the s3.yaml file
"""

import yaml
from pathlib import Path
import sys

# Load the generation script
sys.path.insert(0, '/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services/s3')
from generate_remaining_checks import generate_checks

def add_missing_discovery_steps():
    """Add discovery steps that are missing"""
    
    # Additional discovery steps needed
    additional_discovery = [
        {
            "discovery_id": "aws.s3.account_public_access_block",
            "calls": [
                {
                    "client": "s3control",
                    "action": "get_public_access_block",
                    "params": {
                        "AccountId": "{{ account_id }}"
                    },
                    "save_as": "account_public_access",
                    "on_error": "continue",
                    "fields": ["PublicAccessBlockConfiguration"]
                }
            ],
            "emit": {
                "item": {
                    "block_public_acls": "{{ account_public_access.PublicAccessBlockConfiguration.BlockPublicAcls if account_public_access.PublicAccessBlockConfiguration else false }}",
                    "ignore_public_acls": "{{ account_public_access.PublicAccessBlockConfiguration.IgnorePublicAcls if account_public_access.PublicAccessBlockConfiguration else false }}",
                    "block_public_policy": "{{ account_public_access.PublicAccessBlockConfiguration.BlockPublicPolicy if account_public_access.PublicAccessBlockConfiguration else false }}",
                    "restrict_public_buckets": "{{ account_public_access.PublicAccessBlockConfiguration.RestrictPublicBuckets if account_public_access.PublicAccessBlockConfiguration else false }}"
                }
            }
        },
        {
            "discovery_id": "aws.s3.bucket_notification",
            "for_each": "aws.s3.buckets",
            "calls": [
                {
                    "client": "s3",
                    "action": "get_bucket_notification_configuration",
                    "params": {
                        "Bucket": "{{ item.name }}"
                    },
                    "save_as": "notification",
                    "on_error": "continue"
                }
            ],
            "emit": {
                "item": {
                    "bucket": "{{ item.name }}",
                    "has_notifications": "{{ (notification.TopicConfigurations | length > 0) or (notification.QueueConfigurations | length > 0) or (notification.LambdaFunctionConfigurations | length > 0) }}",
                    "has_secure_destination": "{{ true }}"  # Placeholder - needs deeper analysis
                }
            }
        }
    ]
    
    return additional_discovery

def update_s3_yaml():
    """Update the S3 YAML file with all remaining checks"""
    
    s3_yaml_path = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services/s3/rules/s3.yaml")
    
    # Load existing file
    with open(s3_yaml_path, 'r') as f:
        s3_data = yaml.safe_load(f)
    
    print(f"Current checks: {len(s3_data.get('checks', []))}")
    print(f"Current discovery steps: {len(s3_data.get('discovery', []))}")
    
    # Add missing discovery steps
    additional_discovery = add_missing_discovery_steps()
    existing_discovery_ids = {d['discovery_id'] for d in s3_data.get('discovery', [])}
    
    for disc in additional_discovery:
        if disc['discovery_id'] not in existing_discovery_ids:
            s3_data['discovery'].append(disc)
            print(f"Added discovery: {disc['discovery_id']}")
    
    # Generate and add remaining checks
    new_checks = generate_checks()
    print(f"\nGenerated {len(new_checks)} new checks")
    
    # Append to existing checks
    s3_data['checks'].extend(new_checks)
    
    print(f"Total checks after update: {len(s3_data['checks'])}")
    print(f"Total discovery steps after update: {len(s3_data['discovery'])}")
    
    # Save updated file
    with open(s3_yaml_path, 'w') as f:
        yaml.dump(s3_data, f, default_flow_style=False, sort_keys=False, width=120)
    
    print(f"\n✅ Updated {s3_yaml_path}")
    print(f"   - Discovery steps: {len(s3_data['discovery'])}")
    print(f"   - Checks: {len(s3_data['checks'])}")
    
    return len(s3_data['checks'])

if __name__ == '__main__':
    total_checks = update_s3_yaml()
    print(f"\n🎉 S3 service now has {total_checks} checks!")
    print("\nNext: Run validation to verify structure")

