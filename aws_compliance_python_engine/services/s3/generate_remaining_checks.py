#!/usr/bin/env python3
"""
Generate remaining S3 checks based on metadata files.
"""

import yaml
from pathlib import Path

# Already implemented check rule_ids
IMPLEMENTED = {
    'aws.s3.bucket.encryption_at_rest_enabled',
    'aws.s3.bucket.default_encryption_configured',
    'aws.s3.bucket.kms_encryption_configured',
    'aws.s3.bucket.versioning_enabled',
    'aws.s3.bucket.access_logging_enabled',
    'aws.s3.bucket.block_public_access_enabled',
    'aws.s3.bucket.block_public_access_configured',
    'aws.s3.bucket.immutability_or_object_lock_if_supported',
    'aws.s3.bucket.immutable_or_worm_enabled_if_supported',
    'aws.s3.bucket.lifecycle_policy_configured',
    'aws.s3.bucket.lifecycle_enabled',
    'aws.s3.bucket.replication_enabled',
}

def load_metadata_files():
    """Load all S3 metadata files"""
    metadata_dir = Path("/Users/apple/Desktop/threat-engine/aws_compliance_python_engine/services/s3/metadata")
    metadata = []
    
    for yaml_file in sorted(metadata_dir.glob("*.yaml")):
        with open(yaml_file, 'r') as f:
            data = yaml.safe_load(f)
            if data and data.get('rule_id') not in IMPLEMENTED:
                metadata.append(data)
    
    return metadata

def generate_checks():
    """Generate checks for all remaining rules"""
    
    metadata_list = load_metadata_files()
    
    print(f"Generating {len(metadata_list)} remaining S3 checks...")
    
    checks = []
    
    for meta in metadata_list:
        rule_id = meta['rule_id']
        title = meta['title']
        severity = meta['severity']
        requirement = meta.get('requirement', '')
        description = meta.get('description', '')
        references = meta.get('references', [])
        
        # Determine discovery and condition based on rule pattern
        check = generate_check_from_pattern(rule_id, title, severity, requirement, description, references)
        checks.append(check)
    
    return checks

def generate_check_from_pattern(rule_id, title, severity, requirement, description, references):
    """Generate check structure based on rule_id pattern"""
    
    # Extract key parts
    parts = rule_id.split('.')
    resource_type = parts[2] if len(parts) > 2 else 'bucket'
    check_name = parts[-1] if len(parts) > 3 else parts[-1]
    
    # Pattern matching
    if 'encryption' in check_name or 'cmk' in check_name or 'cmek' in check_name or 'kms' in check_name:
        return generate_encryption_check(rule_id, title, severity, requirement, description, references, resource_type)
    elif 'logging' in check_name or 'audit' in check_name:
        return generate_logging_check(rule_id, title, severity, requirement, description, references, resource_type)
    elif 'public' in check_name or 'access' in check_name:
        return generate_access_check(rule_id, title, severity, requirement, description, references, resource_type)
    elif 'versioning' in check_name:
        return generate_versioning_check(rule_id, title, severity, requirement, description, references, resource_type)
    elif 'policy' in check_name or 'rbac' in check_name or 'least_privilege' in check_name:
        return generate_policy_check(rule_id, title, severity, requirement, description, references, resource_type)
    elif 'tls' in check_name or 'transport' in check_name or 'transit' in check_name:
        return generate_tls_check(rule_id, title, severity, requirement, description, references, resource_type)
    elif 'lifecycle' in check_name or 'retention' in check_name or 'tiering' in check_name:
        return generate_lifecycle_check(rule_id, title, severity, requirement, description, references, resource_type)
    elif 'replication' in check_name:
        return generate_replication_check(rule_id, title, severity, requirement, description, references, resource_type)
    elif 'notification' in check_name:
        return generate_notification_check(rule_id, title, severity, requirement, description, references, resource_type)
    elif 'macie' in check_name:
        return generate_macie_check(rule_id, title, severity, requirement, description, references, resource_type)
    elif 'metrics' in check_name:
        return generate_metrics_check(rule_id, title, severity, requirement, description, references, resource_type)
    elif 'backup' in check_name or 'immuta' in check_name or 'lock' in check_name:
        return generate_backup_check(rule_id, title, severity, requirement, description, references, resource_type)
    else:
        return generate_generic_check(rule_id, title, severity, requirement, description, references, resource_type)

def generate_encryption_check(rule_id, title, severity, requirement, description, references, resource_type):
    """Generate encryption-related check"""
    
    # Determine specific encryption type
    is_cmk = 'cmk' in rule_id or 'cmek' in rule_id
    is_kms = 'kms' in rule_id
    is_transit = 'transit' in rule_id or 'tls' in rule_id
    
    if is_transit:
        discovery_ref = "aws.s3.bucket_policy"
        condition = {
            "var": "policy.has_tls_requirement",
            "op": "equals",
            "value": True
        }
        remediation = f"""Enable TLS/HTTPS-only access for S3:
      1. S3 console > Bucket > Permissions > Bucket Policy
      2. Add policy to deny non-HTTPS requests:
      {{
        "Effect": "Deny",
        "Principal": "*",
        "Action": "s3:*",
        "Resource": [
          "arn:aws:s3:::bucket-name",
          "arn:aws:s3:::bucket-name/*"
        ],
        "Condition": {{
          "Bool": {{ "aws:SecureTransport": "false" }}
        }}
      }}"""
    elif is_cmk:
        discovery_ref = "aws.s3.bucket_encryption"
        condition = {
            "all": [
                {"var": "encryption.sse_algorithm", "op": "equals", "value": "aws:kms"},
                {"var": "encryption.kms_key_id", "op": "exists"}
            ]
        }
        remediation = f"""Enable customer-managed KMS encryption:
      1. S3 console > Bucket > Properties > Default encryption
      2. Select "AWS Key Management Service key (SSE-KMS)"
      3. Choose "Choose from your AWS KMS keys"
      4. Select a customer-managed CMK
      5. Save changes"""
    else:
        discovery_ref = "aws.s3.bucket_encryption"
        condition = {"var": "encryption.encryption_enabled", "op": "equals", "value": True}
        remediation = f"""Enable S3 encryption:
      1. S3 console > Bucket > Properties > Default encryption
      2. Enable server-side encryption
      3. Choose AES-256 (SSE-S3) or AWS-KMS (SSE-KMS)
      4. Save changes"""
    
    return {
        "title": title,
        "severity": severity,
        "rule_id": rule_id,
        "for_each": {
            "discovery": discovery_ref,
            "as": discovery_ref.split('.')[-1],
            "item": resource_type
        },
        "conditions": condition,
        "remediation": remediation,
        "references": references or [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"
        ]
    }

def generate_logging_check(rule_id, title, severity, requirement, description, references, resource_type):
    """Generate logging-related check"""
    return {
        "title": title,
        "severity": severity,
        "rule_id": rule_id,
        "for_each": {
            "discovery": "aws.s3.bucket_logging",
            "as": "logging",
            "item": resource_type
        },
        "conditions": {
            "var": "logging.logging_enabled",
            "op": "equals",
            "value": True
        },
        "remediation": f"""Enable S3 access logging:
      1. S3 console > Bucket > Properties > Server access logging
      2. Click Edit and enable logging
      3. Choose a target bucket for logs
      4. Set target prefix (e.g., "logs/")
      5. Save changes
      
      AWS CLI:
      aws s3api put-bucket-logging --bucket <bucket-name> \\
        --bucket-logging-status '{{
          "LoggingEnabled": {{
            "TargetBucket": "<log-bucket>",
            "TargetPrefix": "logs/"
          }}
        }}'""",
        "references": references or [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html"
        ]
    }

def generate_access_check(rule_id, title, severity, requirement, description, references, resource_type):
    """Generate access control check"""
    
    if 'account' in rule_id and 'level' in rule_id:
        # Account-level public access block
        discovery_ref = "aws.s3.account_public_access_block"
        condition = {
            "all": [
                {"var": "public_access.block_public_acls", "op": "equals", "value": True},
                {"var": "public_access.ignore_public_acls", "op": "equals", "value": True},
                {"var": "public_access.block_public_policy", "op": "equals", "value": True},
                {"var": "public_access.restrict_public_buckets", "op": "equals", "value": True}
            ]
        }
        remediation = """Enable account-level S3 public access block:
      1. S3 console > Block Public Access settings for this account
      2. Click Edit
      3. Enable all four settings:
         - Block all public ACLs
         - Block public bucket policies
         - Ignore public ACLs
         - Restrict public bucket policies
      4. Confirm and save
      
      AWS CLI:
      aws s3control put-public-access-block \\
        --account-id <account-id> \\
        --public-access-block-configuration \\
        BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"""
    else:
        # Bucket-level public access
        discovery_ref = "aws.s3.public_access_block"
        condition = {
            "all": [
                {"var": "public_access.block_public_acls", "op": "equals", "value": True},
                {"var": "public_access.ignore_public_acls", "op": "equals", "value": True}
            ]
        }
        remediation = """Enable S3 bucket public access block:
      1. S3 console > Bucket > Permissions > Block public access
      2. Click Edit and enable all settings
      3. Confirm and save"""
    
    return {
        "title": title,
        "severity": severity,
        "rule_id": rule_id,
        "for_each": {
            "discovery": discovery_ref,
            "as": "public_access",
            "item": resource_type if 'bucket' in rule_id else "account"
        },
        "conditions": condition,
        "remediation": remediation,
        "references": references or [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"
        ]
    }

def generate_versioning_check(rule_id, title, severity, requirement, description, references, resource_type):
    """Generate versioning check"""
    return {
        "title": title,
        "severity": severity,
        "rule_id": rule_id,
        "for_each": {
            "discovery": "aws.s3.bucket_versioning",
            "as": "versioning",
            "item": resource_type
        },
        "conditions": {
            "var": "versioning.versioning_enabled",
            "op": "equals",
            "value": True
        },
        "remediation": f"""Enable S3 bucket versioning:
      1. S3 console > Bucket > Properties > Bucket Versioning
      2. Click Edit and select Enable
      3. Save changes
      
      AWS CLI:
      aws s3api put-bucket-versioning --bucket <bucket-name> \\
        --versioning-configuration Status=Enabled""",
        "references": references or [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html"
        ]
    }

def generate_policy_check(rule_id, title, severity, requirement, description, references, resource_type):
    """Generate policy-related check"""
    return {
        "title": title,
        "severity": severity,
        "rule_id": rule_id,
        "for_each": {
            "discovery": "aws.s3.bucket_policy",
            "as": "policy",
            "item": resource_type
        },
        "conditions": {
            "var": "policy.has_least_privilege",
            "op": "equals",
            "value": True
        },
        "remediation": f"""Review and enforce least privilege on S3 bucket policy:
      1. S3 console > Bucket > Permissions > Bucket Policy
      2. Review current policy for overly permissive statements
      3. Remove wildcard (*) principals and actions where possible
      4. Use specific ARNs and actions
      5. Apply conditions for additional security
      6. Save changes
      
      Best practices:
      - Use principal-specific ARNs instead of "*"
      - Grant only required actions (avoid s3:*)
      - Use condition keys (aws:SourceIp, aws:SecureTransport, etc.)
      - Regularly audit and review policies""",
        "references": references or [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"
        ]
    }

def generate_tls_check(rule_id, title, severity, requirement, description, references, resource_type):
    """Generate TLS/transport security check"""
    return generate_encryption_check(rule_id, title, severity, requirement, description, references, resource_type)

def generate_lifecycle_check(rule_id, title, severity, requirement, description, references, resource_type):
    """Generate lifecycle/retention check"""
    return {
        "title": title,
        "severity": severity,
        "rule_id": rule_id,
        "for_each": {
            "discovery": "aws.s3.bucket_lifecycle",
            "as": "lifecycle",
            "item": resource_type
        },
        "conditions": {
            "var": "lifecycle.lifecycle_enabled",
            "op": "equals",
            "value": True
        },
        "remediation": f"""Configure S3 lifecycle policy:
      1. S3 console > Bucket > Management > Lifecycle rules
      2. Click "Create lifecycle rule"
      3. Define rule name and scope
      4. Add lifecycle rule actions:
         - Transition to IA after X days
         - Transition to Glacier after Y days
         - Expire objects after Z days
      5. Review and create rule""",
        "references": references or [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lifecycle-mgmt.html"
        ]
    }

def generate_replication_check(rule_id, title, severity, requirement, description, references, resource_type):
    """Generate replication check"""
    return {
        "title": title,
        "severity": severity,
        "rule_id": rule_id,
        "for_each": {
            "discovery": "aws.s3.bucket_replication",
            "as": "replication",
            "item": resource_type
        },
        "conditions": {
            "var": "replication.replication_enabled",
            "op": "equals",
            "value": True
        },
        "remediation": f"""Configure S3 replication:
      1. Ensure source bucket has versioning enabled
      2. S3 console > Bucket > Management > Replication rules
      3. Click "Create replication rule"
      4. Configure source and destination
      5. Set up IAM role for replication
      6. Save rule""",
        "references": references or [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html"
        ]
    }

def generate_notification_check(rule_id, title, severity, requirement, description, references, resource_type):
    """Generate notification check"""
    return {
        "title": title,
        "severity": severity,
        "rule_id": rule_id,
        "for_each": {
            "discovery": "aws.s3.bucket_notification",
            "as": "notification",
            "item": resource_type
        },
        "conditions": {
            "var": "notification.has_secure_destination",
            "op": "equals",
            "value": True
        },
        "remediation": f"""Configure secure S3 event notifications:
      1. S3 console > Bucket > Properties > Event notifications
      2. Create event notification
      3. Choose secure destination (SNS/SQS/Lambda with encryption)
      4. Ensure destination has least-privilege access
      5. Save configuration""",
        "references": references or [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/NotificationHowTo.html"
        ]
    }

def generate_macie_check(rule_id, title, severity, requirement, description, references, resource_type):
    """Generate Macie check"""
    return {
        "title": title,
        "severity": severity,
        "rule_id": rule_id,
        "for_each": {
            "discovery": "aws.s3.buckets",
            "as": "bucket",
            "item": resource_type
        },
        "conditions": {
            "var": "bucket.macie_enabled",
            "op": "equals",
            "value": True
        },
        "remediation": f"""Enable Amazon Macie for S3:
      1. Open Macie console
      2. Click "Get started" or "Enable Macie"
      3. Configure S3 buckets to scan
      4. Set up classification jobs
      5. Review findings regularly""",
        "references": references or [
            "https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html"
        ]
    }

def generate_metrics_check(rule_id, title, severity, requirement, description, references, resource_type):
    """Generate metrics check"""
    return {
        "title": title,
        "severity": severity,
        "rule_id": rule_id,
        "for_each": {
            "discovery": "aws.s3.buckets",
            "as": "bucket",
            "item": resource_type
        },
        "conditions": {
            "var": "bucket.metrics_enabled",
            "op": "equals",
            "value": True
        },
        "remediation": f"""Enable S3 metrics:
      1. S3 console > Bucket > Metrics
      2. Create request metrics configuration
      3. Define filter (prefix, tags, or entire bucket)
      4. Enable metrics
      5. Monitor via CloudWatch""",
        "references": references or [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/metrics-configurations.html"
        ]
    }

def generate_backup_check(rule_id, title, severity, requirement, description, references, resource_type):
    """Generate backup/immutability check"""
    return {
        "title": title,
        "severity": severity,
        "rule_id": rule_id,
        "for_each": {
            "discovery": "aws.s3.bucket_object_lock",
            "as": "object_lock",
            "item": resource_type
        },
        "conditions": {
            "var": "object_lock.object_lock_enabled",
            "op": "equals",
            "value": True
        },
        "remediation": f"""Enable S3 Object Lock for immutability:
      1. Create new bucket with Object Lock enabled (cannot be enabled on existing buckets)
      2. Configure retention settings:
         - Compliance mode for immutability
         - Governance mode for flexible retention
      3. Set retention period
      4. Migrate data from existing bucket if needed""",
        "references": references or [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html"
        ]
    }

def generate_generic_check(rule_id, title, severity, requirement, description, references, resource_type):
    """Generate generic check"""
    return {
        "title": title,
        "severity": severity,
        "rule_id": rule_id,
        "for_each": {
            "discovery": "aws.s3.buckets",
            "as": "bucket",
            "item": resource_type
        },
        "conditions": {
            "var": "bucket.compliant",
            "op": "equals",
            "value": True
        },
        "remediation": f"""Configure S3 for compliance:
      1. Review requirement: {requirement}
      2. {description[:200]}
      3. Apply appropriate security settings
      4. Verify compliance""",
        "references": references or [
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html"
        ]
    }

if __name__ == '__main__':
    checks = generate_checks()
    
    print(f"\nGenerated {len(checks)} checks")
    print("\nSample check:")
    print(yaml.dump([checks[0]], default_flow_style=False, sort_keys=False))
    
    print(f"\nTotal checks to append: {len(checks)}")
    print(f"Ready to append to s3.yaml")

