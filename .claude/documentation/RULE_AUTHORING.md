# Rule Authoring Guide

> How to write custom YAML security rules for the CSPM rule engine.

---

## Overview

Security rules are defined in YAML format and stored in the `rule_metadata` table. Each rule checks a specific configuration property of a cloud resource and produces a PASS/FAIL result.

The rule engine supports 7 cloud providers: AWS, Azure, GCP, OCI, AliCloud, IBM Cloud, and Kubernetes.

---

## Rule Structure

```yaml
rule_id: aws.s3.bucket.versioning_enabled
service: s3
provider: aws
resource: bucket
severity: high
title: S3 Bucket Versioning Enabled
description: Ensure S3 bucket versioning is enabled to protect against accidental deletion
remediation: Enable versioning on the S3 bucket via the console or CLI
rationale: Versioning protects objects from accidental deletion and provides audit trail
domain: data_protection
subcategory: backup_recovery

# Compliance framework mappings
compliance_frameworks:
  cis_aws_v1.4:
    - control: "2.1.1"
      title: "Ensure S3 Bucket Versioning is enabled"
  nist_800_53:
    - control: "CP-9"
      title: "Information System Backup"

# MITRE ATT&CK mapping
mitre_tactics: ["impact"]
mitre_techniques: ["T1485", "T1490"]

# Threat classification
threat_category: misconfiguration
threat_tags: ["data-loss", "backup"]
risk_score: 75
risk_indicators: ["no_versioning", "data_destruction_risk"]
```

---

## Using the Rule Engine API

### Generate a Rule

```bash
curl -X POST http://localhost:8011/api/v1/rules/generate \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "aws",
    "service": "s3",
    "resource": "bucket",
    "check_description": "Ensure S3 bucket has versioning enabled",
    "severity": "high"
  }'
```

### Validate a Rule

```bash
curl -X POST http://localhost:8011/api/v1/rules/validate \
  -H "Content-Type: application/json" \
  -d '{
    "rule_yaml": "rule_id: aws.s3.bucket.test\nservice: s3\n...",
    "provider": "aws"
  }'
```

### Preview Rule Execution

```bash
curl -X POST http://localhost:8011/api/v1/rules/preview \
  -H "Content-Type: application/json" \
  -d '{
    "rule_id": "aws.s3.bucket.versioning_enabled",
    "sample_resource": {
      "Versioning": { "Status": "Suspended" }
    }
  }'
```

---

## Rule ID Convention

Format: `{provider}.{service}.{resource}.{check_name}`

Examples:
```
aws.s3.bucket.versioning_enabled
aws.iam.user.mfa_enabled
aws.ec2.security_group.unrestricted_ingress
azure.storage.account.https_only
gcp.compute.firewall.restricted_ssh
```

---

## Severity Levels

| Level | Score Range | Usage |
|-------|-----------|-------|
| `critical` | 90-100 | Direct exposure, immediate exploitation risk |
| `high` | 70-89 | Significant security gap |
| `medium` | 40-69 | Best practice violation |
| `low` | 1-39 | Minor improvement |
| `informational` | 0 | Observation only |

---

## MITRE Technique Mapping

When creating rules, map to relevant MITRE ATT&CK techniques:

| Check Type | Common Techniques |
|-----------|------------------|
| Public access | T1190 (Exploit Public App) |
| Missing MFA | T1078 (Valid Accounts) |
| No encryption | T1530 (Data from Cloud Storage) |
| No logging | T1562 (Impair Defenses) |
| No backups | T1485 (Data Destruction) |
| Weak IAM | T1098 (Account Manipulation) |
| Data exposure | T1537 (Transfer to Cloud Account) |

---

## Templates

Use templates to quickly create rules:

```bash
# List available templates
curl http://localhost:8011/api/v1/rules/templates

# Create rule from template
curl -X POST http://localhost:8011/api/v1/rules/templates/encryption_check/create \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "aws",
    "service": "rds",
    "resource": "instance"
  }'
```

---

## Bulk Operations

### Import Rules

```bash
curl -X POST http://localhost:8011/api/v1/rules/import \
  -H "Content-Type: application/json" \
  -d '{"rules": [{ ... }, { ... }], "format": "json"}'
```

### Export Rules

```bash
curl "http://localhost:8011/api/v1/rules/export?provider=aws&format=yaml"
```

---

## Browse Available Fields

Before writing a rule, check what fields are available:

```bash
# List services for a provider
curl http://localhost:8011/api/v1/providers/aws/services

# Get available fields for a service
curl http://localhost:8011/api/v1/providers/aws/services/s3/fields

# Get service capabilities
curl http://localhost:8011/api/v1/providers/aws/services/s3/capabilities
```
