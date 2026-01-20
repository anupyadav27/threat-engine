# Rule Engine - Quick Reference Guide

## Setup

```bash
cd /Users/apple/Desktop/threat-engine/rule_engine

# Set output directory
export OUTPUT_DIR=/Users/apple/Desktop/threat-engine/engines-output/rule-engine/output
```

## Common Commands

### 1. List Available Providers
```bash
python3 cli.py list-services --provider aws
python3 cli.py list-services --provider azure
python3 cli.py list-services --provider gcp
```

### 2. List Fields for a Service
```bash
# AWS S3 fields
python3 cli.py list-fields --provider aws --service s3

# Azure Compute fields
python3 cli.py list-fields --provider azure --service compute

# GCP Storage fields
python3 cli.py list-fields --provider gcp --service storage
```

### 3. Generate Rules

#### Interactive Mode (Guided)
```bash
python3 cli.py generate --provider aws --service s3
# Follow the prompts to select:
# - Field name
# - Operator
# - Expected value
# - Rule ID, title, description, remediation
```

#### JSON Input Mode (Batch)
Create a JSON file (`rule_input.json`):
```json
[
  {
    "field_name": "BlockPublicAcls",
    "operator": "equals",
    "value": "True",
    "rule_id": "aws.s3.resource.block_public_acls_enabled",
    "title": "S3 Block Public ACLs Enabled",
    "description": "Ensure S3 bucket has BlockPublicAcls enabled",
    "remediation": "Enable Block Public ACLs in S3 bucket settings"
  }
]
```

Then run:
```bash
python3 cli.py generate --provider aws --service s3 --input rule_input.json
```

## Output Structure

Generated files are stored in:
```
engines-output/rule-engine/output/{service}/
├── {service}.yaml          # Rule definition with discovery and checks
└── metadata/
    └── {rule_id}.yaml      # Rule metadata
```

## Example Output Files

### Rule YAML (`s3.yaml`)
```yaml
version: '1.0'
provider: aws
service: s3
discovery:
  - discovery_id: aws.s3.get_public_access_block
    calls:
      - action: get_public_access_block
        save_as: response
    emit:
      as: item
      items_for: '{{ response.PublicAccessBlockConfiguration }}'
checks:
  - rule_id: aws.s3.resource.block_public_acls_enabled
    for_each: aws.s3.get_public_access_block
    conditions:
      var: item.BlockPublicAcls
      op: equals
      value: 'True'
```

### Metadata YAML
```yaml
rule_id: aws.s3.resource.block_public_acls_enabled
provider: aws
service: s3
title: S3 Block Public ACLs Enabled
description: Ensure S3 bucket has BlockPublicAcls enabled
remediation: Enable Block Public ACLs in S3 bucket settings
custom: true
created_at: '2026-01-14T15:53:56.865899Z'
severity: medium
```

## Supported Operators

- `equals` - Exact match
- `not_equals` - Not equal to
- `contains` - Contains substring/value
- `in` - Value in list
- `exists` - Field exists (no value needed)
- `greater_than` - Numeric comparison
- `less_than` - Numeric comparison

## Supported Providers

- **aws** - Amazon Web Services (432 services)
- **azure** - Microsoft Azure
- **gcp** - Google Cloud Platform
- **oci** - Oracle Cloud Infrastructure
- **alicloud** - Alibaba Cloud
- **ibm** - IBM Cloud
- **k8s** - Kubernetes

## Tips

1. **Use OUTPUT_DIR**: Always set the OUTPUT_DIR environment variable to store files in the correct location
2. **Check Existing Rules**: The tool automatically detects duplicate rules based on field+operator+value
3. **Validate Fields**: Use `list-fields` before creating rules to see available fields and operators
4. **Multi-Rule Generation**: You can include multiple rules in the JSON array for batch creation
5. **Rule ID Naming**: Follow the pattern: `{provider}.{service}.{resource}.{description}`

## Integration with Other Engines

The generated YAML files can be used with:
- **configScan engines**: For compliance scanning
- **compliance-engine**: For compliance reporting
- **inventory-engine**: For asset tracking

## Troubleshooting

**Issue**: Output saved to wrong directory  
**Solution**: Set OUTPUT_DIR environment variable before running

**Issue**: Field not found warning  
**Solution**: Use `list-fields` to verify available fields for the service

**Issue**: Service not found  
**Solution**: Use `list-services` to see available services for the provider
















