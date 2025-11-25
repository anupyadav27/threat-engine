# AWS Compliance Check Generation - Implementation Guide

## Quick Start Summary

This guide helps you create **WORKING, VALIDATED** AWS security checks for the compliance engine.

### ✅ What Makes a Good Check
1. **Fetches actual configuration** (not just lists resources)
2. **Validates specific security settings** (matches check title)
3. **Has proper error handling** (on_error: continue where needed)
4. **Maps to rule_ids.yaml** (uses existing rule metadata)

---

## 📁 File Structure Integration

Your check files should align with the new service folder structure:

```
aws_compliance_python_engine/services/
├── {service}/
│   ├── metadata/
│   │   └── aws.{service}.{resource}.{requirement}.yaml  # Already created
│   └── checks/
│       └── {service}_checks.yaml  # TO BE CREATED (this guide)
```

### Linking Checks to Metadata

Each check in `{service}_checks.yaml` should reference a `rule_id` that exists in the `metadata/` folder:

```yaml
checks:
  - title: S3 Bucket Encryption Enabled
    rule_id: aws.s3.bucket.encryption_at_rest_enabled  # Must exist in metadata/
    # ... rest of check
```

---

## 🎯 Core Structure (3-Part Pattern)

Every check file follows this pattern:

### Part 1: Header
```yaml
version: '1.0'
provider: aws
service: s3  # Must match boto3 client name
```

### Part 2: Discovery (Multiple Steps)
```yaml
discovery:
  # Step 1: List all resources
  - discovery_id: aws.{service}.resources
    calls:
      - client: {service}
        action: list_{resources}  # or describe_{resources}
        paginate: true
        save_as: resources_list
        fields:
          - {ResponseArray}[]
    emit:
      items_for: resources_list[]
      as: resource
      item:
        id: '{{ resource.{IdField} }}'
        name: '{{ resource.{NameField} }}'

  # Step 2: Get configuration for each resource
  - discovery_id: aws.{service}.{config_type}
    for_each: aws.{service}.resources
    calls:
      - client: {service}
        action: get_{config}  # or describe_
        params:
          {ResourceParam}: '{{ item.name }}'
        save_as: config_data
        on_error: continue  # Important!
        fields:
          - {ConfigPath}
    emit:
      item:  # or items_for: if array
        resource_id: '{{ item.id }}'
        resource_name: '{{ item.name }}'
        {setting_name}: '{{ config_data.{Path} }}'
```

### Part 3: Checks (Validation)
```yaml
checks:
  - title: {Human Readable Title}
    severity: critical|high|medium|low
    rule_id: aws.{service}.{resource}.{requirement}  # From metadata/
    for_each:
      discovery: aws.{service}.{config_type}  # From discovery step 2+
      as: config
      item: resource_id
    conditions:
      var: config.{actual_setting}
      op: equals|exists|contains|gt|gte|lt|lte
      value: {expected_value}
    remediation: |
      Step-by-step fix instructions:
      1. ...
      2. ...
    references:
      - https://docs.aws.amazon.com/...
```

---

## 🔧 Service-Specific Quick Templates

### S3 (Full Example)
```yaml
version: '1.0'
provider: aws
service: s3

discovery:
  - discovery_id: aws.s3.buckets
    calls:
      - client: s3
        action: list_buckets
        save_as: buckets_list
        fields:
          - Buckets[]
    emit:
      items_for: buckets_list[]
      as: bucket
      item:
        id: '{{ bucket.Name }}'
        name: '{{ bucket.Name }}'

  - discovery_id: aws.s3.bucket_encryption
    for_each: aws.s3.buckets
    calls:
      - client: s3
        action: get_bucket_encryption
        params:
          Bucket: '{{ item.name }}'
        save_as: encryption
        on_error: continue
        fields:
          - ServerSideEncryptionConfiguration.Rules[]
    emit:
      items_for: encryption[]
      as: rule
      item:
        bucket: '{{ item.name }}'
        sse_algorithm: '{{ rule.ApplyServerSideEncryptionByDefault.SSEAlgorithm }}'

checks:
  - title: S3 Bucket Encryption at Rest Enabled
    severity: high
    rule_id: aws.s3.bucket.encryption_at_rest_enabled
    for_each:
      discovery: aws.s3.bucket_encryption
      as: encryption
      item: bucket
    conditions:
      var: encryption.sse_algorithm
      op: exists
    remediation: |
      Enable S3 bucket encryption:
      1. Console: S3 > Bucket > Properties > Default encryption > Edit
      2. Enable with AES-256 or AWS-KMS
      3. CLI: aws s3api put-bucket-encryption --bucket <name> --server-side-encryption-configuration '...'
    references:
      - https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-encryption.html
```

### EC2 (Quick Template)
```yaml
version: '1.0'
provider: aws
service: ec2

discovery:
  - discovery_id: aws.ec2.instances
    calls:
      - client: ec2
        action: describe_instances
        paginate: true
        save_as: reservations
        fields:
          - Reservations[].Instances[]
    emit:
      items_for: reservations[]
      as: instance
      item:
        id: '{{ instance.InstanceId }}'
        metadata_options: '{{ instance.MetadataOptions }}'

checks:
  - title: EC2 Instance IMDSv2 Required
    severity: high
    rule_id: aws.ec2.instance.imdsv2_required
    for_each:
      discovery: aws.ec2.instances
      as: instance
      item: id
    conditions:
      var: instance.metadata_options.HttpTokens
      op: equals
      value: 'required'
    remediation: |
      Enable IMDSv2:
      1. CLI: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required
      2. Console: EC2 > Instances > Actions > Instance settings > Modify instance metadata options
    references:
      - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html
```

### IAM (Quick Template)
```yaml
version: '1.0'
provider: aws
service: iam

discovery:
  - discovery_id: aws.iam.users
    calls:
      - client: iam
        action: list_users
        paginate: true
        save_as: users_list
        fields:
          - Users[]
    emit:
      items_for: users_list[]
      as: user
      item:
        id: '{{ user.UserName }}'

  - discovery_id: aws.iam.user_mfa
    for_each: aws.iam.users
    calls:
      - client: iam
        action: list_mfa_devices
        params:
          UserName: '{{ item.id }}'
        save_as: mfa_devices
        fields:
          - MFADevices[]
    emit:
      item:
        user: '{{ item.id }}'
        mfa_enabled: '{{ mfa_devices | length > 0 }}'

checks:
  - title: IAM User MFA Enabled
    severity: high
    rule_id: aws.iam.user.mfa_enabled
    for_each:
      discovery: aws.iam.user_mfa
      as: mfa
      item: user
    conditions:
      var: mfa.mfa_enabled
      op: equals
      value: true
    remediation: |
      Enable MFA:
      1. IAM Console > Users > Select user > Security credentials
      2. Click "Assign MFA device"
      3. Follow setup wizard
    references:
      - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html
```

---

## 📋 Implementation Workflow

### Step 1: Identify Service and Rules
```bash
# Check what rules exist for your service
ls aws_compliance_python_engine/services/{service}/metadata/

# Example for S3:
ls aws_compliance_python_engine/services/s3/metadata/
# Shows: aws.s3.bucket.encryption_at_rest_enabled.yaml, etc.
```

### Step 2: Group Related Rules
Group rules that can share discovery logic:
- **Encryption checks** → Use same `get_bucket_encryption` discovery
- **Logging checks** → Use same `get_bucket_logging` discovery
- **Access checks** → Use same `get_public_access_block` discovery

### Step 3: Create Discovery Steps
```yaml
discovery:
  # Always start with listing resources
  - discovery_id: aws.{service}.resources
    # ... list all resources ...

  # Then add specific config discoveries
  - discovery_id: aws.{service}.{config1}
    for_each: aws.{service}.resources
    # ... get config1 for each resource ...

  - discovery_id: aws.{service}.{config2}
    for_each: aws.{service}.resources
    # ... get config2 for each resource ...
```

### Step 4: Create Checks
For each rule_id in metadata/:
```yaml
checks:
  - title: {from metadata file}
    severity: {from metadata file}
    rule_id: {filename without .yaml}
    for_each:
      discovery: aws.{service}.{appropriate_discovery}
      as: config
      item: resource_id
    conditions:
      var: config.{setting}
      op: {appropriate operator}
      value: {secure value}
    remediation: |
      {from metadata file or create}
    references:
      - {from metadata file}
```

---

## ⚠️ Critical Rules (Must Follow)

### ✅ DO
- Use multiple discovery steps (list + get config)
- Check actual configuration values
- Add `on_error: continue` for optional configs
- Match rule_id to existing metadata files
- Use proper boto3 client/action names

### ❌ DON'T
- Only list resources without checking config
- Check `item.id exists` (meaningless)
- Hardcode values that should be parameterized
- Use wrong service names (e.g., 'bucket' instead of 's3')
- Skip error handling on optional configs

---

## 🧪 Testing Checklist

Before finalizing:
- [ ] Discovery returns expected data structure
- [ ] Checks validate actual security settings
- [ ] Error handling works for missing configs
- [ ] All rule_ids exist in metadata/ folder
- [ ] Titles match check logic
- [ ] Remediation steps are actionable

---

## 📚 Quick Reference

### Common AWS APIs

| Service | List API | Config API | Important Fields |
|---------|----------|------------|------------------|
| **S3** | `list_buckets` | `get_bucket_encryption` | `SSEAlgorithm`, `KMSMasterKeyID` |
| **EC2** | `describe_instances` | Same | `MetadataOptions`, `State`, `PublicIpAddress` |
| **IAM** | `list_users` | `list_mfa_devices` | `MFADevices[]` |
| **RDS** | `describe_db_instances` | Same | `StorageEncrypted`, `PubliclyAccessible` |
| **Lambda** | `list_functions` | `get_function` | `Environment.Variables` |
| **CloudTrail** | `describe_trails` | `get_trail_status` | `IsLogging`, `IsMultiRegionTrail` |

### Condition Operators

| Operator | Use Case | Example |
|----------|----------|---------|
| `equals` | Exact match | `value: true` or `value: 'Enabled'` |
| `exists` | Check if field present | For optional configs |
| `contains` | String/array contains | Check if value in list |
| `gt` / `gte` | Greater than | Numeric comparisons |
| `lt` / `lte` | Less than | Numeric comparisons |

---

## 🚀 Next Steps

1. **Pick a service** from `aws_compliance_python_engine/services/`
2. **Review metadata files** in `{service}/metadata/`
3. **Create checks file** at `{service}/checks/{service}_checks.yaml`
4. **Follow templates** from this guide
5. **Test against real AWS** resources
6. **Iterate** based on results

---

## 📞 Need Help?

Common issues:
- **"Discovery not working"** → Check boto3 client/action names
- **"Check always passes/fails"** → Verify conditions match actual data structure
- **"Errors on missing config"** → Add `on_error: continue`
- **"Can't find rule_id"** → Check metadata/ folder for exact filename

---

**Remember**: Each check should actually **VALIDATE** a security control, not just check if a resource exists!

