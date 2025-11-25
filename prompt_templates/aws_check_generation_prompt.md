# AWS Compliance Check Generation Prompt Template

## ⚠️ CRITICAL: Minimal Check Structure

**Checks should contain ONLY:**
- `rule_id` - Lookup key for metadata
- `for_each` - Iteration structure
- `conditions` - Validation logic

**Do NOT include in checks:**
- ❌ `title` - Lives in metadata
- ❌ `severity` - Lives in metadata  
- ❌ `remediation` - Lives in metadata
- ❌ `references` - Lives in metadata
- ❌ `description` - Lives in metadata
- ❌ `assertion_id` - Not needed (use rule_id)

**All descriptive data is looked up from metadata using `rule_id`!**

## ⚠️ CRITICAL: Proper Check Implementation Required

**DO NOT create placeholder checks that only verify resource existence!**

Each check MUST actually validate the security control it claims to check.

### ❌ WRONG - Placeholder Check (DO NOT DO THIS)
```yaml
checks:
  - rule_id: aws.s3.bucket.encryption.enabled
    for_each:
      as: resource
      item: id
    conditions:
      var: item.id
      op: exists  # ❌ Only checks if bucket exists, NOT if encryption is enabled!
```

### ✅ CORRECT - Proper Validation
```yaml
discovery:
  - discovery_id: aws.s3.bucket_encryption
    for_each: aws.s3.buckets
    calls:
      - client: s3
        action: get_bucket_encryption  # Get actual encryption config
        params:
          Bucket: '{{ item.name }}'

checks:
  - rule_id: aws.s3.bucket.encryption.enabled
    for_each:
      as: resource
      item: id
    conditions:
      var: encryption.encryption_enabled  # ✅ Actually validates encryption is ON
      op: equals
      value: true
```

---

## Context

You are a compliance engineer creating **WORKING** security checks for AWS infrastructure. Each check must:
1. **Fetch the actual configuration** (not just list resources)
2. **Validate the security setting** (not just check existence)
3. **Match the check title** (what you check must match what the title says)

**Note**: This prompt generates the **rule file** only. For **CSP metadata**, use `aws_metadata_generation_prompt.md`.

---

## Rule File Structure

### Complete Rule Template (With Proper Validation)

```yaml
version: '1.0'
provider: aws
service: <service_name>  # Must match boto3 client name exactly

# Discovery section - MUST be an array with multiple steps
discovery:
  # Step 1: List all resources
  - discovery_id: aws.<service>.resources
    calls:
      - client: <boto3_client>  # e.g., 's3', 'ec2', 'iam'
        action: <list_action>  # e.g., 'list_buckets', 'describe_instances'
        paginate: true
        save_as: resources_list
        fields:
          - <ArrayField>[]  # e.g., 'Buckets[]', 'Reservations[].Instances[]'
    emit:
      items_for: resources_list[]
      as: resource
      item:
        id: '{{ resource.<IdField> }}'  # Resource identifier
        name: '{{ resource.<NameField> }}'  # Resource name (if different from id)

  # Step 2: Get detailed configuration for each resource
  - discovery_id: aws.<service>.<config_type>
    for_each: aws.<service>.resources  # Iterate over resources from Step 1
    calls:
      - client: <boto3_client>
        action: <get_config_action>  # e.g., 'get_bucket_encryption', 'describe_instances'
        params:
          <ResourceParam>: '{{ item.name }}'  # e.g., 'Bucket: {{ item.name }}'
        save_as: config_response
        on_error: continue  # Handle cases where config might not exist
        fields:
          - <ConfigField>  # e.g., 'ServerSideEncryptionConfiguration.Rules[]'
    emit:
      items_for: config_response[]  # Or just 'item:' if single object
      as: config
      item:
        resource_id: '{{ item.id }}'
        resource_name: '{{ item.name }}'
        <setting_name>: '{{ config.<SettingField> }}'  # Actual setting value
        # Add more fields as needed

  # Step 3+: Additional configuration checks as needed
  # (versioning, logging, policies, etc.)

checks:
  # Each check validates ONE specific security control
  - title: <Human Readable Title>  # Must match what you're actually checking
    severity: <critical|high|medium|low>
    rule_id: aws.<service>.<category>.<check_name>
    assertion_id: <framework>.<domain>.<control>
    for_each:
      discovery: aws.<service>.<config_type>  # Use the discovery with actual config
      as: config
      item: resource_id
    conditions:
      var: config.<actual_setting>  # Check the ACTUAL configuration value
      op: equals  # or contains, exists, gt, etc.
      value: <expected_secure_value>  # What the setting SHOULD be
    remediation: |
      <Detailed steps to fix the issue>
      1. Step by step instructions
      2. With specific commands or console actions
      3. Include verification steps
    references:
      - https://docs.aws.amazon.com/<service>/specific-topic.html
```

---

## Discovery Patterns by AWS Service

### S3 Configuration Checks

```yaml
service: s3

discovery:
  # List buckets
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

  # Get encryption config
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
        kms_key_id: '{{ rule.ApplyServerSideEncryptionByDefault.KMSMasterKeyID }}'

  # Get versioning config
  - discovery_id: aws.s3.bucket_versioning
    for_each: aws.s3.buckets
    calls:
      - client: s3
        action: get_bucket_versioning
        params:
          Bucket: '{{ item.name }}'
        save_as: versioning
    emit:
      item:
        bucket: '{{ item.name }}'
        status: '{{ versioning.Status }}'
        mfa_delete: '{{ versioning.MFADelete }}'

  # Get logging config
  - discovery_id: aws.s3.bucket_logging
    for_each: aws.s3.buckets
    calls:
      - client: s3
        action: get_bucket_logging
        params:
          Bucket: '{{ item.name }}'
        save_as: logging
    emit:
      item:
        bucket: '{{ item.name }}'
        logging_enabled: '{{ logging.LoggingEnabled }}'
        target_bucket: '{{ logging.LoggingEnabled.TargetBucket }}'

  # Get public access block
  - discovery_id: aws.s3.public_access_block
    for_each: aws.s3.buckets
    calls:
      - client: s3
        action: get_public_access_block
        params:
          Bucket: '{{ item.name }}'
        save_as: public_access
        on_error: continue
    emit:
      item:
        bucket: '{{ item.name }}'
        block_public_acls: '{{ public_access.PublicAccessBlockConfiguration.BlockPublicAcls }}'
        block_public_policy: '{{ public_access.PublicAccessBlockConfiguration.BlockPublicPolicy }}'

checks:
  - title: S3 Bucket Encryption Enabled
    severity: high
    rule_id: aws.s3.bucket.encryption_enabled
    for_each:
      discovery: aws.s3.bucket_encryption
      as: encryption
      item: bucket
    conditions:
      var: encryption.sse_algorithm
      op: exists
    remediation: |
      Enable S3 bucket encryption:
      1. Open S3 console and select the bucket
      2. Go to Properties > Default encryption
      3. Enable encryption with AES-256 or AWS-KMS
    references:
      - https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html
```

### EC2 Configuration Checks

```yaml
service: ec2

discovery:
  # Get instances with details
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
        state: '{{ instance.State.Name }}'
        public_ip: '{{ instance.PublicIpAddress }}'
        metadata_options: '{{ instance.MetadataOptions }}'

  # Get EBS volumes
  - discovery_id: aws.ec2.volumes
    calls:
      - client: ec2
        action: describe_volumes
        paginate: true
        save_as: volumes_list
        fields:
          - Volumes[]
    emit:
      items_for: volumes_list[]
      as: volume
      item:
        id: '{{ volume.VolumeId }}'
        encrypted: '{{ volume.Encrypted }}'
        kms_key_id: '{{ volume.KmsKeyId }}'
        state: '{{ volume.State }}'

  # Get security groups
  - discovery_id: aws.ec2.security_groups
    calls:
      - client: ec2
        action: describe_security_groups
        paginate: true
        save_as: sg_list
        fields:
          - SecurityGroups[]
    emit:
      items_for: sg_list[]
      as: sg
      item:
        id: '{{ sg.GroupId }}'
        name: '{{ sg.GroupName }}'
        ingress_rules: '{{ sg.IpPermissions }}'
        egress_rules: '{{ sg.IpPermissionsEgress }}'

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
      Enable IMDSv2 for EC2 instances:
      1. Stop the instance (or modify while running)
      2. Use AWS CLI: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required
      3. Verify with: aws ec2 describe-instances --instance-ids <id>
    references:
      - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html

  - title: EBS Volume Encryption Enabled
    severity: high
    rule_id: aws.ec2.ebs.volume_encrypted
    for_each:
      discovery: aws.ec2.volumes
      as: volume
      item: id
    conditions:
      var: volume.encrypted
      op: equals
      value: true
    remediation: |
      Enable EBS volume encryption:
      1. For new volumes: Enable encryption during creation
      2. For existing volumes: Create encrypted snapshot and restore
      3. Enable EBS encryption by default: aws ec2 enable-ebs-encryption-by-default
    references:
      - https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html
```

### IAM Configuration Checks

```yaml
service: iam

discovery:
  # List users
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
        arn: '{{ user.Arn }}'
        create_date: '{{ user.CreateDate }}'

  # Get MFA devices for each user
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
        device_count: '{{ mfa_devices | length }}'

  # Get access keys for each user
  - discovery_id: aws.iam.user_access_keys
    for_each: aws.iam.users
    calls:
      - client: iam
        action: list_access_keys
        params:
          UserName: '{{ item.id }}'
        save_as: access_keys
        fields:
          - AccessKeyMetadata[]
    emit:
      items_for: access_keys[]
      as: key
      item:
        user: '{{ item.id }}'
        key_id: '{{ key.AccessKeyId }}'
        status: '{{ key.Status }}'
        create_date: '{{ key.CreateDate }}'

  # Get password policy
  - discovery_id: aws.iam.password_policy
    calls:
      - client: iam
        action: get_account_password_policy
        save_as: policy
    emit:
      item:
        min_length: '{{ policy.PasswordPolicy.MinimumPasswordLength }}'
        require_symbols: '{{ policy.PasswordPolicy.RequireSymbols }}'
        require_numbers: '{{ policy.PasswordPolicy.RequireNumbers }}'
        require_uppercase: '{{ policy.PasswordPolicy.RequireUppercaseCharacters }}'
        require_lowercase: '{{ policy.PasswordPolicy.RequireLowercaseCharacters }}'
        max_age: '{{ policy.PasswordPolicy.MaxPasswordAge }}'
        reuse_prevention: '{{ policy.PasswordPolicy.PasswordReusePrevention }}'

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
      Enable MFA for IAM users:
      1. Sign in to AWS Console
      2. Go to IAM > Users > Select user
      3. Security credentials tab > Assign MFA device
      4. Follow the setup wizard (virtual MFA app or hardware token)
    references:
      - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html

  - title: IAM Password Policy Requires Minimum Length
    severity: medium
    rule_id: aws.iam.password_policy.min_length
    for_each:
      discovery: aws.iam.password_policy
      as: policy
      item: min_length
    conditions:
      var: policy.min_length
      op: gte
      value: 14
    remediation: |
      Update IAM password policy:
      1. Go to IAM > Account settings
      2. Set minimum password length to at least 14 characters
      3. Or use CLI: aws iam update-account-password-policy --minimum-password-length 14
    references:
      - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html
```

### RDS Configuration Checks

```yaml
service: rds

discovery:
  # Get DB instances
  - discovery_id: aws.rds.instances
    calls:
      - client: rds
        action: describe_db_instances
        paginate: true
        save_as: instances_list
        fields:
          - DBInstances[]
    emit:
      items_for: instances_list[]
      as: instance
      item:
        id: '{{ instance.DBInstanceIdentifier }}'
        engine: '{{ instance.Engine }}'
        encrypted: '{{ instance.StorageEncrypted }}'
        kms_key_id: '{{ instance.KmsKeyId }}'
        publicly_accessible: '{{ instance.PubliclyAccessible }}'
        multi_az: '{{ instance.MultiAZ }}'
        backup_retention: '{{ instance.BackupRetentionPeriod }}'
        auto_minor_upgrade: '{{ instance.AutoMinorVersionUpgrade }}'

  # Get DB snapshots
  - discovery_id: aws.rds.snapshots
    calls:
      - client: rds
        action: describe_db_snapshots
        paginate: true
        save_as: snapshots_list
        fields:
          - DBSnapshots[]
    emit:
      items_for: snapshots_list[]
      as: snapshot
      item:
        id: '{{ snapshot.DBSnapshotIdentifier }}'
        encrypted: '{{ snapshot.Encrypted }}'
        kms_key_id: '{{ snapshot.KmsKeyId }}'
        snapshot_type: '{{ snapshot.SnapshotType }}'

checks:
  - title: RDS Instance Encryption Enabled
    severity: high
    rule_id: aws.rds.instance.encryption_enabled
    for_each:
      discovery: aws.rds.instances
      as: instance
      item: id
    conditions:
      var: instance.encrypted
      op: equals
      value: true
    remediation: |
      Enable RDS encryption:
      1. Cannot enable on existing instance - must create new encrypted instance
      2. Take snapshot of unencrypted instance
      3. Copy snapshot with encryption enabled
      4. Restore from encrypted snapshot
      5. Update application endpoints
    references:
      - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html

  - title: RDS Instance Not Publicly Accessible
    severity: critical
    rule_id: aws.rds.instance.not_public
    for_each:
      discovery: aws.rds.instances
      as: instance
      item: id
    conditions:
      var: instance.publicly_accessible
      op: equals
      value: false
    remediation: |
      Disable public accessibility for RDS:
      1. Go to RDS console > Databases
      2. Select the instance > Modify
      3. Under Connectivity > Additional configuration
      4. Set Publicly accessible to No
      5. Apply immediately or during maintenance window
    references:
      - https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_VPC.WorkingWithRDSInstanceinaVPC.html
```

### CloudTrail Configuration Checks

```yaml
service: cloudtrail

discovery:
  # Get trails
  - discovery_id: aws.cloudtrail.trails
    calls:
      - client: cloudtrail
        action: describe_trails
        save_as: trails_list
        fields:
          - trailList[]
    emit:
      items_for: trails_list[]
      as: trail
      item:
        id: '{{ trail.TrailARN }}'
        name: '{{ trail.Name }}'
        s3_bucket: '{{ trail.S3BucketName }}'
        is_multi_region: '{{ trail.IsMultiRegionTrail }}'
        log_file_validation: '{{ trail.LogFileValidationEnabled }}'
        kms_key_id: '{{ trail.KmsKeyId }}'

  # Get trail status
  - discovery_id: aws.cloudtrail.trail_status
    for_each: aws.cloudtrail.trails
    calls:
      - client: cloudtrail
        action: get_trail_status
        params:
          Name: '{{ item.name }}'
        save_as: status
    emit:
      item:
        trail: '{{ item.name }}'
        is_logging: '{{ status.IsLogging }}'
        latest_delivery_time: '{{ status.LatestDeliveryTime }}'

  # Get event selectors
  - discovery_id: aws.cloudtrail.event_selectors
    for_each: aws.cloudtrail.trails
    calls:
      - client: cloudtrail
        action: get_event_selectors
        params:
          TrailName: '{{ item.name }}'
        save_as: selectors
        fields:
          - EventSelectors[]
    emit:
      items_for: selectors[]
      as: selector
      item:
        trail: '{{ item.name }}'
        read_write_type: '{{ selector.ReadWriteType }}'
        include_management_events: '{{ selector.IncludeManagementEvents }}'

checks:
  - title: CloudTrail Enabled and Logging
    severity: critical
    rule_id: aws.cloudtrail.enabled
    for_each:
      discovery: aws.cloudtrail.trail_status
      as: status
      item: trail
    conditions:
      var: status.is_logging
      op: equals
      value: true
    remediation: |
      Enable CloudTrail logging:
      1. Go to CloudTrail console
      2. Select the trail
      3. Click Start logging
      4. Verify logs are being delivered to S3
    references:
      - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html

  - title: CloudTrail Multi-Region Enabled
    severity: high
    rule_id: aws.cloudtrail.multi_region
    for_each:
      discovery: aws.cloudtrail.trails
      as: trail
      item: id
    conditions:
      var: trail.is_multi_region
      op: equals
      value: true
    remediation: |
      Enable multi-region CloudTrail:
      1. Go to CloudTrail console
      2. Select the trail > Modify
      3. Enable "Apply trail to all regions"
      4. Save changes
    references:
      - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/receive-cloudtrail-log-files-from-multiple-regions.html

  - title: CloudTrail Log File Validation Enabled
    severity: medium
    rule_id: aws.cloudtrail.log_validation
    for_each:
      discovery: aws.cloudtrail.trails
      as: trail
      item: id
    conditions:
      var: trail.log_file_validation
      op: equals
      value: true
    remediation: |
      Enable CloudTrail log file validation:
      1. Go to CloudTrail console
      2. Select the trail > Modify
      3. Enable "Log file validation"
      4. This creates a digest file for each log delivery
    references:
      - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html
```

---

## ⚠️ CRITICAL RULES (Validated Through Production Use)

### Rule 1: Discovery MUST Be an Array
```yaml
# ✓ CORRECT
discovery:
- discovery_id: aws.service.resources
  calls: [...]

# ✗ WRONG
discovery:
  discovery_id: aws.service.resources
```

### Rule 2: Multiple Discovery Blocks for Proper Validation
```yaml
# ✓ CORRECT - Multiple discoveries for complete validation
discovery:
- discovery_id: aws.s3.buckets  # Step 1: List resources
  calls: [...]
- discovery_id: aws.s3.bucket_encryption  # Step 2: Get encryption config
  for_each: aws.s3.buckets
  calls: [...]
- discovery_id: aws.s3.bucket_versioning  # Step 3: Get versioning config
  for_each: aws.s3.buckets
  calls: [...]

# ✗ WRONG - Only listing, no validation
discovery:
- discovery_id: aws.s3.buckets
  calls: [...]  # Only lists buckets, doesn't check encryption!
```

### Rule 3: Check Must Validate Actual Configuration
```yaml
# ✓ CORRECT - Validates actual setting
conditions:
  var: encryption.sse_algorithm
  op: exists  # Actually checks if encryption is configured

# ✗ WRONG - Only checks if resource exists
conditions:
  var: item.id
  op: exists  # Meaningless - just checks if bucket exists!
```

### Rule 4: Use for_each with Discovery ID
```yaml
# ✓ CORRECT
for_each:
  discovery: aws.s3.bucket_encryption  # Links to specific discovery
  as: encryption
  item: bucket

# ✗ WRONG
for_each:
  as: resource
  item: id  # Doesn't specify which discovery to use
```

### Rule 5: Service Names Must Match boto3
```yaml
# ✓ CORRECT
service: s3  # NOT 'bucket'
service: iam  # NOT 'user'
service: ec2  # NOT 'instance' or 'vpc'
service: logs  # NOT 'log'
service: events  # NOT 'eventbridge'
```

### Rule 6: Common API Patterns

| Resource | List API | Get Config API | Key Fields |
|----------|----------|----------------|------------|
| S3 Buckets | `list_buckets` | `get_bucket_encryption` | `ServerSideEncryptionConfiguration` |
| EC2 Instances | `describe_instances` | Same API | `MetadataOptions`, `State` |
| IAM Users | `list_users` | `list_mfa_devices` | `MFADevices` |
| RDS Instances | `describe_db_instances` | Same API | `StorageEncrypted`, `PubliclyAccessible` |
| EBS Volumes | `describe_volumes` | Same API | `Encrypted`, `KmsKeyId` |
| Security Groups | `describe_security_groups` | Same API | `IpPermissions`, `IpPermissionsEgress` |

---

## Implementation Checklist

For each check you create, verify:

- [ ] **Discovery fetches actual configuration** (not just lists resources)
- [ ] **Check validates the specific setting** mentioned in title
- [ ] **Conditions check actual values** (not just `item.id exists`)
- [ ] **Title accurately describes** what is being validated
- [ ] **Remediation provides specific steps** to fix the issue
- [ ] **Severity matches impact** of the security control
- [ ] **References link to relevant** AWS documentation

---

## Testing Your Checks

After creating a check:

1. **Run against real AWS account** with both compliant and non-compliant resources
2. **Verify false positives** - check shouldn't pass when it should fail
3. **Verify false negatives** - check shouldn't fail when it should pass
4. **Check error handling** - ensure `on_error: continue` is used where appropriate
5. **Review output** - ensure emitted fields contain expected data

---

## Common Mistakes to Avoid

### ❌ Mistake 1: Only Checking Existence
```yaml
# WRONG
conditions:
  var: item.id
  op: exists  # This is useless!
```

### ❌ Mistake 2: Missing Configuration Discovery
```yaml
# WRONG - Only lists buckets, doesn't check encryption
discovery:
- discovery_id: aws.s3.buckets
  calls:
  - action: list_buckets
# Missing: get_bucket_encryption call!
```

### ❌ Mistake 3: Wrong Discovery in for_each
```yaml
# WRONG
for_each:
  discovery: aws.s3.buckets  # This only has bucket names
  as: encryption  # But we need encryption config!
```

### ❌ Mistake 4: Not Handling Errors
```yaml
# WRONG - Will fail if encryption not configured
calls:
- action: get_bucket_encryption
  # Missing: on_error: continue
```

---

## Severity Guidelines

- **`critical`**: Data exposure, public access to sensitive data, authentication bypass
- **`high`**: Encryption disabled, missing MFA on privileged accounts, unrestricted network access
- **`medium`**: Missing logging, suboptimal configuration, missing monitoring
- **`low`**: Best practices, optimization, non-critical configuration

---

## Next Steps

1. Review the service-specific patterns above
2. Understand the 2-3 step discovery process:
   - List resources
   - Get configuration for each resource
   - Validate specific settings
3. Create checks that actually validate security controls
4. Test against real AWS resources
5. Generate corresponding metadata using `aws_metadata_generation_prompt.md`

---

## Related Files
- **Metadata Generation**: `aws_metadata_generation_prompt.md`
- **Metadata Template**: `aws_csp_metadata_template.yaml`
- **Reference Implementation**: `services/s3/rules/s3_reference.yaml`
- **Implementation Guide**: `PROPER_CHECK_IMPLEMENTATION_GUIDE.md`
