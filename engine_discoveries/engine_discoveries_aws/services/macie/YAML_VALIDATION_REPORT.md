# Macie YAML Validation Report

**Validation Date**: 2026-01-08  
**Service**: macie  
**Total Rules**: 13  
**Test Region**: us-east-1

---

## Test Results Summary

**Scan Execution**: ✅ PASSED (no errors)  
**Total Checks**: 25 (5 per account across 5 accounts)  
**PASS**: 0  
**FAIL**: 25  
**Status**: Logic issues identified - all checks failed (expected when Macie is not enabled)

**Note**: Macie is not enabled in test accounts, so all checks fail with AccessDeniedException. This is expected behavior. However, field path and logic issues still need to be validated.

---

## Critical Issues Summary

### Discovery ID Mismatches

Several rules use discovery IDs that don't match the actual discovery definitions:

1. **`aws.macie2.list_members`** - Used by rules but discovery calls `describe_buckets` (not `list_members`)
2. **`aws.macie2.list_organization_admin_accounts`** - Used by rules but discovery calls `describe_buckets` (not `list_organization_admin_accounts`)

### Field Path Issues

Many rules reference fields that don't match the emit structure:

1. Rules reference `item.JobStatus` but emit shows `item.jobStatus` (case mismatch)
2. Rules reference `item.policy.BlocksPublicAccess` but emit doesn't show `policy` field
3. Rules reference `item.s3Destination` but emit doesn't show this field
4. Rules reference nested paths that may not exist in actual API response

---

## Per-Rule Validation (Key Issues)

### 1. `aws.macie.findings.retention_days_minimum`

**Metadata Intent**: Verify retention days minimum is configured

**YAML Implementation**:
```yaml
- rule_id: aws.macie.findings.retention_days_minimum
  for_each: aws.macie.list_findings
  conditions:
    var: item.classificationDetails.result.sensitiveDataOccurrences.retentionDays
    op: greater_than
    value: '30'
```

**Issues**: 
- ⚠️ Field path may not exist - `classificationDetails.result.sensitiveDataOccurrences.retentionDays` is deeply nested and may not be present in all findings
- Need to verify if this field exists in actual API response

**Status**: ⚠️ Needs verification

---

### 2. `aws.macie.custom_data_identifier.macie_auto_classification_enabled_if_supported`

**Metadata Intent**: Verify auto classification is enabled

**YAML Implementation**:
```yaml
- rule_id: aws.macie.custom_data_identifier.macie_auto_classification_enabled_if_supported
  for_each: aws.macie2.list_classification_jobs
  conditions:
    var: item.JobStatus
    op: equals
    value: RUNNING
```

**Issues**: 
- ❌ **CRITICAL**: Field path case mismatch - emit shows `item.jobStatus` (lowercase) but rule checks `item.JobStatus` (uppercase)
- ❌ Logic issue - Checks if job status is RUNNING, but this doesn't verify "auto classification enabled" - it just checks if a job is running

**Status**: ❌ Critical - Wrong field path and logic

---

### 3. `aws.macie.custom_data_identifier.policy_blocks_public_for_sensitive_configured`

**Metadata Intent**: Verify policy blocks public access for sensitive data

**YAML Implementation**:
```yaml
- rule_id: aws.macie.custom_data_identifier.policy_blocks_public_for_sensitive_configured
  for_each: aws.macie.list_custom_data_identifiers
  conditions:
    all:
    - var: item.policy.BlocksPublicAccess
      op: equals
      value: 'true'
    - var: item.sensitivityLevel
      op: equals
      value: HIGH
```

**Issues**: 
- ❌ **CRITICAL**: Field path `item.policy.BlocksPublicAccess` doesn't exist in emit structure
- ❌ Field path `item.sensitivityLevel` doesn't exist in emit structure
- Emit structure only shows: `arn`, `createdAt`, `deleted`, `description`, `id`, `name`

**Status**: ❌ Critical - Wrong field paths

---

### 4. `aws.macie.findings.macie_logs_centralized_and_encrypted`

**Metadata Intent**: Verify logs are centralized and encrypted

**YAML Implementation**:
```yaml
- rule_id: aws.macie.findings.macie_logs_centralized_and_encrypted
  for_each: aws.macie.list_findings
  conditions:
    all:
    - var: item.resourcesAffected.s3BucketDetails.defaultServerSideEncryption
      op: exists
      value: null
    - var: item.resourcesAffected.s3BucketDetails.defaultServerSideEncryption.encryptionType
      op: in
      value:
      - aws:kms
      - AES256
    - var: item.resourcesAffected.s3BucketDetails.defaultServerSideEncryption.kmsMasterKeyId
      op: exists
      value: null
```

**Issues**: 
- ⚠️ Field path may be incorrect - `resourcesAffected.s3BucketDetails.defaultServerSideEncryption` may not match actual API structure
- Emit shows `resourcesAffected` but structure may be different
- This checks S3 bucket encryption, not Macie logs encryption

**Status**: ⚠️ Needs verification - May check wrong resource

---

### 5. `aws.macie.custom_data_identifier.macie_required_sensitivity_tags_present`

**Metadata Intent**: Verify required sensitivity tags are present

**YAML Implementation**:
```yaml
- rule_id: aws.macie.custom_data_identifier.macie_required_sensitivity_tags_present
  for_each: aws.macie2.list_members
  conditions:
    all:
    - var: item.tags
      op: exists
      value: null
    - var: item.tags
      op: not_equals
      value: []
```

**Issues**: 
- ❌ **CRITICAL**: Wrong discovery ID - `aws.macie2.list_members` discovery calls `describe_buckets`, not `list_members`
- ❌ Field path `item.tags` doesn't exist in emit structure (emit shows bucket fields, not tags)
- Rule name says "custom_data_identifier" but uses bucket discovery

**Status**: ❌ Critical - Wrong discovery and field paths

---

### 6. `aws.macie.findings.macie_export_destinations_private_configured`

**Metadata Intent**: Verify export destinations are private

**YAML Implementation**:
```yaml
- rule_id: aws.macie.findings.macie_export_destinations_private_configured
  for_each: aws.macie2.describe_buckets
  conditions:
    all:
    - var: item.s3Destination.bucketName
      op: exists
      value: null
    - var: item.s3Destination.bucketName
      op: contains
      value: private
    - var: item.s3Destination.kmsKeyArn
      op: exists
      value: null
```

**Issues**: 
- ❌ **CRITICAL**: Field path `item.s3Destination` doesn't exist in emit structure
- Emit structure shows bucket fields like `bucketName`, `bucketArn`, etc., but not `s3Destination`
- Rule name says "findings" but uses bucket discovery

**Status**: ❌ Critical - Wrong field paths

---

### 7. `aws.macie.findings.rbac_least_privilege`

**Metadata Intent**: Verify RBAC least privilege

**YAML Implementation**:
```yaml
- rule_id: aws.macie.findings.rbac_least_privilege
  for_each: aws.macie2.list_resource_profile_detections
  conditions:
    all:
    - var: item.ResourcesAffected.S3Bucket.AccessControlList.Grants.Grantee.Type
      op: equals
      value: CanonicalUser
    - var: item.ResourcesAffected.S3Bucket.AccessControlList.Grants.Permission
      op: in
      value:
      - READ
      - WRITE
      - READ_ACP
      - WRITE_ACP
```

**Issues**: 
- ❌ **CRITICAL**: Wrong discovery ID - `aws.macie2.list_resource_profile_detections` discovery calls `get_usage_totals`, not `list_resource_profile_detections`
- ❌ Field paths don't match emit structure - emit shows `usageTotals` with `currency`, `estimatedCost`, `type`, not `ResourcesAffected`
- Logic checks S3 bucket ACLs, not Macie RBAC

**Status**: ❌ Critical - Wrong discovery and field paths

---

### 8. `aws.macie.classification_job.macie_auto_classification_enabled_if_supported`

**Metadata Intent**: Verify auto classification is enabled

**YAML Implementation**:
```yaml
- rule_id: aws.macie.classification_job.macie_auto_classification_enabled_if_supported
  for_each: aws.macie2.list_organization_admin_accounts
  conditions:
    all:
    - var: item.s3JobDefinition.bucketDefinitions.accountId
      op: exists
      value: null
    - var: item.s3JobDefinition.bucketDefinitions.buckets.name
      op: exists
      value: null
    - var: item.s3JobDefinition.scoping.includes.and.simpleScopeTerm.comparator
      op: equals
      value: EQ
    - var: item.s3JobDefinition.scoping.includes.and.simpleScopeTerm.key
      op: equals
      value: OBJECT_EXTENSION
    - var: item.s3JobDefinition.scoping.includes.and.simpleScopeTerm.values
      op: exists
      value: null
```

**Issues**: 
- ❌ **CRITICAL**: Wrong discovery ID - `aws.macie2.list_organization_admin_accounts` discovery calls `describe_buckets`, not `list_organization_admin_accounts`
- ❌ Field paths `item.s3JobDefinition` don't exist in emit structure
- Emit structure shows bucket fields, not job definition fields

**Status**: ❌ Critical - Wrong discovery and field paths

---

### 9. `aws.macie.findings.integrations_authenticated_configured`

**Metadata Intent**: Verify integrations are authenticated

**YAML Implementation**:
```yaml
- rule_id: aws.macie.findings.integrations_authenticated_configured
  for_each: aws.macie.list_findings
  conditions:
    var: item.Resources.Details.AwsMacieFinding.IntegrationsAuthenticated
    op: equals
    value: 'true'
```

**Issues**: 
- ❌ Field path doesn't match emit structure - emit shows `resourcesAffected`, not `Resources.Details.AwsMacieFinding`
- Case mismatch - emit uses lowercase `resourcesAffected`, rule uses uppercase `Resources`

**Status**: ❌ Critical - Wrong field path

---

### 10. `aws.macie.classification_job.macie_required_sensitivity_tags_present`

**Metadata Intent**: Verify required sensitivity tags are present

**YAML Implementation**:
```yaml
- rule_id: aws.macie.classification_job.macie_required_sensitivity_tags_present
  for_each: aws.macie2.list_members
  conditions:
    all:
    - var: item.tags
      op: exists
      value: null
    - var: item.tags
      op: not_equals
      value: []
```

**Issues**: 
- ❌ **CRITICAL**: Same as rule 5 - wrong discovery ID and field paths

**Status**: ❌ Critical - Wrong discovery and field paths

---

### 11. `aws.macie.findings.macie_reports_storage_encrypted`

**Metadata Intent**: Verify reports storage is encrypted

**YAML Implementation**:
```yaml
- rule_id: aws.macie.findings.macie_reports_storage_encrypted
  for_each: aws.macie.list_findings
  conditions:
    all:
    - var: item.Resources.S3BucketDetails.Encryption
      op: exists
      value: 'true'
    - var: item.Resources.S3BucketDetails.Encryption
      op: equals
      value: AES256
```

**Issues**: 
- ❌ Field path doesn't match emit structure - emit shows `resourcesAffected`, not `Resources.S3BucketDetails`
- Case mismatch and wrong structure
- Logic issue - checks if encryption equals 'true' AND equals 'AES256' (contradictory)

**Status**: ❌ Critical - Wrong field path and contradictory logic

---

### 12. `aws.macie.classification_job.policy_blocks_public_for_sensitive_configured`

**Metadata Intent**: Verify policy blocks public access for sensitive

**YAML Implementation**:
```yaml
- rule_id: aws.macie.classification_job.policy_blocks_public_for_sensitive_configured
  for_each: aws.macie2.list_organization_admin_accounts
  conditions:
    all:
    - var: item.s3JobDefinition.bucketDefinitions.accountId
      op: exists
      value: null
    - var: item.s3JobDefinition.bucketDefinitions.buckets
      op: exists
      value: null
    - var: item.s3JobDefinition.scoping.includes.and.simpleScopeTerm.comparator
      op: equals
      value: EQ
    - var: item.s3JobDefinition.scoping.includes.and.simpleScopeTerm.key
      op: equals
      value: OBJECT_EXTENSION
    - var: item.s3JobDefinition.scoping.includes.and.simpleScopeTerm.values
      op: in
      value:
      - pdf
      - docx
      - xlsx
```

**Issues**: 
- ❌ **CRITICAL**: Same as rule 8 - wrong discovery ID and field paths

**Status**: ❌ Critical - Wrong discovery and field paths

---

### 13. `aws.macie.findings.alert_destinations_configured`

**Metadata Intent**: Verify alert destinations are configured

**YAML Implementation**:
```yaml
- rule_id: aws.macie.findings.alert_destinations_configured
  for_each: aws.macie.list_findings
  conditions:
    all:
    - var: item.Resources.S3BucketDetails.AlertDestinations
      op: exists
      value: null
    - var: item.Resources.S3BucketDetails.AlertDestinations
      op: not_equals
      value: []
```

**Issues**: 
- ❌ Field path doesn't match emit structure - emit shows `resourcesAffected`, not `Resources.S3BucketDetails`
- Case mismatch

**Status**: ❌ Critical - Wrong field path

---

## Summary of Critical Issues

### Discovery ID Mismatches (4 rules)

1. `aws.macie2.list_members` - Calls `describe_buckets` instead of `list_members`
2. `aws.macie2.list_organization_admin_accounts` - Calls `describe_buckets` instead of `list_organization_admin_accounts`
3. `aws.macie2.list_resource_profile_detections` - Calls `get_usage_totals` instead of `list_resource_profile_detections`

### Field Path Issues (10+ rules)

- Case mismatches: `JobStatus` vs `jobStatus`, `Resources` vs `resourcesAffected`
- Missing fields: `policy`, `s3Destination`, `tags`, `s3JobDefinition` don't exist in emit structures
- Wrong structure: Rules reference nested paths that don't match actual API response

### Logic Issues (2 rules)

1. `macie_auto_classification_enabled_if_supported` - Checks job status instead of auto classification setting
2. `macie_reports_storage_encrypted` - Contradictory conditions (equals 'true' AND equals 'AES256')

---

## Recommendations

### Immediate Fixes Required

1. **Fix discovery IDs**: Update discovery definitions to match actual API calls or update rule `for_each` references
2. **Fix field paths**: Match emit structure exactly (case-sensitive, correct nesting)
3. **Fix logic**: Remove contradictory conditions, verify checks match intent
4. **Verify API structure**: Test against actual Macie API responses to confirm field paths

### Discovery Fixes Needed

- `aws.macie2.list_members` → Should call `list_members` or update rules to use correct discovery
- `aws.macie2.list_organization_admin_accounts` → Should call `list_organization_admin_accounts` or update rules
- `aws.macie2.list_resource_profile_detections` → Should call `list_resource_profile_detections` or update rules

### Field Path Corrections

- Use `item.jobStatus` (lowercase) instead of `item.JobStatus`
- Use `item.resourcesAffected` instead of `item.Resources`
- Verify actual API response structure for nested fields
- Remove references to fields that don't exist in emit structure

---

## Validation Status

**Overall Status**: ❌ **Critical Issues - 10+ rules have wrong discovery IDs, field paths, or logic**

Most rules need significant fixes to match actual Macie API structure and emit definitions.





