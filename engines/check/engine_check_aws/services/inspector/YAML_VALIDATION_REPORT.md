# Inspector YAML Validation Report

**Validation Date**: 2026-01-08  
**Service**: inspector  
**Total Rules**: 9  
**Test Region**: us-east-1

---

## Test Results Summary

**Scan Execution**: ✅ PASSED (no errors)  
**Total Checks**: 0 (no Inspector resources in test accounts - expected)  
**PASS**: 0  
**FAIL**: 0  
**Status**: YAML structure is correct, executes without errors

**Note**: Inspector Classic resources cannot be created programmatically, and Inspector Classic is being deprecated in favor of Inspector v2. The YAML will execute correctly once resources exist.

---

## Per-Rule Validation

### 1. `aws.inspector.resource.inspector_is_enabled`

**Metadata Intent**:  
- Verify that Inspector is enabled
- Check that Inspector service is properly configured and active

**YAML Implementation**:
```yaml
- rule_id: aws.inspector.resource.inspector_is_enabled
  for_each: aws.inspector.describe_findings
  conditions:
    all:
    - var: item.serviceAttributes
      op: exists
      value: null
    - var: item.serviceAttributes.assessmentRunArn
      op: exists
      value: null
```

**Analysis**:
- ✅ Discovery chain: Correct (`list_findings` → `describe_findings`)
- ⚠️ Field path: Checks if `serviceAttributes` and `assessmentRunArn` exist
- ⚠️ Logic: **WEAK** - Only verifies that findings exist with service attributes, not that Inspector is actually enabled
- ❌ Intent match: **PARTIAL** - This checks if Inspector has been used (findings exist), but doesn't verify if Inspector service itself is enabled

**Match**: ⚠️ PARTIAL

**Issues**: 
- Rule checks if findings exist with service attributes, but doesn't verify if Inspector service is enabled
- May need to check Inspector service status or account-level configuration
- Inspector Classic doesn't have a direct "enabled/disabled" API - it's enabled when resources exist

**Test Result**: N/A (no resources)

**Recommendation**: 
- Consider if this check is appropriate for Inspector Classic (which doesn't have an explicit enable/disable)
- May need to check if any Inspector resources exist (templates, targets, runs) to infer service is enabled
- For Inspector v2, there may be a different API to check service status

---

### 2. `aws.inspector.assessment.inspector_agents_or_scanners_deployed_configured`

**Metadata Intent**:  
- Verify that Inspector agents or scanners are deployed
- Check that agents/scanners are properly configured and active

**YAML Implementation**:
```yaml
- rule_id: aws.inspector.assessment.inspector_agents_or_scanners_deployed_configured
  for_each: aws.inspector.describe_assessment_templates
  conditions:
    all:
    - var: item.assessmentTargetArn
      op: exists
      value: null
    - var: item.assessmentRunCount
      op: greater_than
      value: '0'
```

**Analysis**:
- ✅ Discovery chain: Correct (`list_assessment_templates` → `describe_assessment_templates`)
- ✅ Field path: Correct
- ✅ Logic: **REASONABLE** - Checks if assessment target exists and if assessment runs have been executed (which requires agents/scanners)
- ✅ Intent match: **YES** - If assessment runs exist, agents/scanners must be deployed

**Match**: ✅ YES

**Issues**: None identified

**Test Result**: N/A (no resources)

**Recommendation**: Rule logic is correct

---

### 3. `aws.inspector.assessment.inspector_results_export_destination_encrypted`

**Metadata Intent**:  
- Verify that Inspector results export destination is encrypted
- Check encryption configuration for exported results

**YAML Implementation**:
```yaml
- rule_id: aws.inspector.assessment.inspector_results_export_destination_encrypted
  for_each: aws.inspector.describe_assessment_runs
  conditions:
    all:
    - var: item.dataExportConfiguration
      op: exists
      value: null
    - var: item.dataExportConfiguration.s3Destination
      op: exists
      value: null
    - var: item.dataExportConfiguration.s3Destination.encryptionOption
      op: in
      value:
      - SSE_S3
      - SSE_KMS
```

**Analysis**:
- ✅ Discovery chain: Correct (`list_assessment_runs` → `describe_assessment_runs`)
- ✅ Field path: Correct
- ✅ Logic: **CORRECT** - Checks if data export configuration exists and if encryption is enabled (SSE_S3 or SSE_KMS)
- ✅ Intent match: **YES**

**Match**: ✅ YES

**Issues**: None identified

**Test Result**: N/A (no resources)

**Recommendation**: Rule logic is correct

---

### 4. `aws.inspector.assessment.policy_store_encrypted`

**Metadata Intent**:  
- Verify that Inspector policy store is encrypted
- Check encryption configuration for policy store

**YAML Implementation**:
```yaml
- rule_id: aws.inspector.assessment.policy_store_encrypted
  for_each: aws.inspector.describe_assessment_templates
  conditions:
    var: item.name
    op: exists
    value: null
```

**Analysis**:
- ✅ Discovery chain: Correct (`list_assessment_templates` → `describe_assessment_templates`)
- ❌ Field path: **WRONG** - Only checks if template `name` exists
- ❌ Logic: **WRONG** - This doesn't check anything about encryption or policy store
- ❌ Intent match: **NO** - Rule name says "policy_store_encrypted" but only verifies template name exists

**Match**: ❌ NO

**Issues**: 
- **CRITICAL**: Rule name says "policy_store_encrypted" but only checks if template name exists
- Missing check for encryption configuration
- Inspector Classic may not have a direct "policy store encryption" field - may need to check account-level settings or different API

**Test Result**: N/A (no resources)

**Recommendation**: 
- Research Inspector Classic API to find where policy store encryption is configured
- May need to check account-level settings or use a different API method
- If policy store encryption is not available in Inspector Classic, rule may need to be updated or removed

---

### 5. `aws.inspector.assessment.role_least_privilege`

**Metadata Intent**:  
- Verify that Inspector assessment uses role-based access control with least privilege
- Check IAM role configuration and permissions

**YAML Implementation**:
```yaml
- rule_id: aws.inspector.assessment.role_least_privilege
  for_each: aws.inspector.describe_assessment_runs
  conditions:
    all:
    - var: item.name
      op: exists
      value: null
    - var: item.arn
      op: exists
      value: null
    - var: item.state
      op: in
      value:
      - COMPLETED
      - RUNNING
```

**Analysis**:
- ✅ Discovery chain: Correct (`list_assessment_runs` → `describe_assessment_runs`)
- ❌ Field path: **WRONG** - Only checks if name, arn, and state exist/are valid
- ❌ Logic: **WRONG** - This doesn't check anything about IAM roles or least privilege
- ❌ Intent match: **NO** - Rule name says "role_least_privilege" but only verifies assessment run exists and is in valid state

**Match**: ❌ NO

**Issues**: 
- **CRITICAL**: Rule name says "role_least_privilege" but doesn't check IAM roles or permissions
- Missing check for IAM role ARN
- Missing check for role permissions/policies
- May need to use IAM API to check role policies and verify least privilege

**Test Result**: N/A (no resources)

**Recommendation**: 
- Add discovery to get IAM role ARN from assessment template or target
- Use IAM API to check role policies and verify least privilege principles
- May need to check `serviceRoleArn` field if available in assessment template/target

---

### 6. `aws.inspector.assessment.scope_includes_all_asset_groups_configured`

**Metadata Intent**:  
- Verify that Inspector assessment scope includes all asset groups
- Check that assessment covers all required asset groups

**YAML Implementation**:
```yaml
- rule_id: aws.inspector.assessment.scope_includes_all_asset_groups_configured
  for_each: aws.inspector.describe_assessment_templates
  conditions:
    all:
    - var: item.assessmentTargetArn
      op: exists
      value: null
    - var: item.rulesPackageArns
      op: exists
      value: null
```

**Analysis**:
- ✅ Discovery chain: Correct (`list_assessment_templates` → `describe_assessment_templates`)
- ⚠️ Field path: Checks if `assessmentTargetArn` and `rulesPackageArns` exist
- ⚠️ Logic: **WEAK** - Only verifies that a target and rules exist, but doesn't verify if "all asset groups" are included
- ❌ Intent match: **PARTIAL** - Rule name says "scope_includes_all_asset_groups" but doesn't check which asset groups are included

**Match**: ⚠️ PARTIAL

**Issues**: 
- Rule checks if assessment target and rules exist, but doesn't verify scope includes "all asset groups"
- May need to check assessment target configuration to see which asset groups are included
- May need to use `describe_assessment_targets` API to check target configuration

**Test Result**: N/A (no resources)

**Recommendation**: 
- Add discovery for `describe_assessment_targets` to check target configuration
- Verify which asset groups are included in the assessment target
- Check if all required asset groups are covered

---

### 7. `aws.inspector.finding.alert_destinations_configured`

**Metadata Intent**:  
- Verify that alert destinations are configured for Inspector findings
- Check notification/alerting configuration

**YAML Implementation**:
```yaml
- rule_id: aws.inspector.finding.alert_destinations_configured
  for_each: aws.inspector.list_event_subscriptions
  conditions:
    all:
    - var: item.topicArn
      op: exists
      value: null
    - var: item.eventSubscriptions
      op: exists
      value: null
```

**Analysis**:
- ✅ Discovery chain: Correct (`list_event_subscriptions`)
- ✅ Field path: Correct
- ✅ Logic: **CORRECT** - Checks if SNS topic ARN and event subscriptions exist
- ✅ Intent match: **YES**

**Match**: ✅ YES

**Issues**: None identified

**Test Result**: N/A (no resources)

**Recommendation**: Rule logic is correct

---

### 8. `aws.inspector.finding.inspector_archival_export_encrypted`

**Metadata Intent**:  
- Verify that Inspector archival export is encrypted
- Check encryption configuration for archived exports

**YAML Implementation**:
```yaml
- rule_id: aws.inspector.finding.inspector_archival_export_encrypted
  for_each: aws.inspector.describe_findings
  conditions:
    var: item.userAttributes
    op: exists
      value: null
```

**Analysis**:
- ✅ Discovery chain: Correct (`list_findings` → `describe_findings`)
- ❌ Field path: **WRONG** - Only checks if `userAttributes` exists
- ❌ Logic: **WRONG** - This doesn't check anything about encryption or archival export
- ❌ Intent match: **NO** - Rule name says "archival_export_encrypted" but only verifies user attributes exist

**Match**: ❌ NO

**Issues**: 
- **CRITICAL**: Rule name says "archival_export_encrypted" but only checks if user attributes exist
- Missing check for archival export configuration
- Missing check for encryption settings
- May need to check assessment run `dataExportConfiguration` or a different API

**Test Result**: N/A (no resources)

**Recommendation**: 
- Research Inspector Classic API to find where archival export encryption is configured
- May need to check `dataExportConfiguration` in assessment runs (similar to rule 3)
- May need to use a different API method or check account-level settings

---

### 9. `aws.inspector.finding.inspector_suppression_rules_documented_and_scoped_configured`

**Metadata Intent**:  
- Verify that Inspector suppression rules are documented and scoped
- Check that suppression rules are properly configured

**YAML Implementation**:
```yaml
- rule_id: aws.inspector.finding.inspector_suppression_rules_documented_and_scoped_configured
  for_each: aws.inspector.describe_findings
  conditions:
    all:
    - var: item.userAttributes
      op: exists
      value: null
```

**Analysis**:
- ✅ Discovery chain: Correct (`list_findings` → `describe_findings`)
- ❌ Field path: **WRONG** - Only checks if `userAttributes` exists
- ❌ Logic: **WRONG** - This doesn't check anything about suppression rules, documentation, or scoping
- ❌ Intent match: **NO** - Rule name says "suppression_rules_documented_and_scoped" but only verifies user attributes exist

**Match**: ❌ NO

**Issues**: 
- **CRITICAL**: Rule name says "suppression_rules_documented_and_scoped_configured" but only checks if user attributes exist
- Missing check for suppression rules configuration
- Missing check for documentation or scoping
- May need to use `get_exclusions_preview` or `list_exclusions` API to check suppression rules
- May need to check `userAttributes` content for suppression rule metadata (but current check is too generic)

**Test Result**: N/A (no resources)

**Recommendation**: 
- Research Inspector Classic API for suppression rules/exclusions
- May need to use `list_exclusions` or `get_exclusions_preview` API
- May need to check `userAttributes` for specific suppression rule metadata
- May need to check assessment template or target configuration for exclusion rules

---

## Summary of Issues

### Critical Issues (4 rules)

1. **`policy_store_encrypted`**: Checks template name instead of encryption
2. **`role_least_privilege`**: Checks run state instead of IAM role permissions
3. **`inspector_archival_export_encrypted`**: Checks user attributes instead of encryption
4. **`inspector_suppression_rules_documented_and_scoped_configured`**: Checks user attributes instead of suppression rules

### Partial/Weak Issues (2 rules)

1. **`inspector_is_enabled`**: Checks if findings exist, but doesn't verify service is enabled
2. **`scope_includes_all_asset_groups_configured`**: Checks if target/rules exist, but doesn't verify "all asset groups" are included

### Correctly Implemented (3 rules)

1. **`inspector_agents_or_scanners_deployed_configured`**: ✅ Correct
2. **`inspector_results_export_destination_encrypted`**: ✅ Correct
3. **`alert_destinations_configured`**: ✅ Correct

---

## Recommendations

### Immediate Fixes Required

1. **Fix `policy_store_encrypted`**: Research Inspector Classic API for policy store encryption configuration
2. **Fix `role_least_privilege`**: Add IAM role ARN discovery and IAM API integration to check role policies
3. **Fix `inspector_archival_export_encrypted`**: Check archival export encryption configuration (may be in assessment run dataExportConfiguration)
4. **Fix `inspector_suppression_rules_documented_and_scoped_configured`**: Use `list_exclusions` API or check userAttributes for suppression rule metadata

### Enhancements Needed

1. **Enhance `inspector_is_enabled`**: Consider checking if any Inspector resources exist to infer service is enabled
2. **Enhance `scope_includes_all_asset_groups_configured`**: Add `describe_assessment_targets` discovery to check which asset groups are included

### API Research Needed

- Check if Inspector Classic has policy store encryption API
- Verify IAM role ARN location in assessment templates/targets
- Research archival export encryption configuration location
- Research suppression rules/exclusions API methods

### Testing

- After fixes, test against AWS accounts with Inspector Classic resources:
  - Assessment templates and targets
  - Assessment runs with data export configuration
  - Event subscriptions
  - Findings with user attributes

---

## Validation Status

| Rule ID | Intent Match | Field Path | Operator | Value | Discovery | Status |
|---------|-------------|------------|----------|-------|-----------|--------|
| `inspector_is_enabled` | ⚠️ | ⚠️ | ✅ | ✅ | ✅ | ⚠️ Weak logic |
| `inspector_agents_or_scanners_deployed_configured` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Correct |
| `inspector_results_export_destination_encrypted` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Correct |
| `policy_store_encrypted` | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ Critical - Wrong field |
| `role_least_privilege` | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ Critical - Wrong field |
| `scope_includes_all_asset_groups_configured` | ⚠️ | ⚠️ | ✅ | ✅ | ✅ | ⚠️ Weak logic |
| `alert_destinations_configured` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ Correct |
| `inspector_archival_export_encrypted` | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ Critical - Wrong field |
| `inspector_suppression_rules_documented_and_scoped_configured` | ❌ | ❌ | ✅ | ❌ | ✅ | ❌ Critical - Wrong field |

**Overall Status**: ❌ **4 out of 9 rules have critical logic issues, 2 have weak logic**





