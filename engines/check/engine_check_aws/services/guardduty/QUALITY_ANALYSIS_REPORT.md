# GuardDuty (AWS GuardDuty) Metadata Mapping Quality Analysis Report

**Date:** 2026-01-03  
**Total Rules:** 24  
**Service:** guardduty (AWS GuardDuty)

---

## Executive Summary

**Overall Quality Score:** 20/100 ❌ (Critical issues - needs major fixes)

### Key Findings
- ❌ **CRITICAL ISSUES**: 16 unique critical issues identified
- ✅ **Type Mismatches**: None found
- ✅ **Field Path Issues**: None found
- ⚠️ **DUPLICATES**: 3 duplicate groups found (19 rules can be consolidated)
- ✅ **Cross-Service Analysis**: No cross-service suggestions (correctly uses guardduty API methods)
- ✅ **YAML Alignment**: Perfect 100% alignment

---

## 1. Critical Issues ⚠️

### Issue Pattern: Rules Checking DetectorIds Existence Instead of Configuration

**Common Problem:** Most rules check if `DetectorIds` exists (detector existence) instead of checking actual configuration status.

#### Group 1: Rules Checking DetectorIds Existence (16 rules)

**Affected Rules:**
- `aws.guardduty.resource.security_center_enabled` - Should check Security Hub integration
- `aws.guardduty.finding.guardduty_finding_archival_export_encrypted` - Should check archival export encryption
- `aws.guardduty.no.guardduty_finding_high_severity_findings_configured` - Should check for high severity findings
- `aws.guardduty.resource.guardduty_vulnerability_assessment_enabled` - Should check vulnerability assessment enablement
- `aws.guardduty.ipset.guardduty_storage_encrypted` - Should check IPSet storage encryption
- `aws.guardduty.finding.guardduty_finding_suppression_rules_documented_and_scoped_configured` - Should check suppression rules
- `aws.guardduty.finding.rbac_least_privilege` - Should check RBAC configuration
- `aws.guardduty.detector.finding_detector_finding_export_encrypted_destination` - Should check finding export encryption
- `aws.guardduty.finding.guardduty_finding_reports_storage_encrypted` - Should check finding reports encryption
- `aws.guardduty.custom_identifier.guardduty_storage_encrypted` - Should check custom identifier storage encryption
- `aws.guardduty.ipset.guardduty_detector_used_by_detectors_configured` - Should check IPSet usage by detectors
- `aws.guardduty.no_high_severity_findings.guardduty_finding_no_high_severity_findings_configured` - Should check for high severity findings

**Current Pattern:**
```json
{
  "python_method": "list_detectors",
  "response_path": "DetectorIds[]",
  "nested_field": [{
    "field_path": "DetectorIds",
    "operator": "exists"
  }]
}
```

**Problem:**
- Rules check if `DetectorIds` **exists** (detector existence)
- This only verifies that a detector exists, **NOT** that the specific feature is configured
- Example: `guardduty_finding_archival_export_encrypted` checks if detector exists, not if archival export is encrypted

**Impact:** HIGH - Rules will pass if detectors exist, regardless of configuration

**Recommendation:**
- Use appropriate API methods to check specific configurations:
  - Encryption: Use `describe_publishing_destination` or `get_detector` to check encryption settings
  - Findings: Use `list_findings` to check for high severity findings
  - RBAC: Use `get_master_account` or organization configuration APIs
  - IPSet: Use `get_ip_set` or `list_ip_sets` to check encryption
  - Suppression rules: Use `list_filters` or `get_filter` to check suppression rules
  - Security Hub: Use `get_master_account` or organization APIs to check Security Hub integration
  - Vulnerability assessment: Use `get_master_account` or detector configuration to check vulnerability assessment

---

### Rules with Correct Implementation ✅

#### Rule 1: `aws.guardduty.resource.eks_audit_log_enabled`

**Current Mapping:**
```json
{
  "python_method": "describe_organization_configuration",
  "response_path": "OrganizationConfiguration",
  "nested_field": [{
    "field_path": "EKSClusterAuditLogsConfiguration.AutoEnable",
    "expected_value": true,
    "operator": "equals"
  }]
}
```

**Analysis:**
- ✅ Checks `EKSClusterAuditLogsConfiguration.AutoEnable` equals true
- ✅ Validates actual EKS audit log configuration

**Status:** ✅ **Correct** - Validates actual configuration

---

#### Rule 2: `aws.guardduty.finding.guardduty_finding_export_destinations_private_configured`

**Current Mapping:**
```json
{
  "python_method": "describe_organization_configuration",
  "nested_field": [
    {
      "field_path": "DataSources.S3Logs.Enable",
      "expected_value": true,
      "operator": "equals"
    },
    {
      "field_path": "DataSources.S3Logs.DestinationType",
      "expected_value": "S3",
      "operator": "equals"
    },
    {
      "field_path": "DataSources.S3Logs.DestinationProperties.DestinationArn",
      "operator": "exists"
    }
  ]
}
```

**Analysis:**
- ✅ Checks multiple fields for export destination configuration
- ✅ Validates actual configuration (S3 logs enabled, destination type, destination ARN)

**Status:** ✅ **Correct** - Validates actual configuration

---

#### Rule 3: `aws.guardduty.detector.guardduty_detector_destinations_encrypted`

**Current Mapping:**
```json
{
  "python_method": "describe_organization_configuration",
  "nested_field": [
    {
      "field_path": "DataSources.S3Logs.Enable",
      "expected_value": true,
      "operator": "equals"
    },
    {
      "field_path": "DataSources.S3Logs.Destination.KmsKeyId",
      "operator": "exists"
    }
  ]
}
```

**Analysis:**
- ✅ Checks if S3 logs are enabled and KMS key exists
- ✅ Validates encryption configuration (KMS key for destination)

**Status:** ✅ **Correct** - Validates encryption configuration (though may want to verify KMS key is valid)

---

#### Rule 4: Detector Enabled Rules

**Rules:**
- `aws.guardduty.detector.guardduty_detectors_enabled`
- `aws.guardduty.is.guardduty_enabled`
- `aws.guardduty.resource.guardduty_enabled`
- `aws.guardduty.detector.guardduty_detector_s_enabled`
- `aws.guardduty.detector.guardduty_detector_enabled_in_all_regions`

**Current Mapping:**
```json
{
  "field_path": "DetectorIds",
  "operator": "exists" or "not_equals",
  "expected_value": null or "value": "null"
}
```

**Analysis:**
- ✅ Checks if detectors exist (which means GuardDuty is enabled)
- ✅ Acceptable for "enabled" rules - detector existence = GuardDuty enabled

**Status:** ✅ **Correct** - Validates that GuardDuty is enabled

---

## 2. Type Mismatches ✅

**Status:** None found

All operators are used correctly with appropriate expected_value types.

---

## 3. Field Path Issues ✅

**Status:** None found

Field paths are consistent and well-structured.

---

## 4. Cross-Service Analysis ✅

**Status:** Correct

- ✅ **No cross-service suggestions found**
- ✅ All methods used belong to guardduty service:
  - `list_detectors` - guardduty method
  - `describe_organization_configuration` - guardduty method
- ✅ Rules are correctly placed in guardduty service

**Recommendation:** No action needed - rules correctly use guardduty API methods

---

## 5. Consolidation Opportunities ⚠️

### Group 1: DetectorIds Existence Checks (14 rules → 1)

**Keep:** One with most compliance (e.g., `aws.guardduty.resource.guardduty_enabled`)

**Remove:**
- 13 rules that incorrectly check DetectorIds existence for non-enabled checks
- 2 rules that correctly check DetectorIds for enabled checks (but can be consolidated)

**Confidence:** 95% - Exact duplicate, all check `DetectorIds exists` with `list_detectors`

**Note:** However, **13 of these rules have bugs** - they check detector existence instead of configuration. **Fix bugs before consolidating.**

---

### Group 2: Detector Enabled Checks (2 rules → 1)

**Keep:** `aws.guardduty.detector.guardduty_detectors_enabled`

**Remove:**
- `aws.guardduty.resource.guardduty_enabled`

**Confidence:** 95% - Both check `DetectorIds not_equals "null"`

**Note:** ✅ **These are correctly implemented** - can be consolidated immediately

---

### Group 3: DetectorIds with "all" Operator (4 rules → 1)

**Keep:** One with most compliance

**Remove:**
- `aws.guardduty.finding.alert_destinations_configured`
- `aws.guardduty.custom_identifier.guardduty_source_trusted_configured`
- `aws.guardduty.centrally_managed.guardduty_centrally_managed_configured`
- `aws.guardduty.ipset.guardduty_sources_trusted_configured`

**Confidence:** 95% - All check `DetectorIds exists` with `list_detectors` and logical_operator "all"

**Note:** ⚠️ **All have bugs** - check detector existence instead of configuration. **Fix bugs before consolidating.**

---

**Total Consolidation Impact:**
- 19 rules can be removed (after fixing bugs for 16 of them)
- 5 rules will remain after consolidation
- **Note:** Fix bugs first before consolidating Groups 1 and 3

---

## 6. Method Usage Analysis 📊

### Distribution

**Methods:**
- `list_detectors`: 20 rules (83%) - Most check DetectorIds existence
- `describe_organization_configuration`: 3 rules (13%) - Check organization-level configuration
- Other: 1 rule (4%)

### Observations

✅ **Good:** Appropriate use of guardduty API methods  
⚠️ **Issue:** Most rules use `list_detectors` correctly but check wrong fields (existence instead of configuration)

---

## 7. Logical Operator Usage 🔧

### Distribution

- **`null`**: 19 rules (79%) - Single field checks
- **`all`**: 5 rules (21%) - Multiple field checks

### Observations

✅ **Good:** Appropriate use of logical operators  
✅ **Good:** `all` operator correctly used for multiple field checks

---

## 8. YAML Metadata Alignment ✅

**Status:** Perfect alignment

- ✅ 24 rules have corresponding YAML files
- ✅ No orphaned YAML files
- ✅ Rule ID matches between mapping and YAML
- ✅ 100% coverage

---

## 9. Detailed Rule Analysis 📋

### High Priority Rules to Fix

1. **`aws.guardduty.resource.security_center_enabled`** ⚠️
   - ❌ Checks DetectorIds existence instead of Security Hub integration
   - Impact: HIGH

2. **`aws.guardduty.finding.guardduty_finding_archival_export_encrypted`** ⚠️
   - ❌ Checks DetectorIds existence instead of archival export encryption
   - Impact: HIGH

3. **`aws.guardduty.finding.guardduty_finding_reports_storage_encrypted`** ⚠️
   - ❌ Checks DetectorIds existence instead of finding reports encryption
   - Impact: HIGH

4. **`aws.guardduty.no.guardduty_finding_high_severity_findings_configured`** ⚠️
   - ❌ Checks DetectorIds existence instead of checking for high severity findings
   - Impact: HIGH

5. **`aws.guardduty.resource.guardduty_vulnerability_assessment_enabled`** ⚠️
   - ❌ Checks DetectorIds existence instead of vulnerability assessment enablement
   - Impact: HIGH

6. **`aws.guardduty.ipset.guardduty_storage_encrypted`** ⚠️
   - ❌ Checks DetectorIds existence instead of IPSet storage encryption
   - Impact: HIGH

7. **`aws.guardduty.finding.guardduty_finding_suppression_rules_documented_and_scoped_configured`** ⚠️
   - ❌ Checks DetectorIds existence instead of suppression rules configuration
   - Impact: HIGH

8. **`aws.guardduty.finding.rbac_least_privilege`** ⚠️
   - ❌ Checks DetectorIds existence instead of RBAC configuration
   - Impact: HIGH

9. **`aws.guardduty.detector.finding_detector_finding_export_encrypted_destination`** ⚠️
   - ❌ Checks DetectorIds existence instead of finding export encryption
   - Impact: HIGH

10. **`aws.guardduty.custom_identifier.guardduty_storage_encrypted`** ⚠️
    - ❌ Checks DetectorIds existence instead of custom identifier storage encryption
    - Impact: HIGH

11. **`aws.guardduty.ipset.guardduty_detector_used_by_detectors_configured`** ⚠️
    - ❌ Checks DetectorIds existence instead of IPSet usage by detectors
    - Impact: HIGH

12. **`aws.guardduty.no_high_severity_findings.guardduty_finding_no_high_severity_findings_configured`** ⚠️
    - ❌ Checks DetectorIds existence instead of checking for high severity findings
    - Impact: HIGH

### Rules with Good Quality

- **`aws.guardduty.resource.eks_audit_log_enabled`** ✅
- **`aws.guardduty.finding.guardduty_finding_export_destinations_private_configured`** ✅
- **`aws.guardduty.detector.guardduty_detector_destinations_encrypted`** ✅
- **`aws.guardduty.detector.guardduty_detectors_enabled`** ✅
- **`aws.guardduty.is.guardduty_enabled`** ✅
- **`aws.guardduty.resource.guardduty_enabled`** ✅
- **`aws.guardduty.detector.guardduty_detector_s_enabled`** ✅
- **`aws.guardduty.detector.guardduty_detector_enabled_in_all_regions`** ✅

---

## 10. Recommendations 🎯

### Priority 1: HIGH (Critical Fixes)

1. **Fix All Rules Checking DetectorIds Existence** ⚠️
   - Review all 16 rules that check DetectorIds existence instead of configuration
   - Change to check actual configuration fields:
     - Encryption: Use `describe_publishing_destination` or `get_detector` to check encryption settings
     - Findings: Use `list_findings` with severity filter to check for high severity findings
     - RBAC: Use `get_master_account` or organization configuration APIs
     - IPSet: Use `get_ip_set` or `list_ip_sets` to check encryption
     - Suppression rules: Use `list_filters` or `get_filter` to check suppression rules
     - Security Hub: Use `get_master_account` or organization APIs to check Security Hub integration
     - Vulnerability assessment: Use detector configuration to check vulnerability assessment enablement

### Priority 2: HIGH (Consolidation)

2. **Consolidate Duplicate Rules**
   - Merge 3 duplicate groups (19 rules → 5 rules)
   - **After fixing bugs first** (for Groups 1 and 3)
   - Group 2 (detector enabled) can be consolidated immediately

---

## 11. Quality Metrics 📈

| Metric | Value | Status |
|--------|-------|--------|
| Total Rules | 24 | ✅ |
| Critical Bugs | 16 | ❌ |
| Type Mismatches | 0 | ✅ |
| Field Path Issues | 0 | ✅ |
| Consolidation Opportunities | 3 groups (19 rules) | ⚠️ |
| Cross-Service Suggestions | 0 | ✅ |
| YAML Alignment | 100% | ✅ |
| Overall Score | 20/100 | ❌ |

---

## Conclusion

GuardDuty metadata mapping has **poor quality** with **16 critical issues** and **3 duplicate groups**:

1. ⚠️ **12 rules check DetectorIds existence instead of actual configuration**
2. ⚠️ **3 duplicate groups** (19 rules can be consolidated)
3. ✅ **8 rules correctly implemented** (detector enabled, EKS audit logs, export destinations, encryption)
4. ✅ **No type mismatches or field path issues**
5. ✅ **Perfect YAML alignment** (100%)
6. ✅ **No cross-service issues** (correctly uses guardduty API methods)

The quality score of **20/100** reflects:
- 12 critical bugs affecting validation accuracy
- Rules pass when detectors exist, regardless of configuration
- Good structure and API method usage otherwise
- Some rules correctly validate actual configuration

**Strengths:**
- Correct use of guardduty API methods
- Appropriate method selection for resource types
- Good field path structure
- Clean, well-structured implementation
- 8 rules correctly validate actual configuration
- Appropriate use of logical operators

**Weaknesses:**
- 67% of rules only check detector existence, not configuration
- Need to check actual configuration fields (encryption, findings, RBAC, etc.)
- Multiple duplicate rules checking same fields
- Consolidation needed but bugs must be fixed first

---

**Next Steps:**
1. **HIGH PRIORITY:** Fix all 16 rules to check actual configuration, not just DetectorIds existence
2. **HIGH PRIORITY:** Consolidate 3 duplicate groups (after fixing bugs)
3. **MEDIUM:** Verify correct field names in GuardDuty API for each configuration type
4. **LOW:** Consider if additional validation logic needed for some rules (RBAC, least privilege)

