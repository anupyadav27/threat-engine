# Inspector (AWS Inspector) Metadata Mapping Quality Analysis Report

**Date:** 2026-01-03  
**Total Rules:** 9  
**Service:** inspector (AWS Inspector)

---

## Executive Summary

**Overall Quality Score:** 65/100 ⚠️ (Needs improvement - critical issues found)

### Key Findings
- ⚠️ **CRITICAL ISSUES**: 5 unique critical issues identified
- ✅ **Type Mismatches**: None found
- ✅ **Field Path Issues**: None found
- ✅ **DUPLICATES**: None found
- ✅ **Cross-Service Analysis**: No cross-service suggestions (correctly uses inspector API methods)
- ✅ **YAML Alignment**: Perfect 100% alignment

---

## 1. Critical Issues ⚠️

### Issue 1: Contradictory Encryption Check ❌

**Rule:** `aws.inspector.assessment.inspector_results_export_destination_encrypted`

**Current Mapping:**
```json
{
  "nested_field": [
    {
      "field_path": "dataExportConfiguration.s3Destination.encryptionOption",
      "expected_value": "SSE_S3",
      "operator": "equals"
    },
    {
      "field_path": "dataExportConfiguration.s3Destination.encryptionOption",
      "expected_value": "SSE_KMS",
      "operator": "equals"
    }
  ]
}
```

**Problem:**
- Rule checks same field `encryptionOption` equals **two different values** (`SSE_S3` and `SSE_KMS`)
- A field cannot equal two different values simultaneously
- This is a logical contradiction - rule will never pass

**Impact:** CRITICAL - Rule will never pass validation

**Recommendation:**
- Use `in` operator with list: `["SSE_S3", "SSE_KMS"]`
- Or check if encryption option is one of the valid encryption types
- Or use separate rules if checking for specific encryption types

---

### Issue 2: Contradictory Check (exists and not_equals)

**Rule:** `aws.inspector.resource.inspector_is_enabled`

**Current Mapping:**
```json
{
  "nested_field": [
    {
      "field_path": "serviceAttributes.assessmentRunArn",
      "operator": "exists"
    },
    {
      "field_path": "serviceAttributes.assessmentRunArn",
      "operator": "not_equals",
      "value": "null"
    }
  ]
}
```

**Problem:**
- Rule checks same field with `exists` AND `not_equals "null"`
- Both checks verify the field is not null (redundant)
- `exists` operator typically checks for non-null, same as `not_equals "null"`

**Impact:** MEDIUM - Redundant logic but doesn't break functionality

**Recommendation:**
- Remove one of the redundant checks
- Keep either `exists` OR `not_equals "null"`, not both

---

### Issue 3: Redundant Check in Alert Destinations

**Rule:** `aws.inspector.finding.alert_destinations_configured`

**Current Mapping:**
```json
{
  "nested_field": [
    {
      "field_path": "notificationConfiguration",
      "operator": "exists"
    },
    {
      "field_path": "notificationConfiguration.destinations",
      "operator": "exists"
    },
    {
      "field_path": "notificationConfiguration.destinations",
      "operator": "not_equals",
      "value": "null"
    }
  ]
}
```

**Problem:**
- Checks `notificationConfiguration.destinations` with both `exists` AND `not_equals "null"`
- Redundant checks on the same field
- Also checks parent `notificationConfiguration` exists (which is good, but child check makes it redundant)

**Impact:** MEDIUM - Redundant logic but doesn't break functionality

**Recommendation:**
- Remove redundant `not_equals "null"` check
- Keep `notificationConfiguration` and `notificationConfiguration.destinations` exists checks

---

### Issue 4: Policy Store Encryption Checking Wrong Field

**Rule:** `aws.inspector.assessment.policy_store_encrypted`

**Current Mapping:**
```json
{
  "python_method": "describe_assessment_templates",
  "nested_field": [{
    "field_path": "assessmentTemplateName",
    "operator": "exists"
  }]
}
```

**Problem:**
- Rule name says "policy_store_encrypted"
- Checks if `assessmentTemplateName` exists (template existence)
- This doesn't verify encryption configuration at all
- Should check encryption settings for policy store or assessment data

**Impact:** HIGH - Rule passes if template exists, regardless of encryption

**Recommendation:**
- Check encryption configuration fields (may need different API method)
- Verify correct field name in Inspector API for policy store encryption
- May need to check assessment template encryption settings or S3 bucket encryption

---

### Issue 5: Role Least Privilege Checking Wrong Fields

**Rule:** `aws.inspector.assessment.role_least_privilege`

**Current Mapping:**
```json
{
  "nested_field": [
    {
      "field_path": "assessmentRunName",
      "operator": "exists"
    },
    {
      "field_path": "assessmentRunArn",
      "operator": "exists"
    },
    {
      "field_path": "state",
      "expected_value": ["COMPLETED", "RUNNING"],
      "operator": "in"
    }
  ]
}
```

**Problem:**
- Rule name says "role_least_privilege"
- Checks if assessment run name/ARN exists and state is COMPLETED/RUNNING
- This doesn't verify least privilege configuration at all
- Should check IAM role permissions or policy attached to assessment role

**Impact:** HIGH - Rule passes if assessment runs exist, regardless of role permissions

**Recommendation:**
- Check IAM role attached to assessment template/run
- Verify role policy for least privilege (may need IAM API call)
- Check role ARN or policy document from assessment configuration

---

### Issue 6: Scope Includes All Asset Groups Checking Wrong Fields

**Rule:** `aws.inspector.assessment.scope_includes_all_asset_groups_configured`

**Current Mapping:**
```json
{
  "nested_field": [
    {
      "field_path": "assessmentTargetArn",
      "operator": "exists"
    },
    {
      "field_path": "rulesPackageArns",
      "operator": "exists"
    }
  ]
}
```

**Problem:**
- Rule name says "scope_includes_all_asset_groups"
- Checks if `assessmentTargetArn` and `rulesPackageArns` exist
- This doesn't verify that scope includes all asset groups
- Should check asset group configuration or assessment target scope

**Impact:** HIGH - Rule passes if target/rules exist, regardless of scope configuration

**Recommendation:**
- Check assessment target resource group ARN or asset group ARNs
- Verify that all asset groups are included in scope
- May need to check assessment target configuration or resource group ARNs

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
- ✅ All methods used belong to inspector service:
  - `list_findings` - inspector method
  - `describe_assessment_templates` - inspector method
  - `describe_assessment_runs` - inspector method
- ✅ Rules are correctly placed in inspector service

**Recommendation:** No action needed - rules correctly use inspector API methods

---

## 5. Consolidation Opportunities ✅

**Status:** None

- No duplicate rules found
- All rules check different fields/methods
- 100% efficiency (no redundancy)

---

## 6. Method Usage Analysis 📊

### Distribution

**Methods:**
- `list_findings`: 4 rules (44%)
- `describe_assessment_templates`: 3 rules (33%)
- `describe_assessment_runs`: 2 rules (22%)

### Observations

✅ **Good:** Appropriate use of inspector API methods  
✅ **Good:** Methods correctly match resource types  
⚠️ **Issue:** Some rules use methods correctly but check wrong fields

---

## 7. Logical Operator Usage 🔧

### Distribution

- **`all`**: 7 rules (78%) - Multiple field checks
- **`null`**: 2 rules (22%) - Single field checks

### Observations

✅ **Good:** Appropriate use of logical operators  
⚠️ **Issue:** Some rules with `all` operator have contradictory or redundant checks

---

## 8. YAML Metadata Alignment ✅

**Status:** Perfect alignment

- ✅ 9 rules have corresponding YAML files
- ✅ No orphaned YAML files
- ✅ Rule ID matches between mapping and YAML
- ✅ 100% coverage

---

## 9. Detailed Rule Analysis 📋

### High Priority Rules to Fix

1. **`aws.inspector.assessment.inspector_results_export_destination_encrypted`** ❌
   - Contradictory: checks same field equals two different values
   - Impact: CRITICAL

2. **`aws.inspector.assessment.policy_store_encrypted`** ⚠️
   - Checks template name existence instead of encryption
   - Impact: HIGH

3. **`aws.inspector.assessment.role_least_privilege`** ⚠️
   - Checks run name/ARN/state instead of role permissions
   - Impact: HIGH

4. **`aws.inspector.assessment.scope_includes_all_asset_groups_configured`** ⚠️
   - Checks target/rules existence instead of scope configuration
   - Impact: HIGH

5. **`aws.inspector.resource.inspector_is_enabled`** ⚠️
   - Contradictory: exists and not_equals on same field
   - Impact: MEDIUM

6. **`aws.inspector.finding.alert_destinations_configured`** ⚠️
   - Redundant: exists and not_equals on same field
   - Impact: MEDIUM

### Rules with Good Quality

1. **`aws.inspector.finding.inspector_archival_export_encrypted`** ✅
   - ✅ Checks `archivalExportEncrypted equals true` correctly
   - ✅ Validates actual encryption configuration

2. **`aws.inspector.finding.inspector_suppression_rules_documented_and_scoped_configured`** ✅
   - ✅ Checks suppression attributes correctly
   - ✅ Validates reason and scope fields

3. **`aws.inspector.assessment.inspector_agents_or_scanners_deployed_configured`** ✅
   - ✅ Checks assessment target ARN and run count
   - ✅ Validates that agents/scanners are deployed (run count > 0)

---

## 10. Recommendations 🎯

### Priority 1: CRITICAL (Critical Fixes)

1. **Fix Contradictory Encryption Check** ❌
   - Review `aws.inspector.assessment.inspector_results_export_destination_encrypted`
   - Change from checking same field equals two values to using `in` operator with list
   - Or use separate conditions if checking for either encryption type

2. **Fix Policy Store Encryption Rule** ⚠️
   - Review `aws.inspector.assessment.policy_store_encrypted`
   - Change from checking template name to checking actual encryption configuration
   - Verify correct field name in Inspector API for policy store encryption

3. **Fix Role Least Privilege Rule** ⚠️
   - Review `aws.inspector.assessment.role_least_privilege`
   - Change from checking run existence to checking IAM role permissions
   - May need to check IAM role attached to assessment or use IAM API

4. **Fix Scope Includes All Asset Groups Rule** ⚠️
   - Review `aws.inspector.assessment.scope_includes_all_asset_groups_configured`
   - Change from checking target/rules existence to checking actual scope/asset group configuration
   - Verify correct field names for asset group scope

### Priority 2: MEDIUM (Code Quality)

5. **Fix Contradictory Logic** ⚠️
   - Remove redundant checks:
     - `aws.inspector.resource.inspector_is_enabled` - remove one of exists/not_equals
     - `aws.inspector.finding.alert_destinations_configured` - remove not_equals check

---

## 11. Quality Metrics 📈

| Metric | Value | Status |
|--------|-------|--------|
| Total Rules | 9 | ✅ |
| Critical Bugs | 5 | ⚠️ |
| Type Mismatches | 0 | ✅ |
| Field Path Issues | 0 | ✅ |
| Consolidation Opportunities | 0 | ✅ |
| Cross-Service Suggestions | 0 | ✅ |
| YAML Alignment | 100% | ✅ |
| Overall Score | 65/100 | ⚠️ |

---

## Conclusion

Inspector metadata mapping has **moderate quality** with **5 critical issues**:

1. ❌ **1 rule has contradictory checks** (same field equals two different values - will never pass)
2. ⚠️ **3 rules check wrong fields** (policy store encryption, role least privilege, scope includes all asset groups)
3. ⚠️ **2 rules have redundant/contradictory logic** (exists and not_equals on same field)
4. ✅ **No duplicate rules**
5. ✅ **No type mismatches or field path issues**
6. ✅ **Perfect YAML alignment** (100%)
7. ✅ **No cross-service issues** (correctly uses inspector API methods)
8. ✅ **3 rules correctly implemented** (archival export encryption, suppression rules, agents/scanners deployed)

The quality score of **65/100** reflects:
- 1 critical bug that breaks rule functionality (contradictory encryption check)
- 3 rules checking wrong fields (policy encryption, role least privilege, scope)
- 2 rules with redundant logic
- Otherwise good structure and API method usage

**Strengths:**
- Correct use of inspector API methods
- Appropriate method selection for resource types
- Good field path structure
- Clean implementation for 3 rules
- No duplicate rules
- No type mismatches

**Weaknesses:**
- 1 rule with contradictory logic that will never pass
- 3 rules checking wrong fields (resource existence instead of configuration)
- 2 rules with redundant checks
- 56% of rules have issues (5 out of 9)

---

**Next Steps:**
1. **CRITICAL PRIORITY:** Fix encryption rule - change to use `in` operator with list instead of checking equals two values
2. **HIGH PRIORITY:** Fix 3 rules to check actual configuration (policy encryption, role least privilege, scope)
3. **MEDIUM PRIORITY:** Remove redundant checks from 2 rules
4. **LOW:** Verify correct field names in Inspector API for encryption, role permissions, and scope configuration

