# EventBridge Metadata Mapping Quality Analysis Report

**Date:** 2026-01-03  
**Total Rules:** 20  
**Service:** eventbridge (AWS EventBridge)

---

## Executive Summary

**Overall Quality Score:** 40/100 ⚠️ (Needs significant improvement - many issues found)

### Key Findings
- ⚠️ **CRITICAL ISSUES**: 12 unique critical issues identified
- ✅ **Type Mismatches**: None found
- ✅ **Field Path Issues**: None found
- ⚠️ **DUPLICATES**: 4 duplicate groups found (10 rules can be consolidated)
- ✅ **Cross-Service Analysis**: No cross-service suggestions (correctly uses eventbridge API methods)
- ✅ **YAML Alignment**: Perfect 100% alignment

---

## 1. Critical Issues ⚠️

### Issue Pattern: Rules Checking Existence Instead of Configuration

**Common Problem:** Many rules check if resource names/ARNs exist instead of checking actual configuration status.

#### Affected Rules:
- `aws.eventbridge.rule.change_audit_logging_enabled`
- `aws.eventbridge.rule.eventbridge_artifacts_private_and_encrypted`
- `aws.eventbridge.rule.eventbridge_logs_and_metrics_enabled`
- `aws.eventbridge.rule.kms_encryption_enabled`
- `aws.eventbridge.rule.policy_exists_for_critical_severity_configured`
- `aws.eventbridge.rule.oncall_contacts_verified`
- `aws.eventbridge.eventbus.oncall_contacts_verified`
- `aws.eventbridge.rule.eventbridge_destinations_configured`
- `aws.eventbridge.rule.message_encryption_in_transit_configured`
- `aws.eventbridge.rule.private_networking_enforced`

**Current Pattern:**
```json
{
  "field_path": "Name",
  "expected_value": null,
  "operator": "exists"
}
```

**Problem:**
- Rules check if `Name` exists (or `Arn` exists)
- This only verifies that a resource exists, **NOT** that it's configured correctly
- Example: `change_audit_logging_enabled` checks if rule Name exists, not if logging is enabled

**Impact:** HIGH - Rules will pass if resources exist, regardless of configuration

**Recommendation:**
- Audit logging rules: Check if logging configuration is enabled (not just if rule/bus exists)
- Encryption rules: Check if KMS key is configured/enabled (not just if rule exists)
- Policy rules: Check if policy exists AND has correct content (not just if rule exists)
- Oncall rules: Check if oncall contacts are configured (not just if bus/rule exists)
- Destination rules: Check if destinations are properly configured (not just if ARN exists)

---

### Specific Critical Issues

#### Issue 1: Audit Logging Rules

**Rules:**
- `aws.eventbridge.eventbus.change_audit_logging_enabled`
- `aws.eventbridge.rule.change_audit_logging_enabled`
- `aws.eventbridge.rule.eventbridge_logs_and_metrics_enabled`

**Current Mapping:**
- EventBus rule checks if `LogConfig` exists
- Rule-level rules check if `Name` exists

**Problem:**
- EventBus rule checks if LogConfig exists, but doesn't verify if logging is enabled
- Rule-level rules check if rule Name exists, not if logging is enabled

**Fix:** Check actual logging configuration (e.g., `LogConfig.Enabled` or similar field)

---

#### Issue 2: Encryption Rules

**Rules:**
- `aws.eventbridge.eventbus.message_encryption_in_transit_configured`
- `aws.eventbridge.rule.kms_encryption_enabled`

**Current Mapping:**
- EventBus rule checks if `KmsKeyIdentifier` exists (this is correct!)
- Rule-level rule checks if `Name` exists (WRONG)

**Problem:**
- Rule-level encryption rule checks if rule Name exists instead of checking KMS encryption configuration

**Fix:** Check KMS key configuration for rules (similar to EventBus rule)

---

#### Issue 3: Policy/Authentication/Oncall Rules

**Rules:**
- `aws.eventbridge.eventbus.policy_exists_for_critical_severity_configured`
- `aws.eventbridge.rule.policy_exists_for_critical_severity_configured`
- `aws.eventbridge.rule.oncall_contacts_verified`
- `aws.eventbridge.eventbus.oncall_contacts_verified`

**Current Mapping:**
- Policy rules check if `Policy` or `Name` exists
- Oncall rules check if `Name` exists

**Problem:**
- Only verify existence, not actual policy content or oncall contact configuration

**Fix:** Check policy content or oncall contact configuration details

---

#### Issue 4: Destination/Networking Rules

**Rules:**
- `aws.eventbridge.rule.eventbridge_destinations_configured`
- `aws.eventbridge.rule.message_encryption_in_transit_configured`
- `aws.eventbridge.rule.private_networking_enforced`

**Current Mapping:**
All check if `Targets[].Arn` exists

**Problem:**
- Check if target ARN exists, not if destinations are properly configured
- Don't verify encryption or private networking configuration

**Fix:** Check actual destination configuration, encryption settings, or networking configuration

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
- ✅ All methods used belong to eventbridge service:
  - `describe_event_bus` - eventbridge method
  - `list_endpoints` - eventbridge method
  - `list_api_destinations` - eventbridge method
  - `describe_rule` - eventbridge method
  - `list_targets_by_rule` - eventbridge method
  - `list_rules` - eventbridge method
- ✅ Rules are correctly placed in eventbridge service

**Recommendation:** No action needed - rules correctly use eventbridge API methods

---

## 5. Consolidation Opportunities ⚠️

### Group 1: Endpoints Authenticated (2 rules → 1)

**Keep:** `aws.eventbridge.eventbus.endpoints_authenticated_configured`

**Remove:**
- `aws.eventbridge.rule.endpoints_authenticated_configured`

**Confidence:** 95% - Exact duplicate, both check `Endpoints[].RoleArn exists`

---

### Group 2: No Public Webhooks (2 rules → 1)

**Keep:** `aws.eventbridge.eventbus.no_public_webhooks_configured`

**Remove:**
- `aws.eventbridge.rule.no_public_webhooks_configured`

**Confidence:** 95% - Exact duplicate, both check `ApiDestinations[].InvocationEndpoint not_contains "public"`

---

### Group 3: Rule Name Checks (5 rules → 1)

**Keep:** One with most compliance (likely `aws.eventbridge.rule.eventbridge_logs_and_metrics_enabled`)

**Remove:**
- `aws.eventbridge.rule.change_audit_logging_enabled`
- `aws.eventbridge.rule.eventbridge_artifacts_private_and_encrypted`
- `aws.eventbridge.rule.eventbridge_logs_and_metrics_enabled`
- `aws.eventbridge.rule.kms_encryption_enabled`
- `aws.eventbridge.rule.policy_exists_for_critical_severity_configured`

**Confidence:** 95% - Exact duplicate, all check `Name exists` with `describe_rule`

**Note:** These rules have different purposes but check the same field. They all have the bug of checking Name existence instead of actual configuration.

---

### Group 4: Target ARN Checks (3 rules → 1)

**Keep:** One with most compliance

**Remove:**
- `aws.eventbridge.rule.eventbridge_destinations_configured`
- `aws.eventbridge.rule.message_encryption_in_transit_configured`
- `aws.eventbridge.rule.private_networking_enforced`

**Confidence:** 95% - Exact duplicate, all check `Targets[].Arn exists` with `list_targets_by_rule`

**Note:** These rules have different purposes but check the same field. They all have the bug of checking ARN existence instead of actual configuration.

---

**Total Consolidation Impact:**
- 10 rules can be removed
- 10 rules will remain after consolidation
- Compliance standards will be merged to kept rules
- **Note:** Fix bugs before consolidating, as consolidated rules will still have the same bugs

---

## 6. Method Usage Analysis 📊

### Distribution

**Methods:**
- `describe_rule`: 8 rules (40%)
- `list_targets_by_rule`: 3 rules (15%)
- `describe_event_bus`: 3 rules (15%)
- `list_endpoints`: 2 rules (10%)
- `list_api_destinations`: 2 rules (10%)
- `list_rules`: 1 rule (5%)
- `list_event_buses`: 1 rule (5%)

### Observations

✅ **Good:** Appropriate use of eventbridge API methods  
⚠️ **Issue:** Many rules use `describe_rule` but only check `Name exists`, not actual configuration

---

## 7. Logical Operator Usage 🔧

### Distribution

- **`all`**: 14 rules (70%) - Multiple field checks or array checks
- **`null`**: 6 rules (30%) - Single field checks

### Observations

✅ **Good:** Appropriate use of logical operators  
⚠️ **Issue:** Many rules with `null` operator check Name/Arn existence, which doesn't validate actual configuration

---

## 8. YAML Metadata Alignment ✅

**Status:** Perfect alignment

- ✅ 20 rules have corresponding YAML files
- ✅ No orphaned YAML files
- ✅ Rule ID matches between mapping and YAML
- ✅ 100% coverage

---

## 9. Recommendations 🎯

### Priority 1: HIGH (Critical Fixes)

1. **Fix All Rules Checking Name/Arn Existence** ⚠️
   - Review all rules that check `Name exists` or `Arn exists`
   - Change to check actual configuration fields:
     - Audit logging: Check `LogConfig.Enabled` or similar
     - Encryption: Check `KmsKeyIdentifier` or encryption configuration
     - Policy: Check policy content, not just existence
     - Destinations: Check destination configuration, not just ARN
     - Private networking: Check networking configuration
   - See specific issues above

2. **Fix Before Consolidating** ⚠️
   - Fix bugs in duplicate groups before consolidating
   - Otherwise, consolidated rules will still have the same bugs

### Priority 2: HIGH (Consolidation)

3. **Consolidate Duplicate Rules**
   - Merge 4 duplicate groups (10 rules → 4 rules)
   - Merge compliance standards to kept rules
   - **After fixing bugs first**

---

## 10. Quality Metrics 📈

| Metric | Value | Status |
|--------|-------|--------|
| Total Rules | 20 | ✅ |
| Critical Bugs | 12 | ⚠️ |
| Type Mismatches | 0 | ✅ |
| Field Path Issues | 0 | ✅ |
| Consolidation Opportunities | 4 groups (10 rules) | ⚠️ |
| Cross-Service Suggestions | 0 | ✅ |
| YAML Alignment | 100% | ✅ |
| Overall Score | 40/100 | ⚠️ |

---

## Conclusion

EventBridge metadata mapping has **poor quality** with **12 critical issues** and **4 duplicate groups**:

1. ⚠️ **12 rules check Name/Arn existence instead of actual configuration**
2. ⚠️ **4 duplicate groups** checking identical fields (10 rules can be consolidated)
3. ✅ **No type mismatches or field path issues**
4. ✅ **Perfect YAML alignment** (100%)
5. ✅ **No cross-service issues** (correctly uses eventbridge API methods)

The quality score of **40/100** reflects:
- Many critical bugs affecting validation accuracy
- Rules pass when resources exist, regardless of configuration
- Duplicate rules that need consolidation
- Good structure and API method usage otherwise

**Strengths:**
- Correct use of eventbridge API methods
- Appropriate method selection for resource types
- Good field path structure
- Clean, well-structured implementation

**Weaknesses:**
- Most rules only check resource existence, not configuration
- Need to check actual configuration fields (logging enabled, encryption configured, etc.)
- Multiple duplicate rules checking same fields
- Consolidation needed but bugs must be fixed first

---

**Next Steps:**
1. **HIGH PRIORITY:** Fix all 12 rules to check actual configuration, not just existence
2. **HIGH PRIORITY:** Consolidate 4 duplicate groups (after fixing bugs)
3. **MEDIUM:** Verify correct field names in EventBridge API for each configuration type
4. **LOW:** Consider if additional validation logic needed for some rules

