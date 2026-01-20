# ECS Metadata Mapping Quality Analysis Report

**Date:** 2026-01-03  
**Total Rules:** 8  
**Service:** ecs (Elastic Container Service)

---

## Executive Summary

**Overall Quality Score:** 85/100 ⚠️ (Issues found requiring attention)

### Key Findings
- ✅ **Structure**: Well-organized with consistent format
- ✅ **YAML Alignment**: Perfect 100% alignment (all rules have corresponding YAML files)
- 🔴 **CRITICAL BUGS**: 3 rules only check field existence, not actual configuration state
- ✅ **Type Mismatches**: None found
- ✅ **Field Path Issues**: None found
- ✅ **Cross-Service Analysis**: No cross-service suggestions (all rules correctly use ECS methods)
- ✅ **Consolidation Opportunities**: 1 duplicate group identified (can remove 1 rule, 13% reduction)

---

## 1. Critical Bugs 🔴

### Bug 1: Logging Enabled Rule Only Checks Field Existence

**Rule:** `aws.ecs.resource.task_definition_logging_enabled`

**Current Mapping:**
```json
{
  "python_method": "describe_task_definition",
  "response_path": "taskDefinition",
  "nested_field": [
    {
      "field_path": "taskDefinition.containerDefinitions[].logConfiguration",
      "expected_value": null,
      "operator": "exists"  // ❌ Only checks if field exists
    }
  ]
}
```

**Problem:**
- Rule name indicates "logging_enabled" (logging feature is enabled)
- But only checks if `logConfiguration` field exists using `exists` operator
- Does NOT verify that logging is actually configured/enabled
- A field can exist but logging might not be properly configured

**Impact:** HIGH - Rule may pass even when logging is not actually enabled, giving false sense of compliance.

**Fix Needed:** 
- Should check specific logging configuration fields
- Verify `logConfiguration.logDriver` is set (e.g., "awslogs", "fluentd", etc.)
- Or verify `logConfiguration.options` contains required logging settings
- Research ECS task definition logging configuration structure

---

### Bug 2: Task Definitions Logging Enabled Rule Has Same Issue

**Rule:** `aws.ecs.resource.task_definitions_logging_enabled`

**Current Mapping:**
```json
{
  "field_path": "taskDefinition.containerDefinitions[].logConfiguration",
  "expected_value": null,
  "operator": "exists"  // ❌ Same issue
}
```

**Problem:** Same as Bug 1 - only checks if field exists, not if logging is enabled

**Note:** This rule is also a duplicate of `task_definition_logging_enabled` and should be consolidated after fixing.

**Fix Needed:** Same as Bug 1 - verify logging is actually configured

---

### Bug 3: Secrets Rule Checks Wrong Field

**Rule:** `aws.ecs.container_instance.container_env_no_plaintext_secrets_configured`

**Current Mapping:**
```json
{
  "python_method": "describe_task_definition",
  "response_path": "taskDefinition",
  "nested_field": [
    {
      "field_path": "taskDefinition.containerDefinitions[].environment",
      "expected_value": null,
      "operator": "exists"  // ❌ Checks environment field, not secrets
    }
  ]
}
```

**Problem:**
- Rule name indicates "no_plaintext_secrets" (should verify secrets are not in plaintext)
- But checks if `environment` field exists
- This doesn't verify if secrets are used or if they're plaintext
- Should check `secrets` field (AWS Secrets Manager/Parameter Store integration) or verify environment variables don't contain sensitive values

**Impact:** HIGH - Rule may pass when plaintext secrets exist in environment variables, failing to detect security violations.

**Fix Needed:**
- Should check `containerDefinitions[].secrets` field to verify secrets are used instead of plaintext
- Or verify `environment` variables don't contain sensitive patterns (requires value inspection)
- Or check that sensitive values use `valueFrom` pattern instead of direct `value`

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

**Status:** Excellent

- ✅ **No cross-service suggestions found**
- ✅ All 8 rules correctly use ECS API methods
- ✅ No ambiguous method usage
- ✅ Rules are correctly placed in ECS service

**Recommendation:** No action needed - rules are correctly organized.

---

## 5. Consolidation Opportunities 📋

### Summary

The review report identified **1 duplicate group**:

### Group 1: Task Definition Logging (2 duplicates)
- **Keep:** `aws.ecs.resource.task_definition_logging_enabled` (2 compliance standards)
- **Remove:** `aws.ecs.resource.task_definitions_logging_enabled` (2 compliance standards, different ones)
- **Note:** Both have the same critical bug - fix before consolidating
- **Action:** Merge compliance standards, then remove duplicate

**Total Rules to Remove:** 1 rule (13% reduction)

**Note:** Both rules in the duplicate group have the critical bug. Fix the bug first, then consolidate.

---

## 6. Method Usage Analysis 📊

### Distribution

**Top Methods:**
- `describe_task_definition`: 6 rules (75%) - Task definition configuration checks
- `describe_services`: 1 rule (13%) - Service configuration checks
- `list_account_settings`: 1 rule (13%) - Account-level settings

### Observations

✅ **Good:** Appropriate use of ECS API methods  
✅ **Good:** Methods correctly match resource types  
✅ **Good:** No ambiguous method usage

---

## 7. Logical Operator Usage 🔧

### Distribution

- **`null`**: 8 rules (100%) - Single field checks (no logical operator needed)

### Observations

✅ **Good:** Consistent use - all rules use single field checks  
✅ **Good:** Appropriate for simple validation rules  
⚠️ **Note:** Some rules might need `all` operator if checking multiple containers in array

---

## 8. YAML Metadata Alignment ✅

**Status:** Perfect alignment

- ✅ All 8 rules have corresponding YAML files
- ✅ No orphaned YAML files
- ✅ Rule IDs match between mapping and YAML
- ✅ 100% coverage

---

## 9. Recommendations 🎯

### Priority 1: CRITICAL (Fix Immediately)

1. **Fix Logging Rules** 🔴
   - Fix `aws.ecs.resource.task_definition_logging_enabled`
   - Fix `aws.ecs.resource.task_definitions_logging_enabled`
   - Change from `exists` operator to check actual logging configuration
   - Verify `logConfiguration.logDriver` is set or `logConfiguration.options` contains required settings
   - Research ECS task definition logging structure

2. **Fix Secrets Rule** 🔴
   - Fix `aws.ecs.container_instance.container_env_no_plaintext_secrets_configured`
   - Should check `secrets` field instead of `environment` field
   - Or verify that sensitive values use `valueFrom` pattern (Secrets Manager/Parameter Store)
   - May need to check environment variable values for sensitive patterns

### Priority 2: HIGH (After Bug Fixes)

3. **Implement Consolidation**
   - Merge duplicate logging rules (remove 1 rule)
   - **BUT** fix critical bugs first before consolidating

### Priority 3: LOW (Long-term)

4. **Consider Enhanced Checks**
   - Array iteration: Some rules check array fields (`containerDefinitions[]`)
   - Consider if `all` operator should be used to verify ALL containers meet requirement
   - Current approach may only check first container

---

## 10. Quality Metrics 📈

| Metric | Value | Status |
|--------|-------|--------|
| Total Rules | 8 | ✅ |
| Critical Bugs | 3 | 🔴 |
| Type Mismatches | 0 | ✅ |
| Field Path Issues | 0 | ✅ |
| Consolidation Opportunities | 1 group (1 rule) | ⚠️ |
| Cross-Service Suggestions | 0 | ✅ |
| YAML Alignment | 100% | ✅ |
| Overall Score | 85/100 | ⚠️ |

---

## Conclusion

ECS metadata mapping is **mostly good** with **8 well-structured rules**, but has **critical bugs** that must be fixed:

1. 🔴 **2 logging rules only check field existence** (not if logging is enabled)
2. 🔴 **1 secrets rule checks wrong field** (checks environment instead of secrets)
3. ✅ **Perfect YAML alignment** (100%)
4. ✅ **No cross-service issues** (all rules correctly placed)
5. ✅ **No type mismatches or field path issues**

After fixing the critical bugs, the quality score could improve from **85/100 to 100/100**.

**Strengths:**
- Excellent YAML alignment (100%)
- No cross-service issues
- Clean structure with no type mismatches
- Appropriate use of ECS API methods

**Areas for Improvement:**
- Fix critical bugs in logging rules (verify logging is enabled, not just field exists)
- Fix critical bug in secrets rule (check secrets field, not environment)
- Implement consolidation (after bug fixes)
- Consider array iteration logic for container checks

---

**Next Steps:**
1. Research ECS task definition logging configuration structure
2. Research ECS secrets field structure (vs environment field)
3. Fix critical bugs in logging rules (verify actual configuration)
4. Fix critical bug in secrets rule (check secrets field)
5. Implement consolidation (after bug fixes)
6. Consider if array checks need `all` operator for all containers

