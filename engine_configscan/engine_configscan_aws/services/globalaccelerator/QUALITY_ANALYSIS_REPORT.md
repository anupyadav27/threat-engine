# Global Accelerator (AWS Global Accelerator) Metadata Mapping Quality Analysis Report

**Date:** 2026-01-03  
**Total Rules:** 4  
**Service:** globalaccelerator (AWS Global Accelerator)

---

## Executive Summary

**Overall Quality Score:** 85/100 ⚠️ (Good quality with some issues)

### Key Findings
- ⚠️ **CRITICAL ISSUES**: 3 unique critical issues identified
- ✅ **Type Mismatches**: None found
- ✅ **Field Path Issues**: None found
- ⚠️ **DUPLICATES**: 1 duplicate group found (2 rules can be consolidated)
- ✅ **Cross-Service Analysis**: No cross-service suggestions (correctly uses globalaccelerator API methods)
- ✅ **YAML Alignment**: Perfect 100% alignment

---

## 1. Critical Issues ⚠️

### Issue 1: WAF Attachment Rule Checking Accelerator Existence

**Rule:** `aws.globalaccelerator.accelerator.waf_attached_if_supported`

**Current Mapping:**
```json
{
  "python_method": "list_accelerators",
  "response_path": "Accelerators",
  "nested_field": [{
    "field_path": "Accelerators[].AcceleratorArn",
    "operator": "exists"
  }]
}
```

**Problem:**
- Rule name says "waf_attached_if_supported"
- Checks if `AcceleratorArn` **exists** (accelerator existence)
- This only verifies that an accelerator exists, **NOT** that WAF is attached
- WAF attachment requires checking WAF association or firewall configuration

**Impact:** HIGH - Rule will pass if accelerator exists, regardless of WAF attachment

**Recommendation:**
- Check WAF firewall association or security group configuration
- May need to use WAF API (`list_web_acls`, `get_web_acl`) to verify attachment
- Or check `SecurityGroups` field if Global Accelerator supports WAF integration via security groups

---

### Issue 2: TLS Minimum Version Rule Checking Protocol Type

**Rule:** `aws.globalaccelerator.accelerator.listener_tls_min_1_2_configured`

**Current Mapping:**
```json
{
  "python_method": "list_listeners",
  "response_path": "Listeners",
  "nested_field": [{
    "field_path": "Listeners[].Protocol",
    "expected_value": "TLS",
    "operator": "equals"
  }]
}
```

**Problem:**
- Rule name says "tls_min_1_2_configured" (TLS minimum version 1.2)
- Checks if `Protocol` equals "TLS"
- This only verifies that TLS protocol is used, **NOT** the TLS version
- TLS 1.0, 1.1, and 1.2 all use Protocol="TLS"
- Rule should verify minimum TLS version is 1.2 or higher

**Impact:** HIGH - Rule will pass if TLS is used, even with TLS 1.0/1.1 (insecure)

**Recommendation:**
- Check TLS version field (may be `Certificates[].CertificateArn` or TLS policy configuration)
- Verify certificate or listener configuration specifies TLS 1.2+ minimum
- May need to check certificate configuration or security policy

---

### Issue 3: Certificate Validity Rule Checking Protocol Type

**Rule:** `aws.globalaccelerator.accelerator.valid_certificate_enabled`

**Current Mapping:**
```json
{
  "python_method": "list_listeners",
  "response_path": "Listeners",
  "nested_field": [{
    "field_path": "Listeners[].Protocol",
    "expected_value": "TLS",
    "operator": "equals"
  }]
}
```

**Problem:**
- Rule name says "valid_certificate_enabled"
- Checks if `Protocol` equals "TLS"
- This only verifies that TLS protocol is used, **NOT** certificate validity
- Certificate validity requires checking:
  - Certificate expiration date
  - Certificate status (valid/expired/revoked)
  - Certificate chain validity

**Impact:** HIGH - Rule will pass if TLS is used, even with expired/invalid certificates

**Recommendation:**
- Check certificate validity fields (may be in `Certificates[]` array)
- Verify certificate expiration date or status
- May need to use ACM API (`describe_certificate`) to check certificate validity
- Or check certificate expiration date in listener configuration

**Note:** This rule is also a duplicate of `listener_tls_min_1_2_configured` (same check signature)

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
- ✅ All methods used belong to globalaccelerator service:
  - `describe_accelerator_attributes` - globalaccelerator method
  - `list_listeners` - globalaccelerator method
  - `list_accelerators` - globalaccelerator method
- ✅ Rules are correctly placed in globalaccelerator service

**Recommendation:** No action needed - rules correctly use globalaccelerator API methods

---

## 5. Consolidation Opportunities ⚠️

### Group 1: TLS Protocol Checks (2 rules → 1)

**Keep:** `aws.globalaccelerator.accelerator.listener_tls_min_1_2_configured` (more specific name)

**Remove:**
- `aws.globalaccelerator.accelerator.valid_certificate_enabled`

**Confidence:** 95% - Exact duplicate, both check `Listeners[].Protocol equals "TLS"` with `list_listeners`

**Note:** However, both rules have bugs:
- TLS rule should check TLS version, not just protocol
- Certificate rule should check certificate validity, not just protocol
- **Fix bugs before consolidating** - they need different fixes

**Recommendation:** 
- Keep both rules separate for now
- Fix each rule to check correct fields:
  - TLS rule: Check TLS version (1.2+)
  - Certificate rule: Check certificate validity/expiration
- Consider consolidating after fixes if they still check same fields

---

## 6. Method Usage Analysis 📊

### Distribution

**Methods:**
- `list_listeners`: 2 rules (50%) - Both check Protocol
- `list_accelerators`: 1 rule (25%) - Checks AcceleratorArn
- `describe_accelerator_attributes`: 1 rule (25%) - Checks FlowLogsEnabled

### Observations

✅ **Good:** Appropriate use of globalaccelerator API methods  
⚠️ **Issue:** Some rules use methods correctly but check wrong fields (protocol instead of version/validity)

---

## 7. Logical Operator Usage 🔧

### Distribution

- **`all`**: 2 rules (50%) - Array checks (Listeners)
- **`null`**: 2 rules (50%) - Single field checks

### Observations

✅ **Good:** Appropriate use of logical operators  
✅ **Good:** `all` operator correctly used for array checks

---

## 8. YAML Metadata Alignment ✅

**Status:** Perfect alignment

- ✅ 4 rules have corresponding YAML files
- ✅ No orphaned YAML files
- ✅ Rule ID matches between mapping and YAML
- ✅ 100% coverage

---

## 9. Detailed Rule Analysis 📋

### High Priority Rules to Fix

1. **`aws.globalaccelerator.accelerator.waf_attached_if_supported`** ⚠️
   - ❌ Checks AcceleratorArn existence instead of WAF attachment
   - Impact: HIGH

2. **`aws.globalaccelerator.accelerator.listener_tls_min_1_2_configured`** ⚠️
   - ❌ Checks Protocol equals TLS instead of TLS version
   - Impact: HIGH

3. **`aws.globalaccelerator.accelerator.valid_certificate_enabled`** ⚠️
   - ❌ Checks Protocol equals TLS instead of certificate validity
   - Impact: HIGH
   - ⚠️ Also duplicate of TLS rule

### Rules with Good Quality

4. **`aws.globalaccelerator.accelerator.access_logs_enabled`** ✅
   - ✅ Checks `FlowLogsEnabled equals true` correctly
   - ✅ Validates actual logging configuration

---

## 10. Recommendations 🎯

### Priority 1: HIGH (Critical Fixes)

1. **Fix WAF Attachment Rule** ⚠️
   - Review `aws.globalaccelerator.accelerator.waf_attached_if_supported`
   - Change from checking AcceleratorArn existence to checking WAF attachment
   - May need to use WAF API or check security group/firewall associations

2. **Fix TLS Minimum Version Rule** ⚠️
   - Review `aws.globalaccelerator.accelerator.listener_tls_min_1_2_configured`
   - Change from checking Protocol equals TLS to checking TLS version (1.2+)
   - Verify correct field name in Global Accelerator API for TLS version

3. **Fix Certificate Validity Rule** ⚠️
   - Review `aws.globalaccelerator.accelerator.valid_certificate_enabled`
   - Change from checking Protocol equals TLS to checking certificate validity/expiration
   - May need to use ACM API or check certificate expiration date in listener configuration

### Priority 2: MEDIUM (Consolidation)

4. **Review Consolidation After Fixes** ⚠️
   - After fixing bugs, review if TLS and certificate rules can be consolidated
   - They currently check same field but have different purposes
   - May need to remain separate if they check different fields after fixes

---

## 11. Quality Metrics 📈

| Metric | Value | Status |
|--------|-------|--------|
| Total Rules | 4 | ✅ |
| Critical Bugs | 3 | ⚠️ |
| Type Mismatches | 0 | ✅ |
| Field Path Issues | 0 | ✅ |
| Consolidation Opportunities | 1 group (2 rules) | ⚠️ |
| Cross-Service Suggestions | 0 | ✅ |
| YAML Alignment | 100% | ✅ |
| Overall Score | 85/100 | ⚠️ |

---

## Conclusion

Global Accelerator metadata mapping has **moderate quality** with **3 critical issues** and **1 duplicate group**:

1. ⚠️ **3 rules check wrong fields** (WAF attachment, TLS version, certificate validity)
2. ⚠️ **1 duplicate group** (TLS and certificate rules check same field)
3. ✅ **No type mismatches or field path issues**
4. ✅ **Perfect YAML alignment** (100%)
5. ✅ **No cross-service issues** (correctly uses globalaccelerator API methods)
6. ✅ **1 rule has perfect quality** (access logs enabled)

The quality score of **85/100** reflects:
- 3 critical bugs affecting validation accuracy
- Rules pass when protocol is TLS, regardless of TLS version or certificate validity
- WAF attachment rule passes when accelerator exists, regardless of WAF attachment
- Good structure and API method usage otherwise

**Strengths:**
- Correct use of globalaccelerator API methods
- Appropriate method selection for resource types
- Good field path structure
- Clean, well-structured implementation
- 1 rule correctly validates logging configuration
- Appropriate use of logical operators

**Weaknesses:**
- WAF attachment rule only checks accelerator existence
- TLS rule checks protocol type instead of TLS version
- Certificate rule checks protocol type instead of certificate validity
- TLS and certificate rules are duplicates (same check)

---

**Next Steps:**
1. **HIGH PRIORITY:** Fix WAF attachment rule to check actual WAF attachment
2. **HIGH PRIORITY:** Fix TLS rule to check TLS version (1.2+), not just protocol
3. **HIGH PRIORITY:** Fix certificate rule to check certificate validity/expiration, not just protocol
4. **MEDIUM:** After fixing bugs, review if TLS and certificate rules can be consolidated (may need to remain separate if they check different fields)
5. **LOW:** Verify correct field names in Global Accelerator API for WAF attachment, TLS version, and certificate validity

