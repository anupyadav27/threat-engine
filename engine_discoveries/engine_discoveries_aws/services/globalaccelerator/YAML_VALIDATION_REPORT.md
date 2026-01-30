# Global Accelerator YAML Validation Report

**Validation Date**: 2026-01-08  
**Service**: globalaccelerator  
**Total Rules**: 4  
**Test Region**: us-west-2 (Global Accelerator control plane API is only available in us-west-2)

---

## Test Results Summary

**Scan Execution**: ✅ PASSED (no errors)  
**Total Checks**: 5 (across 5 accounts)  
**PASS**: 0  
**FAIL**: 5  
**Status**: Logic issues identified - all checks failed

---

## Per-Rule Validation

### 1. `aws.globalaccelerator.accelerator.access_logs_enabled`

**Metadata Intent**:  
- Verify that Global Accelerator accelerator has access logs (Flow Logs) enabled
- Check `FlowLogsEnabled` is `true`
- Ensure proper logging configuration for security compliance

**YAML Implementation**:
```yaml
- rule_id: aws.globalaccelerator.accelerator.access_logs_enabled
  for_each: aws.globalaccelerator.describe_accelerator_attributes
  conditions:
    var: item.FlowLogsEnabled
    op: equals
    value: 'true'
```

**Analysis**:
- ✅ Discovery chain: Correct (`list_accelerators` → `describe_accelerator_attributes`)
- ✅ Field path: Correct (`item.FlowLogsEnabled` matches emit structure)
- ✅ Operator: Correct (`equals`)
- ⚠️ Value type: Checking string `'true'` - may need to verify if API returns boolean `true` or string `'true'`

**Match**: ✅ YES (with potential value type issue)

**Issues**: 
- Potential value type mismatch: YAML checks for string `'true'`, but API might return boolean `true`

**Test Result**: FAIL (0 PASS, 5 FAIL across accounts - likely due to FlowLogsEnabled being false or value type mismatch)

**Recommendation**: Verify actual API response type for `FlowLogsEnabled` and adjust value accordingly

---

### 2. `aws.globalaccelerator.accelerator.listener_tls_min_1_2_configured`

**Metadata Intent**:  
- Verify that Global Accelerator listener has TLS minimum version 1.2 configured
- Ensure encryption in transit with secure TLS version
- Check TLS policy/configuration specifies TLS 1.2 or higher

**YAML Implementation**:
```yaml
- rule_id: aws.globalaccelerator.accelerator.listener_tls_min_1_2_configured
  for_each: aws.globalaccelerator.list_listeners
  conditions:
    var: item.Protocol
    op: equals
    value: TLS
```

**Analysis**:
- ✅ Discovery chain: Correct (`list_accelerators` → `list_listeners`)
- ❌ Field path: **WRONG** - Only checks `Protocol == TLS`, does NOT check TLS version
- ❌ Logic: **INCOMPLETE** - TLS 1.0, 1.1, and 1.2 all use `Protocol="TLS"`, so this check doesn't verify minimum version 1.2

**Match**: ❌ NO

**Issues**: 
- **CRITICAL**: Rule name says "tls_min_1_2_configured" but only verifies protocol type, not TLS version
- Missing check for TLS version/policy configuration
- May need to check `Certificates[]` array or listener security policy
- May need to use `describe_listener` API to get detailed TLS configuration

**Test Result**: FAIL (likely because rule logic is incorrect)

**Recommendation**: 
- Add discovery for `describe_listener` to get detailed listener configuration
- Check TLS version field (may be in `Certificates[]` or security policy)
- Verify minimum TLS version is 1.2 or higher

---

### 3. `aws.globalaccelerator.accelerator.valid_certificate_enabled`

**Metadata Intent**:  
- Verify that Global Accelerator listener has a valid certificate enabled
- Check certificate expiration date
- Verify certificate status (valid/expired/revoked)
- Ensure certificate chain validity

**YAML Implementation**:
```yaml
- rule_id: aws.globalaccelerator.accelerator.valid_certificate_enabled
  for_each: aws.globalaccelerator.list_listeners
  conditions:
    var: item.Protocol
    op: equals
    value: TLS
```

**Analysis**:
- ✅ Discovery chain: Correct (`list_accelerators` → `list_listeners`)
- ❌ Field path: **WRONG** - Only checks `Protocol == TLS`, does NOT check certificate validity
- ❌ Logic: **INCOMPLETE** - This only verifies TLS protocol is used, not certificate validity

**Match**: ❌ NO

**Issues**: 
- **CRITICAL**: Rule name says "valid_certificate_enabled" but only verifies protocol type
- Missing check for certificate expiration date
- Missing check for certificate status
- Missing check for certificate chain validity
- May need to use ACM API (`describe_certificate`) to check certificate validity
- May need to check certificate expiration date in listener configuration

**Test Result**: FAIL (likely because rule logic is incorrect)

**Recommendation**: 
- Add discovery for `describe_listener` to get certificate details
- Check certificate ARN from listener configuration
- Use ACM API to verify certificate validity and expiration
- Or check certificate expiration date if available in listener response

**Note**: This rule is also a duplicate of `listener_tls_min_1_2_configured` (both check `Protocol == TLS`), but they should check different things after fixes

---

### 4. `aws.globalaccelerator.accelerator.waf_attached_if_supported`

**Metadata Intent**:  
- Verify that Global Accelerator accelerator has WAF attached if supported
- Check if WAF is actually attached to the accelerator
- Verify WAF configuration if applicable

**YAML Implementation**:
```yaml
- rule_id: aws.globalaccelerator.accelerator.waf_attached_if_supported
  for_each: aws.globalaccelerator.list_accelerators
  conditions:
    var: item.AcceleratorArn
    op: exists
    value: null
```

**Analysis**:
- ✅ Discovery chain: Correct (`list_accelerators`)
- ❌ Field path: **WRONG** - Only checks if `AcceleratorArn` exists, not if WAF is attached
- ❌ Logic: **INCOMPLETE** - This check will always pass if an accelerator exists, regardless of WAF attachment

**Match**: ❌ NO

**Issues**: 
- **CRITICAL**: Rule name says "waf_attached_if_supported" but only verifies accelerator exists
- Missing check for WAF attachment
- May need to check WAF association via WAF API or accelerator attributes
- May need to check if accelerator supports WAF before checking attachment

**Test Result**: FAIL (likely because rule logic is incorrect)

**Recommendation**: 
- Check if Global Accelerator supports WAF attachment (may be region/service specific)
- If supported, add discovery to check WAF association (may need WAF API or accelerator attributes)
- Verify WAF is actually attached to the accelerator

---

## Summary of Issues

### Critical Issues (3)

1. **`listener_tls_min_1_2_configured`**: Checks protocol type instead of TLS version
2. **`valid_certificate_enabled`**: Checks protocol type instead of certificate validity
3. **`waf_attached_if_supported`**: Checks accelerator existence instead of WAF attachment

### Potential Issues (1)

1. **`access_logs_enabled`**: Value type mismatch (string `'true'` vs boolean `true`)

### Consolidation Opportunities (1)

1. **Duplicate rules**: `listener_tls_min_1_2_configured` and `valid_certificate_enabled` currently check the same field (`Protocol == TLS`), but they should check different things after fixes

---

## Recommendations

### Immediate Fixes Required

1. **Fix TLS version check**: Add `describe_listener` discovery and check TLS version/policy
2. **Fix certificate validity check**: Add certificate validation logic (may require ACM API integration)
3. **Fix WAF attachment check**: Add WAF association verification
4. **Verify value types**: Confirm `FlowLogsEnabled` returns boolean or string

### API Research Needed

- Check if `describe_listener` API provides TLS version/policy details
- Check if listener response includes certificate ARN and expiration
- Check if Global Accelerator supports WAF attachment and how to verify it
- Verify `FlowLogsEnabled` return type (boolean vs string)

### Testing

- After fixes, re-test against AWS accounts with:
  - Accelerators with Flow Logs enabled/disabled
  - Listeners with TLS 1.2+ configured
  - Listeners with valid/expired certificates
  - Accelerators with/without WAF attached

---

## Validation Status

| Rule ID | Intent Match | Field Path | Operator | Value | Discovery | Test | Status |
|---------|-------------|------------|----------|-------|-----------|------|--------|
| `access_logs_enabled` | ✅ | ✅ | ✅ | ⚠️ | ✅ | FAIL | ⚠️ Needs value type verification |
| `listener_tls_min_1_2_configured` | ❌ | ❌ | ✅ | ❌ | ✅ | FAIL | ❌ Critical - Wrong field |
| `valid_certificate_enabled` | ❌ | ❌ | ✅ | ❌ | ✅ | FAIL | ❌ Critical - Wrong field |
| `waf_attached_if_supported` | ❌ | ❌ | ✅ | ❌ | ✅ | FAIL | ❌ Critical - Wrong field |

**Overall Status**: ❌ **3 out of 4 rules have critical logic issues**





