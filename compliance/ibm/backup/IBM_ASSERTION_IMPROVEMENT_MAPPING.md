# IBM Cloud CSPM - Assertion Quality Improvement Mapping

## Executive Summary

**Current State:**
- Total Rules: 1,612
- ✅ Good Assertions: 741 (46.0%)
- ⚠️  Needs Improvement: 827 (51.3%)
- ❌ Malformed: 0 (0.0%)

**Issues Breakdown:**
1. **Ends with '_check'**: 174 rules (10.8%) - Missing clear desired state
2. **Too vague**: 4 rules (0.2%) - Missing context/parameter
3. **No clear status**: 653 rules (40.5%) - Ambiguous assertions

---

## Enterprise-Grade Assertion Standards

### Format: `{parameter}_{desired_status}`

**Good Examples:**
```
✅ encryption_at_rest_enabled
✅ public_access_blocked
✅ tls_version_1_2_required
✅ multi_az_deployment_configured
✅ backup_retention_90_days_minimum
✅ admin_privileges_restricted
```

**Bad Examples:**
```
❌ encryption_check              → encryption_at_rest_enabled
❌ configured                    → auto_scaling_configured
❌ enabled                       → logging_enabled
❌ not_publicly_accessible       → public_access_blocked
❌ least_privilege               → least_privilege_enforced
```

---

## Category 1: Assertions Ending with '_check' (174 rules)

### Pattern: Remove '_check' and add clear desired state

| Current Assertion | Improved Assertion | Reasoning |
|-------------------|-------------------|-----------|
| `certificates_expiration_check` | `certificates_expiration_monitored` | Check → active monitoring |
| `tracker_alert_configuration_verification_check` | `tracker_alerts_configured` | Simplify + clear state |
| `tracker_data_encryption_at_rest_check` | `tracker_data_encryption_at_rest_enabled` | Check → enabled |
| `tracker_login_ip_restriction_check` | `tracker_login_ip_restriction_enabled` | Check → enabled |
| `tracker_threat_detection_enumeration_check` | `threat_detection_enumeration_enabled` | Simplify + enabled |
| `tracker_threat_detection_llm_jacking_check` | `threat_detection_llm_jacking_enabled` | Simplify + enabled |
| `tracker_threat_detection_privilege_escalation_check` | `threat_detection_privilege_escalation_enabled` | Simplify + enabled |
| `api_restrictions_configured_check` | `api_restrictions_configured` | Remove redundant _check |
| `connect_restapi_waf_acl_attached_check` | `waf_acl_attached` | Simplify + clear state |
| `minimum_tls_version_12_check` | `tls_version_1_2_minimum_required` | Check → required |
| `workgroup_encryption_check` | `workgroup_encryption_enabled` | Check → enabled |
| `dataset_cmk_encryption_check` | `dataset_cmk_encryption_enabled` | Check → enabled |
| `dataset_public_access_check` | `dataset_public_access_blocked` | Check → blocked |
| `table_cmk_encryption_check` | `table_cmk_encryption_enabled` | Check → enabled |
| `maintain_current_contact_details_check` | `current_contact_details_maintained` | Check → maintained |
| `maintain_different_contact_details_to_security_billing_and_operations_check` | `separate_security_billing_ops_contacts_configured` | Simplify + configured |
| `insecure_ssl_ciphers_check` | `insecure_ssl_ciphers_blocked` | Check → blocked |
| `internet_facing_check` | `internet_facing_reviewed` | Check → reviewed (context-dependent) |
| `is_in_multiple_az_check` | `multi_az_deployment_enabled` | Simplify + enabled |
| `securitygroup_default_restrict_traffic_check` | `default_security_group_restricted` | Simplify + restricted |
| `high_availability_check` | `high_availability_enabled` | Check → enabled |
| `admission_control_check` | `admission_control_enabled` | Check → enabled |

### Automated Fix Pattern:

```python
ASSERTION_CHECK_MAPPINGS = {
    # Encryption
    'encryption_check': 'encryption_enabled',
    'cmk_encryption_check': 'cmk_encryption_enabled',
    'encrypted_check': 'encryption_enabled',
    
    # Access Control
    'public_access_check': 'public_access_blocked',
    'ip_restriction_check': 'ip_restriction_enabled',
    'least_privilege_check': 'least_privilege_enforced',
    'rbac_check': 'rbac_enforced',
    
    # Monitoring/Logging
    'logging_check': 'logging_enabled',
    'monitoring_check': 'monitoring_enabled',
    'alert_check': 'alerts_configured',
    'threat_detection_check': 'threat_detection_enabled',
    
    # Configuration
    'configuration_check': 'configured',
    'verification_check': 'verified',
    'validation_check': 'validated',
    
    # TLS/SSL
    'tls_version_check': 'tls_version_required',
    'ssl_check': 'ssl_enforced',
    'insecure_ssl_ciphers_check': 'insecure_ssl_ciphers_blocked',
    
    # High Availability
    'high_availability_check': 'high_availability_enabled',
    'multi_az_check': 'multi_az_deployment_enabled',
    'redundancy_check': 'redundancy_configured',
    
    # Backup/DR
    'backup_check': 'backup_enabled',
    'retention_check': 'retention_configured',
}
```

---

## Category 2: Too Vague Assertions (4 rules)

### Need Context and Parameter

| Rule | Current | Issue | Improved |
|------|---------|-------|----------|
| `ibm.accessanalyzer.resource.enabled` | `enabled` | What is enabled? | `access_analyzer_enabled` |
| `ibm.accessanalyzer.resource.enabled_without_findings` | `enabled_without_findings` | OK but could be clearer | `access_analyzer_active_no_findings` |
| `ibm.autoscaling.group.configured` | `configured` | What is configured? | `auto_scaling_group_configured` |
| `ibm.autoscaling.group.health_check_enabled` | (good) | ✅ Clear | Keep as-is |

---

## Category 3: No Clear Desired State (653 rules)

### 3.1 Access Control - Missing Desired State

| Current | Issue | Improved |
|---------|-------|----------|
| `not_publicly_accessible` | Negative phrasing | `public_access_blocked` |
| `public_access` | No state | `public_access_blocked` |
| `rbac_least_privilege` | No state | `rbac_least_privilege_enforced` |
| `role_least_privilege` | No state | `role_least_privilege_enforced` |
| `access_rbac_least_privilege` | No state | `rbac_least_privilege_enforced` |
| `unrestricted_inbound_access` | No state | `unrestricted_inbound_access_blocked` |

### 3.2 Encryption - Missing Desired State

| Current | Issue | Improved |
|---------|-------|----------|
| `encrypted` | No state | `encryption_at_rest_enabled` |
| `encrypted_at_rest` | No state | `encryption_at_rest_enabled` |
| `encryption` | No state | `encryption_enabled` |
| `cmk_encryption` | No state | `cmk_encryption_enabled` |
| `kms_encryption` | No state | `kms_encryption_enabled` |

### 3.3 Network - Missing Desired State

| Current | Issue | Improved |
|---------|-------|----------|
| `network_private_only` | No state | `private_networking_enforced` |
| `private_networking` | No state | `private_networking_enabled` |
| `vpc_multi_az` | No state | `vpc_multi_az_configured` |
| `inside_vpc` | No state | `vpc_deployment_required` |

### 3.4 Kubernetes/OpenShift - Unmapped Scope (48 rules)

**Problem**: Rules like `ibm.unmapped.scope.k8s_apiserver` lack proper service context

| Current Pattern | Issue | Improved Pattern |
|----------------|-------|------------------|
| `ibm.unmapped.scope.k8s_apiserver` | Wrong service | `ibm.kubernetes.cluster.apiserver_{specific_check}_enabled` |
| `ibm.unmapped.scope.k8s_kubelet` | Wrong service | `ibm.kubernetes.worker.kubelet_{specific_check}_enabled` |
| `ibm.unmapped.scope.k8s_rbac` | Wrong service | `ibm.kubernetes.cluster.rbac_{specific_check}_enforced` |
| `ibm.unmapped.scope.k8s_etcd` | Wrong service | `ibm.kubernetes.cluster.etcd_{specific_check}_enabled` |
| `ibm.unmapped.scope.crypto_kms` | Wrong service | `ibm.key_protect.key.{specific_check}_enabled` |
| `ibm.unmapped.scope.crypto_kms_key` | Wrong service | `ibm.key_protect.key.{specific_check}_configured` |

### 3.5 Monitoring/Logging - Missing Desired State

| Current | Issue | Improved |
|---------|-------|----------|
| `logging` | No state | `logging_enabled` |
| `monitoring` | No state | `monitoring_enabled` |
| `audit_logging` | No state | `audit_logging_enabled` |
| `access_logging` | No state | `access_logging_enabled` |

---

## Comprehensive Improvement Mappings

### Encryption Assertions

```python
ENCRYPTION_IMPROVEMENTS = {
    'encrypted': 'encryption_at_rest_enabled',
    'encrypted_at_rest': 'encryption_at_rest_enabled',
    'encryption': 'encryption_enabled',
    'cmk_encryption': 'cmk_encryption_enabled',
    'cmek_configured': 'cmek_encryption_configured',
    'kms_encryption': 'kms_encryption_enabled',
    'data_encrypted': 'data_encryption_enabled',
    'disk_encryption': 'disk_encryption_enabled',
    'volume_encryption': 'volume_encryption_enabled',
    'bucket_encryption': 'bucket_encryption_enabled',
    'snapshot_encryption': 'snapshot_encryption_enabled',
}
```

### Access Control Assertions

```python
ACCESS_CONTROL_IMPROVEMENTS = {
    'not_publicly_accessible': 'public_access_blocked',
    'public_access': 'public_access_blocked',
    'is_not_publicly_accessible': 'public_access_blocked',
    'not_public': 'public_access_blocked',
    'private': 'private_access_enforced',
    'rbac_least_privilege': 'rbac_least_privilege_enforced',
    'role_least_privilege': 'role_least_privilege_enforced',
    'least_privilege': 'least_privilege_enforced',
    'access_rbac_least_privilege': 'rbac_least_privilege_enforced',
    'unrestricted_inbound_access': 'unrestricted_inbound_access_blocked',
    'restricted': 'access_restricted',
    'authorization': 'authorization_enforced',
    'authentication': 'authentication_required',
}
```

### Network Assertions

```python
NETWORK_IMPROVEMENTS = {
    'network_private_only': 'private_networking_enforced',
    'private_networking': 'private_networking_enabled',
    'inside_vpc': 'vpc_deployment_required',
    'vpc_multi_az': 'vpc_multi_az_configured',
    'multi_az': 'multi_az_deployment_enabled',
    'multiple_az': 'multi_az_deployment_enabled',
    'internet_facing': 'internet_facing_restricted',  # Context-dependent
}
```

### Logging/Monitoring Assertions

```python
LOGGING_MONITORING_IMPROVEMENTS = {
    'logging': 'logging_enabled',
    'monitoring': 'monitoring_enabled',
    'audit_logging': 'audit_logging_enabled',
    'access_logging': 'access_logging_enabled',
    'flow_logging': 'flow_logging_enabled',
    'log_retention': 'log_retention_configured',
    'logs_encrypted': 'log_encryption_enabled',
    'alert_configured': 'alerts_configured',
    'notification': 'notifications_configured',
}
```

### TLS/SSL Assertions

```python
TLS_SSL_IMPROVEMENTS = {
    'minimum_tls_version_12': 'tls_version_1_2_minimum_required',
    'tls_version_12': 'tls_version_1_2_required',
    'tls_min_1_2': 'tls_version_1_2_minimum_required',
    'ssl_enforced': 'ssl_tls_enforced',
    'insecure_ssl_ciphers': 'insecure_ssl_ciphers_blocked',
    'https_required': 'https_enforced',
    'https_only': 'https_enforced',
}
```

### Backup/DR Assertions

```python
BACKUP_DR_IMPROVEMENTS = {
    'backup': 'backup_enabled',
    'automated_backups': 'automated_backups_enabled',
    'backup_retention': 'backup_retention_configured',
    'cross_region_backup': 'cross_region_backup_enabled',
    'point_in_time_recovery': 'point_in_time_recovery_enabled',
    'deletion_protection': 'deletion_protection_enabled',
}
```

### Compliance/Governance Assertions

```python
COMPLIANCE_IMPROVEMENTS = {
    'compliance': 'compliance_validated',
    'policy_enforced': 'policy_enforcement_enabled',
    'lifecycle_policy': 'lifecycle_policy_configured',
    'retention_policy': 'retention_policy_configured',
    'versioning': 'versioning_enabled',
    'mfa_delete': 'mfa_delete_enabled',
}
```

---

## Priority Fixes

### Priority 1 (High Impact - 174 rules)
**Remove '_check' suffix and add clear state**
- Affects: All 174 rules ending with '_check'
- Impact: Immediate clarity improvement
- Effort: Low (automated fix)

### Priority 2 (Medium Impact - 653 rules)
**Add clear desired state to ambiguous assertions**
- Affects: Rules with no clear status
- Impact: Major quality improvement
- Effort: Medium (requires context-aware mapping)

### Priority 3 (Low Impact - 4 rules)
**Fix vague assertions**
- Affects: Generic 'enabled', 'configured'
- Impact: Minor clarity improvement
- Effort: Low (manual fix)

### Priority 4 (Critical - 48 rules)
**Fix 'unmapped.scope' rules**
- Affects: Kubernetes/KMS rules in wrong service
- Impact: Correctness (wrong service mapping)
- Effort: Medium (needs service remapping + assertion fix)

---

## Automated Fix Strategy

### Step 1: Fix '_check' Suffix (174 rules)
```python
def fix_check_suffix(assertion):
    if not assertion.endswith('_check'):
        return assertion
    
    base = assertion.replace('_check', '')
    
    # Context-based improvements
    if 'encryption' in base or 'encrypted' in base:
        return base + '_enabled'
    elif 'public' in base or 'unrestricted' in base:
        return base + '_blocked'
    elif 'least_privilege' in base or 'rbac' in base:
        return base + '_enforced'
    elif 'tls' in base or 'ssl' in base or 'version' in base:
        return base + '_required'
    elif 'backup' in base or 'logging' in base or 'monitoring' in base:
        return base + '_enabled'
    elif 'configured' in base or 'attached' in base:
        return base  # Already clear
    else:
        return base + '_enabled'  # Default
```

### Step 2: Fix Ambiguous States (653 rules)
```python
def fix_ambiguous_state(assertion):
    # Apply improvement mappings
    for pattern, improvement in ALL_IMPROVEMENTS.items():
        if assertion == pattern or assertion.endswith('_' + pattern):
            return assertion.replace(pattern, improvement)
    
    return assertion
```

### Step 3: Fix Unmapped Scope (48 rules)
```python
def fix_unmapped_scope(rule):
    # ibm.unmapped.scope.k8s_apiserver → ibm.kubernetes.cluster.apiserver_*
    # Requires manual review of actual check
    pass  # Manual fix needed
```

---

## Expected Outcomes

**After Fixes:**
- ✅ Good Assertions: ~1,550 rules (96%+)
- ⚠️  Needs Review: ~60 rules (4%)
- ❌ Malformed: 0 rules (0%)

**Quality Grade:**
- **Current**: C+ (46% good assertions)
- **After Fix**: A+ (96%+ good assertions)

---

## Next Steps

1. ✅ **Review this mapping** - Validate improvement suggestions
2. 🔄 **Create automated fix script** - Apply transformations
3. ✅ **Manual review** - Handle edge cases (unmapped scope)
4. 🧪 **Validate results** - Run quality checks
5. 📊 **Generate report** - Document improvements

---

**Status**: Ready for implementation
**Estimated Rules to Fix**: 827 (51.3%)
**Estimated Time**: 30-45 minutes (automated) + 15 minutes (manual review)

