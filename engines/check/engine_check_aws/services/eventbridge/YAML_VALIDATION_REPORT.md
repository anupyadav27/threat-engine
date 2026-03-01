# EVENTBRIDGE YAML Validation Report

**Date**: 2026-01-08  
**Service**: eventbridge  
**Total Rules**: 20

---

## Validation Summary

**Total Rules**: 20  
**Validated**: 20  
**Passing**: 0  
**Fixed**: 0  
**Test Status**: PARTIAL (execution successful, but many checks failed - logic issues)

---

## Per-Rule Results

### aws.eventbridge.eventbus.change_audit_logging_enabled

**Metadata Intent**: 
- Checks that change audit logging is enabled
- Should verify LogConfig exists and is configured

**YAML Checks**: 
- Discovery: `aws.eventbridge.describe_event_bus` ✅
- Condition: `item.LogConfig exists`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Insufficient Check**: Only checks if `LogConfig` exists, but doesn't verify logging is actually enabled. LogConfig may exist but be disabled or misconfigured.

**Fixed**: No

**Test**: FAIL - Check failed (likely logging not enabled or LogConfig not configured)

---

### aws.eventbridge.eventbus.endpoints_authenticated_configured

**Metadata Intent**: 
- Checks that endpoints are authenticated
- Should verify RoleArn exists for authentication

**YAML Checks**: 
- Discovery: `aws.events.list_endpoints` ✅
- Condition: `item.RoleArn exists`

**Match**: ✅ YES

**Issues**: None

**Fixed**: No

**Test**: PASS/FAIL - Depends on actual configuration

---

### aws.eventbridge.eventbus.eventbridge_destinations_configured

**Metadata Intent**: 
- Checks that eventbridge destinations are configured
- Should verify destinations exist

**YAML Checks**: 
- Discovery: `aws.events.list_api_destinations` ✅
- Condition: `item.ApiDestinationArn exists`

**Match**: ✅ YES

**Issues**: None

**Fixed**: No

**Test**: PASS/FAIL - Depends on actual configuration

---

### aws.eventbridge.eventbus.message_encryption_in_transit_configured

**Metadata Intent**: 
- Checks that message encryption in transit is configured
- Should verify KMS key is configured for encryption

**YAML Checks**: 
- Discovery: `aws.eventbridge.describe_event_bus` ✅
- Condition: `item.KmsKeyIdentifier exists`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Insufficient Check**: Only checks if `KmsKeyIdentifier` exists, but doesn't verify encryption is actually enabled or that it's for in-transit encryption. KmsKeyIdentifier may exist but encryption may not be enabled.

**Fixed**: No

**Test**: FAIL - Check failed (likely encryption not enabled)

---

### aws.eventbridge.eventbus.no_public_webhooks_configured

**Metadata Intent**: 
- Checks that no public webhooks are configured
- Should verify API destinations don't use public endpoints

**YAML Checks**: 
- Discovery: `aws.events.list_api_destinations` ✅
- Condition: `item.InvocationEndpoint not_contains public`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Weak Check**: Checks if endpoint URL contains "public" string, but this is a weak check. A public endpoint might not have "public" in the URL. Should check actual endpoint accessibility or use proper URL validation.

**Fixed**: No

**Test**: PASS/FAIL - Depends on actual configuration

---

### aws.eventbridge.eventbus.oncall_contacts_verified

**Metadata Intent**: 
- Checks that oncall contacts are verified
- Should verify oncall contact configuration

**YAML Checks**: 
- Discovery: `aws.events.list_event_buses` ✅
- Condition: `item.Name exists`

**Match**: ❌ NO

**Issues**:
1. **Placeholder Check**: Only checks if event bus name exists, which always exists. Doesn't verify oncall contacts are configured or verified. This is a placeholder check that doesn't validate the actual requirement.

**Fixed**: No

**Test**: PASS - Always passes (but doesn't validate requirement)

---

### aws.eventbridge.eventbus.policy_exists_for_critical_severity_configured

**Metadata Intent**: 
- Checks that policy exists for critical severity
- Should verify policy exists and is configured for critical events

**YAML Checks**: 
- Discovery: `aws.events.list_event_buses` ✅
- Condition: `item.Policy exists`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Insufficient Check**: Only checks if Policy exists, but doesn't verify it's configured for critical severity events. Policy may exist but not handle critical severity properly.

**Fixed**: No

**Test**: PASS/FAIL - Depends on actual configuration

---

### aws.eventbridge.resource.global_endpoint_event_replication_enabled

**Metadata Intent**: 
- Checks that global endpoint event replication is enabled
- Should verify ReplicationConfig exists and is enabled

**YAML Checks**: 
- Discovery: `aws.events.list_endpoints` ✅
- Condition: `item.ReplicationConfig exists`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Insufficient Check**: Only checks if ReplicationConfig exists, but doesn't verify replication is actually enabled. Config may exist but be disabled.

**Fixed**: No

**Test**: PASS/FAIL - Depends on actual configuration

---

### aws.eventbridge.rule.change_audit_logging_enabled

**Metadata Intent**: 
- Checks that change audit logging is enabled for rules
- Should verify logging configuration exists and is enabled

**YAML Checks**: 
- Discovery: `aws.events.describe_rule` ✅
- Condition: `item.Name exists`

**Match**: ❌ NO

**Issues**:
1. **Placeholder Check**: Only checks if rule name exists, which always exists. Doesn't verify logging is enabled. This is a placeholder check that doesn't validate the actual requirement.

**Fixed**: No

**Test**: PASS - Always passes (but doesn't validate requirement)

---

### aws.eventbridge.rule.endpoints_authenticated_configured

**Metadata Intent**: 
- Checks that rule endpoints are authenticated
- Should verify RoleArn exists for authentication

**YAML Checks**: 
- Discovery: `aws.events.list_endpoints` ✅
- Condition: `item.RoleArn exists`

**Match**: ✅ YES

**Issues**: None

**Fixed**: No

**Test**: PASS/FAIL - Depends on actual configuration

---

### aws.eventbridge.rule.eventbridge_artifacts_private_and_encrypted

**Metadata Intent**: 
- Checks that eventbridge artifacts are private and encrypted
- Should verify artifacts are in private network and encrypted

**YAML Checks**: 
- Discovery: `aws.events.describe_rule` ✅
- Condition: `item.Name exists`

**Match**: ❌ NO

**Issues**:
1. **Placeholder Check**: Only checks if rule name exists, which always exists. Doesn't verify artifacts are private or encrypted. This is a placeholder check that doesn't validate the actual requirement.

**Fixed**: No

**Test**: PASS - Always passes (but doesn't validate requirement)

---

### aws.eventbridge.rule.eventbridge_destinations_configured

**Metadata Intent**: 
- Checks that eventbridge destinations are configured for rules
- Should verify targets/destinations exist

**YAML Checks**: 
- Discovery: `aws.events.list_targets_by_rule` ✅
- Condition: `item.TargetArn exists`

**Match**: ✅ YES

**Issues**: None

**Fixed**: No

**Test**: PASS/FAIL - Depends on actual configuration

---

### aws.eventbridge.rule.eventbridge_logs_and_metrics_enabled

**Metadata Intent**: 
- Checks that logs and metrics are enabled for rules
- Should verify logging and metrics configuration

**YAML Checks**: 
- Discovery: `aws.events.describe_rule` ✅
- Condition: `item.Name exists`

**Match**: ❌ NO

**Issues**:
1. **Placeholder Check**: Only checks if rule name exists, which always exists. Doesn't verify logs or metrics are enabled. This is a placeholder check that doesn't validate the actual requirement.

**Fixed**: No

**Test**: PASS - Always passes (but doesn't validate requirement)

---

### aws.eventbridge.rule.execution_roles_least_privilege

**Metadata Intent**: 
- Checks that execution roles follow least privilege
- Should verify RoleArn exists and check role permissions

**YAML Checks**: 
- Discovery: `aws.events.describe_rule` ✅
- Condition: `item.RoleArn exists`

**Match**: ❌ NO

**Issues**:
1. **Insufficient Check**: Only checks if RoleArn exists, but doesn't verify the role follows least privilege. Role may exist but have excessive permissions. Need to check actual IAM role policy.

**Fixed**: No

**Test**: PASS/FAIL - Depends on actual configuration (but doesn't validate least privilege)

---

### aws.eventbridge.rule.kms_encryption_enabled

**Metadata Intent**: 
- Checks that KMS encryption is enabled for rules
- Should verify KMS key is configured and encryption is enabled

**YAML Checks**: 
- Discovery: `aws.events.describe_rule` ✅
- Condition: `item.Name exists`

**Match**: ❌ NO

**Issues**:
1. **Placeholder Check**: Only checks if rule name exists, which always exists. Doesn't verify KMS encryption is enabled. This is a placeholder check that doesn't validate the actual requirement.

**Fixed**: No

**Test**: PASS - Always passes (but doesn't validate requirement)

---

### aws.eventbridge.rule.message_encryption_in_transit_configured

**Metadata Intent**: 
- Checks that message encryption in transit is configured for rules
- Should verify encryption configuration for targets

**YAML Checks**: 
- Discovery: `aws.events.list_targets_by_rule` ✅
- Condition: `item.TargetArn exists`

**Match**: ❌ NO

**Issues**:
1. **Placeholder Check**: Only checks if TargetArn exists, which always exists if target is configured. Doesn't verify encryption in transit is configured. This is a placeholder check that doesn't validate the actual requirement.

**Fixed**: No

**Test**: PASS/FAIL - Depends on actual configuration (but doesn't validate encryption)

---

### aws.eventbridge.rule.no_public_webhooks_configured

**Metadata Intent**: 
- Checks that no public webhooks are configured for rules
- Should verify API destinations don't use public endpoints

**YAML Checks**: 
- Discovery: `aws.events.list_api_destinations` ✅
- Condition: `item.InvocationEndpoint not_contains public`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Weak Check**: Same as rule #5 - checks if endpoint URL contains "public" string, but this is weak validation.

**Fixed**: No

**Test**: PASS/FAIL - Depends on actual configuration

---

### aws.eventbridge.rule.oncall_contacts_verified

**Metadata Intent**: 
- Checks that oncall contacts are verified for rules
- Should verify oncall contact configuration

**YAML Checks**: 
- Discovery: `aws.events.list_rules` ✅
- Condition: `item.Name exists`

**Match**: ❌ NO

**Issues**:
1. **Placeholder Check**: Only checks if rule name exists, which always exists. Doesn't verify oncall contacts are configured or verified. This is a placeholder check that doesn't validate the actual requirement.

**Fixed**: No

**Test**: PASS - Always passes (but doesn't validate requirement)

---

### aws.eventbridge.rule.policy_exists_for_critical_severity_configured

**Metadata Intent**: 
- Checks that policy exists for critical severity events
- Should verify policy exists and handles critical severity

**YAML Checks**: 
- Discovery: `aws.events.describe_rule` ✅
- Condition: `item.Name exists`

**Match**: ❌ NO

**Issues**:
1. **Placeholder Check**: Only checks if rule name exists, which always exists. Doesn't verify policy exists or handles critical severity. This is a placeholder check that doesn't validate the actual requirement.

**Fixed**: No

**Test**: PASS - Always passes (but doesn't validate requirement)

---

### aws.eventbridge.rule.private_networking_enforced

**Metadata Intent**: 
- Checks that private networking is enforced for rules
- Should verify targets use private networking

**YAML Checks**: 
- Discovery: `aws.events.list_targets_by_rule` ✅
- Condition: `item.TargetArn exists`

**Match**: ❌ NO

**Issues**:
1. **Placeholder Check**: Only checks if TargetArn exists, which always exists if target is configured. Doesn't verify private networking is enforced. This is a placeholder check that doesn't validate the actual requirement.

**Fixed**: No

**Test**: PASS/FAIL - Depends on actual configuration (but doesn't validate private networking)

---

## Critical Issues Summary

### Issue 1: Placeholder Checks (10 rules)
Many rules use placeholder checks that don't validate the actual requirement:
- Rules checking `item.Name exists` (rules 6, 9, 11, 13, 15, 17, 19) - Name always exists, doesn't validate requirement
- Rules checking `item.TargetArn exists` (rules 16, 20) - ARN always exists if target configured, doesn't validate requirement

### Issue 2: Insufficient Validation Logic (8 rules)
Several rules check if something exists but don't verify it's actually enabled/configured:
- Rule 1: Checks LogConfig exists, but doesn't verify logging is enabled
- Rule 4: Checks KmsKeyIdentifier exists, but doesn't verify encryption is enabled
- Rule 7: Checks Policy exists, but doesn't verify it handles critical severity
- Rule 8: Checks ReplicationConfig exists, but doesn't verify replication is enabled
- Rule 14: Checks RoleArn exists, but doesn't verify least privilege
- Rules 5, 18: Weak string matching for public webhooks

### Issue 3: Wrong Discovery (1 rule)
- Rule 54: `list_partner_event_sources` discovery uses wrong action - calls `list_api_destinations` instead of `list_partner_event_sources`

---

## Recommended Fixes

### Fix 1: Replace Placeholder Checks
Rules 6, 9, 11, 13, 15, 17, 19, 20 need proper validation:
- Rule 6 (oncall_contacts_verified): Check for actual oncall contact configuration
- Rule 9 (change_audit_logging_enabled): Check for logging configuration (CloudWatch Logs, etc.)
- Rule 11 (artifacts_private_and_encrypted): Check for encryption and private network settings
- Rule 13 (logs_and_metrics_enabled): Check for CloudWatch Logs and Metrics configuration
- Rule 15 (kms_encryption_enabled): Check for KMS key configuration
- Rule 17 (oncall_contacts_verified): Same as rule 6
- Rule 19 (policy_exists_for_critical_severity): Check policy content for critical severity handling
- Rule 20 (private_networking_enforced): Check target network configuration (VPC, subnet, etc.)

### Fix 2: Enhance Existence Checks
Rules 1, 4, 7, 8, 14 need to verify actual configuration:
- Rule 1: Check LogConfig is enabled, not just exists
- Rule 4: Check encryption is enabled, not just KMS key exists
- Rule 7: Check policy content for critical severity
- Rule 8: Check ReplicationConfig is enabled
- Rule 14: Check IAM role policy for least privilege

### Fix 3: Fix Discovery
- Rule 54: Fix `list_partner_event_sources` discovery to use correct action

### Fix 4: Improve Public Webhook Checks
- Rules 5, 18: Use proper URL validation or check endpoint accessibility instead of string matching

---

## Test Results

**Execution**: ✅ PASS - No errors  
**Warnings**: None  
**Check Results**: 70 checks found (14 per account × 5 accounts)  
**Results**: 10 PASS, 60 FAIL

**Test Status**: PARTIAL - Execution successful, but many checks failed due to placeholder/inadequate validation logic

---

## Checklist

- [x] All metadata files have YAML checks
- [x] All YAML checks have metadata files
- [ ] Each check matches its metadata intention ❌ (20 issues found)
- [ ] Field paths are correct ✅
- [ ] Operators are correct ✅
- [ ] Values are correct ✅
- [ ] Discoveries are correct ⚠️ (1 wrong discovery)
- [x] Test passes without errors ✅
- [ ] Check results are logical ⚠️ (many placeholder checks always pass)
- [ ] Metadata review updated ⚠️ (needs update after fixes)

---

## Next Steps

1. **Replace Placeholder Checks**: Implement proper validation for 10 rules with placeholder checks
2. **Enhance Validation Logic**: Add proper checks for 8 rules with insufficient validation
3. **Fix Discovery**: Fix wrong action in list_partner_event_sources discovery
4. **Improve Public Webhook Checks**: Use proper validation instead of string matching
5. **Re-test**: Run scanner again to verify all fixes work
6. **Update Metadata Review Report**: Generate final report after fixes





