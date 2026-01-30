# DMS YAML Validation Report

**Date**: 2026-01-08  
**Service**: dms  
**Total Rules**: 5

---

## Validation Summary

**Total Rules**: 5  
**Validated**: 5  
**Passing**: 0  
**Fixed**: 0  
**Test Status**: PARTIAL (execution successful, but all checks failed - logic issues)

---

## Per-Rule Results

### aws.dms.instance.dms_multi_az_enabled

**Metadata Intent**: 
- Checks that DMS instance has Multi-AZ enabled
- Should verify MultiAZ is true for high availability

**YAML Checks**: 
- Discovery: `aws.dms.describe_replication_instances` ✅
- Condition: `item.MultiAZ equals 'true'`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Value Type**: Uses string `'true'` but API likely returns boolean `true`. Should verify actual return type.

**Fixed**: No

**Test**: FAIL - All checks failed (likely value type mismatch or MultiAZ not enabled)

---

### aws.dms.instance.no_public_access_configured

**Metadata Intent**: 
- Checks that DMS instance has no public access
- Should verify PubliclyAccessible is false
- Metadata mapping says should use `describe_replication_instances`

**YAML Checks**: 
- Discovery: `aws.dms.describe_instance_profiles` ❌
- Condition: `item.PubliclyAccessible equals 'false'`

**Match**: ❌ NO

**Issues**:
1. **Wrong Discovery**: Uses `describe_instance_profiles` but metadata_mapping.json says should use `describe_replication_instances`. Instance profiles are different from replication instances.
2. **Wrong Resource Type**: Checking instance profiles instead of replication instances.

**Fixed**: No

**Test**: FAIL - All checks failed (wrong discovery, checking wrong resource type)

---

### aws.dms.resource.endpoint_redis_in_transit_encryption_enabled

**Metadata Intent**: 
- Checks that Redis endpoints have in-transit encryption enabled
- Should verify EngineName is redis AND SslMode is require
- Metadata mapping says should use `describe_endpoints`

**YAML Checks**: 
- Discovery: `aws.dms.describe_endpoint_types` ❌
- Conditions:
  - `item.Endpoints.EngineName equals redis`
  - `item.Endpoints.SslMode equals require`

**Match**: ❌ NO

**Issues**:
1. **Wrong Discovery**: Uses `describe_endpoint_types` (returns supported endpoint types) instead of `describe_endpoints` (returns actual endpoints). Should use `describe_endpoints` to check actual endpoint configurations.
2. **Wrong Field Paths**: Uses `item.Endpoints.EngineName` and `item.Endpoints.SslMode`, but after `items_for: '{{ response.SupportedEndpointTypes }}'`, fields should be directly on `item` (e.g., `item.EngineName`, `item.SslMode`). However, since it's the wrong discovery, this is moot.

**Fixed**: No

**Test**: FAIL - All checks failed (wrong discovery, checking endpoint types instead of actual endpoints)

---

### aws.dms.resource.replication_task_source_logging_enabled

**Metadata Intent**: 
- Checks that replication task source logging is enabled
- Should verify logging configuration for source endpoint

**YAML Checks**: 
- Discovery: `aws.dms.describe_replication_tasks` ✅
- Condition: `item.ReplicationTaskSettings exists`

**Match**: ❌ NO

**Issues**:
1. **Insufficient Check**: Only checks if `ReplicationTaskSettings` exists, but doesn't verify that logging is actually enabled. ReplicationTaskSettings is a JSON string that contains various settings - need to check specific logging configuration within it.
2. **Missing Specific Check**: Should check for specific logging settings (e.g., CloudWatchLogGroupArn, EnableLogging) rather than just existence of settings.

**Fixed**: No

**Test**: FAIL - All checks failed (insufficient validation logic)

---

### aws.dms.resource.replication_task_target_logging_enabled

**Metadata Intent**: 
- Checks that replication task target logging is enabled
- Should verify logging configuration for target endpoint

**YAML Checks**: 
- Discovery: `aws.dms.describe_replication_tasks` ✅
- Conditions:
  - `item.ReplicationTaskSettings exists`
  - `item.ReplicationTaskArn exists`

**Match**: ❌ NO

**Issues**:
1. **Insufficient Check**: Same as rule #4 - only checks if settings exist, not if logging is enabled.
2. **Redundant Check**: Checking `ReplicationTaskArn exists` doesn't verify logging - ARN always exists if task exists.
3. **Missing Specific Check**: Should check for specific logging settings rather than just existence.

**Fixed**: No

**Test**: FAIL - All checks failed (insufficient validation logic)

---

## Critical Issues Summary

### Issue 1: Wrong Discovery Methods
- **Rule 2**: Uses `describe_instance_profiles` instead of `describe_replication_instances`
- **Rule 3**: Uses `describe_endpoint_types` instead of `describe_endpoints`

### Issue 2: Insufficient Validation Logic
- **Rules 4 & 5**: Only check if `ReplicationTaskSettings` exists, but don't verify logging is actually enabled. Need to check specific logging configuration fields.

### Issue 3: Field Path Issues
- **Rule 3**: Uses wrong field paths (`item.Endpoints.*` instead of `item.*` after items_for)

### Issue 4: Value Type Verification
- **Rule 1**: Uses string `'true'` but API may return boolean - need to verify

---

## Recommended Fixes

### Fix 1: Correct Discovery for Rule 2
```yaml
- rule_id: aws.dms.instance.no_public_access_configured
  for_each: aws.dms.describe_replication_instances  # Changed from describe_instance_profiles
  conditions:
    var: item.PubliclyAccessible
    op: equals
    value: 'false'
```

**Note**: Need to verify if `describe_replication_instances` returns `PubliclyAccessible` field. If not, may need `describe_replication_instance` (singular) with parameters.

### Fix 2: Correct Discovery for Rule 3
```yaml
- discovery_id: aws.dms.describe_endpoints  # Changed from describe_endpoint_types
  calls:
    - action: describe_endpoints
      save_as: response
  emit:
    items_for: '{{ response.Endpoints }}'
    as: item
    item:
      EngineName: '{{ item.EngineName }}'
      SslMode: '{{ item.SslMode }}'
      # ... other fields

- rule_id: aws.dms.resource.endpoint_redis_in_transit_encryption_enabled
  for_each: aws.dms.describe_endpoints
  conditions:
    all:
    - var: item.EngineName
      op: equals
      value: redis
    - var: item.SslMode
      op: equals
      value: require
```

### Fix 3: Enhance Logging Checks for Rules 4 & 5
Need to check specific logging fields in ReplicationTaskSettings. Options:
1. Parse ReplicationTaskSettings JSON and check for logging configuration
2. Use additional API calls to get logging status
3. Check for CloudWatchLogGroupArn or EnableLogging fields

### Fix 4: Verify Value Types
- Rule 1: Verify if MultiAZ returns boolean or string, adjust value accordingly

---

## Test Results

**Execution**: ✅ PASS - No errors  
**Warnings**: None  
**Check Results**: 205 checks found (41 per account × 5 accounts), all FAILED  
**Field Paths**: ⚠️ Some incorrect (rule 3), others need verification

**Test Status**: PARTIAL - Execution successful but all checks failed, indicating logic issues rather than structural errors

---

## Checklist

- [x] All metadata files have YAML checks
- [x] All YAML checks have metadata files
- [ ] Each check matches its metadata intention ❌ (5 issues found)
- [ ] Field paths are correct ⚠️ (rule 3 incorrect, others need verification)
- [ ] Operators are correct ✅
- [ ] Values are correct ⚠️ (rule 1 needs verification)
- [ ] Discoveries are correct ❌ (rules 2, 3 wrong)
- [x] Test passes without errors ✅
- [ ] Check results are logical ❌ (all failed - logic issues)
- [ ] Metadata review updated ⚠️ (needs update after fixes)

---

## Next Steps

1. **Fix Discovery Methods**: Change rule 2 to use `describe_replication_instances`, rule 3 to use `describe_endpoints`
2. **Fix Field Paths**: Update rule 3 field paths to match emit structure
3. **Enhance Logging Checks**: Add specific logging configuration checks for rules 4 & 5
4. **Verify Value Types**: Check actual API return types and adjust values
5. **Re-test**: Run scanner again to verify all fixes work
6. **Update Metadata Review Report**: Generate final report after fixes





