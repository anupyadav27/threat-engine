# APPSYNC YAML Validation Report

**Date**: 2026-01-08  
**Service**: appsync  
**Total Rules**: 2

---

## Validation Summary

**Total Rules**: 2  
**Validated**: 2  
**Passing**: 0  
**Fixed**: 0  
**Test Status**: PASS (no execution errors, but no resources found to test)

---

## Per-Rule Results

### aws.appsync.field.level_logging_enabled

**Metadata Intent**: 
- Checks that AWS APPSYNC **field** has comprehensive audit logging enabled
- Scope: `appsync.field.logging`
- Should capture API calls, configuration changes, and administrative actions

**YAML Checks**: 
- Discovery: `aws.appsync.list_graphql_apis` (returns GraphQL APIs, not fields)
- Condition: `item.logConfig exists`
- Checks if logConfig object exists on GraphQL API

**Match**: ❌ NO

**Issues**:
1. **Conceptual Mismatch**: Metadata says it checks "field" level logging, but discovery returns GraphQL APIs, not individual GraphQL fields. The scope `appsync.field.logging` suggests it should check field-level logging, but the implementation checks API-level logging configuration.
2. **Insufficient Check**: Only checks if `logConfig` exists, but doesn't verify that logging is actually enabled. According to AWS AppSync, `logConfig` contains `fieldLogLevel` which can be ALL, ERROR, or NONE. Should check that `fieldLogLevel` is not NONE.
3. **Duplicate Logic**: Identical to `aws.appsync.resource.field_level_logging_enabled` - both check the same thing.

**Fixed**: No

**Test**: PASS (no errors, but no resources to validate against)

---

### aws.appsync.resource.field_level_logging_enabled

**Metadata Intent**: 
- Checks that AWS APPSYNC **resource** has field level logging enabled
- Scope: `appsync.resource.logging`
- Should capture API calls, configuration changes, and administrative actions

**YAML Checks**: 
- Discovery: `aws.appsync.list_graphql_apis` (returns GraphQL APIs)
- Condition: `item.logConfig exists`
- Checks if logConfig object exists on GraphQL API

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Insufficient Check**: Only checks if `logConfig` exists, but doesn't verify that logging is actually enabled. Should check that `logConfig.fieldLogLevel` is not NONE (should be ALL or ERROR).
2. **Duplicate Logic**: Identical to `aws.appsync.field.level_logging_enabled` - both check the same thing. These should be consolidated or differentiated.

**Fixed**: No

**Test**: PASS (no errors, but no resources to validate against)

---

## Critical Issues Summary

### Issue 1: Duplicate Rules
Both rules check the exact same condition (`item.logConfig exists`). They should either:
- Be consolidated into a single rule, OR
- Check different aspects (e.g., one checks API-level, one checks field-level if that's possible)

**Recommendation**: Consolidate into `aws.appsync.resource.field_level_logging_enabled` since it has the more appropriate scope name.

### Issue 2: Insufficient Validation Logic
Current check only verifies `logConfig` exists, but doesn't ensure logging is actually enabled. According to AWS AppSync API:
- `logConfig` is an object with structure: `{ fieldLogLevel: "ALL" | "ERROR" | "NONE", cloudWatchLogsRoleArn: string }`
- Should check: `item.logConfig.fieldLogLevel` is not "NONE" (or equals "ALL" or "ERROR")

**Recommendation**: Update condition to check `item.logConfig.fieldLogLevel` is not "NONE".

### Issue 3: Metadata Scope Mismatch
`aws.appsync.field.level_logging_enabled` metadata says it checks "field" level logging with scope `appsync.field.logging`, but:
- Discovery returns GraphQL APIs, not fields
- Implementation checks API-level `logConfig`

**Recommendation**: Either:
- Update metadata to reflect it checks API-level logging, OR
- If field-level logging is a separate concept, implement proper discovery for fields

---

## Recommended Fixes

### Fix 1: Update YAML to Check fieldLogLevel

```yaml
- rule_id: aws.appsync.resource.field_level_logging_enabled
  for_each: aws.appsync.list_graphql_apis
  conditions:
    var: item.logConfig.fieldLogLevel
    op: not_equals
    value: NONE
```

**OR** if we want to ensure it's explicitly enabled:

```yaml
- rule_id: aws.appsync.resource.field_level_logging_enabled
  for_each: aws.appsync.list_graphql_apis
  conditions:
    var: item.logConfig.fieldLogLevel
    op: in
    value: [ALL, ERROR]
```

### Fix 2: Consolidate Duplicate Rules
Remove `aws.appsync.field.level_logging_enabled` and keep only `aws.appsync.resource.field_level_logging_enabled` since:
- They check the same thing
- The "resource" naming is more accurate (checking API-level config)
- Reduces maintenance burden

### Fix 3: Update Metadata
If keeping both rules, update `aws.appsync.field.level_logging_enabled` metadata to clarify it checks API-level field logging configuration, not individual GraphQL field logging.

---

## Test Results

**Execution**: ✅ PASS - No errors  
**Warnings**: None  
**Check Results**: 0 checks (no AppSync APIs found in test accounts)  
**Field Paths**: Valid - `item.logConfig` exists in emit structure

---

## Checklist

- [x] All metadata files have YAML checks
- [x] All YAML checks have metadata files
- [ ] Each check matches its metadata intention ❌ (2 issues found)
- [x] Field paths are correct
- [ ] Operators are correct ⚠️ (should check fieldLogLevel, not just existence)
- [ ] Values are correct ⚠️ (should check for NONE, not just null)
- [x] Discoveries are correct
- [x] Test passes without errors
- [ ] Check results are logical ⚠️ (can't verify without resources)
- [ ] Metadata review updated ⚠️ (needs update after fixes)

---

## Next Steps

1. **Fix YAML**: Update conditions to check `logConfig.fieldLogLevel` is not NONE
2. **Consolidate Rules**: Remove duplicate rule or differentiate their checks
3. **Update Metadata**: Align metadata with actual implementation
4. **Re-test**: Run scanner again to verify fixes work correctly
5. **Update Metadata Review Report**: Generate final report after fixes





