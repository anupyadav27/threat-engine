# ECS YAML Validation Report

**Date**: 2026-01-08  
**Service**: ecs  
**Total Rules**: 8

---

## Validation Summary

**Total Rules**: 8  
**Validated**: 8  
**Passing**: 0  
**Fixed**: 0  
**Test Status**: PARTIAL (execution successful, but all checks failed - logic issues)

---

## Per-Rule Results

### aws.ecs.resource.task_definition_logging_enabled

**Metadata Intent**: 
- Checks that task definition logging is enabled
- Should verify logConfiguration exists in container definitions

**YAML Checks**: 
- Discovery: `aws.ecs.describe_task_definition` ✅
- Condition: `item.taskDefinition.containerDefinitions[].logConfiguration exists`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Array Syntax**: Uses `containerDefinitions[]` - need to verify if this array iteration syntax is supported in the condition evaluator.
2. **Duplicate Rule**: Identical to `aws.ecs.resource.task_definitions_logging_enabled` - both check the same thing.

**Fixed**: No

**Test**: FAIL - All checks failed (likely array syntax or field path issue)

---

### aws.ecs.resource.task_definitions_logging_enabled

**Metadata Intent**: 
- Checks that task definitions logging is enabled
- Should verify logConfiguration exists in container definitions

**YAML Checks**: 
- Discovery: `aws.ecs.describe_task_definition` ✅
- Condition: `item.taskDefinition.containerDefinitions[].logConfiguration exists`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Duplicate Rule**: Identical to `aws.ecs.resource.task_definition_logging_enabled` - both check the same thing.
2. **Array Syntax**: Same as rule #1 - array iteration syntax needs verification.

**Fixed**: No

**Test**: FAIL - All checks failed

---

### aws.ecs.task_definitions_logging_block_mode.task_definitions_logging_block_mode_configured

**Metadata Intent**: 
- Checks that logging block mode is configured
- Should verify defaultLogDriverMode is set to "block"

**YAML Checks**: 
- Discovery: `aws.ecs.list_account_settings` ✅
- Condition: `item.value equals block` with `when: item.name equals defaultLogDriverMode`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **When Condition**: Uses `when` clause which may not be supported in the condition evaluator. Should use `all` conditions instead.
2. **Filtering Logic**: Need to filter settings where name equals defaultLogDriverMode, then check value. Current structure may not work correctly.

**Fixed**: No

**Test**: FAIL - All checks failed (likely when condition not supported)

---

### aws.ecs.resource.task_sets_assign_public_ip_disabled

**Metadata Intent**: 
- Checks that task sets don't assign public IP
- Should verify assignPublicIp is DISABLED

**YAML Checks**: 
- Discovery: `aws.ecs.describe_services` ✅
- Condition: `item.networkConfiguration.awsvpcConfiguration.assignPublicIp equals DISABLED`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Nested Path Verification**: Need to verify if `networkConfiguration.awsvpcConfiguration.assignPublicIp` path matches emit structure. Emit shows `networkConfiguration: '{{ item.networkConfiguration }}'` which is the whole object, so path should work.
2. **Value Type**: Uses string "DISABLED" - need to verify actual API return type.

**Fixed**: No

**Test**: FAIL - All checks failed (likely field path or value type issue)

---

### aws.ecs.container_instance.no_privileged_containers_configured

**Metadata Intent**: 
- Checks that no privileged containers are configured
- Should verify privileged is false for all containers

**YAML Checks**: 
- Discovery: `aws.ecs.describe_task_definition` ✅
- Condition: `item.taskDefinition.containerDefinitions[].privileged equals false`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Array Syntax**: Uses `containerDefinitions[]` - need to verify array iteration syntax.
2. **Logic Issue**: This checks if privileged equals false, but if ANY container has privileged=true, the check should fail. Current logic may not handle this correctly for arrays.

**Fixed**: No

**Test**: FAIL - All checks failed

---

### aws.ecs.container_instance.container_read_only_root_filesystem_configured

**Metadata Intent**: 
- Checks that containers have read-only root filesystem
- Should verify readonlyRootFilesystem is true

**YAML Checks**: 
- Discovery: `aws.ecs.describe_task_definition` ✅
- Condition: `item.taskDefinition.containerDefinitions[].readonlyRootFilesystem equals true`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Array Syntax**: Same as rule #5 - array iteration syntax needs verification.
2. **Logic Issue**: Should verify ALL containers have readonlyRootFilesystem=true. Current logic may not handle this correctly.

**Fixed**: No

**Test**: FAIL - All checks failed

---

### aws.ecs.container_instance.container_env_no_plaintext_secrets_configured

**Metadata Intent**: 
- Checks that containers don't have plaintext secrets in environment
- Should verify secrets are used (not plaintext env vars)

**YAML Checks**: 
- Discovery: `aws.ecs.describe_task_definition` ✅
- Condition: `item.taskDefinition.containerDefinitions[].secrets exists`

**Match**: ❌ NO

**Issues**:
1. **Insufficient Check**: Only checks if `secrets` exists, but doesn't verify that plaintext environment variables don't contain secrets. Should check that sensitive data is in `secrets` (from Secrets Manager/Parameter Store) rather than in `environment` array.
2. **Array Syntax**: Same array iteration issue.
3. **Logic Reversal**: The check should verify that secrets are NOT in environment variables, but current check only verifies secrets array exists.

**Fixed**: No

**Test**: FAIL - All checks failed

---

### aws.ecs.task_definition_image_source_verification.task_ecs_task_definition_image_source_verification_configured

**Metadata Intent**: 
- Checks that image source verification is configured
- Should verify image source/verification settings

**YAML Checks**: 
- Discovery: `aws.ecs.describe_task_definition` ✅
- Condition: `item.taskDefinition.containerDefinitions[].image exists`

**Match**: ❌ NO

**Issues**:
1. **Insufficient Check**: Only checks if `image` exists, but doesn't verify image source verification is enabled. Image always exists - need to check for image verification settings (e.g., imagePullPolicy, imageDigest, or ECR image scanning settings).
2. **Array Syntax**: Same array iteration issue.
3. **Wrong Validation**: Checking image exists doesn't verify source verification - need to check specific verification configuration.

**Fixed**: No

**Test**: FAIL - All checks failed

---

## Critical Issues Summary

### Issue 1: Duplicate Rules
Rules 1 & 2 are identical - both check `taskDefinition.containerDefinitions[].logConfiguration exists`. Should consolidate into one rule.

### Issue 2: Array Iteration Syntax
Multiple rules use `containerDefinitions[]` syntax. Need to verify:
- If this syntax is supported in condition evaluator
- If it properly iterates over all containers
- If logic handles "all containers must meet condition" vs "any container meets condition"

### Issue 3: When Condition Not Supported
Rule 3 uses `when` clause which may not be supported. Should use `all` conditions with proper filtering.

### Issue 4: Insufficient Validation Logic
- **Rule 7**: Only checks if secrets exist, doesn't verify plaintext secrets aren't in environment
- **Rule 8**: Only checks if image exists, doesn't verify image source verification is enabled

### Issue 5: Field Path Verification
Rule 4 uses nested path - need to verify it matches emit structure correctly.

---

## Recommended Fixes

### Fix 1: Consolidate Duplicate Rules
Remove one of the duplicate logging rules (keep `task_definitions_logging_enabled` as it's more comprehensive name).

### Fix 2: Fix When Condition (Rule 3)
```yaml
- rule_id: aws.ecs.task_definitions_logging_block_mode.task_definitions_logging_block_mode_configured
  for_each: aws.ecs.list_account_settings
  conditions:
    all:
    - var: item.name
      op: equals
      value: defaultLogDriverMode
    - var: item.value
      op: equals
      value: block
```

### Fix 3: Verify Array Syntax
Test if `containerDefinitions[]` syntax works. If not, may need to:
- Use different syntax
- Check each container individually
- Use all/any logic properly

### Fix 4: Enhance Rule 7
Should check that sensitive data is NOT in `environment` array, or verify that `secrets` array is used instead of plaintext env vars.

### Fix 5: Enhance Rule 8
Should check for image verification settings (e.g., ECR image scanning, imageDigest, or specific verification configuration) rather than just image existence.

---

## Test Results

**Execution**: ✅ PASS - No errors  
**Warnings**: None  
**Check Results**: 30 checks found (6 per account × 5 accounts), all FAILED  
**Field Paths**: ⚠️ Need verification (array syntax, nested paths)

**Test Status**: PARTIAL - Execution successful but all checks failed, indicating logic issues rather than structural errors

---

## Checklist

- [x] All metadata files have YAML checks
- [x] All YAML checks have metadata files
- [ ] Each check matches its metadata intention ❌ (8 issues found)
- [ ] Field paths are correct ⚠️ (array syntax needs verification)
- [ ] Operators are correct ✅
- [ ] Values are correct ⚠️ (some need verification)
- [ ] Discoveries are correct ✅
- [x] Test passes without errors ✅
- [ ] Check results are logical ❌ (all failed - logic issues)
- [ ] Metadata review updated ⚠️ (needs update after fixes)

---

## Next Steps

1. **Consolidate Duplicates**: Remove duplicate logging rule
2. **Fix When Condition**: Convert rule 3 to use `all` conditions
3. **Verify Array Syntax**: Test and fix array iteration syntax for containerDefinitions
4. **Enhance Validation Logic**: Fix rules 7 & 8 to check actual requirements
5. **Verify Field Paths**: Test nested paths and array access
6. **Re-test**: Run scanner again to verify all fixes work
7. **Update Metadata Review Report**: Generate final report after fixes





