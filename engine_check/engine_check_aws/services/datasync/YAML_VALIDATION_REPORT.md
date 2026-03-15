# DATASYNC YAML Validation Report

**Date**: 2026-01-08  
**Service**: datasync  
**Total Rules**: 1

---

## Validation Summary

**Total Rules**: 1  
**Validated**: 1  
**Passing**: 0  
**Fixed**: 0  
**Test Status**: FAIL (parameter validation errors, all checks failed)

---

## Per-Rule Results

### aws.datasync.resource.task_logging_enabled

**Metadata Intent**: 
- Checks that DataSync task logging is enabled
- Should verify CloudWatchLogGroupArn exists to confirm logging is configured
- Essential for security monitoring, incident investigation, compliance auditing

**YAML Checks**: 
- Discovery: `aws.datasync.describe_task` (requires TaskArn parameter)
- Condition: `item.CloudWatchLogGroupArn exists`

**Match**: ❌ NO

**Issues**:
1. **Missing Discovery Chain**: `describe_task` requires `TaskArn` parameter, but discovery has no `for_each` or `params`. Should chain from `list_tasks` to get task ARNs first.
2. **Empty Emit Structure**: The emit structure is empty (`item: {}`), so no fields are actually emitted. Need to emit `CloudWatchLogGroupArn` and other relevant fields from the response.
3. **Missing items_for**: If `list_tasks` returns a list, may need `items_for` to iterate properly.

**Fixed**: No

**Test**: FAIL - Parameter validation error: Missing required parameter "TaskArn" (5 occurrences, one per account)

---

## Critical Issues Summary

### Issue 1: Missing Discovery Chain
`describe_task` requires `TaskArn` parameter, but discovery has no way to get task ARNs. Need to:
1. Add independent discovery: `list_tasks` (returns list of task ARNs)
2. Chain `describe_task` with `for_each: aws.datasync.list_tasks`
3. Add `params: { TaskArn: '{{ item.TaskArn }}' }` or similar

**Pattern Needed**:
```yaml
# Independent discovery
- discovery_id: aws.datasync.list_tasks
  calls:
    - action: list_tasks
      save_as: response
  emit:
    items_for: '{{ response.Tasks }}'  # or whatever the response structure is
    as: item
    item:
      TaskArn: '{{ item.TaskArn }}'
      # other fields from list response

# Dependent discovery
- discovery_id: aws.datasync.describe_task
  for_each: aws.datasync.list_tasks
  calls:
    - action: describe_task
      params:
        TaskArn: '{{ item.TaskArn }}'
      on_error: continue
  emit:
    item:
      TaskArn: '{{ item.TaskArn }}'
      CloudWatchLogGroupArn: '{{ response.CloudWatchLogGroupArn }}'
      # other fields from describe response
```

### Issue 2: Empty Emit Structure
The emit structure is completely empty (`item: {}`), which means no fields are emitted. Need to:
- Emit `CloudWatchLogGroupArn` from the response
- Emit other relevant fields if needed

### Issue 3: Field Path Verification
Need to verify the actual response structure from `describe_task` to ensure:
- `CloudWatchLogGroupArn` is the correct field name
- Field path in condition matches emit structure

---

## Recommended Fixes

### Fix 1: Add Discovery Chain
1. Create `list_tasks` discovery (independent) to get task ARNs
2. Update `describe_task` to be dependent with `for_each` and `params`
3. Add proper emit structure with `CloudWatchLogGroupArn` field

### Fix 2: Fix Emit Structure
Add proper emit fields:
```yaml
emit:
  item:
    TaskArn: '{{ item.TaskArn }}'
    CloudWatchLogGroupArn: '{{ response.CloudWatchLogGroupArn }}'
```

### Fix 3: Verify Field Names
Verify the actual API response structure to ensure field names are correct.

---

## Test Results

**Execution**: ⚠️ PARTIAL - Parameter validation errors  
**Warnings**: Multiple "Missing required parameter: TaskArn" errors  
**Check Results**: 5 checks found (1 per account × 5 accounts), all FAILED  
**Field Paths**: ⚠️ Cannot verify - emit structure is empty

**Errors**:
- `describe_task`: Missing required parameter "TaskArn" (5 occurrences, one per account)

**Test Status**: FAIL - All 5 checks failed due to discovery parameter errors

---

## Checklist

- [x] All metadata files have YAML checks
- [x] All YAML checks have metadata files
- [ ] Each check matches its metadata intention ❌ (1 issue found)
- [ ] Field paths are correct ⚠️ (cannot verify - emit empty)
- [ ] Operators are correct ✅
- [ ] Values are correct ✅
- [ ] Discoveries are correct ❌ (missing chain, empty emit)
- [ ] Test passes without errors ❌ (parameter validation errors)
- [ ] Check results are logical ❌ (all failed due to errors)
- [ ] Metadata review updated ⚠️ (needs update after fixes)

---

## Next Steps

1. **Fix Discovery Chain**: Add `list_tasks` discovery, chain `describe_task` with params
2. **Fix Emit Structure**: Add proper emit fields including `CloudWatchLogGroupArn`
3. **Verify Field Names**: Check actual API response to ensure field names match
4. **Re-test**: Run scanner again to verify all fixes work
5. **Update Metadata Review Report**: Generate final report after fixes





