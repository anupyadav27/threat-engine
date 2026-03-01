# CODEBUILD YAML Validation Report

**Date**: 2026-01-08  
**Service**: codebuild  
**Total Rules**: 8

---

## Validation Summary

**Total Rules**: 8  
**Validated**: 8  
**Passing**: 0  
**Fixed**: 0  
**Test Status**: FAIL (parameter validation errors, all checks failed)

---

## Per-Rule Results

### aws.codebuild.group.codebuild_export_encrypted

**Metadata Intent**: 
- Checks that codebuild export is encrypted
- Should verify encryptionKey exists and is configured

**YAML Checks**: 
- Discovery: `aws.codebuild.batch_get_projects` (requires `names` parameter)
- Condition: `item.encryptionKey exists` with value `'true'`

**Match**: ❌ NO

**Issues**:
1. **Missing Discovery Chain**: `batch_get_projects` requires `names` parameter (list of project names), but discovery has no `for_each` or `params`. Should chain from `list_projects` to get project names first.
2. **Wrong Operator/Value**: Uses `exists` with value `'true'` - `exists` operator should use `null` as value. Should check `item.encryptionKey exists` (null) OR `item.encryptionKey not_equals null`.
3. **Missing items_for**: The API returns `projects[]` array, but emit doesn't use `items_for` to iterate. Should use `items_for: '{{ response.projects }}'`.

**Fixed**: No

**Test**: FAIL - Parameter validation error: Missing required parameter "names"

---

### aws.codebuild.project.codebuild_older_90_days_configured

**Metadata Intent**: 
- Checks that projects older than 90 days are configured
- Should verify project age and last modification

**YAML Checks**: 
- Discovery: `aws.codebuild.batch_get_projects`
- Conditions:
  - `item.projects.created less_than "90 days ago"`
  - `item.projects.lastModified greater_than "90 days ago"`

**Match**: ❌ NO

**Issues**:
1. **Missing Discovery Chain**: Same as rule #1 - needs `list_projects` first.
2. **Wrong Field Paths**: Conditions check `item.projects.created` and `item.projects.lastModified`, but emit shows fields directly: `item.created` and `item.lastModified` (no `projects` wrapper).
3. **Invalid Value Format**: Uses `"90 days ago"` as value - not a valid format for date comparison. Should use actual date calculation or timestamp.
4. **Missing items_for**: Same as rule #1.

**Fixed**: No

**Test**: FAIL - Parameter validation error + field path errors

---

### aws.codebuild.projectartifact.encryption_enabled

**Metadata Intent**: 
- Checks that project artifacts have encryption enabled
- Should verify artifacts.encryptionKey exists

**YAML Checks**: 
- Discovery: `aws.codebuild.batch_get_projects`
- Condition: `item.artifacts.encryptionKey exists` with value `'true'`

**Match**: ❌ NO

**Issues**:
1. **Missing Discovery Chain**: Same as rule #1.
2. **Wrong Operator/Value**: Same as rule #1 - `exists` with `'true'` is wrong.
3. **Field Path Verification Needed**: Need to verify if `artifacts` is nested object or array. If array, may need different path.
4. **Missing items_for**: Same as rule #1.

**Fixed**: No

**Test**: FAIL - Parameter validation error

---

### aws.codebuild.resource.codebuild_project_envvar_awscred_configured

**Metadata Intent**: 
- Checks that project environment variables and AWS credentials are configured
- Should verify environment and serviceRole exist

**YAML Checks**: 
- Discovery: `aws.codebuild.batch_get_projects`
- Conditions:
  - `item.environment exists`
  - `item.serviceRole exists`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Missing Discovery Chain**: Same as rule #1 - needs `list_projects` first.
2. **Field Paths**: Appear correct based on emit structure (`item.environment`, `item.serviceRole`).
3. **Missing items_for**: Same as rule #1.

**Fixed**: No

**Test**: FAIL - Parameter validation error

---

### aws.codebuild.resource.codebuild_project_s3_logs_encrypted

**Metadata Intent**: 
- Checks that S3 logs are encrypted
- Should verify logsConfig.s3Logs.encryptionDisabled is false

**YAML Checks**: 
- Discovery: `aws.codebuild.batch_get_projects`
- Condition: `item.logsConfig.s3Logs.encryptionDisabled equals 'false'`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Missing Discovery Chain**: Same as rule #1.
2. **Field Path Verification Needed**: Need to verify if `logsConfig.s3Logs.encryptionDisabled` path is correct. May need to check if logsConfig exists first.
3. **Value Type**: Uses string `'false'` - should verify if API returns boolean `false` or string `'false'`.
4. **Missing items_for**: Same as rule #1.

**Fixed**: No

**Test**: FAIL - Parameter validation error

---

### aws.codebuild.resource.codebuild_project_source_repo_url_configured

**Metadata Intent**: 
- Checks that source repository URL is configured
- Should verify source exists

**YAML Checks**: 
- Discovery: `aws.codebuild.batch_get_projects`
- Condition: `item.source exists`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Missing Discovery Chain**: Same as rule #1.
2. **Field Path**: Appears correct based on emit structure (`item.source`).
3. **Missing items_for**: Same as rule #1.

**Fixed**: No

**Test**: FAIL - Parameter validation error

---

### aws.codebuild.resource.project_logging_enabled

**Metadata Intent**: 
- Checks that project logging is enabled
- Should verify logsConfig exists

**YAML Checks**: 
- Discovery: `aws.codebuild.batch_get_projects`
- Condition: `item.logsConfig exists`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Missing Discovery Chain**: Same as rule #1.
2. **Field Path**: Appears correct based on emit structure (`item.logsConfig`).
3. **Missing items_for**: Same as rule #1.

**Fixed**: No

**Test**: FAIL - Parameter validation error

---

### aws.codebuild.user.codebuild_controlled_buildspec_configured

**Metadata Intent**: 
- Checks that buildspec is controlled/configured
- Should verify source.buildspec exists

**YAML Checks**: 
- Discovery: `aws.codebuild.batch_get_projects`
- Condition: `item.source.buildspec exists`

**Match**: ⚠️ PARTIAL

**Issues**:
1. **Missing Discovery Chain**: Same as rule #1.
2. **Field Path Verification Needed**: Need to verify if `source.buildspec` path is correct - `source` may be an object with nested `buildspec` field.
3. **Missing items_for**: Same as rule #1.

**Fixed**: No

**Test**: FAIL - Parameter validation error

---

## Critical Issues Summary

### Issue 1: Missing Discovery Chain
`batch_get_projects` requires `names` parameter (list of project names), but discovery has no way to get these names. Need to:
1. Add independent discovery: `list_projects` (returns project names)
2. Chain `batch_get_projects` with `for_each: aws.codebuild.list_projects`
3. Add `params: { names: ['{{ item }}'] }` or similar

**Pattern Needed**:
```yaml
# Independent discovery
- discovery_id: aws.codebuild.list_projects
  calls:
    - action: list_projects
      save_as: response
  emit:
    items_for: '{{ response.projects }}'
    as: item
    item:
      name: '{{ item }}'

# Dependent discovery
- discovery_id: aws.codebuild.batch_get_projects
  for_each: aws.codebuild.list_projects
  calls:
    - action: batch_get_projects
      params:
        names: ['{{ item.name }}']
      on_error: continue
  emit:
    items_for: '{{ response.projects }}'
    as: item
    item:
      name: '{{ item.name }}'
      encryptionKey: '{{ item.encryptionKey }}'
      # ... other fields
```

### Issue 2: Missing items_for
The emit structure doesn't use `items_for` to iterate over the `projects[]` array. All discoveries should have:
```yaml
emit:
  items_for: '{{ response.projects }}'
  as: item
  item:
    # fields here
```

### Issue 3: Wrong Operator/Value Combinations
- Rule 1 & 3: `exists` with value `'true'` - should be `exists` with `null` OR check if field is not null
- Rule 2: Date comparison with `"90 days ago"` - invalid format, needs proper date calculation

### Issue 4: Field Path Mismatches
- Rule 2: Uses `item.projects.created` but should be `item.created` (no `projects` wrapper after items_for)

---

## Recommended Fixes

### Fix 1: Add Discovery Chain
1. Create `list_projects` discovery (independent)
2. Update `batch_get_projects` to be dependent with `for_each` and `params`
3. Add `items_for` to both discoveries

### Fix 2: Fix Operator/Value Issues
- Rule 1 & 3: Change `exists` value from `'true'` to `null`
- Rule 2: Fix date comparison - use proper date calculation or remove if not critical

### Fix 3: Fix Field Paths
- Rule 2: Remove `projects.` wrapper from field paths
- Verify all nested paths (artifacts, logsConfig, source) match actual structure

### Fix 4: Add items_for
Add `items_for: '{{ response.projects }}'` to all discoveries that return lists

---

## Test Results

**Execution**: ⚠️ PARTIAL - Parameter validation errors  
**Warnings**: Multiple "Missing required parameter: names" errors  
**Check Results**: 40 checks found (8 per account × 5 accounts), all FAILED  
**Field Paths**: ❌ Some incorrect (rule 2), others need verification

**Errors**:
- `batch_get_projects`: Missing required parameter "names" (5 occurrences, one per account)

**Test Status**: FAIL - All 40 checks failed due to discovery errors

---

## Checklist

- [x] All metadata files have YAML checks
- [x] All YAML checks have metadata files
- [ ] Each check matches its metadata intention ❌ (8 issues found)
- [ ] Field paths are correct ⚠️ (some incorrect, some need verification)
- [ ] Operators are correct ❌ (2 rules have wrong operator/value)
- [ ] Values are correct ❌ (date format invalid, wrong exists values)
- [ ] Discoveries are correct ❌ (missing chain, missing items_for)
- [ ] Test passes without errors ❌ (parameter validation errors)
- [ ] Check results are logical ❌ (all failed due to errors)
- [ ] Metadata review updated ⚠️ (needs update after fixes)

---

## Next Steps

1. **Fix Discovery Chain**: Add `list_projects` discovery, chain `batch_get_projects` with params
2. **Add items_for**: Add `items_for` to all discoveries
3. **Fix Operators**: Fix `exists` operator usage (rules 1, 3)
4. **Fix Date Comparison**: Fix or remove date comparison in rule 2
5. **Fix Field Paths**: Remove `projects.` wrapper from rule 2
6. **Re-test**: Run scanner again to verify all fixes work
7. **Update Metadata Review Report**: Generate final report after fixes





