# BUDGETS YAML Validation Report

**Date**: 2026-01-08  
**Service**: budgets  
**Total Rules**: 4

---

## Validation Summary

**Total Rules**: 4  
**Validated**: 4  
**Passing**: 0  
**Fixed**: 0  
**Test Status**: PARTIAL (execution errors due to missing parameters)

---

## Per-Rule Results

### aws.budgets.budget.alert_destinations_configured

**Metadata Intent**: 
- Checks that alert destinations are configured for budgets
- Should verify subscribers/notification destinations exist

**YAML Checks**: 
- Discovery: `aws.budgets.describe_budget_action` (requires AccountId, BudgetName, ActionId)
- Condition: `item.Actions.Subscribers exists`
- Checks if Subscribers exist

**Match**: ❌ NO

**Issues**:
1. **Missing Discovery Chain**: `describe_budget_action` requires AccountId, BudgetName, and ActionId parameters, but discovery has no `for_each` or `params`. Should chain from `describe_budgets` or `describe_budget_actions_for_budget`.
2. **Wrong Field Path**: Condition checks `item.Actions.Subscribers` but emit shows `item.Subscribers` directly (no `Actions` wrapper).
3. **Wrong Discovery Method**: Should use `describe_budget_actions_for_budget` (lists actions for a budget) instead of `describe_budget_action` (describes single action).

**Fixed**: No

**Test**: FAIL - Parameter validation errors: Missing AccountId, BudgetName, ActionId

---

### aws.budgets.budget.alert_thresholds_configured

**Metadata Intent**: 
- Checks that alert thresholds are configured
- Should verify notification thresholds and types exist

**YAML Checks**: 
- Discovery: `aws.budgets.describe_notifications_for_budget` (requires AccountId, BudgetName)
- Conditions: 
  - `item.Notifications.Threshold exists`
  - `item.Notifications.NotificationType exists`

**Match**: ❌ NO

**Issues**:
1. **Missing Discovery Chain**: `describe_notifications_for_budget` requires AccountId and BudgetName parameters, but discovery has no `for_each` or `params`. Should chain from `describe_budgets`.
2. **Wrong Field Path**: Conditions check `item.Notifications.Threshold` and `item.Notifications.NotificationType`, but emit shows fields directly: `item.Threshold` and `item.NotificationType` (no `Notifications` wrapper).
3. **Missing items_for**: The API returns a list of notifications, but emit doesn't use `items_for` to iterate. Should use `items_for: '{{ response.Notifications }}'` if it's a list.

**Fixed**: No

**Test**: FAIL - Parameter validation errors: Missing AccountId, BudgetName

---

### aws.budgets.budget.budgets_s_defined_for_accounts_or_projects_configured

**Metadata Intent**: 
- Checks that budgets are defined for accounts or projects
- Should verify budgets exist with names and limits

**YAML Checks**: 
- Discovery: `aws.budgets.describe_budget` (requires AccountId, BudgetName)
- Conditions:
  - `item.Budgets.BudgetName exists`
  - `item.Budgets.BudgetLimit exists`

**Match**: ❌ NO

**Issues**:
1. **Wrong Discovery Method**: Should use `describe_budgets` (lists all budgets, only needs AccountId) instead of `describe_budget` (describes single budget, needs AccountId + BudgetName).
2. **Missing Discovery Chain**: If using `describe_budget`, needs `for_each` from `describe_budgets` with params.
3. **Wrong Field Path**: Conditions check `item.Budgets.BudgetName` and `item.Budgets.BudgetLimit`, but emit shows fields directly: `item.BudgetName` and `item.BudgetLimit` (no `Budgets` wrapper).
4. **Missing items_for**: If using `describe_budgets`, the API returns `Budgets` array, so should use `items_for: '{{ response.Budgets }}'`.

**Fixed**: No

**Test**: FAIL - Parameter validation errors: Missing AccountId, BudgetName (but scan found 4 checks, likely from a different discovery)

---

### aws.budgets.budget.modify_permissions_restricted

**Metadata Intent**: 
- Checks that modify permissions are restricted
- Should verify execution role exists and approval model is AUTOMATIC (not requiring manual approval)

**YAML Checks**: 
- Discovery: `aws.budgets.describe_budget_action` (requires AccountId, BudgetName, ActionId)
- Conditions:
  - `item.Actions.ExecutionRoleArn exists`
  - `item.Actions.ApprovalModel equals AUTOMATIC`

**Match**: ❌ NO

**Issues**:
1. **Missing Discovery Chain**: Same as rule #1 - `describe_budget_action` requires parameters but discovery has no `for_each` or `params`.
2. **Wrong Field Path**: Conditions check `item.Actions.ExecutionRoleArn` and `item.Actions.ApprovalModel`, but emit shows fields directly: `item.ExecutionRoleArn` and `item.ApprovalModel` (no `Actions` wrapper).
3. **Wrong Discovery Method**: Should use `describe_budget_actions_for_budget` to list actions, then optionally `describe_budget_action` for details.

**Fixed**: No

**Test**: FAIL - Parameter validation errors: Missing AccountId, BudgetName, ActionId

---

## Critical Issues Summary

### Issue 1: Missing Discovery Chains
All discoveries that require parameters (`describe_budget`, `describe_budget_action`, `describe_notifications_for_budget`) are missing:
- `for_each` to chain from parent discovery
- `params` to pass required parameters (AccountId, BudgetName, ActionId)

**Pattern Needed**:
```yaml
# Independent discovery
- discovery_id: aws.budgets.describe_budgets
  calls:
    - action: describe_budgets
      save_as: response
  emit:
    items_for: '{{ response.Budgets }}'
    as: item
    item:
      BudgetName: '{{ item.BudgetName }}'
      AccountId: '{{ item.AccountId }}'  # or get from context

# Dependent discovery
- discovery_id: aws.budgets.describe_notifications_for_budget
  for_each: aws.budgets.describe_budgets
  calls:
    - action: describe_notifications_for_budget
      params:
        AccountId: '{{ item.AccountId }}'
        BudgetName: '{{ item.BudgetName }}'
      on_error: continue
  emit:
    items_for: '{{ response.Notifications }}'
    as: item
    item:
      Threshold: '{{ item.Threshold }}'
      NotificationType: '{{ item.NotificationType }}'
```

### Issue 2: Field Path Mismatches
All conditions use wrong field paths:
- ❌ `item.Actions.Subscribers` → ✅ `item.Subscribers`
- ❌ `item.Notifications.Threshold` → ✅ `item.Threshold`
- ❌ `item.Budgets.BudgetName` → ✅ `item.BudgetName`

The emit structure shows fields directly, not wrapped in parent objects.

### Issue 3: Wrong Discovery Methods
- `describe_budget_action` (singular) requires ActionId - should use `describe_budget_actions_for_budget` (plural) to list actions first
- `describe_budget` (singular) requires BudgetName - should use `describe_budgets` (plural) to list budgets first

### Issue 4: Missing items_for for List Responses
APIs that return lists (`describe_budgets` returns `Budgets[]`, `describe_notifications_for_budget` returns `Notifications[]`) need `items_for` in emit to iterate properly.

---

## Recommended Fixes

### Fix 1: Add Independent Discovery for Budgets
```yaml
- discovery_id: aws.budgets.describe_budgets
  calls:
    - action: describe_budgets
      save_as: response
  emit:
    items_for: '{{ response.Budgets }}'
    as: item
    item:
      BudgetName: '{{ item.BudgetName }}'
      AccountId: '{{ item.AccountId }}'  # May need to get from context
```

### Fix 2: Fix Dependent Discoveries
Update all dependent discoveries to:
- Add `for_each: aws.budgets.describe_budgets`
- Add `params` with AccountId and BudgetName
- Add `on_error: continue` for optional resources
- Use correct field paths in emit

### Fix 3: Fix Field Paths in Conditions
Update all conditions to match emit structure:
- Remove `Actions.`, `Notifications.`, `Budgets.` wrappers
- Use direct field names as shown in emit

### Fix 4: Use Correct Discovery Methods
- For listing actions: Use `describe_budget_actions_for_budget` instead of `describe_budget_action`
- For listing budgets: Use `describe_budgets` instead of `describe_budget`

---

## Test Results

**Execution**: ⚠️ PARTIAL - Parameter validation errors for 3 discoveries  
**Warnings**: Multiple "Missing required parameter" errors  
**Check Results**: 4 checks found (likely from `describe_budgets` working)  
**Field Paths**: ❌ Incorrect - don't match emit structure

**Errors**:
- `describe_budget_action`: Missing AccountId, BudgetName, ActionId
- `describe_notifications_for_budget`: Missing AccountId, BudgetName  
- `describe_budget`: Missing AccountId, BudgetName

---

## Checklist

- [x] All metadata files have YAML checks
- [x] All YAML checks have metadata files
- [ ] Each check matches its metadata intention ❌ (4 issues found)
- [ ] Field paths are correct ❌ (all 4 rules have wrong paths)
- [ ] Operators are correct ✅
- [ ] Values are correct ✅
- [ ] Discoveries are correct ❌ (missing chains, wrong methods)
- [ ] Test passes without errors ❌ (parameter validation errors)
- [ ] Check results are logical ⚠️ (can't fully verify due to errors)
- [ ] Metadata review updated ⚠️ (needs update after fixes)

---

## Next Steps

1. **Fix Discovery Chains**: Add independent `describe_budgets` discovery, chain dependent discoveries
2. **Fix Field Paths**: Update all conditions to match emit structure
3. **Fix Discovery Methods**: Use list methods (`describe_budgets`, `describe_budget_actions_for_budget`) instead of singular
4. **Add items_for**: Use `items_for` for list responses
5. **Re-test**: Run scanner again to verify all fixes work
6. **Update Metadata Review Report**: Generate final report after fixes





