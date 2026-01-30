# Function Selection Analysis: Cognito Example

## The Problem

**Rule:** `aws.cognito.userpool.access_keys_rotated_90_days_or_less_when_present`  
**Field Needed:** `LastModifiedDate`  
**Current Selection:** `update_managed_login_branding()` ❌ (WRONG!)

## Why Current Selection is Wrong

1. **Function Type:** `update_managed_login_branding` is an **UPDATE** operation
2. **Purpose:** UPDATE operations modify resources, not discover them
3. **Error:** `UserPoolId must not be null` - UPDATE needs parameters to modify
4. **Suitability:** Cannot be used for discovery (we want to LIST/GET resources)

## What Should Be Selected Instead?

### Option 1: Two-Step Discovery (RECOMMENDED)

**Step 1: Independent Discovery**
```yaml
discovery_id: aws.cognito.list_user_pools
calls:
  - action: list_user_pools
    params:
      MaxResults: 60
emit:
  item:
    id: '{{ resource.Id }}'
    name: '{{ resource.Name }}'
```

**Step 2: Dependent Discovery**
```yaml
discovery_id: aws.cognito.describe_user_pool
calls:
  - action: describe_user_pool
    params:
      UserPoolId: '{{ item.id }}'  # From list_user_pools
for_each: aws.cognito.list_user_pools
emit:
  item:
    last_modified_date: '{{ describe_user_pool_response.UserPool.LastModifiedDate }}'
```

**Why This Works:**
- `list_user_pools` lists all UserPools (independent, no params needed)
- `describe_user_pool` gets full details including `LastModifiedDate` (dependent, needs UserPoolId)
- This is the correct pattern for discovery

### Option 2: Check if list_user_pools Has LastModifiedDate

If `list_user_pools` response includes `LastModifiedDate` directly, we can use it alone:
```yaml
discovery_id: aws.cognito.list_user_pools
calls:
  - action: list_user_pools
emit:
  item:
    last_modified_date: '{{ resource.LastModifiedDate }}'
```

**Check:** Need to verify if `list_user_pools` response has `LastModifiedDate` in the summary.

## Should AI Suggest Different Field?

### Current AI Selection:
- Field: `LastModifiedDate`
- Function: `update_managed_login_branding` (wrong!)

### The Real Issue:

**Cognito UserPool doesn't have "access keys"!**

The requirement "Access Keys Rotated 90 Days Or Less" doesn't make sense for Cognito UserPool:
- IAM users have access keys ✅
- Cognito UserPools don't have access keys ❌

### What Should We Check Instead?

For Cognito UserPool, we might want to check:
1. **UserPool Last Modified Date** - When was the pool last changed?
2. **UserPool Client Secret Rotation** - When were client secrets last rotated?
3. **UserPool Creation Date** - How old is the pool?

### Recommendation:

**Option A: Fix the Requirement**
- This rule might not apply to Cognito UserPool
- Should be removed or changed to check something relevant

**Option B: Change Field to Something Relevant**
- If we want to check "rotation" concept:
  - Check UserPool client secrets (if they exist)
  - Check UserPool configuration changes
- If we want to check "age":
  - Check `CreationDate` instead of `LastModifiedDate`

**Option C: Use LastModifiedDate but with Right Function**
- Keep `LastModifiedDate` field
- But use `list_user_pools` → `describe_user_pool` chain
- Check when UserPool was last modified (not access keys)

## Agent 2 Fix Needed

Agent 2 should:

1. **Filter by Function Type:**
   ```python
   # Prefer LIST/GET/DESCRIBE functions
   discovery_functions = [
       op for op in functions
       if op['python_method'].startswith(('list_', 'get_', 'describe_'))
   ]
   ```

2. **Prioritize Independent Functions:**
   ```python
   # For independent discovery, prefer functions with no required_params
   if not required_params:
       independent_functions = [f for f in functions if not f.get('required_params')]
       # Search in independent first
   ```

3. **Use Two-Step When Needed:**
   ```python
   # If no independent function has the field, use LIST → GET pattern
   if no_match:
       # Find LIST function for resource type
       list_func = find_list_function(service_data, resource_type)
       # Find GET/DESCRIBE function that needs list result
       get_func = find_get_function(service_data, field, list_func)
   ```

## Summary

**Current:** `update_managed_login_branding()` ❌  
**Should Be:** `list_user_pools()` → `describe_user_pool()` ✅

**Field:** `LastModifiedDate` is OK, but requirement might be wrong  
**Better:** Check if requirement makes sense for Cognito, or use different field

**Fix:** Agent 2 needs to filter out UPDATE/CREATE/DELETE functions and prefer LIST/GET/DESCRIBE functions.

