# Agent 2 Fix Summary: Filter UPDATE/CREATE/DELETE Functions

## Problem

Agent 2 was selecting **UPDATE/CREATE/DELETE** functions for discovery, which:
- ❌ Modify resources instead of discovering them
- ❌ Cause runtime errors (e.g., `UserPoolId must not be null`)
- ❌ Are not suitable for compliance checking

**Example:**
- Field needed: `LastModifiedDate`
- Wrong selection: `update_managed_login_branding()` (UPDATE operation)
- Correct selection: `list_user_pools()` (LIST operation)

## Solution

### 1. Added `is_discovery_function()` Filter

Filters out UPDATE/CREATE/DELETE operations:
```python
def is_discovery_function(op: Dict) -> bool:
    """Check if function is suitable for discovery"""
    # Exclude: update_, create_, delete_, set_, put_, modify_, etc.
    # Include: list_, get_, describe_, batch_get_, scan_, query_
```

**Excluded prefixes:**
- `update_`, `create_`, `delete_`, `remove_`, `set_`
- `put_`, `modify_`, `change_`, `add_`, `attach_`, `detach_`
- `enable_`, `disable_`, `start_`, `stop_`, `terminate_`
- `cancel_`, `revoke_`, `grant_`, `deny_`

**Included prefixes:**
- `list_`, `get_`, `describe_`, `batch_get_`
- `scan_`, `query_`, `search_`, `find_`, `fetch_`, `retrieve_`

### 2. Updated `find_function_for_fields()`

**Before:**
```python
# Checked ALL operations (including UPDATE/CREATE/DELETE)
for op in service_data.get('independent', []) + service_data.get('dependent', []):
    # ... matching logic ...
```

**After:**
```python
# Filter to only discovery functions
discovery_operations = [op for op in all_operations if is_discovery_function(op)]

# Prioritize independent functions
independent_ops = [op for op in discovery_operations if is_effectively_independent(op)]
dependent_ops = [op for op in discovery_operations if not is_effectively_independent(op)]

# Search independent first, then dependent
search_order = independent_ops + dependent_ops
```

### 3. Handle Optional Parameters

Functions with only optional params (like `MaxResults`, `NextToken`) are treated as effectively independent:
```python
def is_effectively_independent(op):
    required = op.get('required_params', [])
    if not required:
        return True
    # MaxResults, NextToken are optional in practice
    optional_only_params = ['maxresults', 'nexttoken', 'paginationtoken']
    return all(any(opt in p for opt in optional_only_params) for p in required_lower)
```

## Result

**Before:**
- Selected: `update_managed_login_branding()` ❌
- Error: `UserPoolId must not be null`

**After:**
- Selected: `list_user_pools()` ✅
- Works: Lists all UserPools with `LastModifiedDate`

## Testing

All test cases pass:
- ✅ `list_user_pools` → Discovery function
- ✅ `get_user_pool` → Discovery function
- ✅ `describe_user_pool` → Discovery function
- ❌ `update_managed_login_branding` → Excluded
- ❌ `create_user_pool` → Excluded
- ❌ `delete_user_pool` → Excluded
- ❌ `set_ui_customization` → Excluded

## Impact

- **Prevents wrong function selection** for all future rules
- **Reduces runtime errors** from UPDATE/CREATE/DELETE functions
- **Improves discovery accuracy** by using appropriate functions
- **Maintains backward compatibility** (only filters, doesn't change matching logic)

## Next Steps

1. Re-run Agent 2 on existing requirements to fix current issues
2. Re-run Agent 3 and Agent 4 to regenerate YAMLs
3. Test with compliance engine to verify fixes

