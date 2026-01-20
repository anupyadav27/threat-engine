# Service Restriction & Error Analysis

## Question 1: Is Field Search Restricted to Service?

### Answer: YES ✅

**Agent 2 restricts search to the specific service:**

```python
# agent2_function_validator.py, line 201-231
for service, rules in requirements.items():
    # Map service name to boto3 service name
    boto3_service = get_boto3_service_name(service)  # cognito → cognito-idp
    service_data = boto3_data.get(boto3_service, {})  # Get ONLY cognito-idp data
    
    # Find function that provides these fields
    matching_function = find_function_for_fields(service_data, fields_needed)
    # ↑ Only searches within service_data (cognito-idp functions)
```

**Example:**
- Rule in `cognito` service needs field `"LastModifiedDate"`
- Agent 2:
  1. Maps `cognito` → `cognito-idp` (boto3 service name)
  2. Gets `service_data = boto3_data.get('cognito-idp', {})`
  3. Searches **ONLY** in `cognito-idp` functions
  4. Does **NOT** search in other services (s3, ec2, etc.)

**Why this is correct:**
- Each service has its own boto3 client
- Fields with same name in different services are different resources
- `LastModifiedDate` in cognito ≠ `LastModifiedDate` in s3

---

## Question 2: Why Are We Still Getting Errors?

### Root Cause Analysis

Even though Agent 2 correctly restricts to service and finds functions, errors still occur because:

### Problem 1: Wrong Function Type Selected

**Example Error:**
```
Failed update_managed_login_branding: 
InvalidParameterException: UserPoolId must not be null
```

**What Happened:**
1. Agent 1: Needs field `"LastModifiedDate"`
2. Agent 2: Searches cognito-idp functions
3. Finds: `update_managed_login_branding()` has `LastModifiedDate` in `item_fields`
4. Selects: `update_managed_login_branding()` ✅ (has the field)
5. **BUT:** This is an **UPDATE** function, not a **LIST/GET** function!

**The Problem:**
- `update_managed_login_branding()` is marked as `is_independent: true` (no required_params)
- But it actually **requires** `UserPoolId` parameter (it's an UPDATE operation)
- The function can't be used for discovery because it needs a UserPoolId to update

**Why This Happens:**
- Agent 2 matches based on **field presence**, not **function purpose**
- It doesn't distinguish between:
  - **LIST/GET functions** (good for discovery) ✅
  - **CREATE/UPDATE/DELETE functions** (bad for discovery) ❌

### Problem 2: Template Variables Not Resolved

**Example Error:**
```
template_not_resolved: Template variable not resolving - check for_each linkage
```

**What Happened:**
- Agent 4 generates: `{{ item.api_id }}` or `{{ item.FIELD_NAME }}`
- But parent discovery doesn't emit `api_id` or `FIELD_NAME`
- Template resolution fails at runtime

**Why This Happens:**
- Parameter matching logic (Agent 4) still has issues
- Falls back to wrong field names when matching fails
- Pattern matching doesn't cover all cases

### Problem 3: API Validation Errors

**Example Errors:**
```
ValidationException: Value '{{ item.api_id }}' at 'workGroup' failed to satisfy constraint
InvalidParameterException: UserPoolId must not be null
```

**What Happened:**
- Function selected has wrong parameter requirements
- Or parameter value type is wrong (string vs list, etc.)

**Why This Happens:**
- Agent 2 doesn't validate function **suitability** for discovery
- Agent 4 doesn't validate parameter **types** match API expectations

### Problem 4: Access Denied / Runtime Errors

**Example Errors:**
```
AccessDeniedException: Insufficient privileges
InvalidTrailNameException: Trail name must start with a letter or number
```

**What Happened:**
- These are runtime errors, not matching errors
- Account doesn't have permissions
- Or invalid data in account

**Why This Happens:**
- Not a matching problem - these are expected in real accounts

---

## Summary: Why Errors Persist

| Error Type | Root Cause | Solution |
|-----------|-----------|----------|
| **Wrong function selected** | Agent 2 matches by field, not function purpose | Filter out CREATE/UPDATE/DELETE functions |
| **Template not resolved** | Parameter matching fails, uses wrong field | Improve Agent 4 matching patterns |
| **API validation errors** | Wrong parameter types/values | Validate parameter types in Agent 4 |
| **Access denied** | Runtime permissions | Expected - not a matching issue |

---

## The Core Issue

**Agent 2's matching logic:**
```python
# Current logic (WRONG):
if "LastModifiedDate" in function.item_fields:
    return function  # ✅ Has the field, but might be wrong function type!
```

**Should be:**
```python
# Better logic:
if "LastModifiedDate" in function.item_fields:
    # Check function purpose
    if function.python_method.startswith(('list_', 'get_', 'describe_')):
        return function  # ✅ Good for discovery
    else:
        continue  # ❌ Skip UPDATE/CREATE/DELETE functions
```

---

## Recommended Fixes

### Fix 1: Filter Function Types in Agent 2
```python
def find_function_for_fields(service_data, required_fields):
    # Only consider LIST/GET/DESCRIBE functions
    discovery_functions = [
        op for op in service_data.get('independent', []) + service_data.get('dependent', [])
        if op['python_method'].startswith(('list_', 'get_', 'describe_', 'batch_get_'))
    ]
    
    # Search only in discovery functions
    for op in discovery_functions:
        # ... matching logic ...
```

### Fix 2: Improve Parameter Matching in Agent 4
- Already added Pattern 5 & 6 (resource type → Name field)
- Need to add more patterns for edge cases

### Fix 3: Validate Function Suitability
- Check if function is actually usable for discovery
- Skip functions that require parameters but are marked independent
- Prefer LIST functions over GET functions when both available

