# Agentic AI Implementation - Failure Analysis

**Date:** 2025-12-20  
**Status:** Critical Failures Identified

## Executive Summary

The agentic AI rule generator has **3 critical failure points** that prevent discoveries from executing:

1. **Template Resolution Failure** - Templates passed as literal strings to boto3
2. **Invalid Action Names** - Non-existent boto3 methods generated
3. **Incorrect Field References** - Wrong field names in parameter mappings

## Critical Failures Identified

### Failure #1: Template Resolution Not Working

**Evidence from S3 Scan Log:**
```
Invalid bucket name "{{ item.name }}": Bucket name must match the regex
```

**Root Cause:**
The engine's template resolution is failing. Templates like `'{{ item.name }}'` are being passed as **literal strings** to boto3 instead of being resolved to actual values.

**Location in Code:**
- `service_scanner.py` line 572: For non-`for_each` calls, `params` are passed directly without resolution
- `service_scanner.py` line 495-498: `for_each` handling tries to extract from `saved_data` but should use `discovery_results`

**Generated YAML (S3):**
```yaml
- discovery_id: aws.s3.get_bucket_encryption
  calls:
  - action: get_bucket_encryption
    params:
      Bucket: '{{ item.name }}'  # ❌ This is passed as literal string!
  for_each: aws.s3.list_buckets
```

**What Should Happen:**
1. `list_buckets` executes first and emits items with `name: '{{ resource.Name }}'`
2. `get_bucket_encryption` should iterate over those items
3. Template `'{{ item.name }}'` should resolve to actual bucket name (e.g., "my-bucket")
4. Resolved value passed to boto3: `Bucket="my-bucket"`

**What Actually Happens:**
1. Template string `'{{ item.name }}'` is passed directly to boto3
2. boto3 validation fails: "Invalid bucket name '{{ item.name }}'"

### Failure #2: Invalid Action Names

**Evidence from S3 Scan Log:**
```
'S3' object has no attribute 'get_bucket_abac'
```

**Root Cause:**
The generator created an action `get_bucket_abac` that **does not exist** in boto3 S3 client.

**Generated YAML (S3):**
```yaml
- discovery_id: aws.s3.get_bucket_abac
  calls:
  - action: get_bucket_abac  # ❌ This method doesn't exist!
```

**Valid boto3 S3 Methods:**
- `get_bucket_acl` ✅
- `get_bucket_cors` ✅
- `get_bucket_encryption` ✅
- `get_bucket_abac` ❌ **DOES NOT EXIST**

**What Should Happen:**
- Generator should validate action names against actual boto3 client methods
- Should use operation registry to get correct method names
- Should skip or map non-existent operations

### Failure #3: Incorrect Field References

**Evidence:**
- S3 uses `item.name` which is correct (matches emit field)
- But some services may use wrong field names
- Parameter field names must exactly match emit field names

**Generated YAML (S3):**
```yaml
- discovery_id: aws.s3.list_buckets
  emit:
    item:
      name: '{{ resource.Name }}'  # ✅ Correct field name
      
- discovery_id: aws.s3.get_bucket_encryption
  params:
    Bucket: '{{ item.name }}'  # ✅ Matches emit field
```

**But in ACM:**
```yaml
- discovery_id: aws.acm.list_certificates
  emit:
    item:
      certificate_arn: '{{ resource.CertificateArn }}'  # ✅ Correct
      
- discovery_id: aws.acm.describe_certificate
  params:
    CertificateArn: '{{ item.certificate_arn }}'  # ✅ Matches emit field
```

**Issue:**
Field names are correct, but template resolution is failing, so it doesn't matter.

### Failure #4: `for_each` Discovery Lookup Issue

**Evidence:**
All dependent discoveries fail because parent discovery results aren't being found.

**Root Cause Analysis:**
In `service_scanner.py` line 495-498:
```python
if for_each:
    items_ref = for_each.replace('{{ ', '').replace(' }}', '')
    items = extract_value(saved_data, items_ref)  # ❌ Wrong!
```

**Problem:**
- `for_each` contains discovery_id like `"aws.s3.list_buckets"`
- Code tries to extract from `saved_data` using this as a key
- But discovery results are stored in `discovery_results` dictionary, not `saved_data`
- `saved_data` contains raw API responses, not processed discovery items

**What Should Happen:**
```python
if for_each:
    # for_each is a discovery_id like "aws.s3.list_buckets"
    parent_discovery_id = for_each
    items = discovery_results.get(parent_discovery_id, [])  # ✅ Correct
```

**Current Code Flow:**
1. `list_buckets` executes → saves response to `saved_data['response']`
2. Emit processes response → saves items to `discovery_results['aws.s3.list_buckets']`
3. `get_bucket_encryption` tries to find items in `saved_data['aws.s3.list_buckets']` ❌
4. Items not found → empty list → no iterations → discovery appears "not executed"

## Detailed Failure Breakdown

### ACM Service Failures

**All 5 discoveries failed:**
1. `aws.acm.list_certificates` - Root discovery, should execute first
2. `aws.acm.describe_certificate` - Depends on list_certificates
3. `aws.acm.get_certificate` - Depends on list_certificates
4. `aws.acm.list_tags_for_certificate` - Depends on list_certificates
5. `aws.acm.get_account_configuration` - Standalone, should execute

**Why Root Discovery Fails:**
- Even root discoveries (no `for_each`) are failing
- Suggests YAML structure or action name issues
- Or template resolution failing even for simple calls

### S3 Service Failures

**All 12 discoveries failed:**
1. `aws.s3.list_buckets` - Root discovery ❌
2. `aws.s3.get_bucket_abac` - Invalid action name ❌
3. `aws.s3.get_bucket_encryption` - Template resolution ❌
4. `aws.s3.get_bucket_inventory_configuration` - Template resolution ❌
5. `aws.s3.get_bucket_logging` - Template resolution ❌
6. `aws.s3.get_bucket_notification` - Template resolution ❌
7. `aws.s3.get_bucket_policy` - Template resolution ❌
8. `aws.s3.get_bucket_replication` - Template resolution ❌
9. `aws.s3.get_bucket_website` - Template resolution ❌
10. `aws.s3.list_objects_v2` - Template resolution ❌
11. `aws.s3.get_object` - Template resolution ❌
12. `aws.s3.list_bucket_intelligent_tiering_configurations` - Template resolution ❌

## Why IAM Works Better

**IAM shows 54% check pass rate**, suggesting:
1. IAM rules may be manually created (not generated)
2. IAM has different structure that works
3. IAM discoveries may be executing correctly

**IAM YAML Structure:**
```yaml
- discovery_id: aws.iam.get_account_authorization_details
  calls:
  - action: get_account_authorization_details
    save_as: response
  emit:
    items_for: '{{ response.UserDetailList }}'
    as: resource
    item:
      user_name: '{{ resource.UserName }}'
```

**Key Differences:**
- IAM uses `items_for` correctly
- Field mappings appear correct
- No invalid action names observed
- May not have `for_each` dependencies that fail

## Root Cause Summary

### Primary Issues

1. **Template Resolution Broken**
   - Templates not resolved before passing to boto3
   - Affects all parameterized calls
   - Critical for dependent discoveries

2. **for_each Lookup Wrong**
   - Looks in `saved_data` instead of `discovery_results`
   - Parent discovery results not found
   - Dependent discoveries can't execute

3. **No Action Name Validation**
   - Generator creates non-existent boto3 methods
   - No validation against actual client methods
   - Causes AttributeError at runtime

4. **Missing Error Handling**
   - Failures are logged but execution continues
   - No clear indication of why discoveries fail
   - Hard to debug without detailed logs

## Fixes Required

### Fix #1: Correct Template Resolution (P0)

**File:** `aws_compliance_python_engine/engine/service_scanner.py`

**Current (Line 572):**
```python
response = _retry_call(getattr(call_client, action), **params)
```

**Should Be:**
```python
# Resolve templates in params even for non-for_each calls
resolved_params = resolve_params_recursive(params, saved_data)
response = _retry_call(getattr(call_client, action), **resolved_params)
```

### Fix #2: Correct for_each Lookup (P0)

**File:** `aws_compliance_python_engine/engine/service_scanner.py`

**Current (Line 495-498):**
```python
if for_each:
    items_ref = for_each.replace('{{ ', '').replace(' }}', '')
    items = extract_value(saved_data, items_ref)
```

**Should Be:**
```python
if for_each:
    # for_each is a discovery_id, look in discovery_results
    parent_discovery_id = for_each
    items = discovery_results.get(parent_discovery_id, [])
```

### Fix #3: Validate Action Names (P1)

**File:** `tools/generate_rules.py`

**Add:**
```python
def validate_boto3_action(service_name: str, action: str) -> bool:
    """Validate action name exists in boto3 client."""
    try:
        import boto3
        client = boto3.client(service_name)
        return hasattr(client, action)
    except:
        return False
```

**Use in generation:**
```python
if not validate_boto3_action(service_name, action):
    logger.warning(f"Skipping invalid action: {action} for {service_name}")
    continue
```

### Fix #4: Verify Field Mappings (P1)

**File:** `tools/generate_rules.py`

**Add validation:**
```python
def verify_parameter_fields(discovery, parent_discovery):
    """Verify parameter fields exist in parent emit."""
    params = discovery.get('calls', [{}])[0].get('params', {})
    parent_emit = parent_discovery.get('emit', {}).get('item', {})
    
    for param_name, param_template in params.items():
        # Extract field from template: {{ item.field_name }}
        field_match = re.search(r'\{\{\s*item\.(\w+)\s*\}\}', param_template)
        if field_match:
            field_name = field_match.group(1)
            if field_name not in parent_emit:
                raise ValueError(
                    f"Parameter {param_name} references field '{field_name}' "
                    f"not found in parent discovery emit"
                )
```

## Testing After Fixes

1. **Test Template Resolution:**
   - Verify templates resolve to actual values
   - Check boto3 receives resolved parameters
   - Validate no literal template strings in API calls

2. **Test for_each Lookup:**
   - Verify parent discovery results are found
   - Check dependent discoveries iterate correctly
   - Validate all items processed

3. **Test Action Names:**
   - Verify all actions exist in boto3
   - Check no AttributeError exceptions
   - Validate method calls succeed

4. **Test Field Mappings:**
   - Verify parameter fields match emit fields
   - Check field names are correct
   - Validate parameter resolution works

## Success Criteria

After fixes:
- ✅ **Discovery Execution Rate:** >90% (currently 0%)
- ✅ **Template Resolution:** 100% of templates resolved
- ✅ **Action Validation:** 100% valid action names
- ✅ **for_each Lookup:** 100% parent discoveries found
- ✅ **Check Pass Rate:** >50% (accounting for legitimate failures)

## Priority Order

1. **P0 - Critical (Fix Immediately):**
   - Fix template resolution
   - Fix for_each lookup

2. **P1 - High (Fix Soon):**
   - Validate action names
   - Verify field mappings

3. **P2 - Medium (Fix Later):**
   - Improve error messages
   - Add validation during generation
   - Better logging

---

**Next Steps:**
1. Implement P0 fixes in `service_scanner.py`
2. Test with ACM and S3
3. Verify discoveries execute
4. Re-run analysis to measure improvement

