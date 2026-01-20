# Template Resolution Fix: Why `{{ item.id }}` Wasn't Resolved

## Problem

Template variables like `{{ item.id }}` were appearing literally in API calls, causing errors like:
```
Invalid API identifier specified 588989875114:{{ item.id }}
```

## Root Cause Analysis

### Example: `get_authorizers` in apigateway

**Current YAML (WRONG):**
```yaml
- discovery_id: aws.apigateway.get_authorizers
  calls:
  - action: get_authorizers
    params:
      restApiId: '{{ item.id }}'
    on_error: continue
  for_each: aws.apigateway.get_usage_plans  ← WRONG PARENT!
```

**What happens:**
1. Engine iterates over `get_usage_plans`
2. For each usage plan, tries: `get_authorizers(restApiId='{{ item.id }}')`
3. But `item.id` is the **USAGE PLAN ID**, not **REST API ID**!
4. Result: `Invalid API identifier specified 588989875114:{{ item.id }}`

**Correct parent should be:**
```yaml
  for_each: aws.apigateway.get_rest_apis  ← CORRECT!
```

### Why Agent 4 Chose Wrong Parent

The `find_parent_discovery()` function used **generic pattern matching**:

```python
# OLD CODE (line 304)
if param.lower().endswith(field.lower()) or field.lower() in param.lower():
    return discovery_id
```

**Problem:**
- `restApiId` parameter → looks for any `id` field
- Finds `get_usage_plans` which has `id` field (usage plan ID)
- Should find `get_rest_apis` which has `id` field (REST API ID)
- **No semantic understanding!**

## Fix Applied

Enhanced `find_parent_discovery()` with **3 strategies**:

### Strategy 1: Parameter → Function Name Semantic Mapping
```python
param_to_function_patterns = {
    'restApiId': ['get_rest_apis', 'list_rest_apis', 'rest_apis'],
    'bucketName': ['list_buckets', 'get_buckets', 'buckets'],
    'analyzerArn': ['list_analyzers', 'get_analyzers', 'analyzers'],
    # ... more patterns
}
```

### Strategy 2: Function Name Pattern Matching
```python
function_to_parent_patterns = {
    'get_authorizers': ['rest_api', 'restapis', 'get_rest'],
    'get_stages': ['rest_api', 'restapis', 'get_rest'],
    'get_resources': ['rest_api', 'restapis', 'get_rest'],
    # ... more patterns
}
```

**Key insight:** `get_authorizers` needs `restApiId` → parent should be `get_rest_apis`

### Strategy 3: Semantic Field Matching
- Checks if parameter context aligns with function context
- `restApiId` → matches with functions containing "rest" and "api"
- Prevents matching `get_usage_plans` when `restApiId` is needed

## Changes Made

1. **Updated `find_parent_discovery()` signature:**
   ```python
   def find_parent_discovery(service, required_params, all_discoveries, 
                           boto3_service_data, current_function=''):
   ```
   - Added `current_function` parameter for context

2. **Added semantic matching logic:**
   - Parameter name → function name mapping
   - Function name → parent function patterns
   - Context-aware field matching

3. **Updated call site:**
   ```python
   parent_id = find_parent_discovery(service, required_params, discoveries, 
                                    boto3_data.get(service, {}), current_function)
   ```

## Testing

After fix, regenerate YAMLs:
```bash
cd Agent-rulesid-rule-yaml
python3 agent4_yaml_generator.py
python3 test_generated_yaml.py --copy-only
```

Expected result:
- `get_authorizers` → `for_each: aws.apigateway.get_rest_apis` ✅
- `get_stages` → `for_each: aws.apigateway.get_rest_apis` ✅
- `get_resources` → `for_each: aws.apigateway.get_rest_apis` ✅

## Next Steps

1. Re-run Agent 4 to regenerate YAMLs with fix
2. Copy to services folder
3. Re-run scan to verify template resolution works
4. Monitor logs for remaining template errors

