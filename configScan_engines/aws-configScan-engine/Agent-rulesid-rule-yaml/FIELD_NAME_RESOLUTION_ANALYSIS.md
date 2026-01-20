# Field Name Resolution Issue - Complete Analysis

## Example: Athena Service

### The Problem

**Current YAML (WRONG):**
```yaml
- discovery_id: aws.athena.get_work_group
  calls:
  - action: get_work_group
    params:
      WorkGroup: '{{ item.api_id }}'  # ❌ WRONG!
  for_each: aws.athena.list_work_groups
```

**Should be:**
```yaml
- discovery_id: aws.athena.get_work_group
  calls:
  - action: get_work_group
    params:
      WorkGroup: '{{ item.name }}'  # ✅ CORRECT!
  for_each: aws.athena.list_work_groups
```

### Data Flow

1. **boto3_dependencies_with_python_names.json:**
   ```json
   {
     "athena": {
       "independent": [{
         "python_method": "list_work_groups",
         "item_fields": ["Name", "State", "Description", ...]
       }],
       "dependent": [{
         "python_method": "get_work_group",
         "required_params": ["WorkGroup"]
       }]
     }
   }
   ```

2. **Agent 2 (agent2_function_validator.py:242):**
   ```python
   'available_fields': matching_function.get('item_fields', []),
   ```
   ✅ Maps `item_fields` → `available_fields`

3. **Agent 4 (agent4_yaml_generator.py:295):**
   ```python
   parent_fields = parent_func.get('available_fields', [])
   ```
   ✅ Uses `available_fields` (should have 'Name' from agent2)

### Why Matching Fails

**Matching Logic (lines 301-328):**
```python
Parameter: 'WorkGroup'
Parent fields: ['Name', 'State', 'Description', ...]  # From available_fields

Pattern 1: 'WorkGroup' == 'Name'? ❌ NO
Pattern 2: 'WorkGroup' ends with 'Name'? ❌ NO  
Pattern 3: 'Name' in 'WorkGroup'? ❌ NO (reverse check)
Pattern 4: Special case for 'bucket'? ❌ NO (only handles 'bucket')

Result: Falls back to {{ item.id }}
But 'id' doesn't exist in parent emit!
So becomes: {{ item.api_id }} (WRONG!)
```

### The Real Issue

The matching logic **CAN'T** connect:
- Parameter: `WorkGroup` 
- To field: `Name`

Because:
- `WorkGroup` ≠ `Name` (exact match fails)
- `WorkGroup` doesn't end with `Name`
- `Name` is not in `WorkGroup` (it's the other way)

### The Solution

**Fix 1: Add Pattern 5 - Resource Type → Name Field**
```python
# Pattern 5: Resource type parameter → Name field
if not matched_field:
    # Common pattern: WorkGroup, Bucket, Table → Name field
    resource_types = ['group', 'bucket', 'table', 'queue', 'stream', 'vault']
    if any(rt in param.lower() for rt in resource_types) and 'Name' in parent_fields:
        matched_field = 'Name'
```

**Fix 2: Better Parameter-to-Field Mapping**
```python
# Pattern 6: Parameter name contains resource type → Name field
if not matched_field:
    # WorkGroup → Name, TableName → Name, BucketName → Name
    if 'Name' in parent_fields and (
        param.lower().endswith('name') or 
        param.lower().endswith('group') or
        param.lower() in ['bucket', 'table', 'queue']
    ):
        matched_field = 'Name'
```

**Fix 3: Use emit structure (more reliable)**
Instead of matching against boto3 field names, match against what's actually emitted:
- Parent emit has: `name`, `state`, `description`
- Parameter `WorkGroup` → should use `name`

### Current Code Location

File: `agent4_yaml_generator.py`
Lines: 295-335
Issue: Matching logic doesn't handle `WorkGroup` → `Name` pattern
