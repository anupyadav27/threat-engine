# Field Name Resolution Issue - Root Cause Analysis

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

### Root Cause

1. **Parent Discovery (`list_work_groups`):**
   - Boto3 response has: `WorkGroups[]` array
   - Each item has field: `Name` (PascalCase)
   - In YAML emit: `Name` → `name` (snake_case)
   - **Available in boto3_dependencies:** `item_fields: ['Name', 'State', ...]`

2. **Dependent Discovery (`get_work_group`):**
   - Requires parameter: `WorkGroup` (string)
   - Needs the workgroup **name** from parent
   - **Available in boto3_dependencies:** `required_params: ['WorkGroup']`

3. **Matching Logic Failure:**
   ```
   Parameter: 'WorkGroup'
   Parent fields: ['Name', 'State', 'Description', ...]
   
   Pattern 1: 'WorkGroup' == 'Name'? ❌ NO
   Pattern 2: 'WorkGroup' ends with 'Name'? ❌ NO  
   Pattern 3: 'Name' in 'WorkGroup'? ❌ NO (reverse check)
   
   Result: Falls back to {{ item.id }}
   But 'id' doesn't exist in parent emit!
   So becomes: {{ item.api_id }} (WRONG!)
   ```

### Why boto3_dependencies Can't Help

The `boto3_dependencies_with_python_names.json` file **HAS** the correct information:
- `list_work_groups.item_fields = ['Name', 'State', ...]`
- `get_work_group.required_params = ['WorkGroup']`

**BUT:**
1. Generator uses `available_fields` instead of `item_fields`
2. Matching logic doesn't understand common patterns:
   - `WorkGroup` parameter → `Name` field
   - `Bucket` parameter → `Name` field  
   - `<ResourceType>` parameter → `Name` field

### The Solution

**Fix 1: Use `item_fields` from boto3_dependencies**
- The file has `item_fields` which shows actual fields in response items
- Should use this instead of `available_fields` for matching

**Fix 2: Improve matching patterns**
Add pattern recognition:
- If parameter is a resource type (e.g., `WorkGroup`, `Bucket`, `Table`)
- And parent has `Name` field
- Then use: `{{ item.name }}`

**Fix 3: Parameter-to-field mapping**
Common patterns:
- `WorkGroup` → `Name` → `name`
- `Bucket` → `Name` → `name`
- `TableName` → `Name` → `name`
- `GroupName` → `Name` → `name`

### Current Generator Code Issue

In `agent4_yaml_generator.py` line 295:
```python
parent_fields = parent_func.get('available_fields', [])
```

**Should be:**
```python
# Try item_fields first (more accurate)
parent_fields = parent_func.get('item_fields', []) or parent_func.get('available_fields', [])
```

And add better matching:
```python
# Pattern 5: Resource type parameter → Name field
if not matched_field:
    # Common pattern: WorkGroup, Bucket, Table → Name field
    resource_types = ['group', 'bucket', 'table', 'queue', 'stream']
    if any(rt in param.lower() for rt in resource_types) and 'Name' in parent_fields:
        matched_field = 'Name'
```
