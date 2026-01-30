# Data Flow: Agent 1 → Agent 2 → Agent 3 → Agent 4

## Overview

Each agent reads from the previous agent's output and enriches the data with additional information. The matching happens through **field names** and **function names**.

---

## Agent 1: Requirements Generator

**Input:** Metadata YAML files (`services/{service}/metadata/*.yaml`)  
**Output:** `output/requirements_initial.json`

### What Agent 1 Does:
1. Reads metadata files for each service
2. Uses AI to generate requirements based on rule descriptions
3. AI picks field names from available boto3 fields

### Output Structure:
```json
{
  "athena": [
    {
      "rule_id": "aws.athena.workgroup.logging_enabled",
      "service": "athena",
      "requirement": "Workgroup should have logging enabled",
      "description": "...",
      "ai_generated_requirements": {
        "fields": [
          {
            "conceptual_name": "logging_configuration",
            "boto3_python_field": "Configuration",  // ← Field name from boto3
            "operator": "exists",
            "boto3_python_field_expected_values": null
          }
        ],
        "condition_logic": "single"
      }
    }
  ]
}
```

**Key Point:** Agent 1 outputs **field names** that AI thinks exist in boto3 (e.g., `"Configuration"`)

---

## Agent 2: Function Validator

**Input:** `output/requirements_initial.json`  
**Output:** `output/requirements_with_functions.json`  
**Matching Logic:** Matches **field names** → **boto3 functions**

### What Agent 2 Does:
1. Reads requirements from Agent 1
2. Extracts field names from `ai_generated_requirements.fields[].boto3_python_field`
3. **Finds which boto3 function provides those fields**
4. Adds `validated_function` to each rule

### Matching Process:

#### Step 1: Extract Required Fields
```python
# From Agent 1 output
fields_needed = ["Configuration", "State", "Name"]
```

#### Step 2: Search boto3_dependencies
```python
# For each operation in service:
for op in service_data.get('independent', []) + service_data.get('dependent', []):
    item_fields = op.get('item_fields', [])  # e.g., ["Name", "State", "Configuration", ...]
    
    # Try to match each required field
    for req_field in fields_needed:
        variants = generate_field_variants(req_field)  # ["Configuration", "configuration", "CONFIGURATION", ...]
        
        if variant in item_fields:
            matches += 1
```

#### Step 3: Score Functions
- Functions that match **more fields** get higher scores
- Requires **≥50% match** to be selected
- Best match is chosen

#### Step 4: Enrich Rule
```python
rule['validated_function'] = {
    'python_method': 'get_work_group',  # ← Function that provides the fields
    'boto3_operation': 'GetWorkGroup',
    'is_independent': False,
    'required_params': ['WorkGroup'],
    'available_fields': ['Name', 'State', 'Configuration', ...],  # ← From item_fields
    'main_output_field': 'WorkGroup'
}
```

### Output Structure:
```json
{
  "athena": [
    {
      "rule_id": "aws.athena.workgroup.logging_enabled",
      "ai_generated_requirements": { ... },
      "validated_function": {  // ← NEW: Added by Agent 2
        "python_method": "get_work_group",
        "available_fields": ["Name", "State", "Configuration", ...],
        "required_params": ["WorkGroup"],
        "is_independent": false
      },
      "validation_status": "function_found"
    }
  ]
}
```

**Key Point:** Agent 2 matches **fields → function** by searching which function's `item_fields` contains the required fields.

---

## Agent 3: Field Validator

**Input:** `output/requirements_with_functions.json`  
**Output:** `output/requirements_validated.json`  
**Matching Logic:** Validates **field names** exist in the **validated function's output**

### What Agent 3 Does:
1. Reads requirements with validated functions from Agent 2
2. For each field in `ai_generated_requirements.fields[]`:
   - Checks if field exists in `validated_function.available_fields`
   - Tries name variants (case conversion, snake_case ↔ PascalCase)
   - Marks fields as valid/invalid/computed
3. Adds `field_validation` to each rule

### Matching Process:

```python
# Get fields from Agent 1
req_fields = ["Configuration", "State"]

# Get available fields from Agent 2's validated_function
available_fields = validated_function['available_fields']  # ["Name", "State", "Configuration", ...]

# For each required field:
for req_field in req_fields:
    # Try variants: "Configuration", "configuration", "CONFIGURATION", etc.
    variants = generate_field_variants(req_field)
    
    for variant in variants:
        if variant in available_fields:
            # Field exists! Mark as valid
            field_validation[req_field] = {
                'valid': True,
                'matched_field': variant,
                'match_type': 'exact_match'
            }
            break
```

### Output Structure:
```json
{
  "athena": [
    {
      "rule_id": "aws.athena.workgroup.logging_enabled",
      "validated_function": { ... },
      "field_validation": {  // ← NEW: Added by Agent 3
        "Configuration": {
          "valid": true,
          "matched_field": "Configuration",
          "match_type": "exact_match"
        }
      },
      "all_fields_valid": true
    }
  ]
}
```

**Key Point:** Agent 3 validates that the **fields from Agent 1** actually exist in the **function selected by Agent 2**.

---

## Agent 4: YAML Generator

**Input:** `output/requirements_validated.json`  
**Output:** `services/{service}/rules/{service}.yaml`  
**Matching Logic:** Uses **validated_function** to generate discovery, then matches **parameters** → **parent fields**

### What Agent 4 Does:
1. Reads validated requirements from Agent 3
2. For each rule with `validated_function`:
   - Generates discovery YAML using `validated_function.python_method`
   - If function is dependent (`required_params` not empty):
     - Finds parent discovery
     - Matches parameters to parent's `available_fields`
3. Generates checks YAML

### Matching Process (Dependent Discoveries):

#### Step 1: Identify Dependent Function
```python
validated_function = {
    'python_method': 'get_work_group',
    'required_params': ['WorkGroup'],  # ← Needs a parameter
    'is_independent': False
}
```

#### Step 2: Find Parent Discovery
```python
# Search for parent that provides the parameter
# Parameter: "WorkGroup" → needs a workgroup name
# Parent: list_work_groups → provides workgroup names
parent_id = find_parent_discovery(service, ['WorkGroup'], discoveries, boto3_data)
# Returns: "aws.athena.list_work_groups"
```

#### Step 3: Match Parameter to Parent Field
```python
# Get parent's available fields
parent_func = discoveries[parent_id]['_function_data']
parent_fields = parent_func.get('available_fields', [])  # ["Name", "State", ...]

# Parameter: "WorkGroup" needs a value
# Try matching patterns:
param = "WorkGroup"
matched_field = None

# Pattern 1: Exact match
if "WorkGroup" in parent_fields:  # NO

# Pattern 2: Parameter ends with field
if "WorkGroup".endswith("Name"):  # NO

# Pattern 3: Field in parameter
if "Name" in "WorkGroup":  # NO

# Pattern 5: Resource type → Name field
if "group" in "WorkGroup".lower() and "Name" in parent_fields:  # YES!
    matched_field = "Name"

# Use: {{ item.name }}
```

### Output Structure:
```yaml
discovery:
  - discovery_id: aws.athena.list_work_groups  # Parent (independent)
    calls:
      - action: list_work_groups
    emit:
      item:
        name: '{{ resource.Name }}'
        state: '{{ resource.State }}'
  
  - discovery_id: aws.athena.get_work_group  # Dependent
    calls:
      - action: get_work_group
        params:
          WorkGroup: '{{ item.name }}'  # ← Matched from parent
    for_each: aws.athena.list_work_groups
```

**Key Point:** Agent 4 matches **parameters** → **parent fields** using pattern matching (exact, ends-with, contains, resource-type patterns).

---

## Summary: How Matching Works

### Agent 1 → Agent 2:
- **Match:** Field names → boto3 functions
- **Method:** Search all functions, find which `item_fields` contains the required fields
- **Result:** `validated_function` added to rule

### Agent 2 → Agent 3:
- **Match:** Field names → validated function's available fields
- **Method:** Try name variants (case conversion, naming conventions)
- **Result:** `field_validation` added to rule

### Agent 3 → Agent 4:
- **Match:** Parameters → parent discovery's fields
- **Method:** Pattern matching (exact, ends-with, contains, resource-type)
- **Result:** YAML with `{{ item.field_name }}` templates

---

## Key Data Structures

### boto3_dependencies_with_python_names.json:
```json
{
  "athena": {
    "independent": [
      {
        "python_method": "list_work_groups",
        "item_fields": ["Name", "State", "Description", ...],  // ← Fields in response
        "required_params": [],
        "main_output_field": "WorkGroups"
      }
    ],
    "dependent": [
      {
        "python_method": "get_work_group",
        "item_fields": ["Name", "State", "Configuration", ...],
        "required_params": ["WorkGroup"],  // ← Needs parameter
        "main_output_field": "WorkGroup"
      }
    ]
  }
}
```

### Rule Structure (after each agent):
```json
{
  "rule_id": "...",
  "ai_generated_requirements": {  // Agent 1
    "fields": [{"boto3_python_field": "Configuration"}]
  },
  "validated_function": {  // Agent 2
    "python_method": "get_work_group",
    "available_fields": ["Name", "State", "Configuration"]
  },
  "field_validation": {  // Agent 3
    "Configuration": {"valid": true}
  }
}
```

---

## Common Issues

### Issue 1: Field name mismatch
- **Problem:** Agent 1 uses `"Status"` but boto3 has `"State"`
- **Solution:** Agent 2 tries variants: `"Status"`, `"status"`, `"STATE"`, etc.

### Issue 2: Function not found
- **Problem:** No function provides the required fields
- **Solution:** Agent 2 marks `validation_status: "function_not_found"`

### Issue 3: Parameter matching fails
- **Problem:** Parameter `"WorkGroup"` can't match to field `"Name"`
- **Solution:** Agent 4 uses Pattern 5 (resource type → Name field)
