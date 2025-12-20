# Complete Example Trace: Agent 1 → Agent 4

## Example Rule
- **Service:** cognito
- **Rule ID:** `aws.cognito.userpool.access_keys_rotated_90_days_or_less_when_present`
- **Requirement:** "Access Keys Rotated 90 Days Or Less When Present"

---

## STEP 1: Agent 1 - Initial Requirements Generation

### Input
- Metadata file: `services/cognito/metadata/aws.cognito.userpool.access_keys_rotated_90_days_or_less_when_present.yaml`
- Rule description from metadata

### Process
1. Agent 1 reads the metadata file
2. Uses AI (GPT-4) to analyze the requirement
3. AI looks at available boto3 fields for cognito service
4. AI generates requirements with field names

### Output (`output/requirements_initial.json`)
```json
{
  "cognito": [
    {
      "rule_id": "aws.cognito.userpool.access_keys_rotated_90_days_or_less_when_present",
      "service": "cognito",
      "requirement": "Access Keys Rotated 90 Days Or Less When Present",
      "ai_generated_requirements": {
        "fields": [
          {
            "conceptual_name": "access_key_last_rotated_date",
            "boto3_python_field": "LastModifiedDate",  // ← AI picked this field
            "operator": "lte",
            "boto3_python_field_expected_values": 90
          }
        ],
        "condition_logic": "single"
      }
    }
  ]
}
```

**What Agent 1 Did:**
- ✅ Extracted requirement from metadata
- ✅ Used AI to determine: "Need to check if LastModifiedDate ≤ 90 days"
- ✅ Generated field requirement: `LastModifiedDate` with operator `lte` and value `90`

**Key Data:**
- Field needed: `"LastModifiedDate"`
- Operator: `"lte"` (less than or equal)
- Expected value: `90`

---

## STEP 2: Agent 2 - Function Validation

### Input
- `output/requirements_initial.json` (from Agent 1)
- `boto3_dependencies_with_python_names.json`

### Process
1. Agent 2 extracts field names from Agent 1's output
2. Searches `boto3_dependencies` for cognito service
3. For each function, checks if `item_fields` contains `"LastModifiedDate"`
4. Finds best matching function (highest field match score)
5. Adds `validated_function` to the rule

### Matching Logic
```python
# Step 1: Extract fields needed
fields_needed = ["LastModifiedDate"]

# Step 2: Search all cognito functions in boto3_dependencies
for function in cognito_functions:
    item_fields = function.get('item_fields', [])
    # Check: Does this function's response have "LastModifiedDate"?
    if "LastModifiedDate" in item_fields:
        match_score += 1

# Step 3: Select function with highest match
# Found: update_managed_login_branding() has "LastModifiedDate" in item_fields
```

### Output (`output/requirements_with_functions.json`)
```json
{
  "cognito": [
    {
      "rule_id": "aws.cognito.userpool.access_keys_rotated_90_days_or_less_when_present",
      "ai_generated_requirements": { ... },
      "validated_function": {  // ← NEW: Added by Agent 2
        "python_method": "update_managed_login_branding",
        "boto3_operation": "UpdateManagedLoginBranding",
        "is_independent": true,
        "required_params": [],
        "available_fields": [
          "ManagedLoginBrandingId",
          "UserPoolId",
          "UseCognitoProvidedValues",
          "Settings",
          "Assets",
          "LastModifiedDate",  // ← This field exists!
          ...
        ],
        "main_output_field": ""
      },
      "validation_status": "function_found"
    }
  ]
}
```

**What Agent 2 Did:**
- ✅ Extracted: `fields_needed = ["LastModifiedDate"]`
- ✅ Searched: All cognito functions in `boto3_dependencies`
- ✅ Found: `update_managed_login_branding()` has `"LastModifiedDate"` in `item_fields`
- ✅ Added: `validated_function` with function details

**Key Data:**
- Function: `update_managed_login_branding()`
- Type: `is_independent: true` (no parameters needed)
- Available fields: Includes `"LastModifiedDate"` ✅

---

## STEP 3: Agent 3 - Field Validation

### Input
- `output/requirements_with_functions.json` (from Agent 2)
- `boto3_dependencies_with_python_names.json`

### Process
1. Agent 3 takes `validated_function` from Agent 2
2. Gets `available_fields` from the validated function
3. For each field from Agent 1, validates it exists in `available_fields`
4. Tries name variants (case conversion, naming conventions)
5. Marks fields as valid/invalid/computed
6. Adds `field_validation` to the rule

### Validation Logic
```python
# Step 1: Get field from Agent 1
req_field = "LastModifiedDate"

# Step 2: Get available fields from Agent 2's validated_function
available_fields = ["ManagedLoginBrandingId", "UserPoolId", ..., "LastModifiedDate", ...]

# Step 3: Try to match
if "LastModifiedDate" in available_fields:
    # Exact match found!
    validation = {
        "valid": True,
        "matched_field": "LastModifiedDate",
        "match_type": "exact_match"
    }
```

### Output (`output/requirements_validated.json`)
```json
{
  "cognito": [
    {
      "rule_id": "aws.cognito.userpool.access_keys_rotated_90_days_or_less_when_present",
      "ai_generated_requirements": { ... },
      "validated_function": { ... },
      "field_validation": {  // ← NEW: Added by Agent 3
        "LastModifiedDate": {
          "exists": true,
          "correct_name": "LastModifiedDate",
          "original_name": null,
          "validation": "exact_match"
        }
      },
      "all_fields_valid": true
    }
  ]
}
```

**What Agent 3 Did:**
- ✅ Took: `validated_function.available_fields` from Agent 2
- ✅ Checked: Does `"LastModifiedDate"` exist in available fields?
- ✅ Result: ✅ YES - exact match found
- ✅ Added: `field_validation` confirming field is valid

**Key Data:**
- Field `"LastModifiedDate"`: ✅ VALID
- Match type: `"exact_match"`
- All fields valid: `true`

---

## STEP 4: Agent 4 - YAML Generation

### Input
- `output/requirements_validated.json` (from Agent 3)
- `boto3_dependencies_with_python_names.json`

### Process
1. Agent 4 reads `validated_function` from Agent 3
2. Generates discovery YAML using `python_method`
3. Since `is_independent: true`, creates independent discovery (no parent)
4. Generates emit section using `available_fields`
5. Generates check YAML using field validation and operators

### Generation Logic
```python
# Step 1: Get validated function
validated_func = {
    "python_method": "update_managed_login_branding",
    "is_independent": True,  # No parent needed
    "available_fields": ["LastModifiedDate", ...]
}

# Step 2: Generate discovery
discovery = {
    "discovery_id": "aws.cognito.update_managed_login_branding",
    "calls": [{
        "action": "update_managed_login_branding",
        "save_as": "update_managed_login_branding_response"
    }],
    "emit": {
        "item": {
            "last_modified_date": "{{ update_managed_login_branding_response.LastModifiedDate }}"
        }
    }
}

# Step 3: Generate check
check = {
    "rule_id": "aws.cognito.userpool.access_keys_rotated_90_days_or_less_when_present",
    "for_each": "aws.cognito.update_managed_login_branding",
    "conditions": {
        "var": "item.last_modified_date",
        "op": "lte",
        "value": 90
    }
}
```

### Output (`services/cognito/rules/cognito.yaml`)
```yaml
discovery:
  - discovery_id: aws.cognito.update_managed_login_branding
    calls:
      - action: update_managed_login_branding
        save_as: update_managed_login_branding_response
    emit:
      item:
        managed_login_branding_id: '{{ update_managed_login_branding_response.ManagedLoginBrandingId }}'
        user_pool_id: '{{ update_managed_login_branding_response.UserPoolId }}'
        last_modified_date: '{{ update_managed_login_branding_response.LastModifiedDate }}'
        # ... other fields

checks:
  - rule_id: aws.cognito.userpool.access_keys_rotated_90_days_or_less_when_present
    for_each: aws.cognito.update_managed_login_branding
    conditions:
      var: item.last_modified_date
      op: lte
      value: 90
```

**What Agent 4 Did:**
- ✅ Read: `validated_function.python_method = "update_managed_login_branding"`
- ✅ Generated: Discovery YAML with `action: update_managed_login_branding`
- ✅ Generated: Emit section with `last_modified_date` field (snake_case from `LastModifiedDate`)
- ✅ Generated: Check YAML with `for_each` pointing to discovery
- ✅ Used: Operator `lte` and value `90` from Agent 1's requirements

**Key Data:**
- Discovery ID: `aws.cognito.update_managed_login_branding`
- Check uses: `item.last_modified_date` (from emit)
- Condition: `item.last_modified_date <= 90`

---

## Summary: Data Transformation

| Step | Input | Process | Output |
|------|-------|---------|--------|
| **Agent 1** | Metadata YAML | AI generates field requirements | `fields: [{"boto3_python_field": "LastModifiedDate"}]` |
| **Agent 2** | Agent 1 output | Match fields → boto3 function | `validated_function: {"python_method": "update_managed_login_branding"}` |
| **Agent 3** | Agent 2 output | Validate fields exist in function | `field_validation: {"LastModifiedDate": {"valid": true}}` |
| **Agent 4** | Agent 3 output | Generate YAML discovery + check | `discovery:` + `checks:` YAML |

## Key Matching Points

1. **Agent 1 → Agent 2:** Field `"LastModifiedDate"` → Function `update_managed_login_branding()`
   - **How:** Searched `boto3_dependencies` for function with `"LastModifiedDate"` in `item_fields`

2. **Agent 2 → Agent 3:** Field `"LastModifiedDate"` → Validated function's `available_fields`
   - **How:** Checked if field exists in `validated_function.available_fields`

3. **Agent 3 → Agent 4:** `validated_function` → YAML discovery + check
   - **How:** Used `python_method` to generate discovery, `available_fields` for emit, field validation for check

## Final Result

The rule is now in YAML format and can be used by the compliance engine to:
1. Call `update_managed_login_branding()` API
2. Extract `LastModifiedDate` from response
3. Check if `last_modified_date <= 90` days
4. Report PASS/FAIL for the compliance check
