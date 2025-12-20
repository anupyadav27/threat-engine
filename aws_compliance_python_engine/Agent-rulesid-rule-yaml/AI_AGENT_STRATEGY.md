# AI-Enhanced Agent Pipeline Strategy

## Overview
Following Agent 1's successful AI-assisted approach, we enhance subsequent agents with AI while maintaining pattern matching as fallback.

## Agent Responsibilities

### AGENT 1: Requirements Generator ✅
**Status:** Already uses AI (working well)
- **Task:** Interpret rule requirements from metadata
- **AI Usage:** Primary - generates field requirements
- **Context:** boto3 available fields from all operations
- **Output:** `requirements_initial.json`
- **Action:** Keep as-is

---

### AGENT 2: Function Validator
**Status:** Pattern matching (working, but can be enhanced)
- **Task:** Match requirements to boto3 functions
- **Current Logic:**
  - Pattern match field names → functions
  - Filter by function type (LIST/DESCRIBE/GET)
  - Prioritize by field matches
  - Determine independent vs dependent

**AI Enhancement (Selective):**
- **When to use AI:**
  - When 2+ functions match equally (same score)
  - Ambiguous cases (e.g., `list_` vs `describe_` vs `get_`)
  - Complex semantic matching needed

- **AI Prompt Structure:**
  ```
  Requirement needs fields: [field1, field2]
  Available functions:
    - function1: emits [fields...], type: LIST
    - function2: emits [fields...], type: DESCRIBE
  Which function is better for this requirement?
  Consider: requirement description, field semantics
  ```

- **Context Provided:**
  - Required fields from Agent 1
  - Candidate functions with their item_fields
  - Function types (LIST/DESCRIBE/GET)
  - Requirement description

- **Fallback:** Current pattern matching (primary)

**Output:** `requirements_with_functions.json`

---

### AGENT 3: Field Validator
**Status:** Field validation (working, minimal enhancement needed)
- **Task:** Validate field names exist in chosen function
- **Current Logic:**
  - Check if field exists in function's item_fields
  - Handle case mismatches
  - Validate field names

**AI Enhancement (Minimal):**
- **When to use AI:**
  - Field not found in function
  - Need field name normalization suggestions
  - Alternative field suggestions

- **AI Prompt Structure:**
  ```
  Requirement field: "LastModifiedDate"
  Available fields in function: [field1, field2, ...]
  Suggest correct field name or alternative.
  ```

- **Context Provided:**
  - Required field name
  - All available fields in chosen function
  - Field naming patterns

- **Fallback:** Current validation logic (primary)

**Output:** `requirements_validated.json`

---

### AGENT 4: YAML Generator ⚠️ **URGENT**
**Status:** Pattern matching (FAILING - 510 template errors)
- **Task:** Generate YAML with parent discovery matching
- **Current Issues:**
  - Wrong parent selection (get_usage_plans vs get_rest_apis)
  - Wrong field mapping (id vs name)
  - Template resolution failing

**AI Enhancement (PRIMARY):**
- **Use AI for:**
  1. **Parent Discovery Matching:**
     - Match required parameter → parent discovery
     - Example: `restApiId` → `get_rest_apis` (not `get_usage_plans`)

  2. **Parameter-to-Field Mapping:**
     - Match parameter → field from parent
     - Example: `restApiId` → `id` field (or `name` if appropriate)

- **AI Prompt Structure:**
  ```
  Function: get_authorizers
  Required parameter: restApiId
  Available independent functions:
    - get_rest_apis: emits [id, name, ...]
    - get_usage_plans: emits [id, name, ...]
  Which function should provide restApiId?
  Which field from that function should be used?
  Consider semantic meaning: restApiId = REST API ID
  ```

- **Context Provided:**
  - Current function name
  - Required parameters
  - All independent discoveries with their item_fields
  - Dependent discoveries (for reference)

- **Implementation:**
  - Use `ai_parent_matcher.py` (already created)
  - Try AI first
  - Fallback to pattern matching if AI fails
  - Verify AI suggestions against boto3 data

- **Fallback:** Current pattern matching (if AI fails)

**Output:** `*_generated.yaml` files

---

## Implementation Priority

### Phase 1: AGENT 4 (URGENT) 🔴
**Goal:** Fix 510 template resolution errors
- Integrate `ai_parent_matcher.py` into Agent 4
- Use AI-first approach for parent discovery
- Test with apigateway and athena cases
- Verify fixes in full scan

**Files:**
- `agent4_yaml_generator.py` - integrate AI
- `ai_parent_matcher.py` - already created

---

### Phase 2: AGENT 2 (Optional) 🟡
**Goal:** Improve function selection for ambiguous cases
- Add AI helper for tie-breaking
- Only when multiple functions match equally
- Keep pattern matching as primary

**Files:**
- `agent2_function_validator.py` - add AI helper

---

### Phase 3: AGENT 3 (Optional) 🟢
**Goal:** Better field name suggestions
- Add AI for field normalization
- Only when field not found
- Keep validation as primary

**Files:**
- `agent3_field_validator.py` - add AI helper

---

## AI Helper Pattern (Following Agent 1)

All AI helpers should:
1. **Build structured context** (like Agent 1 does with boto3 fields)
2. **Provide clear prompts** with examples
3. **Validate responses** against real data
4. **Have fallback logic** to pattern matching
5. **Log AI suggestions** for debugging

## Example: Agent 4 Integration

```python
# In agent4_yaml_generator.py

from ai_parent_matcher import ai_suggest_parent

def find_parent_discovery(...):
    # Try AI first
    ai_result = ai_suggest_parent(
        current_function=current_function,
        required_params=required_params,
        independent_discoveries=independent_discoveries,
        dependent_discoveries=dependent_discoveries,
        boto3_service_data=boto3_service_data
    )
    
    if ai_result:
        parent_id, field_name = ai_result
        # Verify it's valid
        if parent_id in all_discoveries:
            return parent_id, field_name
    
    # Fallback to pattern matching
    return pattern_match_parent(...)
```

## Benefits

✅ **Semantic Understanding:** AI understands `restApiId` → REST API → `get_rest_apis`
✅ **Context Prevents Hallucination:** Only suggests from provided function list
✅ **Verified Against Data:** All suggestions validated against boto3 data
✅ **Maintainable:** Less complex pattern matching code
✅ **Handles Edge Cases:** Better at complex semantic relationships

