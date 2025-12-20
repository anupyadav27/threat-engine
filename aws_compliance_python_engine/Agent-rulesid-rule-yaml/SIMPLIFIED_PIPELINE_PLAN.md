# Simplified AI-Enhanced Pipeline Plan

## Overview
Enhance Agent 1 to do more (function suggestions), simplify Agent 2 to validate, and streamline the pipeline.

## Revised Pipeline Flow

```
Agent 1 (Enhanced) → Agent 2 (Validation) → Agent 3 (Minimal) → Agent 4 (Generate + Copy)
     ↓                      ↓                      ↓                    ↓
  AI suggests          Pattern verify          Quick check        AI parent match
  function + fields    AI suggestions          field names        + Auto-copy
```

## Agent Responsibilities

### AGENT 1: Enhanced Requirements Generator (AI-Powered)

**Current:** Only suggests fields
**Enhanced:** Suggests function + fields + type

**Input:** Metadata YAML files
**Output:** `requirements_initial.json` with:
```json
{
  "rule_id": "aws.cognito.userpool.access_keys_rotated",
  "service": "cognito",
  "suggested_function": "list_user_pools",           // NEW: AI suggests
  "function_type": "independent",                    // NEW: AI determines
  "ai_generated_requirements": {
    "fields": [
      {
        "boto3_python_field": "LastModifiedDate",
        "operator": "lte",
        "boto3_python_field_expected_values": 90
      }
    ]
  }
}
```

**AI Prompt Enhancement:**
- Show ALL available boto3 functions (not just fields)
- Include function types (LIST/DESCRIBE/GET)
- Include independent vs dependent classification
- Include function item_fields
- Ask AI to:
  1. Suggest best function for this requirement
  2. Determine if function is independent or dependent
  3. Suggest fields to check
  4. All in one response

**Benefits:**
- AI has full context (metadata + all functions + fields)
- Single AI call does function selection + field selection
- More accurate than separate pattern matching

---

### AGENT 2: Function Validator (Simplified - Pattern-Based Verification)

**Current:** Pattern matching to find functions
**New:** Validate AI suggestions from Agent 1

**Input:** `requirements_initial.json` (with AI function suggestions)
**Output:** `requirements_with_functions.json`

**Tasks:**
1. **Verify Function Exists:**
   - Check if `suggested_function` exists in boto3 catalog
   - Validate function name spelling

2. **Verify Function Type:**
   - Check if `function_type` matches actual function (independent/dependent)
   - Validate against function's `required_params`

3. **Verify Fields Exist:**
   - Check if suggested fields exist in function's `item_fields`
   - Handle case mismatches

4. **Fallback (if validation fails):**
   - Use current pattern matching logic
   - Log which AI suggestions were rejected

**No AI needed** - just pattern-based validation

---

### AGENT 3: AI-Powered Refinement (Similar to Agent 1)

**Purpose:** Fix/improve cases where Agent 2 failed or needs improvement

**Input:** `requirements_with_functions.json` (with validation results)
**Output:** `requirements_validated.json` (final, ready for YAML generation)

**Tasks:**
1. **Identify Problem Cases:**
   - Cases where Agent 2 validation failed
   - Cases where Agent 2 used fallback pattern matching
   - Cases flagged for improvement

2. **AI-Powered Refinement:**
   - Use AI (similar to Agent 1) to generate correct function + fields
   - Context: Original requirement + Agent 2's attempt + why it failed
   - AI suggests final function name, fields, types, etc.

3. **Generate Final Output:**
   - Final function name
   - Final field names
   - Final function type (independent/dependent)
   - All validated and ready for YAML generation

**AI Prompt Structure:**
```
Agent 2 attempted to match this requirement but:
- Validation failed: [reason]
- Or: Used fallback pattern matching
- Or: Needs improvement: [issue]

Original requirement: [metadata]
Agent 2's attempt: [function, fields]

Available boto3 functions: [all functions with fields]

Task: Generate the CORRECT function + fields for YAML generation.
Consider: Why Agent 2 failed, what's the right approach.
```

**Benefits:**
- AI fixes problematic cases
- Similar approach to Agent 1 (proven to work)
- Ensures quality before YAML generation
- Handles edge cases that pattern matching misses

---

### AGENT 4: YAML Generator + Auto-Copy (AI for Parent Discovery)

**Input:** `requirements_validated.json`
**Output:** `*_generated.yaml` files + Auto-copy to services folder

**AI Tasks:**
1. **Parent Discovery Matching:**
   - Use `ai_parent_matcher.py` for dependent functions
   - Match required parameter → parent discovery
   - Example: `restApiId` → `get_rest_apis`

2. **Parameter-to-Field Mapping:**
   - Use AI to map parameter → field from parent
   - Example: `restApiId` → `id` field (or `name` if appropriate)

**Additional Features:**
- Auto-copy generated YAMLs to `services/{service}/rules/{service}.yaml`
- Skip manual `test_generated_yaml.py` step
- Generate and copy in one go

**Fallback:** Pattern matching if AI fails

---

## Implementation Steps

### Phase 1: Enhance Agent 1

**File:** `agent1_requirements_generator.py`

**Changes:**
1. Load boto3 functions (not just fields)
2. Include function metadata in AI prompt:
   - Function name
   - Function type (LIST/DESCRIBE/GET)
   - Independent vs dependent
   - Item fields
3. Update AI prompt to ask for:
   - Suggested function name
   - Function type
   - Fields to check
4. Update output format to include:
   - `suggested_function`
   - `function_type`

**Example Enhanced Prompt:**
```
You are analyzing an AWS {service} compliance rule.

Rule ID: {rule_id}
Requirement: {requirement}
Description: {description}

AVAILABLE BOTO3 FUNCTIONS FOR {service.upper()}:
{
  "list_user_pools": {
    "type": "LIST",
    "independent": true,
    "item_fields": ["Id", "Name", "LastModifiedDate", ...]
  },
  "describe_user_pool": {
    "type": "DESCRIBE",
    "independent": false,
    "required_params": ["UserPoolId"],
    "item_fields": ["UserPool", ...]
  },
  ...
}

TASK:
1. Suggest the BEST function for this requirement
2. Determine if function is independent or dependent
3. Suggest which fields from that function to check
4. Provide field operators and expected values

Respond with:
{
  "suggested_function": "list_user_pools",
  "function_type": "independent",
  "fields": [...]
}
```

---

### Phase 2: Simplify Agent 2

**File:** `agent2_function_validator.py`

**Changes:**
1. Read `suggested_function` from Agent 1 output
2. Validate function exists in boto3 catalog
3. Validate function type matches
4. Validate fields exist in function
5. If validation fails → use pattern matching fallback
6. Output validated function (same format as before)

**Simplified Logic:**
```python
def validate_ai_suggestion(requirement, boto3_data):
    suggested_func = requirement.get('suggested_function')
    
    # Verify function exists
    if not function_exists(suggested_func, boto3_data):
        return fallback_pattern_match(requirement, boto3_data)
    
    # Verify function type
    if not function_type_matches(suggested_func, requirement.get('function_type')):
        return fallback_pattern_match(requirement, boto3_data)
    
    # Verify fields exist
    if not fields_exist_in_function(suggested_func, requirement.get('fields')):
        return fallback_pattern_match(requirement, boto3_data)
    
    # All valid - use AI suggestion
    return suggested_func
```

---

### Phase 3: Enhance Agent 3 (AI-Powered Refinement)

**File:** `agent3_field_validator.py` (rename to `agent3_ai_refinement.py`)

**Changes:**
1. Identify cases needing refinement:
   - Agent 2 validation failed
   - Agent 2 used fallback pattern matching
   - Flagged for improvement

2. Use AI (similar to Agent 1) to fix:
   - Generate correct function name
   - Generate correct fields
   - Determine function type
   - All with full context

3. Output final validated requirements ready for YAML

**Logic:**
```python
def refine_with_ai(requirement, agent2_result, boto3_data):
    # Check if needs refinement
    if agent2_result.get('validation_failed') or agent2_result.get('used_fallback'):
        # Use AI to fix (similar to Agent 1)
        ai_result = ai_refine_requirement(
            requirement=requirement,
            agent2_attempt=agent2_result,
            boto3_data=boto3_data
        )
        return ai_result
    else:
        # Agent 2 result is good, use as-is
        return agent2_result
```

---

### Phase 4: Integrate Agent 4

**File:** `agent4_yaml_generator.py`

**Changes:**
1. Import `ai_parent_matcher.py`
2. Use AI for parent discovery (instead of pattern matching)
3. Use AI for parameter-to-field mapping
4. Add auto-copy functionality:
   ```python
   def copy_generated_yamls():
       for service in services:
           src = f"output/{service}_generated.yaml"
           dst = f"../services/{service}/rules/{service}.yaml"
           shutil.copy(src, dst)
   ```
5. Call copy after generation

---

## Benefits

✅ **Simpler Pipeline:** Less complexity, fewer places for errors
✅ **AI Does Heavy Lifting:** Agent 1 has full context, makes better decisions
✅ **Agent 2 Just Validates:** Simpler, more reliable
✅ **Agent 4 Uses AI:** Fixes template resolution issues
✅ **Auto-Copy:** One less manual step
✅ **Better Accuracy:** AI sees full picture in Agent 1

## Migration Path

1. **Enhance Agent 1** → Test output format (function + fields)
2. **Simplify Agent 2** → Test validation logic (verify AI suggestions)
3. **Enhance Agent 3** → Test AI refinement (fix failed cases)
4. **Integrate Agent 4** → Test parent discovery + copy
5. **Full Pipeline Test** → Verify end-to-end
6. **Compare Results** → Ensure quality maintained/improved

## Revised Pipeline Flow

```
Agent 1 (AI) → Agent 2 (Validate) → Agent 3 (AI Refine) → Agent 4 (AI Generate + Copy)
     ↓              ↓                      ↓                      ↓
  AI suggests   Pattern verify      AI fixes failed      AI parent match
  function +    AI suggestions      cases + generates    + Auto-copy
  fields                            final function
```

**Key Points:**
- Agent 1: AI generates initial suggestions
- Agent 2: Validates (pattern-based, no AI)
- Agent 3: AI refines failed/improvement cases (similar to Agent 1)
- Agent 4: AI for parent discovery + generates YAML + auto-copy

