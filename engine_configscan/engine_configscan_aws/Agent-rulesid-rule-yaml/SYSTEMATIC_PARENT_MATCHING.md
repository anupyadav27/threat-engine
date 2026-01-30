# Systematic Parent Discovery Matching

## Problem

Template variables like `{{ item.id }}` weren't being resolved because Agent 4 used fragile pattern matching that didn't understand the actual function relationships and field mappings.

## Solution: Systematic Field-Based Matching

### Approach

1. **Identify Primary LIST/DESCRIBE/GET Functions**
   - These are independent functions (no required params or only optional pagination params)
   - They serve as root discovery functions
   - Examples: `get_rest_apis`, `list_buckets`, `list_analyzers`

2. **Build Field-to-Discovery Mapping**
   - Map each field to which discovery(ies) can provide it
   - Track: primary vs dependent, depth from primary
   - Uses actual `item_fields` and `available_fields` from boto3 data

3. **Match Required Parameters to Discoveries**
   - For each required param, find which discovery(ies) can provide it
   - Priority: 1) Primary independent, 2) Dependent from primary, 3) Others
   - Match types: exact, partial, semantic

4. **Select Best Match**
   - Score each match (primary gets higher score)
   - Return discovery with highest score

### Example: `get_authorizers` needs `restApiId`

**Before (WRONG):**
- Generic pattern matching: `restApiId` → matches any `id` field
- Found: `get_usage_plans` (has `id` field, but it's usage plan ID)
- Result: Wrong parent, template not resolved

**After (CORRECT):**
- STEP 1: Identify `get_rest_apis` as primary independent (emits `id` field)
- STEP 2: Map `id` field → `get_rest_apis` (primary, depth 0)
- STEP 3: Match `restApiId` → `id` field → `get_rest_apis` (exact match, score 100)
- STEP 4: Select `get_rest_apis` as parent
- Result: Correct parent, template resolved ✅

### Code Structure

```python
def find_parent_discovery(service, required_params, all_discoveries, ...):
    # STEP 1: Identify primary independent discoveries
    primary_independent_discoveries = []
    # ... logic to identify LIST/DESCRIBE/GET functions that are independent
    
    # STEP 2: Build field-to-discovery mapping
    field_to_discoveries = {}
    # Map each field to [(discovery_id, is_primary, depth), ...]
    
    # STEP 3: Match required params to discoveries
    best_matches = []
    # For each param, find best matching discovery with scoring
    
    # STEP 4: Select best overall match
    # Return discovery with highest score
```

### Benefits

1. **Uses Actual Field Data**: Matches based on `item_fields`/`available_fields`, not patterns
2. **Prioritizes Primary Functions**: Always prefers root discovery functions
3. **Handles Dependencies**: Understands which functions depend on which
4. **Systematic & Maintainable**: Clear logic, easy to debug and extend
5. **Works for All Services**: Not service-specific, works generically

### Testing

After fix, verify:
- `get_authorizers` → `for_each: aws.apigateway.get_rest_apis` ✅
- `get_stages` → `for_each: aws.apigateway.get_rest_apis` ✅
- `get_resources` → `for_each: aws.apigateway.get_rest_apis` ✅
- Other services: Similar systematic matching

