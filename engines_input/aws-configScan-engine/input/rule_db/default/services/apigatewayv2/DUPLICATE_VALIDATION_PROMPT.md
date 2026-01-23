# Duplicate Check Validation and Enhancement Prompt

Add this to your initial prompt when validating and fixing duplicate compliance checks:

## Comprehensive Duplicate Check Validation Process

Please perform the following validation and enhancement steps:

### Step 1: Identify Duplicate Checks
1. Parse the YAML file and identify all checks with identical conditions (same `for_each`, `var`, `op`, and `value`)
2. Group them by condition signature
3. Output groups with 2+ identical checks

### Step 2: Expert Review with Metadata Context
For each group of identical checks:
1. Load and review the metadata file for each rule_id in the group
2. Understand the requirement and intent of each rule:
   - What should the rule actually validate?
   - Is the current condition appropriate for the rule's purpose?
   - Should it check nested fields instead of parent objects?
3. Classify each rule:
   - ✅ **Truly Identical**: Same intent, same validation needed
   - ❌ **False Positive**: Different intent, needs different conditions
   - ⚠️ **Incorrect Placement**: Rule should be in a different service (e.g., CloudWatch)

### Step 3: Enhance boto3_dependencies with Nested Fields
If nested fields are needed but not accessible:
1. Check AWS boto3 API documentation for nested field structure
2. Update `boto3_dependencies_with_python_names_fully_enriched.json`:
   - Add `nested_fields` structure to complex objects
   - Include all nested properties with proper types, operators, and descriptions
   - Follow the pattern used for similar nested structures (e.g., AccessLogSettings.item_fields)

### Step 4: Update YAML Discovery Emit Section
For nested fields that should be accessed directly:
1. Add nested fields as direct fields in the discovery `emit.item` section
   - Example: `ThrottlingBurstLimit: '{{ response.Items.DefaultRouteSettings.ThrottlingBurstLimit }}'`
   - This allows using `item.ThrottlingBurstLimit` instead of `item.DefaultRouteSettings.ThrottlingBurstLimit`
2. Update all checks to use direct field names

### Step 5: Update direct_vars.json for Validation
To ensure validation tools recognize the fields:
1. Add new nested fields to `seed_from_list` array
2. Add field definitions in `fields` object with:
   - `field_name`: The direct field name
   - `dependency_index_entity`: Entity from dependency_index
   - `operations`: List of operations that produce this field
   - `main_output_field`: Parent object name (e.g., "DefaultRouteSettings")
   - `discovery_id`: The discovery ID
   - Appropriate `operators` based on field type
   - Correct `type` (boolean, string, integer, number)
   - `possible_values` for enum fields

### Step 6: Fix Incorrect Checks
Based on metadata review:
1. **False Positives**: Update conditions to check appropriate nested fields
   - Example: Change `item.DefaultRouteSettings != null` to `item.ThrottlingBurstLimit != null`
   - Use `all` conditions for multiple field validations
2. **Incorrect Placement**: Add comment indicating service mismatch
   - Format: `# incorrect_placement: This check should be in [service] service as [reason]`

### Step 7: Mark Truly Identical Checks
For checks that are truly identical:
1. Determine replacement rule based on maximum compliance items:
   - Check metadata files for `compliance:` field
   - Count compliance items for each rule in the group
   - Choose rule with maximum compliance items as replacement
2. Add comments to all identical rules:
   - For replacement rule: `# identical: This is the replacement rule (N compliance items) - other identical rules can reference this`
   - For other rules: `# identical: Can be replaced by [replacement_rule_id] (N compliance items)`
3. If rules have 0 compliance items, choose first one alphabetically or most descriptive

### Step 8: Validate Changes
1. Validate JSON syntax for all modified files
2. Validate YAML syntax
3. Check for linter errors
4. Ensure all field references exist in direct_vars.json

## Example Workflow

```
1. Identify duplicates → Found 2 groups
2. Review metadata → Group 1: Both check throttling limits (identical intent)
3. Check if nested fields needed → Yes, need ThrottlingBurstLimit and ThrottlingRateLimit
4. Update boto3_dependencies → Add nested_fields to DefaultRouteSettings
5. Update YAML emit → Add ThrottlingBurstLimit and ThrottlingRateLimit as direct fields
6. Update direct_vars.json → Add field definitions for validation
7. Update YAML checks → Use item.ThrottlingBurstLimit instead of nested path
8. Check compliance counts → api_quota_limit_configured has 0, api_throttle_overrides_bounded has 0
9. Add comments → Mark as identical with replacement rule
10. Validate → All syntax valid, ready to use
```

## Key Principles

1. **Always check metadata first** - Understand the rule's intent before making changes
2. **Enhance schema files** - Update boto3_dependencies and direct_vars for proper validation
3. **Use direct field names** - Prefer `item.FieldName` over `item.ParentObject.FieldName` when possible
4. **Document limitations** - Add comments for incorrect placements or proxy checks
5. **Maximize compliance coverage** - Use rule with most compliance items as replacement
6. **Maintain validation** - Ensure all fields exist in direct_vars.json for validation tools

## Output Format

Provide:
1. Summary of duplicate groups found
2. Analysis with metadata context
3. List of enhancements made (boto3_dependencies, direct_vars, YAML)
4. Final duplicate groups with replacement rules identified
5. All files updated with proper validation

