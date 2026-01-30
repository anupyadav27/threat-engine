# Duplicate Check Validation - Quick Reference Prompt

**Add this to your initial prompt:**

```
Please validate and fix duplicate compliance checks using this comprehensive process:

1. IDENTIFY: Find all checks with identical conditions (same for_each, var, op, value)

2. REVIEW WITH METADATA: For each duplicate group:
   - Load metadata files for each rule_id
   - Understand rule intent and requirement
   - Classify as: Truly Identical / False Positive / Incorrect Placement

3. ENHANCE SCHEMA: If nested fields needed:
   - Update boto3_dependencies_with_python_names_fully_enriched.json with nested_fields
   - Add nested fields to YAML discovery emit section as direct fields
   - Update direct_vars.json (seed_from_list + fields object) for validation

4. FIX FALSE POSITIVES: Update conditions to check appropriate nested fields using direct names

5. MARK IDENTICAL: 
   - Count compliance items in metadata for each rule
   - Choose rule with MAX compliance items as replacement
   - Add comments: "# identical: Can be replaced by [rule_id] (N compliance items)"
   - Mark replacement rule: "# identical: This is the replacement rule (N compliance items)"

6. MARK INCORRECT PLACEMENT: Add "# incorrect_placement: Should be in [service] service as [reason]"

7. VALIDATE: Check JSON/YAML syntax, linter errors, ensure fields exist in direct_vars.json
```

**Key Principles:**
- Always check metadata first to understand rule intent
- Use direct field names (item.FieldName) when possible
- Update both boto3_dependencies AND direct_vars.json for validation
- Choose replacement rule based on maximum compliance items
- Document limitations with comments

