# Nested Fields Improvement Guide for All Services

## Answer: Update Individual Service Files (Not All Services File)

### Why Individual Service Files?

1. **Complete Structure**: Individual service files have:
   - `fields` section (simplified field definitions)
   - `field_mappings` section (detailed field definitions with all metadata)
   - `seed_from_list` and `final_union` arrays

2. **All Services File Limitations**: The `direct_vars_all_services.json` file:
   - Only contains aggregated lists (`seed_from_list`, `final_union`)
   - Does NOT have `fields` or `field_mappings` sections
   - Appears to be generated from individual files
   - Not suitable for adding detailed field definitions

### File Locations

**Individual Service Files** (Source of Truth):
```
pythonsdk-database/aws/<service_name>/direct_vars.json
```

**All Services File** (Aggregated - Do NOT edit directly):
```
pythonsdk-database/aws/direct_vars_all_services.json
```

## Systematic Approach for All Services

### Step 1: Identify Services Needing Improvements

Use this process for each service:

1. **Check boto3_dependencies**: Look for `nested_fields` in `boto3_dependencies_with_python_names_fully_enriched.json`
2. **Check direct_vars**: Verify if nested fields exist in both `fields` and `field_mappings` sections
3. **Compare**: If boto3 has nested_fields but direct_vars doesn't, add them

### Step 2: Add to Both Sections

When adding nested fields to a service's `direct_vars.json`:

#### A. Add to `fields` section (simplified structure):
```json
"FieldName": {
  "operators": ["equals", "not_equals", ...],
  "dependency_index_entity": "service.entity_name"
}
```

#### B. Add to `field_mappings` section (detailed structure):
```json
"FieldName": {
  "field_name": "FieldName",
  "dependency_index_entity": "service.entity_name",
  "operations": ["GetOperation"],
  "main_output_field": "ParentObject",
  "operators": [...],
  "type": "string|boolean|integer|number",
  "discovery_id": "aws.service.operation",
  "for_each": null,
  "consumes": [...],
  "produces": []
}
```

#### C. Add to lists:
- Add to `seed_from_list` array
- Add to `final_union` array (if not auto-generated)

### Step 3: Prioritization Strategy

**High Priority** (Services with many nested structures):
- Services with complex configuration objects
- Services used frequently in compliance rules
- Services where you've already identified missing nested fields

**Medium Priority**:
- Services with some nested structures
- Services with recent boto3_dependencies updates

**Low Priority**:
- Services with simple flat structures
- Rarely used services

### Step 4: Validation Checklist

For each service updated:

- [ ] Fields added to `fields` section
- [ ] Fields added to `field_mappings` section  
- [ ] Fields added to `seed_from_list` array
- [ ] Fields added to `final_union` array
- [ ] JSON syntax valid
- [ ] Field types match boto3_dependencies
- [ ] Operators appropriate for field type
- [ ] dependency_index_entity matches dependency_index.json

## Example: apigatewayv2 (Completed)

We successfully added:
- `DataTraceEnabled`
- `DetailedMetricsEnabled`
- `LoggingLevel`
- `ThrottlingBurstLimit`
- `ThrottlingRateLimit`

All added to:
1. `seed_from_list` ✓
2. `final_union` ✓
3. `fields` section ✓
4. `field_mappings` section ✓

## Automation Possibilities

You could create a script to:
1. Scan all services for nested_fields in boto3_dependencies
2. Compare with direct_vars.json
3. Generate a report of missing fields
4. Auto-generate field definitions (with manual review)

However, **manual review is recommended** to ensure:
- Correct field types
- Appropriate operators
- Proper entity mappings
- Context-appropriate field definitions

## Summary

**✅ DO**: Update individual service files in `pythonsdk-database/aws/<service>/direct_vars.json`

**❌ DON'T**: Update `direct_vars_all_services.json` directly (it's aggregated/generated)

**Process**: Follow the same pattern we used for apigatewayv2:
1. Identify nested fields in boto3_dependencies
2. Add to both `fields` and `field_mappings` sections
3. Add to lists
4. Validate JSON syntax

