# Placeholder Fix Summary

## Problem
YAML rule files contained unresolved placeholders:
- `PARENT_DISCOVERY` - Should be replaced with actual parent discovery ID
- `FIELD_NAME` - Should be replaced with actual field name from parent discovery

These placeholders caused validation errors during scans (e.g., "Invalid bucket name '{{ item.FIELD_NAME }}'").

## Solution

### 1. Fix Script (`fix_placeholders.py`)
Created a script to fix existing placeholders across all services:

**Features:**
- Automatically detects services with placeholders
- Resolves `PARENT_DISCOVERY` → actual parent discovery ID
- Resolves `FIELD_NAME` → actual field name from parent emit
- Supports dry-run mode for testing
- Can target specific services

**Usage:**
```bash
# Dry run (see what would be fixed)
python fix_placeholders.py --dry-run

# Fix all services
python fix_placeholders.py

# Fix specific service
python fix_placeholders.py --service s3
```

**Results:**
- Fixed 66 placeholders across 14 services
- 41 PARENT_DISCOVERY fixes
- 25 FIELD_NAME fixes

### 2. Agent Generator Improvements (`agent4_yaml_generator.py`)
Updated the YAML generator to resolve placeholders during generation:

**Improvements:**
1. **Enhanced parent discovery resolution:**
   - Better field matching patterns
   - Extracts identifier fields from parent emit structure
   - Handles template extraction (e.g., `{{ resource.Name }}` → `name`)

2. **Smart field name resolution:**
   - Pattern 1: Exact match (case-insensitive)
   - Pattern 2: Parameter ends with field name (e.g., `bucketName` → `name`)
   - Pattern 3: Field name in parameter
   - Pattern 4: Special cases (e.g., `Bucket` → `name` for S3)

3. **Fallback mechanisms:**
   - Uses identifier field from parent emit if matching fails
   - Falls back to common fields (`id`, `name`) if needed

**Key Changes:**
- `generate_discovery_for_function()` now accepts optional `parent_discovery_id` and `parent_field_name`
- Second pass now extracts field names from parent emit templates
- Better error handling and warnings for unmatched fields

## Fixed Services

| Service | PARENT_DISCOVERY | FIELD_NAME | Total |
|---------|-----------------|------------|-------|
| s3 | 11 | 12 | 23 |
| guardduty | 5 | 6 | 11 |
| budgets | 2 | 5 | 7 |
| quicksight | 7 | 0 | 7 |
| ebs | 3 | 0 | 3 |
| glacier | 3 | 0 | 3 |
| apigatewayv2 | 2 | 0 | 2 |
| firehose | 1 | 1 | 2 |
| sqs | 2 | 0 | 2 |
| transfer | 1 | 1 | 2 |
| workflows | 2 | 0 | 2 |
| codeartifact | 1 | 0 | 1 |
| opensearch | 1 | 0 | 1 |

## Verification

After fixes:
- ✅ No `PARENT_DISCOVERY` placeholders in active YAML files
- ✅ No `FIELD_NAME` placeholders in active YAML files
- ✅ All parent discoveries properly linked
- ✅ All field names correctly resolved

## Future Prevention

The updated `agent4_yaml_generator.py` will now:
1. Resolve placeholders during generation
2. Extract field names from parent emit structures
3. Use smart matching patterns
4. Provide warnings for unmatched fields

This ensures future generated YAML files won't have unresolved placeholders.


