# Filter direct_vars.json to Read-Only Operations

## Recommendation: ✅ **YES - Filter to Read-Only Operations**

For CSPM (Cloud Security Posture Management) use cases, filtering `direct_vars.json` to only include fields from read operations is **strongly recommended**.

## Why Filter?

### Current State

- **77.5%** of fields already come from read operations
- **1.2%** of fields come from write operations
- **21.3%** of fields have no operations listed (kept by default)

### Benefits for CSPM

1. **Clear Mapping**: All fields map directly to read operations that can discover resources
2. **100% Traceability**: All fields can trace back to dependency_index.json and root operations
3. **No Confusion**: Eliminates write operation fields that don't apply to read-only discovery
4. **Simplified Model**: Cleaner data model focused on what CSPM tools actually need
5. **Matches Use Case**: CSPM tools query/discover existing resources - they don't create/update/delete

## Impact Analysis

### Fields Affected

- **Total Fields**: 35,749
- **Would Be Kept**: 34,843 (97.5%)
- **Would Be Removed**: 906 (2.5%)

### Minimal Impact

Only **906 fields (2.5%)** would be removed, all from write operations that CSPM tools don't need.

## How to Filter

### Option 1: Use the Filter Script (Recommended)

```bash
# Dry run first to see what would be changed
python3 filter_direct_vars_read_only.py --dry-run

# Apply the filter (creates backups automatically)
python3 filter_direct_vars_read_only.py

# Apply without creating backups (faster but no rollback)
python3 filter_direct_vars_read_only.py --no-backup
```

The script will:
- ✅ Create backups (`direct_vars.json.backup`)
- ✅ Filter out fields from write operations only
- ✅ Keep all fields from read operations
- ✅ Keep fields with no operations listed (assumed read-only)

### Option 2: Manual Review

If you want more control, you can manually review and filter based on the analysis report:

```bash
python3 analyze_direct_vars_operation_types.py
```

## Validation After Filtering

After filtering, validate that all fields are traceable:

```bash
# Validate traceability
python3 validate_direct_vars_traceability.py

# Validate read operations coverage
python3 validate_read_operations_dependency_index.py
```

Expected results after filtering:
- ✅ **100% of fields have dependency_index_entity**
- ✅ **100% are in dependency_index.json**
- ✅ **100% have read operations**
- ✅ **~95-98% have root operations** (some may require dependencies)

## Services Most Affected

Services with most write operation fields (would be removed):

| Service | Fields Removed | Percentage |
|---------|---------------|------------|
| geo-places | 18 | 66.7% |
| mediaconvert | 31 | 51.7% |
| wisdom | 29 | 45.3% |
| braket | 23 | 45.1% |
| marketplace-agreement | 9 | 37.5% |
| iotthingsgraph | 17 | 37.0% |
| qconnect | 37 | 29.6% |
| servicecatalog | 29 | 23.6% |

**Note**: These services have a higher percentage of write operation fields, but the absolute numbers are still small.

## Rollback

If you need to rollback after filtering:

```bash
# For each service directory
cd <service_dir>
mv direct_vars.json.backup direct_vars.json
```

Or use a script to restore all backups:

```bash
# Restore all backups
find . -name "direct_vars.json.backup" -exec sh -c 'mv "$1" "${1%.backup}"' _ {} \;
```

## Recommendations

1. ✅ **Filter to Read-Only**: Recommended for CSPM use cases
2. ✅ **Create Backups**: Always backup before filtering (script does this automatically)
3. ✅ **Validate After**: Run validation scripts to confirm 100% traceability
4. ✅ **Document**: Document that direct_vars.json now contains only read operations

## Scripts Available

1. **`analyze_direct_vars_operation_types.py`**
   - Analyzes which fields come from read vs write operations
   - Generates detailed report

2. **`filter_direct_vars_read_only.py`**
   - Filters direct_vars.json to read-only operations
   - Creates backups automatically
   - Supports dry-run mode

3. **`validate_direct_vars_traceability.py`**
   - Validates that all fields can trace to read operations
   - Checks dependency_index.json coverage

4. **`validate_read_operations_dependency_index.py`**
   - Validates read operations dependency index coverage
   - Ensures all read operation entities are present

## Next Steps

1. Review the analysis: `python3 analyze_direct_vars_operation_types.py`
2. Dry run the filter: `python3 filter_direct_vars_read_only.py --dry-run`
3. Apply the filter: `python3 filter_direct_vars_read_only.py`
4. Validate results: `python3 validate_direct_vars_traceability.py`
5. Update documentation to reflect that direct_vars.json now contains only read operations

