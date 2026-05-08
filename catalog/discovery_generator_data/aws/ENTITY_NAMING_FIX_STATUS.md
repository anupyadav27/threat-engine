# Entity Naming Fix Status

## Current State

The `fix_entity_naming_mismatches.py` script has been created and tested. Here's the current status:

### Script Status
✅ **Script created and working**
- Detects duplicated prefix patterns
- Matches entities by suffix
- Uses similarity matching for variations
- Adds entity_aliases to operation_registry.json

### Services Status

Many services already have entity aliases from previous runs or manual fixes:

- **EC2**: 542 aliases (0 missing from dependency_index - fully fixed!)
- **SageMaker**: 399 aliases (0 missing from dependency_index - fully fixed!)
- **Other services**: Various numbers of aliases

### Remaining Missing Entities

The validation report shows **8,224 missing entities** across 256 services. These fall into categories:

1. **Services with many aliases but still missing entities**: 
   - Some entities don't match any patterns in operation_registry.json
   - May need operation_registry.json updates

2. **Services with very high missing counts**:
   - `ebs`: 1,046 missing
   - `eip`: 1,046 missing  
   - `vpc`: 1,046 missing
   - `vpcflowlogs`: 1,046 missing
   - These likely share the same issue (possibly missing operations)

3. **Data quality issues**:
   - Entities like `ec2.purchase_purchase`, `ec2.result_result`
   - Generic/duplicate names that may need manual review

## How to Use the Script

### For services that need aliases:

```bash
# Check a specific service
python3 fix_entity_naming_mismatches.py --service <service_name>

# Run on all services (will skip services that already have aliases)
python3 fix_entity_naming_mismatches.py
```

### After adding aliases:

```bash
# Re-run dependency_index fix to use new aliases
python3 fix_dependency_index.py

# Validate results
python3 validate_dependency_index.py
```

## What the Script Does

1. **Detects** entities in `direct_vars.json` that don't exist in `operation_registry.json`
2. **Matches** them to similar entities using three patterns:
   - Duplicated prefix removal
   - Suffix matching
   - Similarity matching (≥75% threshold)
3. **Adds** entity aliases to `operation_registry.json`
4. **Enables** `fix_dependency_index.py` to find operations for these entities

## Limitations

The script can only fix entities that:
- Have a matching entity in operation_registry.json
- Can be matched using the pattern detection algorithms

Entities that can't be fixed:
- Don't exist in operation_registry.json at all (missing operations)
- Have no similar matches (data quality issues)
- Require manual review

## Next Steps

1. ✅ Script is ready to use
2. ✅ Many services already have aliases
3. 🔄 Remaining issues may need:
   - Operation registry updates (add missing operations)
   - Manual review for data quality issues
   - Alternative matching strategies for edge cases

