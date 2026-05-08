# Fix Entity Naming Mismatches

## Overview

This script (`fix_entity_naming_mismatches.py`) detects and fixes entity naming mismatches between `direct_vars.json` and `operation_registry.json`.

## The Problem

Some fields in `direct_vars.json` reference entities that don't exactly match entity names in `operation_registry.json`, causing them to not be found when building `dependency_index.json`. Common issues:

1. **Duplicated Prefix Pattern**: `connection_connection_id` vs `connection_id`
2. **Different Parent Context**: `prefix_list_prefix_list_name` vs `prefix_list_name`
3. **Naming Variations**: Slight differences in how entities are named between the two files

## Solution

The script detects these mismatches and adds `entity_aliases` to `operation_registry.json` to map the `direct_vars.json` entity names to the correct `operation_registry.json` entity names.

## Usage

### Detect mismatches (dry run)
```bash
python3 fix_entity_naming_mismatches.py --dry-run
```

### Fix a specific service
```bash
python3 fix_entity_naming_mismatches.py --service ec2
```

### Fix all services
```bash
python3 fix_entity_naming_mismatches.py
```

### Fix with limit (test on a few services first)
```bash
python3 fix_entity_naming_mismatches.py --limit 10
```

## How It Works

1. **Detect Missing Entities**: Finds entities in `direct_vars.json` that don't exist in `operation_registry.json`
2. **Pattern Matching**: Uses three strategies to find matching entities:
   - **Duplicated Prefix Detection**: Removes duplicated prefixes (e.g., `connection_connection_id` → `connection_id`)
   - **Suffix Matching**: Matches entities with the same suffix (last 2 parts)
   - **Similarity Matching**: Uses string similarity (≥75% threshold) to find similar entities
3. **Add Aliases**: Adds mappings to `operation_registry.json`'s `entity_aliases` section
4. **Re-run Fix Script**: After adding aliases, run `fix_dependency_index.py` to use them

## Example

**Before:**
- `direct_vars.json` field uses: `ec2.connection_connection_established_time`
- `operation_registry.json` has: `ec2.connection_established_time`
- Result: Entity not found, can't create dependency_index entry

**After running script:**
- Added alias: `"ec2.connection_connection_established_time": "ec2.connection_established_time"`
- `fix_dependency_index.py` can now find the entity via the alias
- Dependency_index entry gets created correctly

## Results

After running on all services:
- Detected thousands of naming mismatches
- Added entity aliases to map them correctly
- Enabled automatic fixing of dependency_index entries

## Next Steps

After running this script:

1. **Verify aliases were added**: Check `operation_registry.json` files for new entries in `entity_aliases`
2. **Re-run fix script**: Run `fix_dependency_index.py` to use the new aliases
3. **Validate**: Run `validate_dependency_index.py` to check remaining missing entities

## Files Generated

- `entity_naming_mismatch_report.json`: Detailed report of all mismatches found and fixes applied

## Notes

- The script preserves existing aliases (doesn't overwrite)
- Only adds aliases when a clear match is found (high confidence)
- Skips entities that already have aliases
- Creates backups (via git) before modifying files

