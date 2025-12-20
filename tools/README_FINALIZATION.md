# Service Finalization Pipeline

This pipeline consolidates all AI suggestions and regenerates final service artifacts.

## Overview

The finalization process:
1. Merges AI suggestions from `fixes_applied.json` and `manual_review.json` into `overrides.json`
2. Applies confidence-based filtering (HIGH always, MEDIUM conditionally)
3. Regenerates final artifacts: `operation_registry.json`, `adjacency.json`, `validation_report.json`, `manual_review.json`
4. Cleans up intermediate files
5. Generates audit trails

## Files

- `finalize_service.py` - Finalize a single service
- `finalize_all_services.py` - Batch process all services
- `README_FINALIZATION.md` - This file

## Usage

### Finalize Single Service

```bash
python tools/finalize_service.py pythonsdk-database/aws/s3
```

This will:
- Load `overrides.json` (or create empty)
- Merge suggestions from `fixes_applied.json` and `manual_review.json`
- Apply confidence filtering
- Regenerate all final artifacts
- Clean up `fixes_applied.json` (after backup)
- Save audit files: `accepted_suggestions.json`, `rejected_suggestions.json`

### Finalize All Services

```bash
python tools/finalize_all_services.py pythonsdk-database/aws
```

This will:
- Process all service folders in the root directory
- Run `finalize_service.py` on each service
- Generate `finalization_summary_report.json` with:
  - `services_pass` - Successfully finalized
  - `services_warn` - Finalized with conflicts
  - `services_fail` - Failed to finalize
  - `services_with_conflicts` - Services with merge conflicts
  - `services_with_remaining_manual_review` - Services still needing review

## Confidence Levels

- **HIGH** (≥0.90): Always accepted
- **MEDIUM** (≥0.80): Accepted only if it reduces validation issues
- **LOW** (<0.80): Rejected

## Merge Logic

### From `fixes_applied.json`

Merges `suggested_aliases`:
- `entity_aliases` → `overrides.entity_aliases`
- `param_aliases` → `overrides.overrides.param_aliases`

### From `manual_review.json`

1. **suggested_overrides**: Merged into `overrides.overrides.produces/consumes`
2. **unresolved_items with structured evidence**: Added to `param_aliases` if evidence contains:
   - Operation prefix: `List`, `Get`, `Describe`, `Search`, `Lookup`
   - Entity identifier: `Id`, `Arn`, `Name`, `Key`, `Tag`

## Output Files

### Per Service

- `overrides.json` - Merged overrides (backed up before overwrite)
- `operation_registry.json` - Regenerated with overrides applied
- `adjacency.json` - Regenerated from updated registry
- `validation_report.json` - Regenerated validation results
- `manual_review.json` - Only remaining unresolved issues
- `accepted_suggestions.json` - Audit trail of accepted suggestions
- `rejected_suggestions.json` - Audit trail of rejected suggestions
- `finalize_result.json` - Processing result (for batch summary)

### Root Directory

- `finalization_summary_report.json` - Batch processing summary

## Safety Features

1. **Backups**: All files are backed up (`.bak`) before overwriting
2. **Error Handling**: If finalization fails, intermediate files are preserved
3. **Conflict Tracking**: All merge conflicts are recorded
4. **Audit Trails**: All accepted/rejected suggestions are logged

## Example Output

```
======================================================================
Finalizing service: s3
======================================================================
  ✓ Source spec: boto3_dependencies_with_python_names_fully_enriched.json
  ✓ Overrides loaded/created
  📝 Merging fixes_applied.json...
     Merged 5 items, 0 conflicts
  📝 Merging manual_review.json...
     Merged 3 items, 1 conflicts
  ✓ Saved overrides.json
  🔄 Regenerating artifacts...
     ✓ Regenerated operation_registry.json
     ✓ Regenerated adjacency.json
     ✓ Regenerated validation_report.json
     ✓ Regenerated manual_review.json
  🗑️  Cleaned up fixes_applied.json
  ✅ Finalization complete

======================================================================
Summary for s3:
  Status: success
  Merged aliases: 5
  Merged params: 3
  Accepted suggestions: 8
  Rejected suggestions: 2
  Conflicts: 1
======================================================================
```

## Troubleshooting

### Error: Source spec not found

Ensure the service folder contains:
- `boto3_dependencies_with_python_names_fully_enriched.json`, OR
- `{service}_dependencies_with_python_names_fully_enriched.json`, OR
- `{service}_spec.json`

### Error: Cannot regenerate artifacts

The script requires `build_dependency_graph.py` functions. Ensure:
- `pythonsdk-database/aws/tools/build_dependency_graph.py` exists
- Functions are importable: `process_service_spec`, `build_adjacency`, `validate_service`, `generate_manual_review`

### Conflicts detected

Conflicts occur when:
- Same alias maps to different canonical entities
- Same param has conflicting candidate lists

Review `accepted_suggestions.json` and `rejected_suggestions.json` to resolve.

## Integration with Existing Tools

This pipeline integrates with:
- `tools/manual_review_fixer/` - Generates `fixes_applied.json`
- `pythonsdk-database/aws/tools/build_dependency_graph.py` - Regenerates artifacts
- Validation pipeline - Validates final artifacts

## Next Steps

After finalization:
1. Review `finalization_summary_report.json`
2. Check services with conflicts
3. Manually resolve remaining issues in `manual_review.json`
4. Re-run finalization if needed

