# Manual Review Auto-Fixer

Automatically fixes issues in `manual_review.json` files across service folders to reduce manual review work to near-zero.

## Overview

This tool processes service folders containing:
- `operation_registry.json`
- `adjacency.json`
- `manual_review.json`
- `validation_report.json` (optional)

It applies deterministic rules first, then optionally uses LLM assistance for remaining unresolved items.

## Features

### Part 1: Direct Variables Generation
- Generates/refreshes `direct_vars.json` from `operation_registry.json`
- Extracts read-only variables from List/Get/Describe/Search/Lookup operations
- Excludes pagination tokens (nextToken, maxResults, etc.)

### Part 2: Derived Catalog Management
- Ensures `derived_catalog.yaml` exists at repo root
- Provides seed catalog with common derived variables:
  - `is_public`, `has_findings`, `is_encrypted`, `logging_enabled`
  - `versioning_enabled`, `mfa_enabled`, `has_wildcards`
  - `tls_required`, `public_access_block_enabled`, `has_admin_permissions`

### Part 3: Deterministic Auto-Fix Rules
Applies fixes in this order:

**A) Missing/Unknown Variable Fixes**
- Checks if variable exists in `direct_vars.final_union`
- Performs fuzzy matching (case-insensitive, strip underscores)
- Falls back to derived variable mapping

**B) Derived Variable Mapping**
Maps keywords to derived variables:
- `public/wildcard/anonymous/principal/0.0.0.0` → `derived.is_public` (op: equals, value: false)
- `findings/finding/without_findings` → `derived.has_findings` (op: equals, value: false)
- `encrypt/encryption/kms/cmk` → `derived.is_encrypted` (op: equals, value: true)
- `logging/logs/cloudtrail/accesslog` → `derived.logging_enabled` (op: equals, value: true)
- `versioning/version` → `derived.versioning_enabled` (op: equals, value: true)
- `mfa` → `derived.mfa_enabled` (op: equals, value: true)
- `tls/ssl/https` → `derived.tls_required` (op: equals, value: true)
- `public_access_block` → `derived.public_access_block_enabled` (op: equals, value: true)
- `admin/full_access/star_policy` → `derived.has_admin_permissions` (op: equals, value: false)
- `wildcard on action/principal` → `derived.has_wildcards` (op: equals, value: false)

**C) Alias Suggestions**
- Detects entity alias mismatches (e.g., `analyzerArn` vs `arn`)
- Infers aliases from operation registry dependencies
- Generates `overrides.json` with entity_aliases and param_aliases

### Part 4: Optional LLM Assistance
- Only used if `--use-llm` flag is provided
- Batches unresolved items (max N per batch)
- Sends context: service_name, unresolved items, direct_vars, derived_catalog
- Applies suggestions only if confidence >= 0.80 and variable is valid

## Installation

```bash
# Install required dependencies
pip install pyyaml openai  # openai only needed if using --use-llm
```

## Usage

### Basic Usage (Deterministic Rules Only)

```bash
python tools/manual_review_fixer/fix_manual_review.py --root pythonsdk-database/aws
```

### With LLM Assistance

```bash
# Set OpenAI API key
export OPENAI_API_KEY=your-api-key-here

# Run with LLM
python tools/manual_review_fixer/fix_manual_review.py \
  --root pythonsdk-database/aws \
  --use-llm \
  --model gpt-4o-mini \
  --max-batch 50
```

## Outputs

### Per Service
- `services/<service>/direct_vars.json` - Generated/refreshed from operation_registry.json
- `services/<service>/manual_review.json` - Updated with only remaining unresolved items
- `services/<service>/fixes_applied.json` - Audit log of all fixes applied

### Repo Root
- `manual_review_global_summary.json` - Summary across all services

## Output File Formats

### fixes_applied.json
```json
{
  "service": "s3",
  "fixes": [
    {
      "type": "var_fix",
      "original": {...},
      "fix": {
        "var": "BucketName",
        "source": "direct_var"
      }
    },
    {
      "type": "derived_fix",
      "original": {...},
      "fix": {
        "var": "derived.is_public",
        "op": "equals",
        "value": "false",
        "derive_key": "aws.s3.bucketpolicy.is_public"
      }
    }
  ],
  "summary": {
    "total_fixes": 5,
    "remaining_unresolved": 2
  }
}
```

### manual_review_global_summary.json
```json
{
  "total_services": 10,
  "services": [...],
  "summary": {
    "total_fixed": 45,
    "total_remaining": 12,
    "successful": 8,
    "skipped": 1,
    "errors": 1
  }
}
```

## Safety Features

- **Never deletes existing keys** - Only adds/patches check blocks and overrides
- **Audit trail** - All changes written to `fixes_applied.json`
- **Confidence thresholds** - LLM suggestions only applied if confidence >= 0.80
- **Validation** - Only applies fixes if variable exists in direct_vars or derived_catalog

## How It Works

### Why Deterministic Rules First?

Deterministic rules are:
- **Fast** - No API calls needed
- **Reliable** - Same input always produces same output
- **Cost-effective** - No LLM costs
- **Transparent** - Easy to debug and understand

### How Derived Catalog is Used

The `derived_catalog.yaml` provides semantic mappings from keywords to derived variables. When a manual review item mentions keywords like "public access" or "encryption", the tool maps them to the appropriate derived variable with the correct operation and expected value.

### How overrides.json Helps

When the same field appears with different entity names (e.g., `analyzerArn` vs `arn`), the tool creates `overrides.json` to map aliases to canonical entity names. This helps resolve ambiguous token issues.

### Inspecting fixes_applied.json

Each service's `fixes_applied.json` contains:
- All fixes that were applied
- Original items that were fixed
- Fix details (type, source, confidence)
- Summary statistics

Use this to:
- Audit what was changed
- Understand fix patterns
- Debug issues
- Roll back if needed

## Troubleshooting

### "operation_registry.json not found"
- Ensure you're running from the correct root directory
- Check that service folders contain `operation_registry.json`

### "OpenAI API key not provided"
- Set `OPENAI_API_KEY` environment variable
- Or pass `api_key` parameter to `LLMClient`

### "No fixes applied"
- Check if manual_review.json has issues that match fix patterns
- Review `fixes_applied.json` to see what was attempted
- Consider using `--use-llm` for more complex cases

## Examples

### Example 1: Fix Missing Variable
**Input (manual_review.json):**
```json
{
  "issue": "Missing var 'BucketName' in check"
}
```

**Output (fixes_applied.json):**
```json
{
  "type": "var_fix",
  "fix": {
    "var": "BucketName",
    "source": "direct_var"
  }
}
```

### Example 2: Fix Derived Variable
**Input:**
```json
{
  "rule_id": "s3-bucket-public-access",
  "issue": "Bucket should not be publicly accessible"
}
```

**Output:**
```json
{
  "type": "derived_fix",
  "fix": {
    "var": "derived.is_public",
    "op": "equals",
    "value": "false",
    "derive_key": "aws.s3.bucketpolicy.is_public"
  }
}
```

## Contributing

When adding new fix rules:
1. Add deterministic rules first (in `ManualReviewFixer.fix_item`)
2. Update derived_catalog.yaml if adding new derived variables
3. Test with multiple services
4. Document in README

