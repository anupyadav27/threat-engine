# Prerequisites Generator

## Overview

The Prerequisites Generator extracts direct variables from AWS service dependency graphs and generates derived variable catalogs. It processes per-service `operation_registry.json` files to identify available variables from READ operations.

## What It Generates

### 1. `direct_vars.json` (Per Service)

Generated for each service folder: `services/<service_name>/direct_vars.json`

**What it contains:**
- Variables extracted from READ operations (List, Get, Describe, Search, Lookup)
- Separated into:
  - `seed_from_list`: Variables from List/Search/Lookup operations
  - `enriched_from_get_describe`: Variables from Get/Describe operations
  - `final_union`: Combined set of all variables

**How it's derived:**
- Only considers operations where the operation name starts with: `List`, `Get`, `Describe`, `Search`, or `Lookup`
- Extracts `item_fields` keys from these operations
- Excludes pagination tokens (`nextToken`, `maxResults`, and keys containing "token")
- Preserves original casing from the registry

**Example:**
```json
{
  "service": "accessanalyzer",
  "seed_from_list": ["arn", "createdAt", "name", "status", "type"],
  "enriched_from_get_describe": ["arn", "createdAt", "name", "status", "type", "lastAnalyzedResource"],
  "final_union": ["arn", "createdAt", "lastAnalyzedResource", "name", "status", "type"],
  "source": {
    "operation_registry": "services/accessanalyzer/operation_registry.json",
    "read_ops_rule": "operation name startswith List/Get/Describe/Search/Lookup",
    "excluded_keys": ["nextToken", "maxResults"]
  }
}
```

### 2. `direct_vars_all_services.json` (Aggregated)

Generated at the repository root, combines all per-service `direct_vars.json` files.

**Schema:**
```json
{
  "generated_at": "2024-01-01T00:00:00Z",
  "services": {
    "accessanalyzer": {
      "seed_from_list": [...],
      "enriched_from_get_describe": [...],
      "final_union": [...]
    },
    ...
  }
}
```

### 3. `derived_catalog.yaml` (Seed Catalog)

Generated at the repository root if it doesn't already exist. Contains a seed library of common derived variables used in AWS security/compliance checks.

**Initial variables included:**
- `is_public`: Resource is publicly accessible
- `has_findings`: Resource has security findings
- `is_encrypted`: Resource data is encrypted at rest
- `logging_enabled`: Resource has logging enabled
- `versioning_enabled`: Resource has versioning enabled
- `mfa_enabled`: Multi-factor authentication is enabled
- `has_wildcards`: Resource policy contains wildcard permissions
- `tls_required`: TLS/SSL encryption is required
- `public_access_block_enabled`: Public access block is enabled
- `has_admin_permissions`: Resource has administrative permissions

**Schema:**
```yaml
is_public:
  meaning: "Resource is publicly accessible (no authentication required)"
  default:
    op: "check_public_access"
    value: "false"
  hints: ["public", "anonymous", "wildcard", "publicly accessible"]
```

**Note:** If `derived_catalog.yaml` already exists, it will NOT be overwritten.

### 4. `derived_candidates_report.json` (Analysis Report)

Generated at the repository root by scanning all `manual_review.json` files across services.

**What it shows:**
- Aggregated statistics from manual review items
- Counts by reason/category
- Suggested derived concepts based on rule_id tokens
- Examples of manual review items with suggested derived variables

**Schema:**
```json
{
  "generated_at": "2024-01-01T00:00:00Z",
  "total_services_scanned": 411,
  "total_manual_review_items": 1234,
  "by_reason": {
    "missing_var": 500,
    "needs_derivation": 300,
    ...
  },
  "suggested_derived_concepts": {
    "is_public": 150,
    "has_findings": 100,
    "is_encrypted": 80,
    ...
  },
  "examples": [
    {
      "service": "s3",
      "rule_id": "s3.bucket.public_access",
      "reason": "missing_var",
      "suggested_derived": "is_public",
      "file_path": "rules/s3.yaml",
      "tokens": ["bucket", "public", "access"]
    }
  ]
}
```

**Derived concept suggestions:**
The tool analyzes rule_id tokens and suggests derived concepts:
- Tokens like `["public", "wildcard", "anonymous"]` → `is_public`
- Tokens like `["finding", "findings"]` → `has_findings`
- Tokens like `["encrypt", "kms", "encryption"]` → `is_encrypted`
- Tokens like `["logging", "log"]` → `logging_enabled`
- And more...

## Usage

### Basic Usage

```bash
python tools/prereq_generator/generate_prereqs.py --root services
```

### With Custom Output Directory

```bash
python tools/prereq_generator/generate_prereqs.py --root services --output output/
```

### Expected Directory Structure

```
services/
├── accessanalyzer/
│   ├── operation_registry.json
│   ├── manual_review.json (optional)
│   └── direct_vars.json (generated)
├── account/
│   └── ...
└── ...

direct_vars_all_services.json (generated at root)
derived_catalog.yaml (generated at root if doesn't exist)
derived_candidates_report.json (generated at root)
```

## Requirements

- Python 3.11+
- Standard library only (no external dependencies required)
- Optional: `ruamel.yaml` or `PyYAML` for YAML support (falls back to plain text if not available)

## Output Summary

After running, the tool prints:
- Number of services processed
- Number of services skipped (with reasons)
- Location of all generated outputs

## Error Handling

The tool is robust and will:
- Skip services missing `operation_registry.json`
- Skip services with invalid JSON (logs warning)
- Continue processing even if some services fail
- Report all skipped services in the summary

## Integration

This tool is designed to work with the dependency graph generator outputs:
- Reads from `operation_registry.json` (generated by `build_dependency_graph.py`)
- Optionally reads from `manual_review.json` (generated by `build_dependency_graph.py`)
- Generates prerequisites for downstream tools that need to know available variables

## Notes

- **Direct vars** are extracted from READ operations only (List, Get, Describe, Search, Lookup)
- **Pagination tokens** are automatically excluded
- **Original casing** is preserved from the operation registry
- **Derived catalog** is only created if it doesn't exist (won't overwrite existing)
- **Manual review parsing** handles multiple JSON formats gracefully

