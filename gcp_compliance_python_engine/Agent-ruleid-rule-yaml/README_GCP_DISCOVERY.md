# GCP SDK Auto-Discovery and Catalog Generation

## Overview

This script automatically discovers all GCP services from installed `google-cloud-*` Python SDK packages and generates comprehensive enriched catalogs.

## Purpose

The script discovers services by:
1. Scanning installed `google-cloud-*` packages
2. Introspecting client classes and methods
3. Extracting operations and parameters
4. Enriching with field metadata (compliance categories, operators, types)
5. Generating consolidated and per-service JSON files

## Prerequisites

### Install GCP SDK Packages

You have several options:

#### Option 1: Install using requirements file
```bash
cd gcp_compliance_python_engine
pip install -r gcp_sdk_requirements.txt
```

#### Option 2: Install common packages manually
```bash
pip install google-cloud-storage google-cloud-compute google-cloud-container \
            google-cloud-bigquery google-cloud-dns google-cloud-iam \
            google-cloud-kms google-cloud-logging google-cloud-monitoring
```

#### Option 3: Install all available packages (may take time)
```bash
# This will attempt to install all google-cloud-* packages
./install_gcp_sdk_packages.sh
```

## Usage

### Run Discovery

```bash
cd gcp_compliance_python_engine/Agent-ruleid-rule-yaml
python3 discover_and_generate_all_gcp_services.py
```

### Output

The script generates:

1. **Consolidated File**:
   - `pythonsdk-database/gcp/gcp_dependencies_with_python_names_fully_enriched.json`
   - Contains all services in one file

2. **Per-Service Files**:
   - `pythonsdk-database/gcp/<service_name>/gcp_dependencies_with_python_names_fully_enriched.json`
   - Individual files for each service

3. **Service List**:
   - `pythonsdk-database/gcp/all_services.json`
   - Summary of discovered services

## How It Works

### 1. Package Discovery
- Scans `google.cloud.*` packages
- Extracts service names from package paths
- Filters out utility packages (core, common, auth, etc.)

### 2. Service Introspection
- Imports each service package
- Finds client classes (contains "Client" or "Service" in name)
- Extracts public methods from client classes

### 3. Operation Extraction
- Identifies operation types:
  - **Independent**: list, get, describe operations (read-only)
  - **Dependent**: create, update, delete operations (modify state)
- Extracts method signatures (parameters, types)
- Categorizes parameters as required or optional

### 4. Field Enrichment
- Uses `enrich_gcp_api_fields.py` to add metadata:
  - `compliance_category`: identity, security, network, etc.
  - `operators`: equals, not_equals, contains, etc.
  - `type`: string, integer, boolean, etc.
  - `security_impact`: high, medium, low
- Adds common GCP response fields (kind, id, name, selfLink, etc.)
- Applies service-specific field patterns

### 5. Catalog Generation
- Organizes operations by resource type
- Groups into independent/dependent operations
- Calculates operation counts
- Formats to match existing GCP catalog structure

## Output Format

Each service follows this structure:

```json
{
  "storage": {
    "service": "storage",
    "module": "google.cloud.storage",
    "total_operations": 81,
    "resources": {
      "buckets": {
        "independent": [
          {
            "operation": "list",
            "python_method": "list_buckets",
            "yaml_action": "list_buckets",
            "required_params": ["project"],
            "optional_params": {
              "maxResults": {
                "type": "integer",
                "description": "Maximum number of results"
              }
            },
            "item_fields": {
              "name": {
                "type": "string",
                "compliance_category": "identity",
                "operators": ["equals", "not_equals", "contains", "in"]
              },
              "id": {
                "type": "string",
                "compliance_category": "identity",
                "operators": ["equals", "not_equals", "exists"]
              }
            }
          }
        ],
        "dependent": [...]
      }
    }
  }
}
```

## Troubleshooting

### No packages found
- Ensure you've installed at least one `google-cloud-*` package
- Check that packages are installed in the correct Python environment
- Try: `python3 -c "import google.cloud.storage; print('OK')"`

### Import errors
- Some packages may require authentication setup
- Missing dependencies: install `google-cloud-core`, `google-auth`
- Version conflicts: ensure compatible versions

### No operations found for a service
- The service may not follow standard client patterns
- Check if the package has a different structure
- Manual inspection may be needed

## Integration with Existing Catalog

The script generates files compatible with the existing GCP database structure:
- Uses same file naming convention
- Matches JSON structure format
- Can be merged with existing Discovery API-based catalogs

## Next Steps

After running discovery:
1. Review generated files for completeness
2. Compare with existing catalog
3. Merge or update as needed
4. Validate enrichment quality
5. Test with compliance engine

## Notes

- Discovery is based on installed packages, not all available services
- Some services may need manual review/adjustment
- Field enrichment uses patterns and may need service-specific customization
- The script preserves existing data when merging

