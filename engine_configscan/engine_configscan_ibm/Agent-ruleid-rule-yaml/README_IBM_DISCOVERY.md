# IBM Cloud SDK Auto-Discovery and Catalog Generation

## Overview

This script automatically discovers all IBM Cloud services from installed SDK packages and generates comprehensive catalogs with full enrichment (parameters, output fields, item fields) similar to AWS format.

## Features

- **Automatic Discovery**: Discovers services from installed `ibm_*` packages
- **Service Introspection**: Extracts operations from service classes (VpcV1, IamIdentityV1, etc.)
- **Full Enrichment**: Adds required_params, optional_params, output_fields, item_fields with metadata
- **Compliance Categories**: Automatically categorizes fields (identity, security, network, availability)
- **Per-Service Files**: Creates individual service files in addition to consolidated file

## Installation

### Step 1: Install IBM Cloud SDK Packages

```bash
# Install all IBM SDK packages
pip install -r requirements_ibm_sdk.txt

# Or install individually
pip install ibm-vpc ibm-platform-services ibm-schematics ibm-cloud-sdk-core
```

### Step 2: Run Discovery

```bash
cd ibm_compliance_python_engine/Agent-ruleid-rule-yaml
python3 discover_and_generate_all_ibm_services.py
```

### Alternative: Use Installation Script

```bash
cd ibm_compliance_python_engine
./install_and_discover_ibm_sdk.sh
```

## Output Structure

The script generates:

```
pythonsdk-database/ibm/
├── ibm_dependencies_with_python_names_fully_enriched.json  # Main consolidated file
└── <service_name>/
    └── ibm_dependencies_with_python_names_fully_enriched.json  # Per-service file
```

## Enrichment Format

Each operation is enriched with:

```json
{
  "operation": "list_instances",
  "python_method": "list_instances",
  "yaml_action": "list-instances",
  "required_params": [],
  "optional_params": ["limit", "start", "resource_group_id"],
  "total_optional": 3,
  "output_fields": {
    "instances": {
      "type": "array",
      "description": "List of vpc instances",
      "compliance_category": "general",
      "operators": ["contains", "not_empty", "exists"]
    },
    "next_token": {
      "type": "string",
      "description": "Pagination token",
      "compliance_category": "general",
      "operators": ["equals", "not_equals", "contains"],
      "security_impact": "high"
    }
  },
  "main_output_field": "instances",
  "item_fields": {
    "id": {
      "type": "string",
      "description": "Resource identifier",
      "compliance_category": "identity",
      "operators": ["equals", "not_equals", "contains", "in", "exists"]
    },
    "name": {
      "type": "string",
      "description": "Resource name",
      "compliance_category": "identity",
      "operators": ["equals", "not_equals", "contains", "in"]
    },
    "status": {
      "type": "string",
      "description": "Resource status",
      "compliance_category": "general",
      "operators": ["equals", "not_equals", "in"]
    }
  }
}
```

## Supported Services

The script automatically discovers services from installed packages. Common services include:

- **VPC** (ibm-vpc)
- **Platform Services** (ibm-platform-services)
- **Schematics** (ibm-schematics)
- **Watson** (ibm-watson)
- **Cloud Databases** (ibm-cloud-databases)
- **Key Protect** (ibm-key-protect)
- **Secrets Manager** (ibm-secrets-manager)
- **Container Registry** (ibm-container-registry)
- **Code Engine** (ibm-code-engine)
- And more...

## How It Works

1. **Package Discovery**: Scans for installed `ibm_*` packages using pkgutil
2. **Service Class Detection**: Finds service classes (VpcV1, IamIdentityV1, etc.)
3. **Operation Extraction**: Introspects service classes to find all methods
4. **Parameter Analysis**: Extracts required and optional parameters from method signatures
5. **Field Inference**: Infers output_fields and item_fields from operation names
6. **Enrichment**: Adds compliance categories, operators, and metadata
7. **File Generation**: Creates consolidated and per-service JSON files

## Troubleshooting

### No Services Discovered

If no services are found:

1. **Check Installation**:
   ```bash
   pip list | grep ibm
   ```

2. **Install Missing Packages**:
   ```bash
   pip install ibm-vpc ibm-platform-services
   ```

3. **Check Python Path**:
   Ensure you're using the correct Python environment

### Import Errors

If you see import errors:

1. **Install Core SDK**:
   ```bash
   pip install ibm-cloud-sdk-core
   ```

2. **Check Package Names**:
   Some packages use different names (e.g., `ibmcloudsql` vs `ibm-cloud-sql`)

## Comparison with AWS Format

The IBM database now matches AWS enrichment format:

| Field | AWS | IBM | Status |
|------|-----|-----|---------|
| required_params | ✅ | ✅ | Complete |
| optional_params | ✅ | ✅ | Complete |
| output_fields | ✅ | ✅ | Complete |
| item_fields | ✅ | ✅ | Complete |
| compliance_category | ✅ | ✅ | Complete |
| operators | ✅ | ✅ | Complete |
| main_output_field | ✅ | ✅ | Complete |

## Next Steps

After running discovery:

1. **Review Generated Files**: Check `pythonsdk-database/ibm/` for output
2. **Verify Enrichment**: Use the audit script to check completeness
3. **Update Services**: Re-run discovery when new SDK packages are installed
4. **Use in Rules**: The enriched data can be used for compliance rule generation

## Related Files

- `discover_and_generate_all_ibm_services.py` - Main discovery script
- `enrich_ibm_fields.py` - Field enrichment utilities
- `requirements_ibm_sdk.txt` - Required packages
- `install_and_discover_ibm_sdk.sh` - Installation script

