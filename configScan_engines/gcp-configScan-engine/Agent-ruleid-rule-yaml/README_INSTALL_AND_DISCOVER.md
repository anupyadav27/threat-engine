# GCP SDK Installation and Discovery Guide

## Quick Start

### Option 1: Automated Script (Recommended)
```bash
cd gcp_compliance_python_engine/Agent-ruleid-rule-yaml
./install_and_discover_gcp.sh
```

This script will:
1. Discover installed packages
2. Install common GCP SDK packages (25+ packages)
3. Run service discovery automatically

### Option 2: Python Script with Options
```bash
cd gcp_compliance_python_engine/Agent-ruleid-rule-yaml

# Discover only (no installation)
python3 discover_and_install_gcp_sdks.py --no-install

# Install common packages automatically
python3 discover_and_install_gcp_sdks.py --install-common --run-discovery

# Install ALL packages (takes longer)
python3 discover_and_install_gcp_sdks.py --install-all --run-discovery
```

### Option 3: Manual Installation
```bash
# Install from requirements file
cd gcp_compliance_python_engine
pip install -r gcp_sdk_requirements.txt

# Then run discovery
cd Agent-ruleid-rule-yaml
python3 discover_and_generate_all_gcp_services.py
```

## What Gets Installed

### Common Packages (25 packages)
- Storage: `google-cloud-storage`, `google-cloud-bigquery`, `google-cloud-firestore`
- Compute: `google-cloud-compute`, `google-cloud-container`, `google-cloud-functions`
- Security: `google-cloud-iam`, `google-cloud-kms`, `google-cloud-secret-manager`
- Monitoring: `google-cloud-logging`, `google-cloud-monitoring`
- And more...

### All Packages (99+ packages)
The full list includes all available `google-cloud-*` packages from PyPI.

## Discovery Process

After installation, the discovery script will:

1. **Scan installed packages** - Finds all `google-cloud-*` packages
2. **Introspect clients** - Extracts client classes and methods
3. **Extract operations** - Identifies list/get/create/update/delete operations
4. **Enrich with metadata** - Adds compliance categories, operators, field types
5. **Generate JSON files**:
   - `pythonsdk-database/gcp/gcp_dependencies_with_python_names_fully_enriched.json` (consolidated)
   - `pythonsdk-database/gcp/<service_name>/gcp_dependencies_with_python_names_fully_enriched.json` (per-service)

## Troubleshooting

### No packages found after installation
- Verify installation: `python3 -m pip list | grep google-cloud`
- Check Python environment: `which python3`
- Reinstall: `python3 -m pip install --upgrade google-cloud-storage`

### Import errors during discovery
- Install dependencies: `pip install google-cloud-core google-auth`
- Check package versions: Some packages may need specific versions

### Installation fails
- Check internet connection
- Try installing packages one by one
- Some packages may not be available in your Python version

## Output Files

After successful discovery:

```
pythonsdk-database/gcp/
├── gcp_dependencies_with_python_names_fully_enriched.json  # Main file
├── all_services.json                                       # Service list
└── <service_name>/
    └── gcp_dependencies_with_python_names_fully_enriched.json
```

## Next Steps

1. Review generated files
2. Compare with existing catalog (if any)
3. Validate enrichment quality
4. Integrate with compliance engine

