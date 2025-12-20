# AliCloud SDK Auto-Discovery and Catalog Generation

## Overview

This script automatically discovers all AliCloud services from installed SDK packages and generates comprehensive catalogs with field enrichment.

## Why Use SDK Discovery Instead of service_list.json?

1. **Automatic Discovery**: No need to manually maintain service lists
2. **Always Up-to-Date**: Discovers services from actually installed packages
3. **Complete Coverage**: Finds all services, not just those in a config file
4. **SDK-Based**: Uses the actual SDK to introspect operations

## How It Works

1. **Discovers SDK Packages**: 
   - Uses `service_list.json` as reference (if available)
   - Scans installed Python packages for `aliyun*` modules
   - Introspects `aliyunsdkcore` for available services

2. **Introspects Operations**:
   - Imports each service module
   - Discovers request classes and methods
   - Extracts operation names

3. **Generates Catalogs**:
   - Creates basic catalog with discovered operations
   - Enriches with field metadata (using `enrich_alicloud_fields.py`)
   - Prioritizes read operations (Describe, List, Get)

4. **Updates Database**:
   - Updates `pythonsdk-database/alicloud/alicloud_dependencies_with_python_names_fully_enriched.json`
   - Creates per-service folders and files
   - Merges with existing data

## Usage

### Prerequisites

Install AliCloud SDK packages:

```bash
# Install core SDK
pip install aliyun-python-sdk-core

# Install specific services (recommended)
pip install aliyun-python-sdk-ecs aliyun-python-sdk-vpc aliyun-python-sdk-oss \
            aliyun-python-sdk-ram aliyun-python-sdk-rds aliyun-python-sdk-slb \
            aliyun-python-sdk-kms

# Or install all services (if available)
pip install aliyun-python-sdk-*
```

### Run Discovery

```bash
cd alicloud_compliance_python_engine/Agent-ruleid-rule-yaml
python3 discover_and_generate_all_services.py
```

### Output

The script generates:

1. **`alicloud_sdk_catalog.json`** - Basic catalog with operations
2. **`alicloud_sdk_catalog_enhanced.json`** - Enriched with field metadata
3. **`pythonsdk-database/alicloud/alicloud_dependencies_with_python_names_fully_enriched.json`** - Main dependencies file
4. **`pythonsdk-database/alicloud/<service>/alicloud_dependencies_with_python_names_fully_enriched.json`** - Per-service files

## Service Discovery Methods

The script uses multiple methods to discover services:

1. **service_list.json** (if available) - Uses as reference for service names and SDK packages
2. **pkgutil** - Scans installed Python packages
3. **Direct Import** - Tries to import common SDK modules
4. **aliyunsdkcore introspection** - Walks core SDK to find services

## Limitations

- Requires AliCloud SDK packages to be installed
- Some services may not be discoverable if packages aren't installed
- Operation discovery depends on SDK structure (may vary by service)
- Field enrichment relies on documentation-based patterns

## Comparison with service_list.json

| Method | Pros | Cons |
|--------|------|------|
| **SDK Discovery** | Automatic, always current, finds all installed services | Requires SDK installation |
| **service_list.json** | Works without SDK, has rule counts | Manual maintenance, may be outdated |

## Best Practice

Use **both**:
- `service_list.json` as a reference for service names and priorities
- SDK discovery to actually find and introspect services
- The script combines both approaches for best results

## Troubleshooting

### No services discovered

```bash
# Check if SDK is installed
pip list | grep aliyun

# Install core SDK
pip install aliyun-python-sdk-core
```

### Import errors

Some services may have different module names:
- OSS uses `oss2` not `aliyunsdkoss`
- ACK uses `aliyunsdkcs` not `aliyunsdkack`

The script handles these automatically.

### Missing operations

If operations aren't discovered:
1. Check if the service package is installed
2. Verify the module can be imported
3. Check the SDK documentation for operation names

## Next Steps

After discovery:
1. Review generated catalogs
2. Manually add any missing operations
3. Enhance field metadata as needed
4. Run validation to ensure completeness

