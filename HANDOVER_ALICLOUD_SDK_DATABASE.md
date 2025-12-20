# AliCloud SDK Database - Handover Document

## Overview

This document provides a complete guide for creating and maintaining the AliCloud SDK database, which can be used as a template for other Cloud Service Providers (CSPs): Azure, GCP, Kubernetes, IAM, and OCI.

## Purpose

The AliCloud SDK database contains:
- Complete service catalogs with operations
- Field metadata and enrichment
- Python SDK method mappings
- Per-service and consolidated dependency files

## Repository Structure

```
pythonsdk-database/alicloud/
├── alicloud_dependencies_with_python_names_fully_enriched.json  # Main consolidated file
├── all_services.json                                           # Service list with counts
├── ALL_SERVICES_FINAL.txt                                      # Human-readable list
└── <service_name>/
    └── alicloud_dependencies_with_python_names_fully_enriched.json  # Per-service file
```

## Key Files and Scripts

### 1. Discovery Script
**Location:** `alicloud_compliance_python_engine/Agent-ruleid-rule-yaml/discover_and_generate_all_services.py`

**Purpose:** Automatically discovers all AliCloud services from installed SDK packages and generates enriched catalogs.

**Key Features:**
- Discovers services from installed `aliyunsdk*` packages
- Extracts operations from request modules (pattern: `package.request.v20200706`)
- Generates service catalogs with field metadata
- Enriches catalogs with compliance categories
- Updates consolidated and per-service files

**Usage:**
```bash
# Activate virtual environment
source venv_alicloud/bin/activate

# Run discovery
python3 alicloud_compliance_python_engine/Agent-ruleid-rule-yaml/discover_and_generate_all_services.py
```

### 2. Service List Configuration
**Location:** `alicloud_compliance_python_engine/config/service_list.json`

**Purpose:** Reference list of all AliCloud services with SDK package names.

**Structure:**
```json
{
  "version": "1.0",
  "provider": "alicloud",
  "services": [
    {
      "name": "ecs",
      "sdk": "aliyun-python-sdk-ecs",
      "description": "Elastic Compute Service",
      "rule_count": 230
    }
  ]
}
```

### 3. Virtual Environment
**Location:** `venv_alicloud/`

**Purpose:** Isolated Python environment for AliCloud SDK packages.

**Setup:**
```bash
python3 -m venv venv_alicloud
source venv_alicloud/bin/activate
pip install aliyun-python-sdk-core
```

## Process Flow

### Step 1: Install SDK Packages

```bash
# Activate virtual environment
source venv_alicloud/bin/activate

# Install core SDK
pip install aliyun-python-sdk-core

# Install service-specific packages (batch install)
pip install aliyun-python-sdk-ecs aliyun-python-sdk-kms aliyun-python-sdk-ram \
            aliyun-python-sdk-rds aliyun-python-sdk-slb aliyun-python-sdk-vpc

# Install additional packages as needed
pip install aliyun-python-sdk-actiontrail aliyun-python-sdk-alb aliyun-python-sdk-arms \
            aliyun-python-sdk-bss aliyun-python-sdk-cdn aliyun-python-sdk-cloudfw \
            aliyun-python-sdk-cms aliyun-python-sdk-config aliyun-python-sdk-cr \
            aliyun-python-sdk-cs aliyun-python-sdk-dms aliyun-python-sdk-dts \
            aliyun-python-sdk-elasticsearch aliyun-python-sdk-emr aliyun-python-sdk-ess \
            aliyun-python-sdk-eventbridge aliyun-python-sdk-fnf aliyun-python-sdk-hbr \
            aliyun-python-sdk-ims
```

**Note:** Some packages may not be available on PyPI. Check availability before installing.

### Step 2: Run Discovery Script

The discovery script:
1. Finds all installed `aliyunsdk*` packages
2. For each package:
   - Discovers the request package (`package.request`)
   - Finds versioned request modules (`package.request.v20200706`)
   - Extracts operation names from request class modules
   - Generates operation catalog
3. Enriches catalogs with field metadata
4. Updates consolidated file and creates per-service files

### Step 3: Verify Results

```bash
# Check total services discovered
python3 << 'EOF'
import json
from pathlib import Path

deps_file = Path("pythonsdk-database/alicloud/alicloud_dependencies_with_python_names_fully_enriched.json")
with open(deps_file, 'r') as f:
    data = json.load(f)

print(f"Total Services: {len(data)}")
for svc in sorted(data.keys()):
    ops = len(data[svc].get('operations', []))
    print(f"  {svc:30s} - {ops:4d} operations")
EOF
```

## AliCloud SDK Structure

### Package Naming Convention
- SDK packages: `aliyun-python-sdk-<service>`
- Python modules: `aliyunsdk<service>` (no hyphens)
- Example: `aliyun-python-sdk-ecs` → `aliyunsdkecs`

### Request Module Pattern
```
aliyunsdk<service>/
├── __init__.py
└── request/
    └── v20200706/          # Versioned request package
        ├── CreateTrailRequest.py      # Individual request class modules
        ├── DeleteTrailRequest.py
        └── ...
```

**Key Discovery Logic:**
1. Find `package.request` (it's a package, not a module)
2. Walk into `package.request` to find versioned packages (`v20*`, `v1*`, `v2*`)
3. Walk into versioned package to find request class modules
4. Extract operation name from module name (remove `Request` suffix)

### Operation Extraction
- Module name pattern: `DescribeTrailsRequest.py`
- Operation name: `DescribeTrails` (remove `Request` suffix)

## Current Status

### AliCloud Database
- **Total Services:** 26
- **Total Operations:** 3,060 discovered, 367 in catalog (top 15 per service)
- **Services Covered:**
  - ack, actiontrail, alb, arms, bss, cdn, cloudfw, cms, config, cr
  - dms, dts, ecs, elasticsearch, emr, ess, eventbridge, fnf, hbr, ims
  - kms, oss, ram, rds, slb, vpc

### Files Generated
1. **Consolidated:** `pythonsdk-database/alicloud/alicloud_dependencies_with_python_names_fully_enriched.json`
2. **Per-service:** `pythonsdk-database/alicloud/<service>/alicloud_dependencies_with_python_names_fully_enriched.json`
3. **Service list:** `pythonsdk-database/alicloud/all_services.json`
4. **Human-readable:** `pythonsdk-database/alicloud/ALL_SERVICES_FINAL.txt`

## Adapting for Other CSPs

### Azure
**SDK Package Pattern:** `azure-<service>` or `azure-mgmt-<service>`
**Module Pattern:** `azure.mgmt.<service>` or `azure.<service>`
**Operation Discovery:** Check Azure SDK documentation for operation patterns

**Steps:**
1. Create `venv_azure`
2. Install Azure SDK packages: `pip install azure-mgmt-compute azure-mgmt-storage ...`
3. Adapt discovery script to Azure SDK structure
4. Update paths: `pythonsdk-database/azure/`

### GCP (Google Cloud Platform)
**SDK Package Pattern:** `google-cloud-<service>`
**Module Pattern:** `google.cloud.<service>`
**Operation Discovery:** Check GCP SDK documentation

**Steps:**
1. Create `venv_gcp`
2. Install GCP SDK packages: `pip install google-cloud-compute google-cloud-storage ...`
3. Adapt discovery script to GCP SDK structure
4. Update paths: `pythonsdk-database/gcp/`

### Kubernetes
**SDK Package Pattern:** `kubernetes`
**Module Pattern:** `kubernetes.client.api`
**Operation Discovery:** Kubernetes Python client uses API groups

**Steps:**
1. Create `venv_k8s`
2. Install: `pip install kubernetes`
3. Adapt discovery script to Kubernetes client structure
4. Update paths: `pythonsdk-database/k8s/`

### IAM (Identity and Access Management)
**Note:** IAM is typically part of each CSP's SDK, not a separate SDK.
- AWS: `boto3` (IAM service)
- Azure: `azure-mgmt-authorization`
- GCP: `google-cloud-iam`
- AliCloud: `aliyun-python-sdk-ram`

**Steps:**
1. Identify IAM service in each CSP
2. Extract IAM-specific operations
3. Create consolidated IAM database

### OCI (Oracle Cloud Infrastructure)
**SDK Package Pattern:** `oci-<service>` or `oci`
**Module Pattern:** `oci.<service>`
**Operation Discovery:** Check OCI SDK documentation

**Steps:**
1. Create `venv_oci`
2. Install OCI SDK: `pip install oci oci-core oci-identity ...`
3. Adapt discovery script to OCI SDK structure
4. Update paths: `pythonsdk-database/oci/`

## Key Adaptations Needed

### 1. Package Discovery
```python
# AliCloud pattern
for importer, modname, ispkg in pkgutil.iter_modules():
    if modname.startswith('aliyunsdk') and modname != 'aliyunsdkcore':
        # Process service

# Adapt for other CSPs:
# Azure: modname.startswith('azure.mgmt.')
# GCP: modname.startswith('google.cloud.')
# OCI: modname.startswith('oci.')
```

### 2. Operation Discovery
```python
# AliCloud: Find request modules in versioned packages
# Azure: Check for operation classes in service modules
# GCP: Check for client methods
# OCI: Check for operation classes
```

### 3. File Naming
```python
# AliCloud
output_file = f"alicloud_dependencies_with_python_names_fully_enriched.json"

# Adapt for other CSPs:
# Azure: azure_dependencies_with_python_names_fully_enriched.json
# GCP: gcp_dependencies_with_python_names_fully_enriched.json
# OCI: oci_dependencies_with_python_names_fully_enriched.json
```

### 4. Service Name Mapping
```python
# AliCloud: Package name to service name mapping
package_to_service = {
    'aliyunsdkecs': 'ecs',
    'aliyunsdkcs': 'ack',  # Special case
}

# Adapt for other CSPs based on their naming conventions
```

## Troubleshooting

### Issue: No operations found
**Solution:**
1. Verify package is installed: `pip list | grep <package>`
2. Check module structure: `python3 -c "import <module>; print(<module>.__file__)"`
3. Inspect module contents: `python3 -c "import <module>; import inspect; print(dir(<module>))"`

### Issue: Package not found on PyPI
**Solution:**
1. Check alternative package names
2. Verify package exists: `pip search <package>` (if available)
3. Check official SDK documentation for correct package name

### Issue: Import errors
**Solution:**
1. Install missing dependencies
2. Check Python version compatibility
3. Use virtual environment to isolate dependencies

### Issue: Wrong operation names
**Solution:**
1. Inspect actual module structure
2. Adjust operation extraction logic
3. Test with a known service first

## Best Practices

1. **Use Virtual Environments:** Isolate each CSP's dependencies
2. **Test Incrementally:** Start with one service, verify, then scale
3. **Document Exceptions:** Note any special cases (e.g., `aliyunsdkcs` → `ack`)
4. **Version Control:** Track SDK package versions used
5. **Validation:** Verify operation counts match expected values

## Validation Checklist

- [ ] All expected services discovered
- [ ] Operations extracted correctly
- [ ] Field metadata enriched
- [ ] Consolidated file created
- [ ] Per-service files created
- [ ] Service list generated
- [ ] No duplicate operations
- [ ] File structure matches AWS pattern

## Next Steps for Other CSPs

1. **Research SDK Structure:** Understand how each CSP organizes their SDK
2. **Create Discovery Script:** Adapt `discover_and_generate_all_services.py`
3. **Set Up Environment:** Create virtual environment and install packages
4. **Test Discovery:** Run on a few services first
5. **Scale Up:** Process all services
6. **Validate:** Compare with official documentation
7. **Document:** Update this handover document with CSP-specific notes

## Contact and Support

For questions or issues:
1. Review this document
2. Check the discovery script comments
3. Inspect existing AliCloud implementation
4. Test with a small subset first

## Appendix: AliCloud Service List

Current services in database (26 total):
- ack, actiontrail, alb, arms, bss, cdn, cloudfw, cms, config, cr
- dms, dts, ecs, elasticsearch, emr, ess, eventbridge, fnf, hbr, ims
- kms, oss, ram, rds, slb, vpc

See `pythonsdk-database/alicloud/all_services.json` for complete list with operation counts.

---

**Last Updated:** 2024-12-19
**Status:** Complete for AliCloud, ready for adaptation to other CSPs

