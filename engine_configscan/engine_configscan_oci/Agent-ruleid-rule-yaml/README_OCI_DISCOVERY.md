# OCI SDK Auto-Discovery and Catalog Generation

## Overview

This script automatically discovers all OCI (Oracle Cloud Infrastructure) services from installed SDK packages and generates comprehensive catalogs with field enrichment.

## Purpose

The OCI SDK database contains:
- Complete service catalogs with operations
- Field metadata and enrichment
- Python SDK method mappings
- Per-service and consolidated dependency files

## Prerequisites

### 1. Install OCI SDK Packages

Install all OCI SDK packages:

```bash
# Option 1: Use the installation script
./install_all_oci_packages.sh

# Option 2: Install manually
pip install oci

# Or install individual service packages
pip install oci-core oci-identity oci-database oci-object-storage \
            oci-compute oci-container-engine oci-data-science \
            oci-monitoring oci-logging oci-dns oci-file-storage \
            oci-streaming oci-data-catalog oci-data-integration \
            oci-cloud-guard oci-apigateway oci-events oci-audit \
            oci-waf oci-edge-services oci-mysql oci-data-flow \
            oci-nosql oci-devops oci-artifacts oci-certificates \
            oci-resource-manager oci-bds oci-data-safe oci-ons \
            oci-network-firewall oci-queue oci-redis \
            oci-container-instances oci-ai-anomaly-detection \
            oci-ai-language oci-vault oci-analytics
```

### 2. Verify Installation

```bash
python3 -c "import oci; print('OCI SDK version:', oci.__version__)"
```

## Usage

### Run Discovery

```bash
cd oci_compliance_python_engine/Agent-ruleid-rule-yaml
python3 discover_and_generate_all_oci_services.py
```

## How It Works

1. **Discovers SDK Packages**: 
   - Uses `service_list.json` as reference (if available)
   - Scans installed Python packages for `oci.*` modules
   - Introspects OCI SDK structure for available services

2. **Introspects Operations**:
   - Imports each service module
   - Discovers client classes and methods
   - Extracts operation names (focuses on `list_*` and `get_*` operations)

3. **Generates Catalogs**:
   - Creates basic catalog with discovered operations
   - Enriches with field metadata (using `enrich_oci_fields.py`)
   - Prioritizes read operations (List, Get)

4. **Updates Database**:
   - Updates `pythonsdk-database/oci/oci_dependencies_with_python_names_fully_enriched.json`
   - Creates per-service folders and files
   - Merges with existing data

## Output Files

The script generates:

1. **`oci_sdk_catalog.json`** - Basic catalog with operations (in script directory)
2. **`pythonsdk-database/oci/oci_dependencies_with_python_names_fully_enriched.json`** - Main consolidated enriched file
3. **`pythonsdk-database/oci/<service>/oci_dependencies_with_python_names_fully_enriched.json`** - Per-service files
4. **`pythonsdk-database/oci/all_services.json`** - Service list with counts

## Expected Services

Based on `service_list.json`, the following services should be discovered:

- identity (210 rules)
- compute (181 rules)
- database (176 rules)
- container_engine (111 rules)
- data_science (106 rules)
- monitoring (103 rules)
- cloud_guard (84 rules)
- data_catalog (83 rules)
- data_integration (81 rules)
- object_storage (80 rules)
- virtual_network (68 rules)
- analytics (58 rules)
- apigateway (43 rules)
- events (43 rules)
- key_management (41 rules)
- functions (39 rules)
- block_storage (36 rules)
- audit (35 rules)
- waf (28 rules)
- edge_services (25 rules)
- file_storage (24 rules)
- load_balancer (24 rules)
- mysql (24 rules)
- data_flow (22 rules)
- nosql (22 rules)
- streaming (19 rules)
- dns (16 rules)
- devops (15 rules)
- logging (15 rules)
- artifacts (15 rules)
- certificates (13 rules)
- resource_manager (10 rules)
- bds (10 rules)
- data_safe (10 rules)
- ons (10 rules)
- network_firewall (9 rules)
- queue (6 rules)
- redis (6 rules)
- container_instances (5 rules)
- ai_anomaly_detection (4 rules)
- ai_language (3 rules)
- vault (1 rule)

**Total: 42 services**

## Troubleshooting

### Issue: No services discovered
**Solution:**
1. Verify OCI SDK is installed: `pip list | grep oci`
2. Check Python path: `python3 -c "import oci; print(oci.__path__)"`
3. Install missing packages: `pip install oci`

### Issue: Import errors
**Solution:**
1. Install missing dependencies
2. Check Python version compatibility (OCI SDK requires Python 3.6+)
3. Use virtual environment to isolate dependencies

### Issue: Wrong operation names
**Solution:**
1. Check OCI SDK documentation for correct method names
2. Verify client class exists in the module
3. Check service_list.json for correct client class names

### Issue: Missing enrichment
**Solution:**
1. Ensure `enrich_oci_fields.py` is in the same directory
2. Check that enrichment script has field definitions for the service
3. Verify service name matches between discovery and enrichment

## Comparison with AWS

The OCI database structure matches AWS enrichment format:
- `item_fields` with metadata (type, description, compliance_category, operators)
- `operations` array with operation details
- Per-service and consolidated files
- Service list with operation counts

## Next Steps

After running discovery:
1. Verify all 42 services are discovered
2. Check enrichment completeness
3. Compare with AWS database structure
4. Update service_list.json if new services are found

