# CSP Structure Review and Implementation Plan

## Executive Summary

We need to standardize the database structure across all Cloud Service Providers (CSPs) to match the AWS pattern. Each service should have three core files:
1. **SDK Dependencies File** (e.g., `boto3_dependencies_with_python_names_fully_enriched.json`)
2. **Dependency Index File** (`dependency_index.json`)
3. **Direct Variables File** (`direct_vars.json`)

---

## Current Status by CSP

### ✅ AWS (Complete - Reference Pattern)

**Structure:**
- `pythonsdk-database/aws/<service>/boto3_dependencies_with_python_names_fully_enriched.json` ✅
- `pythonsdk-database/aws/<service>/dependency_index.json` ✅
- `pythonsdk-database/aws/<service>/direct_vars.json` ✅

**Statistics:**
- Services: ~411 services
- All three files present per service
- Fully validated and complete

**Key Scripts:**
- `generate_dependency_index.py` - Generates dependency_index.json from CSV and boto3_deps
- `enrich_fields_with_operations.py` - Enriches direct_vars with operations
- `fix_dependency_index.py` - Fixes missing entities in dependency_index
- `validate_dependency_index.py` - Validates dependency_index consistency

---

### ⚠️ Azure (Partially Complete)

**Current Structure:**
- `pythonsdk-database/azure/<service>/azure_dependencies_with_python_names_fully_enriched.json` ✅ (per service)
- `pythonsdk-database/azure/<service>/dependency_index.json` ⚠️ (some services have it)
- `pythonsdk-database/azure/<service>/direct_vars.json` ✅ (many services have it)

**What's Missing:**
1. ❌ **dependency_index.json** - Not present in all services (needs generation)
2. ✅ **direct_vars.json** - Present in many services (needs verification/completion)
3. ✅ **SDK dependencies** - Present per service

**Action Items:**
1. Generate `dependency_index.json` for all Azure services
2. Verify `direct_vars.json` coverage and completeness
3. Ensure consistency between dependency_index and direct_vars

---

### ⚠️ GCP (Partially Complete)

**Current Structure:**
- `pythonsdk-database/gcp/<service>/gcp_dependencies_with_python_names_fully_enriched.json` ✅ (per service)
- `pythonsdk-database/gcp/<service>/dependency_index.json` ⚠️ (some services have it)
- `pythonsdk-database/gcp/<service>/direct_vars.json` ❌ (NOT FOUND)

**What's Missing:**
1. ❌ **direct_vars.json** - Completely missing (HIGH PRIORITY)
2. ⚠️ **dependency_index.json** - Present in some services only (needs generation for all)
3. ✅ **SDK dependencies** - Present per service

**Action Items:**
1. Generate `direct_vars.json` for all GCP services (HIGH PRIORITY)
2. Generate `dependency_index.json` for all GCP services
3. Link dependency_index entities to direct_vars fields

---

### ⚠️ Alicloud (Partially Complete)

**Current Structure:**
- `pythonsdk-database/alicloud/<service>/alicloud_dependencies_with_python_names_fully_enriched.json` ✅ (per service)
- `pythonsdk-database/alicloud/<service>/dependency_index.json` ⚠️ (some services have it)
- `pythonsdk-database/alicloud/<service>/direct_vars.json` ❌ (NOT FOUND)

**What's Missing:**
1. ❌ **direct_vars.json** - Completely missing (HIGH PRIORITY)
2. ⚠️ **dependency_index.json** - Present in some services only (needs generation for all)
3. ✅ **SDK dependencies** - Present per service

**Action Items:**
1. Generate `direct_vars.json` for all Alicloud services (HIGH PRIORITY)
2. Generate `dependency_index.json` for all Alicloud services
3. Link dependency_index entities to direct_vars fields

---

### ❌ OCI (Mostly Incomplete)

**Current Structure:**
- `pythonsdk-database/oci/<service>/oci_dependencies_with_python_names_fully_enriched.json` ✅ (per service)
- `pythonsdk-database/oci/<service>/dependency_index.json` ❌ (NOT FOUND - only operation_registry.json exists)
- `pythonsdk-database/oci/<service>/direct_vars.json` ❌ (NOT FOUND)

**What's Missing:**
1. ❌ **direct_vars.json** - Completely missing (HIGH PRIORITY)
2. ❌ **dependency_index.json** - Missing (needs generation)
3. ✅ **SDK dependencies** - Present per service

**Action Items:**
1. Generate `direct_vars.json` for all OCI services (HIGH PRIORITY)
2. Generate `dependency_index.json` for all OCI services (HIGH PRIORITY)
3. Link dependency_index entities to direct_vars fields

---

### ⚠️ IBM (Partially Complete)

**Current Structure:**
- `pythonsdk-database/ibm/<service>/ibm_dependencies_with_python_names_fully_enriched.json` ✅ (per service)
- `pythonsdk-database/ibm/<service>/dependency_index.json` ⚠️ (some services have it)
- `pythonsdk-database/ibm/<service>/direct_vars.json` ❌ (NOT FOUND)

**What's Missing:**
1. ❌ **direct_vars.json** - Completely missing (HIGH PRIORITY)
2. ⚠️ **dependency_index.json** - Present in some services only (needs generation for all)
3. ✅ **SDK dependencies** - Present per service

**Action Items:**
1. Generate `direct_vars.json` for all IBM services (HIGH PRIORITY)
2. Generate `dependency_index.json` for all IBM services
3. Link dependency_index entities to direct_vars fields

---

## Standard File Structure (Per Service)

Each service should have exactly these three files:

```
pythonsdk-database/<csp>/<service>/
├── <csp>_dependencies_with_python_names_fully_enriched.json  # SDK operations & fields
├── dependency_index.json                                      # Entity dependency graph
└── direct_vars.json                                          # Field definitions & operators
```

### File Naming Convention by CSP:

| CSP | SDK Dependencies File Name |
|-----|---------------------------|
| AWS | `boto3_dependencies_with_python_names_fully_enriched.json` |
| Azure | `azure_dependencies_with_python_names_fully_enriched.json` |
| GCP | `gcp_dependencies_with_python_names_fully_enriched.json` |
| Alicloud | `alicloud_dependencies_with_python_names_fully_enriched.json` |
| OCI | `oci_dependencies_with_python_names_fully_enriched.json` |
| IBM | `ibm_dependencies_with_python_names_fully_enriched.json` |

---

## Implementation Plan (By Priority)

### Phase 1: High Priority (Missing direct_vars.json)

**Target CSPs:** GCP, Alicloud, OCI, IBM

**Tasks:**
1. Create generic script to generate `direct_vars.json` from SDK dependencies
2. Extract fields from SDK dependencies (output_fields, item_fields)
3. Map fields to operations
4. Generate field metadata (operators, types, possible_values)
5. Link to dependency_index entities

**Estimated Services:**
- GCP: ~286 services
- Alicloud: ~113 services
- OCI: ~770 services
- IBM: ~234 services
- **Total: ~1,403 services**

### Phase 2: Medium Priority (Missing dependency_index.json)

**Target CSPs:** All CSPs (partial coverage)

**Tasks:**
1. Adapt AWS `generate_dependency_index.py` script for each CSP
2. Generate dependency_index.json from SDK dependencies
3. Map entities to operations
4. Identify root operations (independent operations)
5. Build entity dependency graph

**Estimated Services:**
- Azure: ~100+ services missing dependency_index
- GCP: ~250+ services missing dependency_index
- Alicloud: ~100+ services missing dependency_index
- OCI: ~770 services missing dependency_index
- IBM: ~200+ services missing dependency_index

### Phase 3: Validation & Linking

**All CSPs**

**Tasks:**
1. Validate consistency between dependency_index and direct_vars
2. Link dependency_index_entity in direct_vars to dependency_index.json
3. Verify all entities in direct_vars exist in dependency_index
4. Fix missing entities and broken links
5. Run comprehensive validation

---

## Recommended Implementation Approach

### Option 1: CSP-by-CSP (Recommended for Discussion)

**Pros:**
- Focus on one CSP at a time
- Learn and refine process
- Easier to validate and fix issues
- Can prioritize based on usage

**Cons:**
- Takes longer overall
- May need to adapt process for each CSP

**Suggested Order:**
1. Azure (easiest - already has direct_vars, just needs dependency_index completion)
2. GCP (moderate - needs both files but SDK structure similar to AWS)
3. Alicloud (moderate - needs both files)
4. IBM (moderate - needs both files)
5. OCI (most complex - needs both files, most services)

### Option 2: File Type Approach

**Pros:**
- Consistent process for all CSPs
- Can parallelize across CSPs
- Easier to validate patterns

**Cons:**
- Need generic scripts that work for all CSPs
- More complex to handle CSP-specific differences

---

## Next Steps for Discussion

1. **Choose CSP to start with** (recommendation: Azure)
2. **Decide on approach** (CSP-by-CSP vs File Type)
3. **Review AWS scripts** to understand the generation process
4. **Adapt scripts** for the chosen CSP
5. **Generate test service** to validate approach
6. **Scale to all services** once validated

---

## Questions to Resolve

1. Should we maintain the exact same structure as AWS or adapt for CSP-specific needs?
2. What's the priority order? (Business usage? Easiest first?)
3. Do we need to backfill all historical data or start fresh?
4. Should we create generic scripts that work for all CSPs or CSP-specific scripts?
5. What validation checks should we run after generation?

---

## Notes

- AWS scripts can be used as reference but need adaptation for each CSP's SDK structure
- Each CSP has different SDK naming conventions and structures
- Some CSPs may have additional metadata we want to capture
- Validation is critical to ensure consistency and correctness

