# Complete CSP Files Generation Plan

## Current Status

| CSP | Total Services | Complete (Both Files) | Missing DI | Missing DV | Readiness |
|-----|---------------|----------------------|------------|------------|-----------|
| **AliCloud** | 26 | 26/26 (100%) | 0 | 0 | ✅ **100%** |
| **IBM** | 62 | 0/62 (0%) | 34 | 62 | ❌ **0%** |
| **OCI** | 153 | 0/153 (0%) | 152 | 153 | ❌ **0%** |

**Total to complete: 215 services (IBM: 62 + OCI: 153)**

---

## Generation Strategy

### Approach
1. **Generate `direct_vars.json` first** - This extracts fields from SDK dependencies (read operations)
2. **Generate `dependency_index.json` second** - This maps entities to operations (can use direct_vars for entities)

### File Sources
- **SDK Dependencies File**: `<csp>_dependencies_with_python_names_fully_enriched.json` (per service)
- **Operation Registry** (if available): `operation_registry.json` (enriches data)
- **Existing dependency_index.json** (if exists): Can help link entities to fields

---

## IBM Generation (62 services)

### Current State
- 28 services have `dependency_index.json` ✅
- 0 services have `direct_vars.json` ❌
- 28 services have `operation_registry.json` ✅

### Strategy
1. **Generate `direct_vars.json` for all 62 services** from SDK dependencies
2. **Generate missing `dependency_index.json` for 34 services** (use existing 28 as reference)
3. **Link entities** from dependency_index to direct_vars fields

### IBM Structure
```json
{
  "iam": {
    "service": "iam",
    "independent": [
      {
        "operation": "list_users",
        "item_fields": {},
        "output_fields": {}
      }
    ],
    "dependent": [
      {
        "operation": "get_user",
        "item_fields": {},
        "output_fields": {}
      }
    ]
  }
}
```

### Generation Steps
1. Extract read operations from `independent` and `dependent` lists
2. Extract fields from `item_fields` and `output_fields`
3. Map operations to fields
4. Create entity names (format: `ibm.{service}.{field}`)
5. Link to dependency_index if exists

---

## OCI Generation (153 services)

### Current State
- 1 service has `dependency_index.json` ✅
- 0 services have `direct_vars.json` ❌
- 153 services have `operation_registry.json` ✅

### Strategy
1. **Generate `direct_vars.json` for all 153 services** from SDK dependencies
2. **Generate missing `dependency_index.json` for 152 services** (use operation_registry + SDK deps)
3. **Link entities** using operation_registry produces/consumes

### OCI Structure
```json
{
  "core": {
    "service": "core",
    "operations": [
      {
        "operation": "get_all_drg_attachments",
        "python_method": "get_all_drg_attachments",
        "item_fields": {
          "id": {
            "type": "string",
            "operators": ["equals", "not_equals", "exists"]
          }
        }
      }
    ]
  }
}
```

### Generation Steps
1. Extract read operations from `operations` list (get_*, list_*)
2. Extract fields from `item_fields` (already has metadata!)
3. Map operations to fields
4. Create entity names (format: `oci.{service}.{field}`)
5. Use operation_registry for dependency graph

---

## AliCloud Status

### ✅ Already Complete
- 26/26 services have both `dependency_index.json` and `direct_vars.json`
- No action needed

---

## Scripts to Create

### 1. `generate_ibm_direct_vars.py`
- Input: `ibm_dependencies_with_python_names_fully_enriched.json` per service
- Output: `direct_vars.json` per service
- Uses: `independent` and `dependent` operations, extracts `item_fields`

### 2. `generate_ibm_dependency_index.py`
- Input: `direct_vars.json` + `ibm_dependencies_with_python_names_fully_enriched.json`
- Output: `dependency_index.json` for missing services
- Uses: Existing 28 services as template

### 3. `generate_oci_direct_vars.py`
- Input: `oci_dependencies_with_python_names_fully_enriched.json` per service
- Output: `direct_vars.json` per service
- Uses: `operations` list, extracts `item_fields` (already has metadata!)

### 4. `generate_oci_dependency_index.py`
- Input: `operation_registry.json` + `oci_dependencies_with_python_names_fully_enriched.json`
- Output: `dependency_index.json` for missing services
- Uses: operation_registry produces/consumes for dependency graph

---

## Priority Order

1. **IBM `direct_vars.json`** (62 services) - Foundation for dependency_index
2. **OCI `direct_vars.json`** (153 services) - Foundation for dependency_index
3. **IBM `dependency_index.json`** (34 missing) - Link to direct_vars
4. **OCI `dependency_index.json`** (152 missing) - Use operation_registry + direct_vars

---

## Validation

After generation:
- ✅ All services have `direct_vars.json`
- ✅ All services have `dependency_index.json`
- ✅ Entities in dependency_index match fields in direct_vars
- ✅ Operations in dependency_index match operations in direct_vars

---

## Expected Outcome

After completion:
- **IBM**: 62/62 (100%) - Production Ready ✅
- **OCI**: 153/153 (100%) - Production Ready ✅
- **AliCloud**: 26/26 (100%) - Already Complete ✅

**Total: 241 services ready across 3 CSPs**

