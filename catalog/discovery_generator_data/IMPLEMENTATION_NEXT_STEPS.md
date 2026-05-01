# Implementation Next Steps - CSP Structure Standardization

## ✅ Completed

1. ✅ **Review and document AWS structure** - Complete reference pattern identified
2. ✅ **Audit all CSPs** - Comprehensive audit completed
3. ✅ **Azure verification** - All 160 services COMPLETE (all 3 files present)

## 📊 Current Status Summary

| CSP | Status | Services | Missing DI | Missing DV | Priority |
|-----|--------|----------|------------|------------|----------|
| AWS | ✅ COMPLETE | 428/430 | 2 | 2 | Low (fix 2 test services) |
| Azure | ✅ COMPLETE | 160/160 | 0 | 0 | None |
| GCP | ❌ INCOMPLETE | 143 | 108 | 143 | **HIGH** |
| OCI | ❌ INCOMPLETE | 153 | 152 | 153 | **HIGH** |
| IBM | ❌ INCOMPLETE | 61 | 33 | 61 | Medium |
| Alicloud | ❌ INCOMPLETE | 26 | 22 | 26 | Low |

**Total Missing:**
- dependency_index.json: 317 services
- direct_vars.json: 385 services

---

## 🎯 Next Steps - GCP (Recommended Starting Point)

### Why GCP First?
1. Moderate number of services (143) - good test case
2. SDK structure exists and is populated
3. Some dependency_index files exist (35 services) - can learn from them
4. Good balance of complexity

### Phase 1: Generate direct_vars.json for GCP (143 services)

**Challenge:** GCP SDK structure differs from AWS/Azure:
- AWS: `independent` / `dependent` operations at top level
- Azure: Similar structure with categories
- GCP: `resources` → resource types → `independent` / `dependent`

**Approach:**
1. Study existing GCP dependency_index.json files (35 services) to understand structure
2. Extract fields from GCP SDK dependencies:
   - From `independent` operations (read operations)
   - From `item_fields` in operations
   - From `output_fields` in operations
3. Map fields to operations
4. Generate direct_vars.json structure matching AWS pattern:
   ```json
   {
     "service": "servicename",
     "seed_from_list": [...],
     "enriched_from_get_describe": [...],
     "fields": {
       "fieldName": {
         "field_name": "fieldName",
         "dependency_index_entity": "servicename.entity_name",
         "operations": ["ListX", "GetX"],
         "main_output_field": "items",
         "operators": ["equals", "not_equals", ...],
         "possible_values": null,
         "enum": false,
         "type": "string",
         "discovery_id": "gcp.servicename.list_x",
         "consumes": [],
         "produces": ["servicename.entity_name"]
       }
     }
   }
   ```

### Phase 2: Generate dependency_index.json for GCP (108 services)

**Approach:**
1. Adapt AWS `generate_dependency_index.py` for GCP structure
2. Extract entities from direct_vars.json (once generated)
3. Map entities to operations from SDK dependencies
4. Build dependency graph
5. Identify root operations

---

## 🔍 Key Differences to Address

### SDK Structure Differences:

**AWS:**
```json
{
  "servicename": {
    "independent": [...],
    "dependent": [...]
  }
}
```

**GCP:**
```json
{
  "servicename": {
    "resources": {
      "resourceType": {
        "independent": [...],
        "dependent": [...]
      }
    }
  }
}
```

### Dependency Index Differences:

**AWS:** Well-populated with roots and entity_paths
**GCP (sample):** Empty `{ "roots": [], "entity_paths": {} }`

**Action:** Need to understand why GCP dependency_index is empty and how to populate it properly.

---

## 📝 Recommended Action Plan

### Step 1: Deep Dive into GCP Structure (1-2 hours)
- [ ] Examine GCP services that have dependency_index.json (35 services)
- [ ] Compare with GCP services that don't have dependency_index
- [ ] Understand GCP operation naming and structure
- [ ] Map GCP operation structure to AWS/Azure patterns

### Step 2: Create GCP direct_vars Generator (2-4 hours)
- [ ] Create script: `pythonsdk-database/gcp/generate_direct_vars.py`
- [ ] Extract fields from GCP SDK dependencies structure
- [ ] Map fields to operations (handle GCP resource-based structure)
- [ ] Generate direct_vars.json matching AWS structure
- [ ] Test on 1-2 GCP services
- [ ] Validate output structure

### Step 3: Generate GCP direct_vars (1-2 hours)
- [ ] Run script on all 143 GCP services
- [ ] Validate generated files
- [ ] Fix any issues
- [ ] Document any GCP-specific patterns

### Step 4: Create GCP dependency_index Generator (2-4 hours)
- [ ] Adapt AWS script for GCP structure
- [ ] Generate dependency_index.json using direct_vars + SDK dependencies
- [ ] Test on 1-2 services
- [ ] Run on all missing GCP services (108)

### Step 5: Validation & Testing (1 hour)
- [ ] Validate consistency between dependency_index and direct_vars
- [ ] Fix any broken links
- [ ] Document GCP-specific patterns

**Total Estimated Time: 8-14 hours**

---

## 🚀 Quick Start Commands

Once scripts are ready:

```bash
# Generate direct_vars for all GCP services
cd pythonsdk-database/gcp
python3 generate_direct_vars.py

# Generate dependency_index for missing GCP services
python3 generate_dependency_index.py

# Validate
python3 validate_structure.py
```

---

## 📚 Reference Files

- **AWS Reference:** `pythonsdk-database/aws/s3vectors/` (complete example)
- **Azure Reference:** `pythonsdk-database/azure/devcenter/` (complete example)
- **GCP Sample:** `pythonsdk-database/gcp/accessapproval/` (has dependency_index but empty)
- **Audit Script:** `pythonsdk-database/audit_csp_structure.py`

---

## ❓ Questions to Resolve

1. Why are GCP dependency_index.json files empty? (need investigation)
2. How should we handle GCP's resource-based structure?
3. Should we generate dependency_index before direct_vars, or vice versa?
4. What's the relationship between GCP operation_registry.json and dependency_index.json?

---

## 📋 Checklist

- [x] Review AWS structure
- [x] Audit all CSPs
- [x] Verify Azure completeness
- [ ] Study GCP structure differences
- [ ] Create GCP direct_vars generator
- [ ] Generate GCP direct_vars (143 services)
- [ ] Create GCP dependency_index generator
- [ ] Generate GCP dependency_index (108 services)
- [ ] Validate GCP structure
- [ ] Repeat for OCI, IBM, Alicloud

