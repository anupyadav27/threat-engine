# Compliance Database - Tables & Views Usage Analysis

**Date:** February 1, 2026  
**Database:** `threat_engine_compliance` on RDS

---

## 📊 **ACTUAL DATABASE SCHEMA**

### **TABLES (8 total)**

| Table Name | Rows | Used By | Purpose |
|------------|------|---------|---------|
| `tenants` | ? | ✅ Compliance Writer | Store tenant metadata |
| `report_index` | 1 | ✅ **ACTIVE** - Compliance Writer | Primary compliance reports storage |
| `finding_index` | 231 | ✅ **ACTIVE** - Compliance Writer | Individual compliance findings |
| `compliance_control_mappings` | 960 | ✅ **ACTIVE** - Framework Loader | Maps rule_ids → compliance controls (loaded from CSV) |
| `compliance_frameworks` | ~5 | ❓ Unused currently | Framework metadata (CIS, PCI-DSS, ISO27001, etc.) |
| `compliance_assessments` | 0 | ❌ Unused | Manual compliance assessments (future feature) |
| `control_assessment_results` | 0 | ❌ Unused | Assessment details (future feature) |
| `remediation_tracking` | 0 | ❌ Unused | Remediation workflow (future feature) |

### **VIEWS (8 total)**

| View Name | Used By | Purpose | Depends On |
|-----------|---------|---------|------------|
| `compliance_scans` | ❌ API endpoints (broken) | Scan-level summary | report_index |
| `framework_scores` | ❌ API endpoints (broken) | Framework scores | report_index |
| `control_results` | ❌ API endpoints (broken) | Control-level results | report_index, finding_index |
| `compliance_controls` | ❓ Unknown | Control definitions | compliance_frameworks |
| `rule_control_mapping` | ❓ Unknown | Rule → Control mapping | compliance_control_mappings |
| `compliance_by_service` | ❌ Unused | Group by service | finding_index |
| `framework_coverage` | ❌ Unused | Coverage analysis | compliance_control_mappings |
| `multi_framework_controls` | ❌ Unused | Cross-framework view | compliance_control_mappings |

---

## ✅ **CURRENTLY WORKING**

### **Compliance Engine Core Flow:**

```
1. CheckDBLoader 
   └─ Reads FROM check_results (threat_engine_check DB)
   └─ Uses: CHECK_DB_* env vars

2. FrameworkLoader
   └─ Reads FROM compliance_control_mappings
   └─ Maps rule_ids → compliance controls

3. Compliance Report Generation
   └─ Aggregates check results by framework
   └─ Calculates scores

4. Storage (compliance_db_writer.py)
   ✅ INSERT INTO report_index (1 row per compliance run)
   ✅ INSERT INTO finding_index (N rows, one per failed check)

5. File Output
   ✅ Writes to /output/compliance/{tenant_id}/{scan_id}/full_report.json
   ✅ S3 sidecar syncs to s3://cspm-lgtech/engine_output/compliance/
```

---

## ❌ **BROKEN API ENDPOINTS**

These endpoints in `api_server.py` reference views that don't exist in RDS:

### `/api/v1/compliance/dashboard`
```python
SELECT ... FROM compliance_control_detail  # ❌ View doesn't exist
```

### `/api/v1/compliance/framework-detail/{framework}`
```python
SELECT ... FROM compliance_control_detail  # ❌ View doesn't exist
```

### `/api/v1/compliance/control-detail/{framework}/{control_id}`
```python
SELECT ... FROM compliance_control_detail  # ❌ View doesn't exist
SELECT ... FROM resource_compliance_status # ❌ View doesn't exist
```

### `/api/v1/compliance/resource/{resource_uid}/compliance`
```python
SELECT ... FROM resource_compliance_status  # ❌ View doesn't exist
```

**These endpoints won't work until we:**
1. Create the missing views on RDS, OR
2. Rewrite queries to use base tables (`report_index`, `finding_index`, `compliance_control_mappings`)

---

## ✅ **WORKING API ENDPOINTS**

### Core Compliance Generation:
- ✅ `/api/v1/compliance/generate/from-check-db` - **PRIMARY ENDPOINT**
  - Reads: `check_results` (check DB)
  - Reads: `compliance_control_mappings` (compliance DB)
  - Writes: `report_index`, `finding_index`
  - Writes: `/output/*.json` → S3

### Other Working Endpoints:
- ✅ `/api/v1/health` - Health check
- ✅ `/api/v1/compliance/report/{report_id}` - Get in-memory report
- ✅ `/api/v1/compliance/frameworks/all` - List frameworks from CSV

---

## 📋 **TABLES USED BY ENGINE**

### **ACTIVE TABLES (compliance engine uses these):**

1. **`tenants`** (metadata)
   - Written by: `compliance_db_writer.py`
   - Used for: FK relationships

2. **`report_index`** (compliance reports)
   - Written by: `compliance_db_writer.py`
   - Columns: `report_id`, `tenant_id`, `scan_run_id`, `cloud`, `trigger_type`, `total_controls`, `controls_passed`, `controls_failed`, `total_findings`, `report_data`
   - Primary storage for compliance scan results

3. **`finding_index`** (compliance findings)
   - Written by: `compliance_db_writer.py`
   - Columns: `finding_id`, `report_id`, `tenant_id`, `scan_run_id`, `rule_id`, `severity`, `status`, `resource_arn`, `finding_data`
   - One row per failed check/finding

4. **`compliance_control_mappings`** (rule → control mapping)
   - Read by: `FrameworkLoader`
   - Columns: `unique_compliance_id`, `compliance_framework`, `requirement_id`, `requirement_name`, `rule_ids[]`, `service`
   - Loaded from: `aws_consolidated_rules_with_final_checks.csv`

### **UNUSED TABLES (can be removed or kept for future):**

5. **`compliance_frameworks`** 
   - Pre-seeded with framework metadata
   - Not currently read by engine
   - Could be used for framework catalog UI

6. **`compliance_assessments`**
   - Manual assessment tracking
   - Not used by automated engine

7. **`control_assessment_results`**
   - Assessment evidence/testing
   - Not used by automated engine

8. **`remediation_tracking`**
   - Remediation workflow
   - Not used by automated engine

---

## 📊 **VIEWS ANALYSIS**

### **Views That COULD Be Useful (but not implemented yet):**

These views are defined but the API endpoints that use them reference different view names that don't exist (`compliance_control_detail`, `resource_compliance_status`):

1. **`compliance_scans`** - View of report_index
   - Could replace: API queries to `report_index`

2. **`framework_scores`** - Framework-level scores
   - Could provide: Per-framework compliance %

3. **`control_results`** - Control-level results
   - Could provide: Which controls passed/failed

4. **`rule_control_mapping`** - Flattened rule → control mapping
   - Could replace: Queries to `compliance_control_mappings`

### **Views That Are Probably Not Needed:**

5. **`compliance_controls`** - Control definitions from frameworks table
6. **`compliance_by_service`** - Group findings by service
7. **`framework_coverage`** - Coverage analysis
8. **`multi_framework_controls`** - Cross-framework mapping

---

## 🎯 **RECOMMENDATION**

### **KEEP (Active Use):**
- ✅ `tenants`
- ✅ `report_index`
- ✅ `finding_index`
- ✅ `compliance_control_mappings`

### **OPTIONAL (Future Features):**
- `compliance_frameworks` (if building framework catalog)
- `compliance_assessments` (if adding manual assessments)
- `control_assessment_results` (if adding assessment workflow)
- `remediation_tracking` (if adding remediation tracking)

### **VIEWS TO FIX OR REMOVE:**

**Option A: Fix the API endpoints**
- Update `/api/v1/compliance/dashboard` to query `report_index` directly
- Update other endpoints to stop referencing non-existent views
- Remove or update the 8 existing views to match what APIs expect

**Option B: Remove unused views**
- Drop views that aren't being used
- Keep schema simple with just the 4 core tables

---

## 📝 **CURRENT STATUS**

✅ **Working:**
- Compliance report generation
- RDS persistence (report_index + finding_index)
- S3 file output
- 231 findings catalogued from 1,056 checks

❌ **Broken:**
- Dashboard API endpoints (reference non-existent views)
- Some view definitions exist but aren't used

**Next Step:** Decide if you want to:
1. Fix the 4 broken API endpoints to use base tables
2. Create the missing views they reference
3. Remove unused views to simplify schema
