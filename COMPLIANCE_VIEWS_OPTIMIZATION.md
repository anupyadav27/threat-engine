# Compliance Database - Views vs Tables Optimization

**Goal:** Replace computed/derived tables with views to reduce storage and eliminate redundancy

---

## ✅ **CAN Be Replaced with VIEWS (5 tables → views)**

### **1. framework_scores** ✅ **Definitely a VIEW**

**Why:** Computed from report_index data

**Current (Table):**
```sql
CREATE TABLE framework_scores (
    framework_id VARCHAR,
    total_score DECIMAL,
    passed_controls INT,
    failed_controls INT
);
```

**Better (View):**
```sql
CREATE VIEW framework_scores AS
SELECT 
    framework_id,
    AVG(total_controls) as total_controls,
    AVG(controls_passed) as avg_passed,
    AVG(controls_failed) as avg_failed,
    (SUM(controls_passed)::DECIMAL / NULLIF(SUM(total_controls), 0) * 100) as compliance_percentage
FROM report_index
JOIN compliance_control_mappings ON ...
GROUP BY framework_id;
```

**Benefits:** Always up-to-date, no sync needed

---

### **2. compliance_scans** ✅ **Should be a VIEW**

**Why:** Duplicate of report_index

**Current (Table):**
```sql
CREATE TABLE compliance_scans (
    scan_id VARCHAR,
    tenant_id VARCHAR,
    status VARCHAR,
    ...
);
```

**Better (View):**
```sql
CREATE VIEW compliance_scans AS
SELECT 
    scan_run_id as scan_id,
    tenant_id,
    cloud as provider,
    CASE 
        WHEN completed_at IS NOT NULL THEN 'completed'
        ELSE 'running'
    END as status,
    started_at,
    completed_at,
    total_controls,
    controls_passed,
    controls_failed
FROM report_index;
```

**Benefits:** No duplication, single source of truth

---

### **3. control_results** ✅ **Should be a VIEW**

**Why:** Aggregation of finding_index

**Current (Table):**
```sql
CREATE TABLE control_results (
    control_id VARCHAR,
    status VARCHAR,
    pass_count INT,
    fail_count INT
);
```

**Better (View):**
```sql
CREATE VIEW control_results AS
SELECT 
    ccm.requirement_id as control_id,
    ccm.compliance_framework,
    COUNT(DISTINCT fi.finding_id) as total_findings,
    COUNT(*) FILTER (WHERE fi.status = 'PASS') as passed,
    COUNT(*) FILTER (WHERE fi.status = 'FAIL') as failed,
    CASE 
        WHEN COUNT(*) FILTER (WHERE fi.status = 'FAIL') = 0 THEN 'PASS'
        ELSE 'FAIL'
    END as control_status
FROM compliance_control_mappings ccm
LEFT JOIN finding_index fi ON fi.rule_id = ANY(ccm.rule_ids)
GROUP BY ccm.requirement_id, ccm.compliance_framework;
```

**Benefits:** Real-time aggregation from findings

---

### **4. rule_control_mapping** ✅ **Should be a VIEW**

**Why:** Can be derived from compliance_control_mappings.rule_ids array

**Current (Table):**
```sql
CREATE TABLE rule_control_mapping (
    mapping_id UUID,
    rule_id VARCHAR,
    control_id VARCHAR,
    framework_id VARCHAR
);
```

**Better (View):**
```sql
CREATE VIEW rule_control_mapping AS
SELECT 
    gen_random_uuid() as mapping_id,
    unnest(rule_ids) as rule_id,
    requirement_id as control_id,
    compliance_framework as framework_id,
    framework_id as framework_code,
    'direct' as mapping_type,
    100 as coverage_percentage
FROM compliance_control_mappings;
```

**Benefits:** Auto-expands rule_ids array, no manual sync needed

---

### **5. compliance_controls** ⚠️ **Can be VIEW if using control_mappings**

**Why:** Control definitions can come from compliance_control_mappings

**Current (Table):**
```sql
CREATE TABLE compliance_controls (
    control_id VARCHAR,
    framework_id VARCHAR,
    control_name VARCHAR,
    control_description TEXT
);
```

**Better (View if not storing additional data):**
```sql
CREATE VIEW compliance_controls AS
SELECT 
    unique_compliance_id as control_id,
    framework_id,
    requirement_id as control_number,
    requirement_name as control_name,
    requirement_description as control_description,
    'detective' as control_type,
    NULL as severity,
    section as control_family
FROM compliance_control_mappings;
```

**Benefits:** Single source from control_mappings

**OR Keep as Table if:** You want to add extra control metadata not in control_mappings

---

## ❌ **MUST Stay as TABLES (3 tables)**

### **6. compliance_assessments** ❌ **Must be TABLE**

**Why:** Stores mutable assessment state/workflow

**Needs columns:**
- status (draft/active/completed) - changes over time
- assessor, started_at, completed_at - workflow tracking
- overall_score - computed but stored for historical record

**Can't be view:** State changes, workflow data

---

### **7. control_assessment_results** ❌ **Must be TABLE**

**Why:** Stores assessment findings/evidence/remediation dates

**Needs columns:**
- implementation_status - changes over time
- test_results, deficiencies - assessment data
- target_remediation_date, actual_remediation_date - workflow
- assessed_by, reviewed_by - audit trail

**Can't be view:** Stores human input, workflow state

---

### **8. remediation_tracking** ❌ **Must be TABLE**

**Why:** Tracks remediation workflow/tickets

**Needs columns:**
- status (open/in_progress/remediated) - changes over time
- assigned_to, target_date - workflow
- progress_notes - human input
- verified_by, verified_at - audit trail

**Can't be view:** Active workflow data

---

## 🎯 **Recommended Optimization**

### **Convert to Views (5 tables):**
```sql
DROP TABLE IF EXISTS framework_scores CASCADE;
DROP TABLE IF EXISTS compliance_scans CASCADE;
DROP TABLE IF EXISTS control_results CASCADE;
DROP TABLE IF EXISTS rule_control_mapping CASCADE;
DROP TABLE IF EXISTS compliance_controls CASCADE;

-- Then create as views (see SQL above)
CREATE VIEW framework_scores AS...
CREATE VIEW compliance_scans AS...
CREATE VIEW control_results AS...
CREATE VIEW rule_control_mapping AS...
CREATE VIEW compliance_controls AS...  -- Or keep as table if you want extra metadata
```

### **Keep as Tables (8 total):**
```
✅ tenants
✅ compliance_control_mappings (960 rows)
✅ compliance_frameworks (5 rows)
✅ report_index
✅ finding_index
✅ compliance_assessments
✅ control_assessment_results
✅ remediation_tracking
```

---

## 📊 **Benefit of Using Views**

**Storage:** Saves ~5 empty tables  
**Consistency:** Always in sync with source data  
**Performance:** Computed on-demand (fine for low query volume)  
**Maintenance:** No need to populate/sync

**Tradeoff:** Slightly slower queries (but negligible for small datasets)

---

## ✅ **Summary**

**Can be Views:** 5 tables (framework_scores, compliance_scans, control_results, rule_control_mapping, maybe compliance_controls)

**Must be Tables:** 3 tables (assessments, assessment_results, remediation_tracking) + 5 core tables

**Recommendation:** Convert 4-5 tables to views to simplify schema

---

**Want me to create the view definitions and update the compliance schema?**
