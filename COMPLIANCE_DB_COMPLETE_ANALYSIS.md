# Compliance Database - Complete Usage Analysis

**Database:** `threat_engine_compliance` on RDS  
**Last Compliance Run:** February 1, 2026  
**Status:** ✅ Working (report_index + finding_index)

---

## ✅ **ACTIVELY USED BY ENGINE**

### **Tables (4 in active use):**

| Table | Rows | Read/Write | Purpose |
|-------|------|------------|---------|
| **`tenants`** | 1 | Write | Tenant metadata (FK for other tables) |
| **`report_index`** | 1 | Write | **PRIMARY** compliance report storage |
| **`finding_index`** | 231 | Write | Individual compliance findings (failed checks) |
| **`compliance_control_mappings`** | 960 | Read | Maps `rule_ids[]` → compliance framework controls |

### **Views (3 in active use):**

| View | Based On | Used By | Query Pattern |
|------|----------|---------|---------------|
| **`compliance_scans`** | `report_index` | Could be used by API | SELECT for scan summaries |
| **`framework_scores`** | `compliance_control_mappings` | Could be used by API | Aggregate framework stats |
| **`control_results`** | `compliance_control_mappings` + `finding_index` | Could be used by API | JOIN to show control status |

---

## 🔄 **ENGINE DATA FLOW**

```
┌─────────────────────────────────────────────────────────────────┐
│ INPUT                                                           │
├─────────────────────────────────────────────────────────────────┤
│ 1. threat_engine_check.check_results (1,056 rows)              │
│    └─ scan_id: check_20260201_044813                          │
│                                                                 │
│ 2. threat_engine_compliance.compliance_control_mappings (960)  │
│    └─ Maps aws.s3.* rules → CIS/PCI-DSS/ISO27001 controls     │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ PROCESSING (Compliance Engine)                                  │
├─────────────────────────────────────────────────────────────────┤
│ 1. Load check_results via CheckDBLoader                        │
│ 2. Map rule_ids to controls via FrameworkLoader                │
│ 3. Aggregate by framework (CIS, PCI-DSS, ISO27001, etc.)      │
│ 4. Calculate compliance scores                                 │
│ 5. Generate framework reports                                  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ OUTPUT                                                          │
├─────────────────────────────────────────────────────────────────┤
│ 1. RDS (threat_engine_compliance)                              │
│    ├─ report_index: 1 row                                      │
│    │   └─ report_id, scan_run_id, total_controls, scores      │
│    └─ finding_index: 231 rows                                  │
│        └─ One row per failed check (rule_id, resource, etc.)  │
│                                                                 │
│ 2. Local Files (/output)                                       │
│    └─ /output/compliance/{tenant}/{scan}/full_report.json     │
│                                                                 │
│ 3. S3 (via sidecar sync)                                       │
│    └─ s3://cspm-lgtech/engine_output/compliance/...           │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📋 **DETAILED TABLE USAGE**

### **1. `report_index` (PRIMARY OUTPUT)**

**Schema:**
```sql
CREATE TABLE report_index (
    report_id UUID PRIMARY KEY,
    tenant_id VARCHAR(255),
    scan_run_id VARCHAR(255),  -- Links to check scan
    cloud VARCHAR(50),
    trigger_type VARCHAR(50),
    collection_mode VARCHAR(50),
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    total_controls INTEGER,     -- Across all frameworks
    controls_passed INTEGER,
    controls_failed INTEGER,
    total_findings INTEGER,     -- Total failed checks
    report_data JSONB,          -- Full compliance report
    created_at TIMESTAMP
);
```

**Current Data:**
```
report_id: 42a135fa-2348-41c4-8f4e-a6daf9fb6ff6
scan_run_id: check_20260201_044813
tenant_id: dbeaver-demo
total_controls: 11
controls_passed: 0
controls_failed: 11
total_findings: 0 (should be 231 - bug in count)
```

**Used By:**
- ✅ `compliance_db_writer.py` - Writes reports
- ✅ `compliance_scans` VIEW - Exposes scan summaries
- ❌ API endpoints - Should query this for dashboard

---

### **2. `finding_index` (FINDINGS OUTPUT)**

**Schema:**
```sql
CREATE TABLE finding_index (
    finding_id VARCHAR(255) PRIMARY KEY,
    report_id UUID,             -- FK to report_index
    tenant_id VARCHAR(255),
    scan_run_id VARCHAR(255),
    rule_id VARCHAR(255),
    severity VARCHAR(20),       -- critical, high, medium, low
    status VARCHAR(20),         -- open, closed
    resource_type VARCHAR(100),
    resource_id VARCHAR(255),
    resource_arn TEXT,
    region VARCHAR(50),
    finding_data JSONB,         -- Full finding details + compliance context
    first_seen_at TIMESTAMP,
    last_seen_at TIMESTAMP
);
```

**Current Data:**
```
Total: 231 findings (all failed checks)
Example:
  - rule_id: aws.s3.bucket.versioning_enabled
  - severity: medium
  - status: open
  - resource_arn: arn:aws:s3:::www.lgtech.in
```

**Used By:**
- ✅ `compliance_db_writer.py` - Writes findings
- ✅ `control_results` VIEW - JOINs to show control status
- ❌ API endpoints - Should query this for finding drilldown

---

### **3. `compliance_control_mappings` (INPUT MAPPING)**

**Schema:**
```sql
CREATE TABLE compliance_control_mappings (
    unique_compliance_id VARCHAR(255) PRIMARY KEY,
    compliance_framework VARCHAR(100),  -- CIS, PCI-DSS, ISO27001, etc.
    requirement_id VARCHAR(255),        -- Control ID (e.g., "2.1.3")
    requirement_name TEXT,              -- Control description
    service VARCHAR(100),               -- AWS service (s3, ec2, etc.)
    rule_ids TEXT[],                    -- Array of rule_ids for this control
    -- ... other columns ...
);
```

**Current Data:**
```
Total: 960 controls across all frameworks
Loaded from: aws_consolidated_rules_with_final_checks.csv

Examples:
  - CIS 2.1.3: ["aws.s3.bucket.encryption_enabled", "aws.s3.macie_classification_jobs_status"]
  - PCI-DSS 3.4: ["aws.s3.bucket.encryption_enabled", "aws.rds.db_instance.storage_encryption_enabled"]
```

**Used By:**
- ✅ `FrameworkLoader` - Loads rule → control mappings
- ✅ `control_results` VIEW - JOINs to aggregate control status
- ✅ `framework_scores` VIEW - Counts controls by framework

---

## 📊 **VIEW DEFINITIONS**

### **`compliance_scans` (Report Summary View)**

```sql
SELECT 
    report_id AS scan_id,
    tenant_id,
    scan_run_id,
    cloud AS provider,
    trigger_type,
    started_at,
    completed_at,
    CASE 
        WHEN completed_at IS NOT NULL THEN 'completed'
        ELSE 'running'
    END AS status,
    total_controls,
    controls_passed,
    controls_failed,
    total_findings
FROM report_index;
```

**Purpose:** Simple rename/projection of `report_index` for backward compatibility

---

### **`framework_scores` (Framework Stats View)**

```sql
SELECT 
    compliance_framework AS framework_id,
    compliance_framework AS framework_name,
    COUNT(DISTINCT unique_compliance_id) AS total_controls,
    0 AS total_findings,
    0 AS passed_findings,
    0 AS failed_findings,
    0.0 AS compliance_percentage
FROM compliance_control_mappings
GROUP BY compliance_framework;
```

**Purpose:** Shows how many controls each framework has (static count from mappings)  
**Issue:** Doesn't calculate actual compliance % from findings

---

### **`control_results` (Control Status View)** ✅ **MOST USEFUL**

```sql
SELECT 
    ccm.unique_compliance_id AS control_id,
    ccm.compliance_framework,
    ccm.requirement_id,
    ccm.requirement_name,
    ccm.service,
    COUNT(DISTINCT fi.finding_id) AS total_findings,
    COUNT(*) FILTER (WHERE fi.status = 'PASS') AS passed,
    COUNT(*) FILTER (WHERE fi.status = 'FAIL') AS failed,
    CASE 
        WHEN COUNT(*) FILTER (WHERE fi.status = 'FAIL') = 0 THEN 'PASS'
        WHEN COUNT(*) FILTER (WHERE fi.status = 'FAIL') > 0 THEN 'FAIL'
        ELSE 'NOT_TESTED'
    END AS control_status
FROM compliance_control_mappings ccm
LEFT JOIN finding_index fi ON fi.rule_id = ANY(ccm.rule_ids)
GROUP BY ccm.unique_compliance_id, ccm.compliance_framework, 
         ccm.requirement_id, ccm.requirement_name, ccm.service;
```

**Purpose:** ✅ **This is powerful!** Shows which controls passed/failed based on actual findings  
**Query to use:**
```sql
SELECT * FROM control_results 
WHERE compliance_framework = 'CIS' 
ORDER BY failed DESC;
```

---

## 🎯 **SUMMARY**

### **CORE TABLES IN USE:**
1. ✅ `tenants` - Metadata
2. ✅ `report_index` - Compliance reports (1 row per run)
3. ✅ `finding_index` - Findings (231 rows from last run)
4. ✅ `compliance_control_mappings` - Rule mappings (960 rows)

### **USEFUL VIEWS:**
1. ✅ `control_results` - **USE THIS** to see which controls passed/failed
2. ⚠️ `compliance_scans` - Just renames `report_index` columns
3. ⚠️ `framework_scores` - Static counts, doesn't use actual findings

### **UNUSED TABLES:**
- `compliance_frameworks` (5 rows, pre-seeded, not read)
- `compliance_assessments` (0 rows, manual assessments)
- `control_assessment_results` (0 rows, assessment evidence)
- `remediation_tracking` (0 rows, remediation workflow)

### **UNUSED VIEWS:**
- `compliance_by_service`
- `compliance_controls`
- `framework_coverage`
- `multi_framework_controls`
- `rule_control_mapping`

---

## 📝 **RECOMMENDED QUERIES FOR DBEAVER**

### **1. See Latest Compliance Report:**
```sql
SELECT * FROM report_index ORDER BY created_at DESC LIMIT 1;
```

### **2. See All Findings:**
```sql
SELECT 
    rule_id,
    severity,
    status,
    resource_arn,
    finding_data->>'framework' as framework,
    finding_data->>'control_id' as control
FROM finding_index
ORDER BY severity DESC, rule_id
LIMIT 50;
```

### **3. See Which Controls Failed (BEST VIEW):**
```sql
SELECT 
    compliance_framework,
    requirement_id,
    requirement_name,
    failed,
    passed,
    control_status
FROM control_results
WHERE compliance_framework = 'CIS'
ORDER BY failed DESC;
```

### **4. Framework Compliance Summary:**
```sql
SELECT 
    compliance_framework,
    COUNT(*) as total_controls,
    SUM(CASE WHEN control_status = 'PASS' THEN 1 ELSE 0 END) as passed_controls,
    SUM(CASE WHEN control_status = 'FAIL' THEN 1 ELSE 0 END) as failed_controls,
    ROUND(100.0 * SUM(CASE WHEN control_status = 'PASS' THEN 1 ELSE 0 END) / COUNT(*), 2) as compliance_pct
FROM control_results
GROUP BY compliance_framework
ORDER BY compliance_pct DESC;
```

---

## 🎯 **RECOMMENDATION**

### **Keep It Simple:**

**TABLES TO KEEP:**
- ✅ `tenants`
- ✅ `report_index`
- ✅ `finding_index`  
- ✅ `compliance_control_mappings`

**VIEWS TO KEEP:**
- ✅ `control_results` (most useful - shows control status)
- ⚠️ `compliance_scans` (optional - just renames report_index)
- ⚠️ `framework_scores` (optional - but doesn't calculate real scores)

**CAN BE REMOVED (not used by engine):**
- ❌ Tables: `compliance_frameworks`, `compliance_assessments`, `control_assessment_results`, `remediation_tracking`
- ❌ Views: `compliance_by_service`, `compliance_controls`, `framework_coverage`, `multi_framework_controls`, `rule_control_mapping`

---

## ✅ **CURRENT SUCCESS STATUS**

```
✅ Compliance engine working
✅ 1 report in report_index
✅ 231 findings in finding_index  
✅ Files in S3
✅ S3 sidecar syncing

Query to verify:
SELECT COUNT(*) FROM control_results WHERE control_status = 'FAIL';
-- Should return 11 (the failed controls from your scan)
```
