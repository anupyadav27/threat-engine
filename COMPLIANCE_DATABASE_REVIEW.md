# Compliance Database - Complete Review

**Database:** threat_engine_compliance  
**Purpose:** Store compliance framework mappings and compliance reports

---

## 📊 **Current Table Structure (13 Tables)**

### **Core Tables:**

| Table | Rows | Description |
|-------|------|-------------|
| **compliance_control_mappings** | **960** | ✅ Framework control → rule mappings (uploaded from CSV) |
| **compliance_frameworks** | **5** | ✅ Default frameworks (CIS, PCI-DSS, NIST, SOC2, HIPAA) |
| **tenants** | **1** | ✅ dbeaver-demo tenant |
| **report_index** | **0** | Compliance reports (waiting for generation) |
| **finding_index** | **0** | Compliance findings (waiting for generation) |
| **compliance_controls** | **0** | Control definitions |
| **rule_control_mapping** | **0** | Rule-to-control detailed mappings |
| **compliance_assessments** | **0** | Compliance assessments |
| **control_assessment_results** | **0** | Assessment results per control |
| **remediation_tracking** | **0** | Remediation tracking |
| **compliance_scans** | **0** | Compliance scan metadata |
| **control_results** | **0** | Control test results |
| **framework_scores** | **0** | Framework compliance scores |

---

## 📋 **Key Tables Explained**

### **1. compliance_control_mappings (960 rows)**

**What it contains:**
```
- unique_compliance_id: Unique ID per control
- compliance_framework: CIS, PCI-DSS, NIST, ISO27001, SOC2, FedRAMP, etc.
- requirement_id: Control number (e.g., "1.14", "AC-2", "10.2.1.3")
- requirement_name: Control title
- service: Which AWS service (S3, IAM, EC2, etc.)
- rule_ids: Array of check rule_ids that satisfy this control
```

**DBeaver Query:**
```sql
SELECT 
  compliance_framework,
  requirement_id,
  requirement_name,
  service,
  array_length(rule_ids, 1) as mapped_rules,
  rule_ids
FROM compliance_control_mappings
WHERE service = 'S3'
LIMIT 10;
```

---

### **2. report_index (0 rows - Waiting for Reports)**

**What it will contain:**
```
- report_id: UUID
- tenant_id: Tenant identifier  
- scan_run_id: Check scan ID
- total_controls: Total controls checked
- controls_passed: Controls that passed
- controls_failed: Controls that failed
- report_data: Full JSON report
```

**Populated by:** Compliance engine when report is generated

---

### **3. finding_index (0 rows - Waiting for Findings)**

**What it will contain:**
```
- finding_id: Unique finding ID
- report_id: Link to report
- rule_id: Security check rule
- status: PASS/FAIL
- severity: Critical/High/Medium/Low
- resource_arn: Affected resource
- finding_data: Full finding details
```

**Populated by:** Compliance engine when mapping check_results to controls

---

## ⚠️ **Why Reports Aren't Being Generated**

### **Compliance Engine Issue:**

**Error:** "No check results found"

**But data exists:**
```sql
-- In threat_engine_check:
SELECT COUNT(*) FROM check_results 
WHERE scan_id = 'check_20260201_044813' 
  AND tenant_id = 'dbeaver-demo';
-- Returns: 1056 ✅
```

**Root Cause:** Compliance engine can connect to CHECK_DB but query returns 0 results.

**Possible Issues:**
1. ✅ Password encoding - FIXED
2. ✅ Tenant exists - CREATED
3. ❌ Query logic bug - compliance engine's CheckDBLoader query has an issue
4. ❌ Schema search_path - might be looking in wrong schema

---

## 🔧 **Debug Steps**

### **Option 1: Check Schema Search Path**

```sql
-- In threat_engine_check, verify data is in public schema:
SELECT schemaname, tablename 
FROM pg_tables 
WHERE tablename = 'check_results';
-- Should show: public | check_results
```

### **Option 2: Test Compliance Query Directly**

```python
# What compliance engine runs:
import psycopg2
conn = psycopg2.connect(
    host="postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    port=5432,
    database="threat_engine_check",
    user="postgres",
    password="apXuHV%2OSyRWK62"
)
cur = conn.cursor()
cur.execute("""
    SELECT COUNT(*) FROM check_results 
    WHERE scan_id = %s AND tenant_id = %s
""", ('check_20260201_044813', 'dbeaver-demo'))
print(cur.fetchone())  # Should return (1056,)
```

### **Option 3: Add SQL Logging**

Add to compliance engine check_db_loader.py:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
# Will log all SQL queries
```

---

## ✅ **What You Can See in DBeaver**

**Connect to: threat_engine_compliance**

### **Query 1: Framework Mappings**
```sql
SELECT * FROM compliance_control_mappings LIMIT 100;
-- 960 rows ✅
```

### **Query 2: CIS Controls for S3**
```sql
SELECT 
  requirement_id,
  requirement_name,
  rule_ids
FROM compliance_control_mappings
WHERE compliance_framework = 'CIS'
  AND 'aws.s3.bucket.encryption_enabled' = ANY(rule_ids);
```

### **Query 3: Default Frameworks**
```sql
SELECT * FROM compliance_frameworks;
-- 5 frameworks: CIS, PCI-DSS, SOC2, NIST, HIPAA
```

---

## 🎯 **Next Steps**

1. ✅ Tenant created in compliance DB
2. ⏳ Debug why compliance query returns 0 (add logging)
3. ⏳ Fix query and regenerate report
4. ✅ Once working, you'll see:
   - report_index: 1+ reports
   - finding_index: 1,056 findings mapped to controls

---

**The compliance database structure is correct and has 960 mappings ready. Just need to debug the query issue.** Want me to add SQL logging to the compliance engine?