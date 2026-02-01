# 🔗 Complete DBeaver Connection Guide - All 3 Databases

**All databases on same RDS instance - just change database name**

---

## 📝 **Common Settings (Use for All 3 Connections)**

```
Host:     postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
Port:     5432
Username: postgres
Password: apXuHV%2OSyRWK62
SSL Mode: require

☑ Show all databases (check this!)
```

---

## 🔗 **Connection 1: Discoveries Database**

**Name:** `RDS - Discoveries (169 S3 buckets)`

**Settings:**
- Database: **`threat_engine_discoveries`**
- (All other settings same as above)

**What You'll See:**
- `discoveries`: **169 rows** - S3 bucket discoveries
- `rule_definitions`: **2,501 rows** - Rule YAMLs
- `scans`: **5 rows** - Discovery scans

**Test Query:**
```sql
SELECT 
  emitted_fields->>'Name' as bucket_name,
  resource_uid as bucket_arn
FROM discoveries
WHERE discovery_id = 'aws.s3.list_buckets'
ORDER BY emitted_fields->>'Name';
```

---

## 🔗 **Connection 2: Check Database**

**Name:** `RDS - Check (1,056 security findings)`

**Settings:**
- Database: **`threat_engine_check`**
- (All other settings same as above)

**What You'll See:**
- `check_results`: **1,056 rows** - Security findings (1,013 FAIL, 43 PASS)
- `rule_metadata`: **1,918 rows** - Security rules
- `scans`: **2 rows** - Check scans

**Test Query:**
```sql
SELECT 
  rule_id,
  status,
  COUNT(*) as occurrences
FROM check_results
GROUP BY rule_id, status
ORDER BY occurrences DESC
LIMIT 20;
```

---

## 🔗 **Connection 3: Compliance Database**

**Name:** `RDS - Compliance (960 framework mappings)`

**Settings:**
- Database: **`threat_engine_compliance`**
- (All other settings same as above)

**What You'll See:**
- `compliance_control_mappings`: **960 rows** - Framework controls
- `compliance_frameworks`: **5 rows** - CIS, PCI-DSS, NIST, SOC2, HIPAA
- `report_index`: **0 rows** - (will populate after compliance runs)
- `finding_index`: **0 rows** - (will populate after compliance runs)

**Test Query:**
```sql
SELECT 
  compliance_framework,
  COUNT(*) as controls
FROM compliance_control_mappings
GROUP BY compliance_framework
ORDER BY controls DESC;
```

---

## 🎯 **Quick Setup in DBeaver**

1. **Create Connection 1:**
   - Database: `threat_engine_discoveries`
   - Save as: "RDS - Discoveries"

2. **Duplicate Connection:**
   - Right-click connection → Duplicate
   - Change database to: `threat_engine_check`
   - Save as: "RDS - Check"

3. **Duplicate Again:**
   - Change database to: `threat_engine_compliance`
   - Save as: "RDS - Compliance"

**Or use "Show all databases" and browse all 6 from one connection!**

---

## ✅ **Data Summary**

| Database | Key Tables | Total Rows |
|----------|------------|------------|
| **discoveries** | discoveries, rule_definitions | **2,670** |
| **check** | check_results, rule_metadata | **2,974** |
| **compliance** | compliance_control_mappings, frameworks | **965** |

**Grand Total:** **6,609 records** in RDS databases! 🎉

---

**Create all 3 connections in DBeaver to see the complete data flow!**
