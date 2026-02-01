# 🎯 Compliance Analysis Queries - Check Results → Compliance Controls

**Goal:** See which resources pass/fail compliance controls

---

## 📊 **Cross-Database Queries**

Since check_results and compliance_control_mappings are in different databases, you have 2 options:

### **Option 1: Query Each DB Separately (Easier in DBeaver)**

### **Option 2: Use dblink (PostgreSQL extension)**

---

## 🔍 **Compliance Analysis Queries**

### **Query 1: Which S3 Buckets Fail CIS Controls**

**In DBeaver SQL Editor:**

```sql
-- Connect to: threat_engine_check

-- Step 1: See which S3 checks are failing
SELECT 
    cr.rule_id,
    cr.status,
    cr.resource_uid as bucket_arn,
    COUNT(*) as occurrences
FROM check_results cr
WHERE cr.status = 'FAIL'
  AND cr.service = 's3'
GROUP BY cr.rule_id, cr.status, cr.resource_uid
ORDER BY cr.rule_id, cr.resource_uid
LIMIT 50;
```

**Then connect to: threat_engine_compliance**

```sql
-- Step 2: Map those rule_ids to CIS controls
SELECT 
    compliance_framework,
    requirement_id as cis_control,
    requirement_name,
    service,
    rule_ids
FROM compliance_control_mappings
WHERE compliance_framework = 'CIS'
  AND service LIKE '%S3%'
  AND rule_ids && ARRAY[
    'aws.s3.bucket.encryption_enabled',
    'aws.s3.bucket.versioning_enabled',
    'aws.s3.account.level_public_access_blocks_configured'
  ]::VARCHAR[]
ORDER BY requirement_id;
```

---

### **Query 2: Compliance Status Per Resource**

**Step 1: Export check_results to find failing resources**

```sql
-- In threat_engine_check database:
SELECT 
    resource_uid as bucket,
    COUNT(*) as total_checks,
    COUNT(*) FILTER (WHERE status = 'PASS') as passed,
    COUNT(*) FILTER (WHERE status = 'FAIL') as failed,
    ROUND(100.0 * COUNT(*) FILTER (WHERE status = 'PASS') / COUNT(*), 2) as pass_rate
FROM check_results
GROUP BY resource_uid
ORDER BY failed DESC, bucket;
```

**Example Output:**
```
bucket                                        | total_checks | passed | failed | pass_rate
arn:aws:s3:::cspm-lgtech                     |     50       |   2    |   48   |   4.00
arn:aws:s3:::aiwebsite01                     |     50       |   3    |   47   |   6.00
arn:aws:s3:::cloudtrail-test-d736bbca        |     50       |   5    |   45   |  10.00
```

---

### **Query 3: CIS Control Compliance Summary**

**In threat_engine_compliance:**

```sql
-- Which CIS controls have the most failing checks?
SELECT 
    ccm.requirement_id as cis_control,
    ccm.requirement_name,
    ccm.service,
    array_length(ccm.rule_ids, 1) as mapped_rules,
    ccm.rule_ids
FROM compliance_control_mappings ccm
WHERE ccm.compliance_framework = 'CIS'
ORDER BY ccm.requirement_id
LIMIT 30;
```

**Then manually match with your check_results to see pass/fail**

---

## 🔗 **Better: Create Cross-Database View**

**If you want automated cross-DB queries, create this view:**

### **In threat_engine_compliance, create:**

```sql
-- Install dblink extension first
CREATE EXTENSION IF NOT EXISTS dblink;

-- Create view that joins across databases
CREATE OR REPLACE VIEW compliance_with_results AS
SELECT 
    ccm.compliance_framework,
    ccm.requirement_id as control_id,
    ccm.requirement_name as control_name,
    ccm.service,
    unnest(ccm.rule_ids) as rule_id,
    cr.resource_uid,
    cr.status as check_status,
    cr.finding_data
FROM compliance_control_mappings ccm
CROSS JOIN LATERAL unnest(ccm.rule_ids) as rule_id
LEFT JOIN dblink(
    'hostaddr=postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com 
     port=5432 
     dbname=threat_engine_check 
     user=postgres 
     password=apXuHV%2OSyRWK62',
    'SELECT rule_id, resource_uid, status, finding_data FROM check_results'
) AS cr(rule_id VARCHAR, resource_uid TEXT, status VARCHAR, finding_data JSONB)
  ON cr.rule_id = unnest(ccm.rule_ids);
```

**Then query:**
```sql
SELECT 
    compliance_framework,
    control_id,
    control_name,
    resource_uid as bucket,
    check_status
FROM compliance_with_results
WHERE compliance_framework = 'CIS'
  AND check_status = 'FAIL'
LIMIT 50;
```

---

## 📊 **Practical Analysis - What You Want to Know**

### **Which buckets are non-compliant with CIS?**

**Step-by-step in DBeaver:**

1. **Connect to threat_engine_check**
2. **Run:**
```sql
-- Failing S3 buckets
SELECT 
    resource_uid as bucket,
    COUNT(*) FILTER (WHERE status = 'FAIL') as failed_checks,
    string_agg(DISTINCT rule_id, ', ') as failing_rules
FROM check_results
WHERE status = 'FAIL'
GROUP BY resource_uid
HAVING COUNT(*) FILTER (WHERE status = 'FAIL') > 5
ORDER BY failed_checks DESC;
```

3. **Connect to threat_engine_compliance**
4. **Run:**
```sql
-- Which CIS controls do those rules map to?
SELECT 
    compliance_framework,
    requirement_id,
    requirement_name,
    rule_ids
FROM compliance_control_mappings
WHERE compliance_framework = 'CIS'
  AND rule_ids && ARRAY[
    -- Paste the failing_rules from step 2
    'aws.s3.bucket.encryption_enabled',
    'aws.s3.account.level_public_access_blocks_configured'
  ]::VARCHAR[];
```

---

## 🎯 **Simple Summary Query**

**To see overall compliance without joins:**

```sql
-- In threat_engine_check:
SELECT 
    'Total Checks' as metric,
    COUNT(*) as value
FROM check_results
UNION ALL
SELECT 'Passed', COUNT(*) FROM check_results WHERE status = 'PASS'
UNION ALL
SELECT 'Failed', COUNT(*) FROM check_results WHERE status = 'FAIL'
UNION ALL
SELECT 'Pass Rate %', ROUND(100.0 * COUNT(*) FILTER (WHERE status = 'PASS') / COUNT(*), 2)
FROM check_results;

-- Result:
-- Total Checks: 1056
-- Passed: 43 (4%)
-- Failed: 1013 (96%)
-- Your S3 buckets are 96% non-compliant!
```

---

**Use these queries in DBeaver SQL Editor to see your compliance status!** 📊
