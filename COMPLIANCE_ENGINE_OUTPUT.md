# Compliance Engine - Complete Output Explanation

**What it does:** Maps security check findings to compliance framework controls

---

## 🔄 **Compliance Engine Flow**

```
INPUT:
├─ check_results from threat_engine_check (1,056 findings)
│  └─ Each finding has: rule_id, status (PASS/FAIL), resource_arn
│
└─ compliance_control_mappings from threat_engine_compliance (960 controls)
   └─ Each control has: framework, requirement_id, rule_ids (array)
        ↓
PROCESSING:
├─ For each check_result:
│  ├─ Find which compliance controls contain this rule_id
│  ├─ Map finding to control
│  └─ Determine if control PASSED or FAILED
│
└─ Group by framework (CIS, PCI-DSS, NIST, etc.)
        ↓
OUTPUT: Two tables in threat_engine_compliance
├─ report_index: Overall compliance report per framework
└─ finding_index: Individual findings mapped to controls
```

---

## 📊 **Output Table 1: report_index**

**Purpose:** Overall compliance report metadata (one row per framework per scan)

**Structure:**
```sql
CREATE TABLE report_index (
    report_id UUID PRIMARY KEY,
    tenant_id VARCHAR,
    scan_run_id VARCHAR,              -- The check scan ID
    cloud VARCHAR,                     -- 'aws', 'azure', etc.
    trigger_type VARCHAR,
    collection_mode VARCHAR,
    started_at TIMESTAMP,
    completed_at TIMESTAMP,
    
    -- Summary metrics
    total_controls INTEGER,           -- How many controls were tested
    controls_passed INTEGER,          -- How many controls passed
    controls_failed INTEGER,          -- How many controls failed
    total_findings INTEGER,           -- Total check findings
    
    -- Full report JSON
    report_data JSONB                 -- Complete compliance report
);
```

**Example Row (after compliance runs):**
```json
{
  "report_id": "abc-123-xyz",
  "tenant_id": "dbeaver-demo",
  "scan_run_id": "check_20260201_044813",
  "cloud": "aws",
  "total_controls": 85,         // 85 CIS controls tested
  "controls_passed": 5,         // 5 controls passed
  "controls_failed": 80,        // 80 controls failed
  "total_findings": 1056,
  "report_data": {
    "framework": "CIS",
    "version": "1.5.0",
    "compliance_score": 5.9,    // 5.9% compliant
    "controls": [...]
  }
}
```

**How to view:**
```sql
-- After compliance runs:
SELECT 
    scan_run_id,
    cloud,
    total_controls,
    controls_passed,
    controls_failed,
    ROUND(100.0 * controls_passed / total_controls, 2) as compliance_percentage
FROM report_index
ORDER BY completed_at DESC;
```

---

## 📊 **Output Table 2: finding_index**

**Purpose:** Individual findings mapped to compliance controls (one row per finding per control)

**Structure:**
```sql
CREATE TABLE finding_index (
    finding_id VARCHAR PRIMARY KEY,
    report_id UUID,                   -- Links to report_index
    tenant_id VARCHAR,
    scan_run_id VARCHAR,
    
    rule_id VARCHAR,                  -- Security check rule
    category VARCHAR,
    severity VARCHAR,                 -- critical, high, medium, low
    confidence VARCHAR,
    status VARCHAR,                   -- 'PASS', 'FAIL', 'open', 'closed'
    
    first_seen_at TIMESTAMP,
    last_seen_at TIMESTAMP,
    
    resource_type VARCHAR,
    resource_id VARCHAR,
    resource_arn TEXT,                -- Which resource failed/passed
    region VARCHAR,
    
    finding_data JSONB                -- Full finding details + which controls it maps to
);
```

**Example Rows (after compliance runs):**
```json
[
  {
    "finding_id": "finding-1",
    "report_id": "abc-123-xyz",
    "scan_run_id": "check_20260201_044813",
    "rule_id": "aws.s3.bucket.encryption_enabled",
    "status": "FAIL",
    "severity": "high",
    "resource_arn": "arn:aws:s3:::cspm-lgtech",
    "finding_data": {
      "compliance_controls": [
        "CIS 2.1.1",
        "PCI-DSS 3.4",
        "NIST SC-28"
      ],
      "title": "S3 bucket encryption not enabled",
      "remediation": "Enable default encryption..."
    }
  },
  {
    "finding_id": "finding-2",
    "rule_id": "aws.s3.bucket.versioning_enabled",
    "status": "FAIL",
    "resource_arn": "arn:aws:s3:::cspm-lgtech",
    "finding_data": {
      "compliance_controls": [
        "CIS 2.1.3",
        "SOC2 CC6.1"
      ]
    }
  }
]
```

**How to view:**
```sql
-- After compliance runs:
SELECT 
    fi.rule_id,
    fi.status,
    fi.resource_arn,
    fi.severity,
    fi.finding_data->>'compliance_controls' as mapped_controls
FROM finding_index fi
WHERE fi.status = 'FAIL'
  AND fi.severity IN ('critical', 'high')
ORDER BY fi.severity, fi.rule_id
LIMIT 50;
```

---

## 🎯 **Complete Compliance View**

**What you'll see after compliance engine runs successfully:**

### **report_index (1 row per framework):**
```
CIS Framework Report:
  - Total Controls: 85
  - Passed: 5 (5.9%)
  - Failed: 80 (94.1%)
  - Findings: 1,056

PCI-DSS Report:
  - Total Controls: 42
  - Passed: 2 (4.8%)
  - Failed: 40 (95.2%)
  - Findings: 1,056

NIST CSF Report:
  - Total Controls: 35
  - Passed: 3 (8.6%)
  - Failed: 32 (91.4%)
  - Findings: 1,056
```

### **finding_index (1,056+ rows):**
```
Each of your 1,056 check_results mapped to compliance controls:

Finding 1:
  - Rule: aws.s3.bucket.encryption_enabled
  - Resource: arn:aws:s3:::cspm-lgtech
  - Status: FAIL
  - Maps to: CIS 2.1.1, PCI-DSS 3.4, NIST SC-28

Finding 2:
  - Rule: aws.s3.account.level_public_access_blocks_configured
  - Resource: arn:aws:s3:::cspm-lgtech
  - Status: FAIL
  - Maps to: CIS 2.1.5, PCI-DSS 1.2.1

... (1,056 total findings mapped to controls)
```

---

## 📋 **How to View in DBeaver**

### **Once Compliance Engine Works:**

**Connect to: threat_engine_compliance**

**Query 1: Compliance Reports Summary**
```sql
SELECT 
    cloud,
    total_controls,
    controls_passed,
    controls_failed,
    ROUND(100.0 * controls_passed / total_controls, 2) as compliance_pct,
    completed_at
FROM report_index
ORDER BY completed_at DESC;
```

**Query 2: All Compliance Findings**
```sql
SELECT 
    rule_id,
    status,
    severity,
    resource_arn as bucket,
    finding_data->>'compliance_controls' as controls
FROM finding_index
WHERE status = 'FAIL'
ORDER BY severity, rule_id;
```

**Query 3: CIS Control Compliance Status**
```sql
SELECT 
    cr.requirement_id as cis_control,
    cr.requirement_name,
    cr.failed as failing_checks,
    cr.passed as passing_checks,
    cr.control_status
FROM control_results cr  -- This is a VIEW we created!
WHERE cr.compliance_framework = 'CIS'
ORDER BY cr.failed DESC;
```

---

## ⚠️ **Current Status**

**Tables:**
- report_index: **0 rows** (compliance engine not generating due to query bug)
- finding_index: **0 rows** (compliance engine not generating)

**Once fixed, you'll see:**
- report_index: 4-5 rows (one per framework: CIS, PCI-DSS, NIST, SOC2, HIPAA)
- finding_index: ~1,056+ rows (each check_result mapped to its controls)

---

## 🎯 **Summary**

**Compliance engine produces 2 main outputs:**

1. **report_index** - Framework-level compliance reports
2. **finding_index** - Finding-level compliance mappings

**Plus views:**
- control_results - Compliance status per control (aggregated)
- framework_scores - Overall scores per framework

**All queryable in DBeaver once compliance engine successfully generates reports!**

---

**The tables are ready and waiting - just need the compliance query bug fixed to populate them!** 📊
