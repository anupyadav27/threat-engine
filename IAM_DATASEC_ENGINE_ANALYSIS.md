# IAM & DataSec Engines - Architecture Analysis

**Date:** February 1, 2026  
**Purpose:** Understand IAM and DataSec engines before applying database-first fixes

---

## 🎯 **ENGINE PURPOSE**

### **IAM Security Engine (`engine_iam`)**
- **Focus:** Identity & Access Management posture
- **Analyzes:** IAM roles, policies, MFA, password policies, least privilege, access control
- **Input:** Threat DB (`threat_reports.misconfig_findings`)
- **Filter:** Rules where `domain: identity_and_access_management`
- **Port:** 8003

### **Data Security Engine (`engine_datasec`)**
- **Focus:** Data protection, classification, governance
- **Analyzes:** Data encryption, PII/PCI/PHI classification, data residency, lineage, activity monitoring
- **Input:** Threat DB (`threat_reports.misconfig_findings`)
- **Filter:** Rules where `data_security.applicable: true`
- **Port:** 8004

---

## 🔄 **CURRENT ARCHITECTURE (Both Engines)**

```
┌─────────────────────────────────────────────────────────────────┐
│ INPUT SOURCE                                                    │
├─────────────────────────────────────────────────────────────────┤
│ threat_engine_threat.threat_reports                             │
│   └─ report_data JSONB column contains:                        │
│       └─ misconfig_findings[] (all check results from threat)  │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ PROCESSING                                                      │
├─────────────────────────────────────────────────────────────────┤
│ 1. ThreatDBReader                                               │
│    └─ Reads FROM threat_reports (PostgreSQL)                   │
│    └─ Filters misconfig_findings by rule_ids                   │
│                                                                 │
│ 2. RuleDBReader (file-based)                                    │
│    └─ Reads rule metadata YAMLs                                │
│    └─ Identifies IAM/DataSec relevant rules                    │
│                                                                 │
│ 3. FindingEnricher                                              │
│    └─ Adds iam_security_context / data_security_context        │
│                                                                 │
│ 4. Reporter                                                     │
│    └─ Generates IAM/DataSec report                             │
└─────────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│ OUTPUT                                                          │
├─────────────────────────────────────────────────────────────────┤
│ Currently: Local JSON files only                                │
│   └─ engine_output/iam/reports/{tenant_id}/{scan_id}_report.json│
│   └─ engine_output/datasec/reports/{tenant_id}/{scan_id}_report.json│
│                                                                 │
│ ❌ NO RDS persistence yet                                       │
│ ❌ NO S3 sync yet                                               │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔍 **KEY FINDINGS**

### **1. Both Engines Read from Threat DB**

Both engines use `ThreatDBReader` to read from:
```python
# Connection string builder (SAME ISSUE as compliance!)
def _threat_db_connection_string() -> str:
    base = (
        f"postgresql://{os.getenv('THREAT_DB_USER', 'threat_user')}:"
        f"{os.getenv('THREAT_DB_PASSWORD', 'threat_password')}@"  # ❌ Password % issue!
        f"{os.getenv('THREAT_DB_HOST', 'localhost')}:"
        f"{os.getenv('THREAT_DB_PORT', '5432')}/"
        f"{os.getenv('THREAT_DB_NAME', 'threat_engine_threat')}"
    )
```

**Issue:** ❌ Same password parsing bug (`apXuHV%2OSyRWK62` will fail)

### **2. No RDS Output Storage**

Both engines only write to local files:
```python
# IAM
report_storage.save_report(report, tenant_id, scan_id)
  └─ Saves to: engine_output/iam/reports/{tenant_id}/{scan_id}_report.json

# DataSec  
report_storage.save_report(report, tenant_id, scan_id)
  └─ Saves to: engine_output/datasec/reports/{tenant_id}/{scan_id}_report.json
```

**Missing:** ❌ No database writer, no S3 sync sidecar

### **3. No Dedicated RDS Tables**

Unlike compliance engine, these don't have dedicated output tables:
- ❌ No `iam_reports` table
- ❌ No `iam_findings` table
- ❌ No `datasec_reports` table
- ❌ No `datasec_findings` table

---

## 🎯 **WHAT NEEDS TO BE FIXED**

### **Priority 1: Password Parsing Bug (Same as Compliance)**

Both `threat_db_reader.py` files have the DSN password issue:

**Current (broken):**
```python
def _threat_db_connection_string() -> str:
    base = f"postgresql://{user}:{password}@{host}:{port}/{db}"
    # Password with % will fail: apXuHV%2OSyRWK62
```

**Fix (use individual params):**
```python
def _get_threat_db_connection():
    return psycopg2.connect(
        host=os.getenv('THREAT_DB_HOST', 'localhost'),
        port=int(os.getenv('THREAT_DB_PORT', '5432')),
        database=os.getenv('THREAT_DB_NAME', 'threat_engine_threat'),
        user=os.getenv('THREAT_DB_USER', 'postgres'),
        password=os.getenv('THREAT_DB_PASSWORD', '')
    )
```

### **Priority 2: Add RDS Persistence (Optional)**

Decide if IAM/DataSec need dedicated database tables like compliance:

**Option A: Store in threat_engine_threat (reuse existing DB)**
```sql
-- Add to threat_engine_threat:
CREATE TABLE iam_reports (...);
CREATE TABLE iam_findings (...);
CREATE TABLE datasec_reports (...);
CREATE TABLE datasec_findings (...);
```

**Option B: Store in threat_engine_compliance (consolidated)**
```sql
-- Add to threat_engine_compliance:
CREATE TABLE specialized_reports (
    report_id UUID,
    report_type VARCHAR(50),  -- 'iam', 'datasec'
    tenant_id VARCHAR,
    scan_run_id VARCHAR,
    report_data JSONB,
    ...
);
```

**Option C: File-based only (current)**
- Keep storing to local files
- Add S3 sync sidecar
- No dedicated RDS tables

### **Priority 3: Add S3 Sync (Like Compliance)**

Add sidecar containers to deployment YAMLs:
```yaml
# For IAM engine
- name: s3-sync
  image: amazon/aws-cli:latest
  volumeMounts:
    - name: output
      mountPath: /output
  env:
    - name: ENGINE_NAME
      value: "iam"

# For DataSec engine  
- name: s3-sync
  image: amazon/aws-cli:latest
  volumeMounts:
    - name: output
      mountPath: /output
  env:
    - name: ENGINE_NAME
      value: "datasec"
```

---

## 📊 **COMPARISON WITH COMPLIANCE ENGINE**

| Feature | Compliance | IAM | DataSec |
|---------|-----------|-----|---------|
| **Input Source** | check_results (check DB) | threat_reports (threat DB) | threat_reports (threat DB) |
| **Input Query** | Direct SQL | Via ThreatDBReader | Via ThreatDBReader |
| **Password Bug** | ✅ Fixed | ❌ Has bug | ❌ Has bug |
| **RDS Output** | ✅ report_index + finding_index | ❌ None | ❌ None |
| **File Output** | ✅ /output/compliance/ | ✅ /output/iam/ (local only) | ✅ /output/datasec/ (local only) |
| **S3 Sync** | ✅ Sidecar configured | ❌ No sidecar | ❌ No sidecar |
| **Deployment** | ✅ EKS running | ❓ Unknown | ❓ Unknown |

---

## 🎯 **RECOMMENDED FIXES (In Order)**

### **Phase 1: Fix Password Bug (Immediate)**

**Files to fix:**
1. `/Users/apple/Desktop/threat-engine/engine_iam/iam_engine/input/threat_db_reader.py`
2. `/Users/apple/Desktop/threat-engine/engine_datasec/data_security_engine/input/threat_db_reader.py`

**Change:** Replace `_threat_db_connection_string()` with `_get_threat_db_connection()` using individual params

### **Phase 2: Add S3 Sync (High Priority)**

**Files to create/update:**
1. `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/iam-engine-deployment.yaml`
2. `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/datasec-engine-deployment.yaml`

**Changes:**
- Add S3 sync sidecar container
- Add `/output` volume mounts
- Set `OUTPUT_DIR=/output` env var
- Configure IRSA service account

### **Phase 3: Add RDS Persistence (Optional)**

**Decision needed:** Do IAM/DataSec reports need to be in RDS, or is S3 enough?

**If YES (like compliance):**
- Create `iam_reports` and `datasec_reports` tables
- Create DB writer classes
- Update API servers to persist to RDS

**If NO:**
- Keep file-based storage
- Just add S3 sync for durability

---

## 📋 **NEXT STEPS**

### **Minimal Fix (Get them working):**
1. Fix password bug in both `threat_db_reader.py` files
2. Test locally that they can connect to threat DB
3. Add S3 sync sidecars to deployments
4. Deploy to EKS and verify S3 sync works

### **Full Database-First (Match Compliance):**
1. Fix password bug
2. Design IAM/DataSec database schemas
3. Create DB writer classes
4. Add S3 sync sidecars
5. Deploy and verify both RDS + S3 persistence

---

## ❓ **QUESTIONS TO ANSWER**

1. **Are IAM/DataSec currently deployed to EKS?**
   - Check: `kubectl -n threat-engine-engines get deployments | grep -E "iam|datasec"`

2. **Do we have threat_engine_threat database on RDS?**
   - Check: `psql -h <RDS> -U postgres -l | grep threat`

3. **Do IAM/DataSec reports need to be queryable in DBeaver?**
   - If YES → Add RDS tables
   - If NO → Just add S3 sync

4. **What's the expected flow?**
   - Option A: `threat → iam/datasec` (current)
   - Option B: `check → threat → iam/datasec`
   - Option C: `check → iam/datasec` (skip threat)

---

**Let's start with checking if these engines are deployed and if threat DB exists, then decide on the fix strategy.**
