# IAM & DataSec Engines - Status & Fix Plan

**Date:** February 1, 2026

---

## 📊 **CURRENT STATUS**

### **IAM Engine:**
- ✅ Code exists in `engine_iam/`
- ❌ NOT deployed to EKS
- ❌ No K8s deployment YAML
- ✅ Threat DB exists (`threat_engine_threat`)
- ❌ Password bug in `threat_db_reader.py`
- ❌ No S3 sync
- ❌ No RDS output tables

### **DataSec Engine:**
- ✅ Code exists in `engine_datasec/`
- ❌ NOT deployed to EKS
- ❌ No K8s deployment YAML
- ✅ Threat DB exists (`threat_engine_threat`)
- ❌ Password bug in `threat_db_reader.py`
- ❌ No S3 sync
- ❌ No RDS output tables

### **Threat DB on RDS:**
- ✅ Database exists: `threat_engine_threat`
- ❓ Tables unknown (need to check if `threat_reports` table exists)

---

## 🔄 **HOW THEY WORK**

### **Data Flow:**
```
Discoveries → Check → Threat → IAM/DataSec
                        ↓
              threat_reports table
         (contains misconfig_findings)
                        ↓
              ┌─────────┴─────────┐
              ↓                   ↓
         IAM Engine          DataSec Engine
         (filters by         (filters by
         IAM rules)          data rules)
              ↓                   ↓
         IAM Report          DataSec Report
         (JSON only)         (JSON only)
```

### **Key Difference from Compliance:**

| Aspect | Compliance Engine | IAM/DataSec Engines |
|--------|-------------------|---------------------|
| **Input** | check_results (1,056 rows) | threat_reports.misconfig_findings (filtered subset) |
| **Input DB** | threat_engine_check | threat_engine_threat |
| **Filter** | compliance_control_mappings | Rule metadata (domain/data_security fields) |
| **Output DB** | ✅ report_index + finding_index | ❌ None (files only) |
| **Output Files** | ✅ /output → S3 | ❌ Local only |

---

## 🎯 **RECOMMENDED STRATEGY**

### **Option 1: Simple Fix (Files + S3 only) - RECOMMENDED**

**What:**
- Fix password bug in both engines
- Add S3 sync sidecars
- Keep file-based storage (no new RDS tables)

**Why:**
- IAM/DataSec are specialized reports (not core security findings)
- They're derivatives of threat findings (already in threat_reports)
- File-based storage in S3 is sufficient
- Avoids RDS table proliferation

**Steps:**
1. Fix `threat_db_reader.py` password issue (2 files)
2. Create K8s deployment YAMLs with S3 sidecars
3. Deploy to EKS
4. Verify S3 sync works

### **Option 2: Full Database-First (Match Compliance)**

**What:**
- Fix password bug
- Create dedicated RDS tables for IAM/DataSec reports
- Add DB writers
- Add S3 sync sidecars

**Why:**
- Consistent architecture across all engines
- Queryable in DBeaver
- Better for analytics/trending

**Steps:**
1. Fix password bugs
2. Design schemas (`iam_reports`, `datasec_reports`)
3. Create DB writers
4. Create K8s deployments
5. Deploy and verify

---

## 🎯 **MY RECOMMENDATION**

### **Go with Option 1 (Simple Fix)**

**Reasoning:**
1. IAM/DataSec are **enrichment engines** not primary scanners
2. They filter/analyze existing threat findings
3. Their reports are derivatives (already have source data in threat_reports)
4. File-based + S3 storage is sufficient for specialized reports
5. Keeps RDS schema clean (avoid table sprawl)

**Implementation:**
- ✅ Fix password bug (2 files, 10 minutes)
- ✅ Create deployment YAMLs with S3 sidecars (20 minutes)
- ✅ Deploy and test (10 minutes)
- ✅ Total: ~40 minutes

---

## 📋 **IMPLEMENTATION PLAN**

### **Step 1: Fix Password Bug**

Files to update:
```
engine_iam/iam_engine/input/threat_db_reader.py
engine_datasec/data_security_engine/input/threat_db_reader.py
```

Change:
```python
# Replace _threat_db_connection_string() function
def _get_threat_db_connection():
    return psycopg2.connect(
        host=os.getenv('THREAT_DB_HOST', 'localhost'),
        port=int(os.getenv('THREAT_DB_PORT', '5432')),
        database=os.getenv('THREAT_DB_NAME', 'threat_engine_threat'),
        user=os.getenv('THREAT_DB_USER', 'postgres'),
        password=os.getenv('THREAT_DB_PASSWORD', '')
    )

# Update _get_conn() method
def _get_conn(self):
    if self._conn is None or self._conn.closed:
        if not PSYCOPG_AVAILABLE:
            raise RuntimeError("psycopg2 required...")
        self._conn = _get_threat_db_connection()  # Changed line
    return self._conn
```

### **Step 2: Update api_server.py File Writes**

Ensure both engines write to `/output` when `OUTPUT_DIR` is set:

```python
# In api_server.py, after generating report:
output_dir = os.getenv("OUTPUT_DIR", "/output")
if output_dir and os.path.exists(output_dir):
    engine_dir = os.path.join(output_dir, "iam", tenant_id, scan_id)  # or "datasec"
    os.makedirs(engine_dir, exist_ok=True)
    
    with open(os.path.join(engine_dir, "report.json"), "w") as f:
        json.dump(report, f, indent=2)
```

### **Step 3: Create K8s Deployments**

Create deployment YAMLs similar to compliance-engine but simpler (no DB tables):
- Service account: `aws-compliance-engine-sa` (reuse, has S3 permissions)
- Container ports: IAM=8003, DataSec=8004
- S3 sync sidecar: Same pattern as compliance
- Resource requests: Small (128Mi, 50m CPU)

### **Step 4: Build Docker Images**

```bash
cd /Users/apple/Desktop/threat-engine

# IAM
docker build --platform linux/amd64 -f engine_iam/Dockerfile -t yadavanup84/threat-engine-iam:latest .
docker push yadavanup84/threat-engine-iam:latest

# DataSec
docker build --platform linux/amd64 -f engine_datasec/Dockerfile -t yadavanup84/threat-engine-datasec:latest .
docker push yadavanup84/threat-engine-datasec:latest
```

### **Step 5: Deploy & Test**

```bash
kubectl apply -f deployment/aws/eks/engines/iam-engine-deployment.yaml
kubectl apply -f deployment/aws/eks/engines/datasec-engine-deployment.yaml

# Wait and test
kubectl -n threat-engine-engines get pods -l app=iam-engine
kubectl -n threat-engine-engines get pods -l app=datasec-engine

# Test IAM
curl -X POST "http://<iam-lb>/api/v1/iam-security/scan" \
  -H "Content-Type: application/json" \
  -d '{"csp": "aws", "scan_id": "check_20260201_044813", "tenant_id": "dbeaver-demo"}'

# Check S3
aws s3 ls s3://cspm-lgtech/engine_output/iam/ --recursive
aws s3 ls s3://cspm-lgtech/engine_output/datasec/ --recursive
```

---

## ✅ **READY TO PROCEED?**

I can now:
1. Fix the password bug in both engines (2 files)
2. Update file output to use `/output` directory
3. Create K8s deployment YAMLs with S3 sidecars
4. Build and push Docker images
5. Deploy to EKS

**This will make IAM/DataSec follow the same pattern as compliance (minus RDS tables since they're specialized reports).**

Want me to proceed with the fixes?
