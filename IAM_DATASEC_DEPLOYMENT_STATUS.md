# IAM & DataSec Engines - Deployment Status

**Date:** February 1, 2026  
**Status:** ⚠️ Ready to deploy (pending EKS resources)

---

## ✅ **COMPLETED WORK**

### **1. Code Fixes:**
- ✅ Fixed password parsing bug in both `threat_db_reader.py` files
- ✅ Created `check_db_reader.py` for both engines (read from check_results)
- ✅ Added `/output` directory support for S3 sync
- ✅ Added RDS persistence (db_writer modules)
- ✅ Updated `api_server.py` to write to files + RDS

### **2. Database Setup:**
- ✅ Created `threat_engine_iam` database on RDS
- ✅ Created `threat_engine_datasec` database on RDS
- ✅ Applied schemas:
  - `iam_reports` + `iam_findings` tables
  - `datasec_reports` + `datasec_findings` tables

### **3. Docker Images:**
- ✅ Built: `yadavanup84/threat-engine-iam:latest`
- ✅ Built: `yadavanup84/threat-engine-datasec:latest`
- ✅ Pushed to Docker Hub

### **4. Kubernetes Configuration:**
- ✅ Created `iam-engine-deployment.yaml` with S3 sidecar
- ✅ Created `datasec-engine-deployment.yaml` with S3 sidecar
- ✅ Updated ConfigMaps with IAM/DataSec DB credentials
- ✅ Updated Secrets with passwords

### **5. Deployment Applied:**
- ✅ K8s resources created
- ⚠️ Pods in Pending state (insufficient memory)

---

## ❌ **CURRENT ISSUE**

### **EKS Resource Constraint:**
```
0/2 nodes available: Insufficient memory
```

### **Current Running Pods:**
```bash
kubectl -n threat-engine-engines get pods
```

Likely candidates using memory:
- compliance-engine (512Mi limit)
- check-engine (if still running)
- discoveries-engine (if still running)
- api-gateway
- Other engines

---

## 🎯 **SOLUTION OPTIONS**

### **Option 1: Scale Down Non-Essential Engines**
```bash
# Scale to 0 replicas temporarily
kubectl -n threat-engine-engines scale deployment/compliance-engine --replicas=0
# Or other non-critical engines

# Then wait for IAM/DataSec to start
kubectl -n threat-engine-engines get pods -w
```

### **Option 2: Reduce Resource Requests**
Current IAM/DataSec requests:
- Memory: 128Mi request, 512Mi limit
- CPU: 50m request, 250m limit

Could reduce to match compliance's minimal config.

### **Option 3: Add EKS Node or Increase Node Size**
- Add another worker node to cluster
- Or upgrade existing nodes to larger instance type

---

## 📊 **ARCHITECTURE SUMMARY**

### **IAM Engine Flow:**
```
check_results (threat_engine_check)
    ↓ (filter by IAM rules)
IAM Engine (port 8003)
    ├─ Enriches with IAM context
    ├─ Maps to IAM modules (MFA, least privilege, etc.)
    └─ Generates report
        ↓
    ├─→ threat_engine_iam.iam_reports (RDS)
    ├─→ threat_engine_iam.iam_findings (RDS)
    ├─→ /output/iam/{tenant}/{scan}/iam_report.json
    └─→ S3: s3://cspm-lgtech/engine_output/iam/
```

### **DataSec Engine Flow:**
```
check_results (threat_engine_check)
    ↓ (filter by data security rules)
DataSec Engine (port 8004)
    ├─ Enriches with data security context
    ├─ Analyzes: classification, lineage, residency, activity
    └─ Generates report
        ↓
    ├─→ threat_engine_datasec.datasec_reports (RDS)
    ├─→ threat_engine_datasec.datasec_findings (RDS)
    ├─→ /output/datasec/{tenant}/{scan}/datasec_report.json
    └─→ S3: s3://cspm-lgtech/engine_output/datasec/
```

---

## 📋 **DATABASE SCHEMAS**

### **threat_engine_iam:**
- `tenants` (tenant metadata)
- `iam_reports` (IAM security reports)
- `iam_findings` (IAM findings with modules)

### **threat_engine_datasec:**
- `tenants` (tenant metadata)
- `datasec_reports` (data security reports)
- `datasec_findings` (data security findings with classification)

Both follow the same pattern as `threat_engine_compliance`.

---

## 🎯 **NEXT STEPS TO COMPLETE DEPLOYMENT**

### **Step 1: Free Up EKS Resources**
```bash
# Check current memory usage
kubectl -n threat-engine-engines top pods

# Scale down non-essential engines
kubectl -n threat-engine-engines get deployments
kubectl -n threat-engine-engines scale deployment/<non-essential> --replicas=0
```

### **Step 2: Verify IAM/DataSec Pods Start**
```bash
kubectl -n threat-engine-engines get pods -l 'app in (iam-engine,datasec-engine)' -w
# Wait for Running status
```

### **Step 3: Test Endpoints**
```bash
# Get LoadBalancer URLs
IAM_LB=$(kubectl -n threat-engine-engines get svc iam-engine-lb -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')
DATASEC_LB=$(kubectl -n threat-engine-engines get svc datasec-engine-lb -o jsonpath='{.status.loadBalancer.ingress[0].hostname}')

# Test IAM (requires threat_reports data)
curl -X POST "http://${IAM_LB}/api/v1/iam-security/scan" \
  -H "Content-Type: application/json" \
  -d '{"csp": "aws", "scan_id": "check_20260201_044813", "tenant_id": "dbeaver-demo"}'

# Test DataSec
curl -X POST "http://${DATASEC_LB}/api/v1/data-security/scan" \
  -H "Content-Type: application/json" \
  -d '{"csp": "aws", "scan_id": "check_20260201_044813", "tenant_id": "dbeaver-demo"}'
```

### **Step 4: Verify RDS + S3**
```sql
-- Check IAM reports
SELECT COUNT(*) FROM threat_engine_iam.iam_reports;
SELECT COUNT(*) FROM threat_engine_iam.iam_findings;

-- Check DataSec reports
SELECT COUNT(*) FROM threat_engine_datasec.datasec_reports;
SELECT COUNT(*) FROM threat_engine_datasec.datasec_findings;
```

```bash
# Check S3
aws s3 ls s3://cspm-lgtech/engine_output/iam/ --recursive --region ap-south-1
aws s3 ls s3://cspm-lgtech/engine_output/datasec/ --recursive --region ap-south-1
```

---

## ✅ **WHAT'S READY**

All code, schemas, deployments, and images are ready. Just need EKS cluster resources to be freed up so the pods can start.

**Once pods are running, the full flow will be:**
```
Discoveries → Check → Compliance ✅ (working)
                  ↓
                  ├─→ IAM Engine → RDS + S3
                  └─→ DataSec Engine → RDS + S3
```

All engines will follow the same database-first + S3 sync pattern! 🎉
