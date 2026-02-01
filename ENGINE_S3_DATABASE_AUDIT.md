# Engine S3 & Database Configuration Audit

**Date:** January 30, 2026  
**Purpose:** Verify all engines are configured for AWS Secrets Manager + S3 access

---

## ✅ Database Configuration (via K8s ConfigMap + Secrets)

### **ConfigMap:** `threat-engine-db-config`

```yaml
CHECK_DB_HOST: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
CHECK_DB_NAME: threat_engine_check

DISCOVERIES_DB_HOST: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
DISCOVERIES_DB_NAME: threat_engine_discoveries

COMPLIANCE_DB_HOST: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
COMPLIANCE_DB_NAME: threat_engine_compliance

INVENTORY_DB_HOST: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
INVENTORY_DB_NAME: threat_engine_inventory

THREAT_DB_HOST: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
THREAT_DB_NAME: threat_engine_threat

SHARED_DB_HOST: postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com
SHARED_DB_NAME: threat_engine_shared
```

### **Secret:** `threat-engine-db-passwords`

```yaml
CHECK_DB_PASSWORD: apXuHV%2OSyRWK62
DISCOVERIES_DB_PASSWORD: apXuHV%2OSyRWK62
COMPLIANCE_DB_PASSWORD: apXuHV%2OSyRWK62
INVENTORY_DB_PASSWORD: apXuHV%2OSyRWK62
THREAT_DB_PASSWORD: apXuHV%2OSyRWK62
SHARED_DB_PASSWORD: apXuHV%2OSyRWK62
```

**Status:** ✅ Applied to cluster

---

## 📦 S3 Configuration

### **ConfigMap:** `s3-mount-config`

```yaml
s3-bucket: cspm-lgtech
s3-region: ap-south-1
```

### **Expected S3 Structure:**

```
s3://cspm-lgtech/
├── engine_input/          ← Rules, metadata, configs (read by engines)
│   ├── discoveries/
│   ├── checks/
│   └── compliance/
│
└── engine_output/         ← Scan results, reports (written by engines)
    ├── discoveries/
    ├── checks/
    ├── compliance/
    ├── threat/
    └── inventory/
```

---

## 🔍 Engine Audit

| Engine | DB ConfigMap | DB Secret | S3 Bucket Env | S3 Mount | Status |
|--------|-------------|-----------|---------------|----------|--------|
| **Compliance Engine** | ✅ envFrom | ✅ envFrom | ✅ S3_BUCKET | ❌ No mount (emptyDir) | ⚠️ Needs S3 |
| **Threat Engine** | ✅ envFrom | ✅ envFrom | ❓ Check | ❌ No mount | ⚠️ Needs S3 |
| **Inventory Engine** | ✅ envFrom | ✅ envFrom | ✅ S3_BUCKET | ❌ No mount | ⚠️ Needs S3 |
| **Check Engine** | ❓ Not deployed | - | - | - | ⚠️ Missing deployment |
| **Discoveries Engine** | ❓ Not deployed | - | - | - | ⚠️ Missing deployment |
| **CSP Compliance Engines** | ✅ envFrom | ✅ envFrom | ✅ S3_BUCKET | ❌ No mount | ⚠️ Needs S3 |

---

## ⚠️ Issues Found

### **1. No S3 Mounts**
Engines use `emptyDir` volumes which are ephemeral. Data is lost on pod restart.

**Fix:** Add S3 sync sidecar OR use direct S3 SDK writes

### **2. Missing Engine Deployments**
- ❌ No `engine-check-aws` deployment
- ❌ No `engine-discoveries-aws` deployment

**Impact:** Check and Discoveries engines can't be called

### **3. AWS Secrets Manager Integration**
External Secrets Operator not installed, using manual secret creation.

**Current:** Manual `kubectl create secret`  
**Better:** External Secrets Operator syncs from AWS Secrets Manager

---

## 🔧 Recommended Fixes

### **Option 1: Add S3 Sync Sidecar (Recommended)**

Add to each engine deployment:

```yaml
containers:
- name: engine
  # ... existing config ...
  volumeMounts:
  - name: output
    mountPath: /output
  - name: input
    mountPath: /input

- name: s3-sync
  image: amazon/aws-cli:latest
  command: ["/bin/sh", "-c"]
  args:
    - |
      while true; do
        aws s3 sync /output s3://cspm-lgtech/engine_output/<engine-name>/ --delete
        aws s3 sync s3://cspm-lgtech/engine_input/<engine-name>/ /input
        sleep 30
      done
  volumeMounts:
  - name: output
    mountPath: /output
  - name: input
    mountPath: /input
  env:
  - name: AWS_REGION
    value: ap-south-1

volumes:
- name: output
  emptyDir: {}
- name: input
  emptyDir: {}
```

### **Option 2: Direct S3 SDK Writes**

Engines write directly to S3 via boto3 (no sidecar needed):

```python
# In engine code
import boto3
s3 = boto3.client('s3', region_name='ap-south-1')
s3.put_object(
    Bucket='cspm-lgtech',
    Key=f'engine_output/{engine_name}/{scan_id}/results.json',
    Body=json.dumps(results)
)
```

**Pros:** No sidecar overhead  
**Cons:** Slower than local writes

---

## 📋 Action Items

### **High Priority**
1. ⚠️ **Create Check Engine deployment** (K8s YAML)
2. ⚠️ **Create Discoveries Engine deployment** (K8s YAML)
3. ⚠️ **Add S3 sync sidecars** to all engines OR update code for direct S3 writes
4. ⚠️ **Update S3 paths** in engines:
   - Input: `s3://cspm-lgtech/engine_input/`
   - Output: `s3://cspm-lgtech/engine_output/`

### **Medium Priority**
5. ⚠️ **Install External Secrets Operator** for automatic password sync
6. ⚠️ **Create AWS Secrets Manager secret:** `threat-engine/rds-credentials`
7. ⚠️ **Update service accounts** with S3 read/write permissions

### **Low Priority**
8. ✅ Database migration complete
9. ✅ ConfigScan cleanup complete
10. ✅ K8s ConfigMap/Secret updated

---

## 🎯 Current State vs Desired State

### **Database Access**
| Item | Current | Desired | Status |
|------|---------|---------|--------|
| ConfigMap with DB hosts | ✅ | ✅ | **DONE** |
| Secret with DB passwords | ✅ (manual) | ⚠️ (AWS Secrets Manager) | **PARTIAL** |
| Engines load from envFrom | ✅ | ✅ | **DONE** |

### **S3 Access**
| Item | Current | Desired | Status |
|------|---------|---------|--------|
| S3_BUCKET env var | ✅ | ✅ | **DONE** |
| Input path: `s3://cspm-lgtech/engine_input/` | ❌ | ✅ | **TODO** |
| Output path: `s3://cspm-lgtech/engine_output/` | ❌ | ✅ | **TODO** |
| S3 volume mounts OR sync sidecar | ❌ | ✅ | **TODO** |
| IAM permissions (S3 read/write) | ✅ (SA exists) | ✅ | **VERIFY** |

---

## ✅ Summary

**Database:** ✅ **READY** - All 6 databases on RDS, data migrated  
**S3:** ⚠️ **NEEDS WORK** - Engines need S3 input/output integration  
**Deployments:** ⚠️ **MISSING** - Check & Discoveries engines not deployed yet

---

**Next:** Would you like me to create the Check & Discoveries engine K8s deployments with S3 integration?
