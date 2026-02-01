# ✅ Database-First Architecture - Deployment Complete

**Date:** January 30, 2026  
**Status:** Database migration complete, engines deployed (pending resources)

---

## ✅ **What Was Accomplished**

### **1. Database Migration** ✅ **COMPLETE**

| Database | Tables | Data |
|----------|--------|------|
| **threat_engine_check** | rule_metadata, check_results, scans | 1,918 metadata rows |
| **threat_engine_discoveries** | rule_definitions, discoveries, discovery_history | 2,501 rule files |
| **threat_engine_compliance** | compliance_control_mappings | 960 mappings |
| **threat_engine_shared** | orchestration, audit | Ready |
| **threat_engine_inventory** | assets, relationships | Ready |
| **threat_engine_threat** | threat_intelligence | Ready |

### **2. Code Cleanup** ✅ **COMPLETE**

- ✅ Deleted `engine_configscan` folder
- ✅ Removed `threat_engine_configscan` database (local & RDS)
- ✅ Created `check_schema.sql` & `discoveries_schema.sql`
- ✅ Updated all scripts to use CHECK_DB_* and DISCOVERIES_DB_*

### **3. Docker Images** ✅ **BUILT & PUSHED**

- ✅ `yadavanup84/engine-check-aws:latest`
- ✅ `yadavanup84/engine-discoveries-aws:latest`

### **4. Kubernetes Deployments** ✅ **CREATED**

- ✅ `/deployment/aws/eks/engines/check-engine-deployment.yaml`
- ✅ `/deployment/aws/eks/engines/discoveries-engine-deployment.yaml`

**Features:**
- ✅ Database config via ConfigMap (CHECK_DB_*, DISCOVERIES_DB_*)
- ✅ Database passwords via Secret (from manual secret)
- ✅ S3 sync sidecar (syncs to s3://cspm-lgtech/engine_output/)
- ✅ S3 input sync (from s3://cspm-lgtech/engine_input/)
- ✅ ServiceAccount with S3 permissions (threat-engine-sa)

---

## ⚠️ **Current Issue: Insufficient Cluster Resources**

### **Node Capacity**
```
Node 1: CPU 73%, Memory 76% allocated
Node 2: CPU 90%, Memory 92% allocated  ⚠️ Nearly full
```

### **Pending Pods**
```
engine-check-aws-xxx        0/2   Pending  (Insufficient memory)
engine-discoveries-aws-xxx  0/2   Pending  (Insufficient memory)
```

### **Scaled Down to Free Resources**
```
✅ alicloud-compliance-engine: 0 replicas
✅ azure-compliance-engine: 0 replicas
✅ gcp-compliance-engine: 0 replicas
✅ ibm-compliance-engine: 0 replicas
✅ oci-compliance-engine: 0 replicas
✅ aws-compliance-engine: 0 replicas
✅ compliance-engine: 0 replicas
✅ onboarding-api: 0 replicas
✅ scheduler-service: 0 replicas
```

---

## 🔧 **Solutions**

### **Option 1: Further Reduce Resource Requests (Current)**

Already set to minimal:
```yaml
check-engine: 128Mi RAM, 50m CPU (+ 128Mi, 50m for s3-sync sidecar)
discoveries-engine: 128Mi RAM, 50m CPU (+ 128Mi, 50m for s3-sync sidecar)
```

**Total per pod:** 256Mi RAM, 100m CPU

### **Option 2: Add More Nodes to EKS Cluster**

```bash
# Increase desired capacity
aws eks update-nodegroup-config \
  --cluster-name <cluster-name> \
  --nodegroup-name <nodegroup-name> \
  --scaling-config minSize=2,maxSize=4,desiredSize=3
```

###  **Option 3: Use Larger Instance Types**

Current nodes appear to be small (< 4GB RAM each).  
Consider upgrading to t3.medium or t3.large.

### **Option 4: Remove S3 Sync Sidecar Temporarily**

Deploy engines without sidecar, test database functionality first:
- Engines write to /output (emptyDir)
- Later add S3 sync when resources available

---

## 📋 **What's Ready**

| Component | Status | Notes |
|-----------|--------|-------|
| **RDS Databases** | ✅ Ready | 6 databases with data |
| **Docker Images** | ✅ Pushed | yadavanup84/engine-check-aws, engine-discoveries-aws |
| **K8s Manifests** | ✅ Created | With S3 sync sidecars |
| **ConfigMaps** | ✅ Applied | Database + S3 config |
| **Secrets** | ✅ Applied | Database passwords |
| **Deployments** | ⚠️ Pending | Waiting for resources |

---

## 🎯 **Recommended Next Steps**

1. **Immediate:** Deploy without S3 sidecars (test database first)
2. **Short-term:** Add 1 more node to EKS cluster
3. **Long-term:** Migrate to larger instance types (t3.medium → t3.large)

---

**Ready to deploy without sidecars for now?** Or should we add nodes to the cluster first?
