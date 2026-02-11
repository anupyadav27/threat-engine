# EKS Cluster Backup Summary
**Date**: February 11, 2026
**Timestamp**: 20260211-192852

---

## ✅ Backup Status: **SUCCESSFUL**

Complete backup of the EKS cluster `vulnerability-eks-cluster` has been successfully created and uploaded to S3.

---

## 📊 Backup Statistics

| Metric | Value |
|--------|-------|
| **Cluster Name** | vulnerability-eks-cluster |
| **Region** | ap-south-1 (Mumbai) |
| **Timestamp** | 20260211-192852 |
| **Compressed Size** | 156.9 KiB |
| **S3 Bucket** | anup-backup |
| **S3 Path** | s3://anup-backup/eks-backups/2026-02-11/ |
| **Local Backup** | /tmp/eks-backup-20260211-192852.tar.gz |

---

## 📦 Backup Contents

### 1. Cluster Information
- EKS cluster configuration
- Node groups (detailed configs)
- Fargate profiles (if any)
- Add-ons list
- Nodes configuration

### 2. Kubernetes Resources (All Namespaces)
- **cspm**
- **cspm-ui**
- **default**
- **ingress-nginx**
- **kube-node-lease**
- **kube-public**
- **kube-system**
- **secops-engine**
- **threat-engine-engines** (includes vulnerability engine deployment)

For each namespace:
- Deployments
- StatefulSets
- DaemonSets
- Services
- Ingresses
- ConfigMaps
- Secrets
- PersistentVolumeClaims
- ServiceAccounts
- Roles and RoleBindings
- HorizontalPodAutoscalers
- NetworkPolicies

### 3. Cluster-Wide Resources
- StorageClasses
- PersistentVolumes
- ClusterRoles
- ClusterRoleBindings
- CustomResourceDefinitions (CRDs)
- IngressClasses

### 4. AWS Resources
- Load Balancers (ELBv2 and Classic ELB)
- IAM Roles and Policies
- EKS cluster IAM configuration

### 5. Restoration Tools
- `RESTORE_INSTRUCTIONS.md` - Step-by-step restoration guide
- `quick-restore.sh` - Automated restoration script
- `backup-manifest.json` - Complete backup metadata

---

## 🗂️ S3 Location

```
s3://anup-backup/eks-backups/2026-02-11/eks-backup-20260211-192852.tar.gz
```

**File Size**: 156.9 KiB

---

## 📥 Download and Extract

### Download from S3
```bash
aws s3 cp s3://anup-backup/eks-backups/2026-02-11/eks-backup-20260211-192852.tar.gz . --region ap-south-1
```

### Extract Backup
```bash
tar -xzf eks-backup-20260211-192852.tar.gz
cd eks-backup-20260211-192852
```

### View Restoration Instructions
```bash
cat RESTORE_INSTRUCTIONS.md
```

---

## 🔄 Restoration Overview

To restore this cluster to a new EKS cluster or recreate it:

### Step 1: Create New EKS Cluster
```bash
# Review cluster-info/eks-cluster.json for exact configuration
eksctl create cluster \
  --name vulnerability-eks-cluster \
  --region ap-south-1 \
  --version <VERSION_FROM_BACKUP> \
  --nodegroup-name <NODEGROUP_NAME> \
  --node-type <INSTANCE_TYPE> \
  --nodes <NODE_COUNT>
```

### Step 2: Configure kubectl
```bash
aws eks update-kubeconfig \
  --name vulnerability-eks-cluster \
  --region ap-south-1
```

### Step 3: Restore Cluster-Wide Resources
```bash
kubectl apply -f storage/storageclasses.yaml
kubectl apply -f rbac/clusterroles.yaml
kubectl apply -f rbac/clusterrolebindings.yaml
kubectl apply -f crds/all-crds.yaml
```

### Step 4: Restore Namespaces
```bash
# Create namespaces first
kubectl apply -f namespaces/all-namespaces.json

# For each namespace, restore resources in order
for NS in cspm cspm-ui default threat-engine-engines; do
  kubectl apply -f namespaces/${NS}/configmaps.yaml
  kubectl apply -f namespaces/${NS}/secrets.yaml
  kubectl apply -f namespaces/${NS}/pvc.yaml
  kubectl apply -f namespaces/${NS}/serviceaccounts.yaml
  kubectl apply -f namespaces/${NS}/services.yaml
  kubectl apply -f namespaces/${NS}/deployments.yaml
  kubectl apply -f namespaces/${NS}/statefulsets.yaml
  kubectl apply -f namespaces/${NS}/daemonsets.yaml
  kubectl apply -f namespaces/${NS}/hpa.yaml
  kubectl apply -f namespaces/${NS}/ingress.yaml
done
```

### Step 5: Quick Restore (Alternative)
```bash
# Or use the automated restoration script
chmod +x quick-restore.sh
./quick-restore.sh
```

### Step 6: Verify
```bash
kubectl get all --all-namespaces
kubectl get pv,pvc --all-namespaces
kubectl get ingress --all-namespaces
```

---

## ⚠️ Important Notes

1. **Secrets**: All secrets are backed up in YAML format. They contain base64-encoded values.

2. **PersistentVolumes**:
   - PV configurations are backed up
   - Data on EBS volumes is NOT included in this backup
   - You may need to restore data from separate EBS snapshots

3. **LoadBalancers**:
   - LoadBalancer services will create new AWS ELB/NLB endpoints
   - DNS records will need to be updated after restoration

4. **Node Groups**:
   - Review `cluster-info/nodegroup-*.json` files for exact configuration
   - Recreate node groups with same instance types and sizes

5. **IAM Roles**:
   - Backed up for reference only
   - May need to recreate with same policies

6. **Container Images**:
   - Backup contains image references (e.g., yadavanup84/vulnerability_engine:latest)
   - Ensure images are accessible in your container registry

---

## 🔐 Security Considerations

- **Secrets**: The backup contains Kubernetes secrets. Store securely.
- **Credentials**: Database passwords and API keys are in the backup.
- **S3 Bucket**: Ensure `anup-backup` has appropriate access controls.
- **Encryption**: Consider encrypting the backup file at rest.

---

## 📋 Backup Manifest

View complete backup metadata:
```bash
aws s3 cp s3://anup-backup/eks-backups/2026-02-11/eks-backup-20260211-192852.tar.gz . --region ap-south-1
tar -xzf eks-backup-20260211-192852.tar.gz
cat eks-backup-20260211-192852/backup-manifest.json
```

---

## 🔄 Automated Backup Script

The backup script is available at:
```
/Users/apple/Desktop/threat-engine/scripts/backup-eks-cluster.sh
```

### Run Manual Backup
```bash
cd /Users/apple/Desktop/threat-engine
bash scripts/backup-eks-cluster.sh
```

### Schedule with Cron (Example)
```bash
# Weekly backup every Sunday at 3 AM
0 3 * * 0 /Users/apple/Desktop/threat-engine/scripts/backup-eks-cluster.sh
```

---

## 📊 What's Included in This Backup

### Deployed Applications
- ✅ Vulnerability Engine API (threat-engine-engines namespace)
- ✅ CSPM Engine (cspm namespace)
- ✅ CSPM UI (cspm-ui namespace)
- ✅ SecOps Engine (secops-engine namespace)
- ✅ Ingress Controller (ingress-nginx namespace)
- ✅ All system components (kube-system namespace)

### Configuration
- ✅ All Kubernetes secrets (DB credentials, API keys)
- ✅ All ConfigMaps
- ✅ All Service configurations
- ✅ Load Balancer configurations
- ✅ Ingress rules
- ✅ Network policies
- ✅ RBAC policies

---

## ✅ Verification

List backup files in S3:
```bash
aws s3 ls s3://anup-backup/eks-backups/2026-02-11/ --region ap-south-1 --human-readable
```

Check backup integrity:
```bash
tar -tzf eks-backup-20260211-192852.tar.gz | head -20
```

---

**Backup completed successfully on**: 2026-02-11 19:28:52 IST

---

## 🎯 Recovery Time Objective (RTO)

Estimated time to restore full cluster:
- **New EKS Cluster Creation**: 15-20 minutes
- **Resource Restoration**: 5-10 minutes
- **Application Startup**: 5-10 minutes
- **Total**: ~30-40 minutes

---

## 📝 Next Steps

1. **Test Restoration**: Periodically test the restoration procedure in a non-production environment
2. **Automate Backups**: Set up cron job for regular automated backups
3. **Backup Retention**: Configure S3 lifecycle policies to manage backup retention
4. **Monitoring**: Set up alerts for backup success/failure
5. **Documentation**: Keep this summary accessible for disaster recovery scenarios
