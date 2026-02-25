#!/bin/bash

###############################################################################
# EKS Cluster Backup Script
# Purpose: Backup all Kubernetes resources, configurations, and state
# This allows you to recreate the cluster exactly as-is
###############################################################################

set -e

# Configuration
CLUSTER_NAME="vulnerability-eks-cluster"
REGION="ap-south-1"
S3_BUCKET="anup-backup"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
BACKUP_DATE=$(date +%Y-%m-%d)
BACKUP_DIR="/tmp/eks-backup-${TIMESTAMP}"
S3_PREFIX="eks-backups/${BACKUP_DATE}"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

log_info "=========================================="
log_info "EKS Cluster Backup - ${CLUSTER_NAME}"
log_info "=========================================="

# Create backup directory structure
mkdir -p "${BACKUP_DIR}"/{cluster-info,namespaces,workloads,configs,storage,networking,rbac,crds}

log_info "Backup directory: ${BACKUP_DIR}"
log_info ""

#############################################################################
# 1. CLUSTER INFORMATION
#############################################################################
log_info "1. Backing up cluster information..."

# EKS Cluster configuration
aws eks describe-cluster \
    --name ${CLUSTER_NAME} \
    --region ${REGION} \
    > "${BACKUP_DIR}/cluster-info/eks-cluster.json"

# Node groups
aws eks list-nodegroups \
    --cluster-name ${CLUSTER_NAME} \
    --region ${REGION} \
    > "${BACKUP_DIR}/cluster-info/nodegroups-list.json"

# Get detailed info for each node group
for NG in $(aws eks list-nodegroups --cluster-name ${CLUSTER_NAME} --region ${REGION} --query 'nodegroups[]' --output text); do
    aws eks describe-nodegroup \
        --cluster-name ${CLUSTER_NAME} \
        --nodegroup-name ${NG} \
        --region ${REGION} \
        > "${BACKUP_DIR}/cluster-info/nodegroup-${NG}.json"
done

# Fargate profiles (if any)
aws eks list-fargate-profiles \
    --cluster-name ${CLUSTER_NAME} \
    --region ${REGION} \
    > "${BACKUP_DIR}/cluster-info/fargate-profiles.json" 2>/dev/null || true

# Cluster add-ons
aws eks list-addons \
    --cluster-name ${CLUSTER_NAME} \
    --region ${REGION} \
    > "${BACKUP_DIR}/cluster-info/addons-list.json"

log_info "✓ Cluster information backed up"

#############################################################################
# 2. KUBERNETES RESOURCES - ALL NAMESPACES
#############################################################################
log_info ""
log_info "2. Backing up Kubernetes resources..."

# Get all namespaces
kubectl get namespaces -o json > "${BACKUP_DIR}/namespaces/all-namespaces.json"

# Backup resources for each namespace
for NS in $(kubectl get ns -o jsonpath='{.items[*].metadata.name}'); do
    log_info "  Backing up namespace: ${NS}"

    NS_DIR="${BACKUP_DIR}/namespaces/${NS}"
    mkdir -p "${NS_DIR}"

    # Deployments
    kubectl get deployments -n ${NS} -o yaml > "${NS_DIR}/deployments.yaml" 2>/dev/null || true

    # StatefulSets
    kubectl get statefulsets -n ${NS} -o yaml > "${NS_DIR}/statefulsets.yaml" 2>/dev/null || true

    # DaemonSets
    kubectl get daemonsets -n ${NS} -o yaml > "${NS_DIR}/daemonsets.yaml" 2>/dev/null || true

    # Services
    kubectl get services -n ${NS} -o yaml > "${NS_DIR}/services.yaml" 2>/dev/null || true

    # Ingresses
    kubectl get ingress -n ${NS} -o yaml > "${NS_DIR}/ingress.yaml" 2>/dev/null || true

    # ConfigMaps
    kubectl get configmaps -n ${NS} -o yaml > "${NS_DIR}/configmaps.yaml" 2>/dev/null || true

    # Secrets (encrypted)
    kubectl get secrets -n ${NS} -o yaml > "${NS_DIR}/secrets.yaml" 2>/dev/null || true

    # PersistentVolumeClaims
    kubectl get pvc -n ${NS} -o yaml > "${NS_DIR}/pvc.yaml" 2>/dev/null || true

    # ServiceAccounts
    kubectl get serviceaccounts -n ${NS} -o yaml > "${NS_DIR}/serviceaccounts.yaml" 2>/dev/null || true

    # Roles and RoleBindings
    kubectl get roles -n ${NS} -o yaml > "${NS_DIR}/roles.yaml" 2>/dev/null || true
    kubectl get rolebindings -n ${NS} -o yaml > "${NS_DIR}/rolebindings.yaml" 2>/dev/null || true

    # HorizontalPodAutoscalers
    kubectl get hpa -n ${NS} -o yaml > "${NS_DIR}/hpa.yaml" 2>/dev/null || true

    # NetworkPolicies
    kubectl get networkpolicies -n ${NS} -o yaml > "${NS_DIR}/networkpolicies.yaml" 2>/dev/null || true
done

log_info "✓ Kubernetes resources backed up"

#############################################################################
# 3. CLUSTER-WIDE RESOURCES
#############################################################################
log_info ""
log_info "3. Backing up cluster-wide resources..."

# Nodes
kubectl get nodes -o yaml > "${BACKUP_DIR}/cluster-info/nodes.yaml"

# StorageClasses
kubectl get storageclasses -o yaml > "${BACKUP_DIR}/storage/storageclasses.yaml"

# PersistentVolumes
kubectl get pv -o yaml > "${BACKUP_DIR}/storage/persistentvolumes.yaml"

# ClusterRoles and ClusterRoleBindings
kubectl get clusterroles -o yaml > "${BACKUP_DIR}/rbac/clusterroles.yaml"
kubectl get clusterrolebindings -o yaml > "${BACKUP_DIR}/rbac/clusterrolebindings.yaml"

# CustomResourceDefinitions
kubectl get crds -o yaml > "${BACKUP_DIR}/crds/all-crds.yaml"

# IngressClasses (if any)
kubectl get ingressclasses -o yaml > "${BACKUP_DIR}/networking/ingressclasses.yaml" 2>/dev/null || true

log_info "✓ Cluster-wide resources backed up"

#############################################################################
# 4. ETCD SNAPSHOT (if accessible)
#############################################################################
log_info ""
log_info "4. Checking for etcd backup options..."
log_warn "EKS manages etcd - using Kubernetes API backup instead"

#############################################################################
# 5. HELM RELEASES
#############################################################################
log_info ""
log_info "5. Backing up Helm releases..."

if command -v helm &> /dev/null; then
    helm list --all-namespaces -o json > "${BACKUP_DIR}/configs/helm-releases.json" || true

    # Export each Helm release values
    for RELEASE in $(helm list --all-namespaces -o json | jq -r '.[] | .name + ":" + .namespace'); do
        RELEASE_NAME=$(echo $RELEASE | cut -d: -f1)
        RELEASE_NS=$(echo $RELEASE | cut -d: -f2)
        helm get values ${RELEASE_NAME} -n ${RELEASE_NS} > "${BACKUP_DIR}/configs/helm-${RELEASE_NAME}-values.yaml" 2>/dev/null || true
    done

    log_info "✓ Helm releases backed up"
else
    log_warn "Helm not installed - skipping Helm backup"
fi

#############################################################################
# 6. AWS LOAD BALANCERS
#############################################################################
log_info ""
log_info "6. Backing up AWS Load Balancers..."

# Get all LoadBalancer services
kubectl get svc --all-namespaces -o json | \
    jq '.items[] | select(.spec.type=="LoadBalancer")' \
    > "${BACKUP_DIR}/networking/loadbalancer-services.json"

# List ELBs
aws elbv2 describe-load-balancers --region ${REGION} > "${BACKUP_DIR}/networking/aws-elb-list.json" || true
aws elb describe-load-balancers --region ${REGION} > "${BACKUP_DIR}/networking/aws-classic-elb-list.json" || true

log_info "✓ Load Balancers backed up"

#############################################################################
# 7. IAM ROLES AND POLICIES
#############################################################################
log_info ""
log_info "7. Backing up IAM roles..."

# Get EKS cluster role
CLUSTER_ROLE=$(aws eks describe-cluster --name ${CLUSTER_NAME} --region ${REGION} --query 'cluster.roleArn' --output text)
ROLE_NAME=$(echo $CLUSTER_ROLE | awk -F'/' '{print $NF}')

aws iam get-role --role-name ${ROLE_NAME} > "${BACKUP_DIR}/cluster-info/cluster-iam-role.json" 2>/dev/null || true
aws iam list-attached-role-policies --role-name ${ROLE_NAME} > "${BACKUP_DIR}/cluster-info/cluster-iam-policies.json" 2>/dev/null || true

log_info "✓ IAM roles backed up"

#############################################################################
# 8. CREATE RESTORATION SCRIPTS
#############################################################################
log_info ""
log_info "8. Creating restoration scripts..."

cat > "${BACKUP_DIR}/RESTORE_INSTRUCTIONS.md" <<'EOF'
# EKS Cluster Restoration Guide

## Prerequisites
1. AWS CLI configured with appropriate credentials
2. kubectl installed and configured
3. eksctl installed (recommended)
4. Helm installed (if Helm charts were used)

## Restoration Steps

### Step 1: Create EKS Cluster
```bash
# Review cluster-info/eks-cluster.json for cluster configuration
# Create cluster using eksctl or AWS console with same configuration

# Example using eksctl:
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
# Apply in order:
kubectl apply -f storage/storageclasses.yaml
kubectl apply -f rbac/clusterroles.yaml
kubectl apply -f rbac/clusterrolebindings.yaml
kubectl apply -f crds/all-crds.yaml
```

### Step 4: Restore Namespaces
```bash
# Create namespaces first
kubectl apply -f namespaces/all-namespaces.json

# For each namespace, restore resources in order:
for NS in default kube-system; do
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

### Step 5: Restore Helm Releases (if applicable)
```bash
# Review configs/helm-releases.json
# Restore each Helm release manually using helm install
```

### Step 6: Verify
```bash
kubectl get all --all-namespaces
kubectl get pv,pvc --all-namespaces
kubectl get ingress --all-namespaces
```

## Important Notes
- Secrets are backed up but may need to be recreated
- PersistentVolumes need to be recreated (data may need separate backup)
- LoadBalancers will get new endpoints
- Update DNS records after restoration
EOF

cat > "${BACKUP_DIR}/quick-restore.sh" <<'EOF'
#!/bin/bash
# Quick restoration script - USE WITH CAUTION
# Review and modify before running

set -e

BACKUP_DIR=$(dirname "$0")

echo "Starting EKS cluster restoration..."

# 1. Apply cluster-wide resources
kubectl apply -f ${BACKUP_DIR}/storage/storageclasses.yaml
kubectl apply -f ${BACKUP_DIR}/rbac/clusterroles.yaml
kubectl apply -f ${BACKUP_DIR}/rbac/clusterrolebindings.yaml
kubectl apply -f ${BACKUP_DIR}/crds/all-crds.yaml

# 2. Create namespaces
kubectl apply -f ${BACKUP_DIR}/namespaces/all-namespaces.json

# 3. Restore each namespace
for NS_DIR in ${BACKUP_DIR}/namespaces/*/; do
  NS=$(basename ${NS_DIR})

  # Skip if not a directory
  [ -d "${NS_DIR}" ] || continue

  echo "Restoring namespace: ${NS}"

  # Apply in order
  [ -f "${NS_DIR}/configmaps.yaml" ] && kubectl apply -f ${NS_DIR}/configmaps.yaml
  [ -f "${NS_DIR}/secrets.yaml" ] && kubectl apply -f ${NS_DIR}/secrets.yaml
  [ -f "${NS_DIR}/pvc.yaml" ] && kubectl apply -f ${NS_DIR}/pvc.yaml
  [ -f "${NS_DIR}/serviceaccounts.yaml" ] && kubectl apply -f ${NS_DIR}/serviceaccounts.yaml
  [ -f "${NS_DIR}/services.yaml" ] && kubectl apply -f ${NS_DIR}/services.yaml
  [ -f "${NS_DIR}/deployments.yaml" ] && kubectl apply -f ${NS_DIR}/deployments.yaml
  [ -f "${NS_DIR}/statefulsets.yaml" ] && kubectl apply -f ${NS_DIR}/statefulsets.yaml
  [ -f "${NS_DIR}/daemonsets.yaml" ] && kubectl apply -f ${NS_DIR}/daemonsets.yaml
  [ -f "${NS_DIR}/hpa.yaml" ] && kubectl apply -f ${NS_DIR}/hpa.yaml
  [ -f "${NS_DIR}/ingress.yaml" ] && kubectl apply -f ${NS_DIR}/ingress.yaml
  [ -f "${NS_DIR}/roles.yaml" ] && kubectl apply -f ${NS_DIR}/roles.yaml
  [ -f "${NS_DIR}/rolebindings.yaml" ] && kubectl apply -f ${NS_DIR}/rolebindings.yaml
done

echo "Restoration complete!"
echo "Please review: kubectl get all --all-namespaces"
EOF

chmod +x "${BACKUP_DIR}/quick-restore.sh"

log_info "✓ Restoration scripts created"

#############################################################################
# 9. CREATE BACKUP MANIFEST
#############################################################################
log_info ""
log_info "9. Creating backup manifest..."

cat > "${BACKUP_DIR}/backup-manifest.json" <<EOF
{
  "backup_date": "${BACKUP_DATE}",
  "backup_timestamp": "${TIMESTAMP}",
  "cluster_name": "${CLUSTER_NAME}",
  "region": "${REGION}",
  "s3_bucket": "${S3_BUCKET}",
  "s3_prefix": "${S3_PREFIX}",
  "backup_type": "full",
  "components": {
    "cluster_info": true,
    "namespaces": true,
    "workloads": true,
    "configs": true,
    "storage": true,
    "networking": true,
    "rbac": true,
    "crds": true,
    "helm_releases": $(command -v helm &> /dev/null && echo "true" || echo "false")
  },
  "created_by": "eks-backup-script",
  "version": "1.0"
}
EOF

log_info "✓ Manifest created"

#############################################################################
# 10. COMPRESS AND UPLOAD TO S3
#############################################################################
log_info ""
log_info "10. Compressing backup..."

cd /tmp
tar -czf "eks-backup-${TIMESTAMP}.tar.gz" "eks-backup-${TIMESTAMP}/"

BACKUP_SIZE=$(du -h "eks-backup-${TIMESTAMP}.tar.gz" | cut -f1)
log_info "Compressed backup size: ${BACKUP_SIZE}"

log_info ""
log_info "11. Uploading to S3..."

aws s3 cp "eks-backup-${TIMESTAMP}.tar.gz" \
    "s3://${S3_BUCKET}/${S3_PREFIX}/eks-backup-${TIMESTAMP}.tar.gz" \
    --region ${REGION}

if [ $? -eq 0 ]; then
    log_info "✓ Upload successful"
else
    log_error "Upload failed"
    exit 1
fi

#############################################################################
# SUMMARY
#############################################################################
log_info ""
log_info "=========================================="
log_info "          BACKUP SUMMARY"
log_info "=========================================="
log_info "Cluster: ${CLUSTER_NAME}"
log_info "Region: ${REGION}"
log_info "Timestamp: ${TIMESTAMP}"
log_info "Backup Size: ${BACKUP_SIZE}"
log_info "S3 Location: s3://${S3_BUCKET}/${S3_PREFIX}/eks-backup-${TIMESTAMP}.tar.gz"
log_info ""
log_info "Local backup: /tmp/eks-backup-${TIMESTAMP}.tar.gz"
log_info ""
log_info "To download backup:"
log_info "  aws s3 cp s3://${S3_BUCKET}/${S3_PREFIX}/eks-backup-${TIMESTAMP}.tar.gz . --region ${REGION}"
log_info ""
log_info "To extract:"
log_info "  tar -xzf eks-backup-${TIMESTAMP}.tar.gz"
log_info ""
log_info "To restore:"
log_info "  See RESTORE_INSTRUCTIONS.md in the backup directory"
log_info "=========================================="
log_info ""

# Cleanup prompt
read -p "Delete local backup files? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "${BACKUP_DIR}"
    rm -f "/tmp/eks-backup-${TIMESTAMP}.tar.gz"
    log_info "✓ Local files deleted"
else
    log_info "Local files retained"
fi

log_info "Backup completed successfully!"
