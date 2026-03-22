#!/bin/bash
# Install Argo Workflows on EKS
# Run: bash deployment/aws/eks/argo/01-install.sh

set -euo pipefail

ARGO_VERSION="v3.5.5"
NAMESPACE="argo"

echo "=== Installing Argo Workflows ${ARGO_VERSION} ==="

# Create namespace
kubectl create namespace ${NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -

# Install Argo (quick-start: controller + server + MinIO for artifacts)
kubectl apply -n ${NAMESPACE} -f "https://github.com/argoproj/argo-workflows/releases/download/${ARGO_VERSION}/quick-start-minimal.yaml"

echo "Waiting for Argo controller..."
kubectl rollout status deployment/argo-server -n ${NAMESPACE} --timeout=120s 2>/dev/null || true
kubectl rollout status deployment/workflow-controller -n ${NAMESPACE} --timeout=120s 2>/dev/null || true

# Grant argo-server access to threat-engine-engines namespace
kubectl apply -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: argo-workflows-threat-engine
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: argo-workflows-workflow
subjects:
- kind: ServiceAccount
  name: argo-server
  namespace: argo
- kind: ServiceAccount
  name: default
  namespace: threat-engine-engines
EOF

echo ""
echo "=== Argo Workflows installed ==="
echo "Controller: kubectl get pods -n argo"
echo "UI:         kubectl port-forward svc/argo-server 2746:2746 -n argo"
echo "            Open https://localhost:2746"
echo ""
echo "Next: Apply workflow templates:"
echo "  kubectl apply -f deployment/aws/eks/argo/cspm-pipeline.yaml"
