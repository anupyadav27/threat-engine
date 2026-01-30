#!/bin/bash
# Deploy to AWS EKS

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOYMENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

echo "=========================================="
echo "AWS EKS Deployment"
echo "=========================================="
echo ""

# Configuration
EKS_CLUSTER_NAME="${EKS_CLUSTER_NAME:-vulnerability-eks-cluster}"
AWS_REGION="${AWS_REGION:-ap-south-1}"
NAMESPACE="${NAMESPACE:-threat-engine-engines}"

# Check prerequisites
echo "Checking prerequisites..."

if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI not found"
    exit 1
fi

if ! command -v kubectl &> /dev/null; then
    echo "❌ kubectl not found"
    exit 1
fi

# Check AWS credentials
if ! aws sts get-caller-identity &>/dev/null; then
    echo "❌ AWS credentials not configured"
    exit 1
fi

echo "✅ Prerequisites check passed"
echo ""

# Update kubeconfig
echo "Updating kubeconfig for EKS cluster..."
aws eks update-kubeconfig --name "$EKS_CLUSTER_NAME" --region "$AWS_REGION"

# Verify cluster access
if ! kubectl cluster-info &>/dev/null; then
    echo "❌ Cannot access EKS cluster"
    exit 1
fi

echo "✅ Connected to EKS cluster: $EKS_CLUSTER_NAME"
echo ""

# Create namespace
echo "Creating namespace..."
kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

# Deploy services
echo "Deploying services..."
cd "$DEPLOYMENT_DIR/eks"

# Deploy in order
kubectl apply -f configmaps/
kubectl apply -f service-accounts/
kubectl apply -f deployments/
kubectl apply -f services/

echo ""
echo "✅ Services deployed"
echo ""

# Wait for deployments
echo "Waiting for deployments to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment -n "$NAMESPACE" --all || true

# Get service endpoints
echo ""
echo "=========================================="
echo "✅ AWS Deployment Complete!"
echo "=========================================="
echo ""
echo "Service Endpoints:"
kubectl get svc -n "$NAMESPACE" -o wide
echo ""
echo "To access services, use LoadBalancer endpoints or port-forward:"
echo "  kubectl port-forward -n $NAMESPACE svc/compliance-engine 8001:80"
echo ""

