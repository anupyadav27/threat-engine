#!/bin/bash

# Deploy SecOps Scanner to EKS Cluster
# Usage: ./deploy.sh [destroy-old]

set -e

NAMESPACE="secops-engine"
OLD_SERVICE="secops"  # Old service name to destroy if exists

echo "=========================================="
echo "SecOps Scanner EKS Deployment"
echo "=========================================="

# Check if kubectl is configured
if ! kubectl cluster-info &> /dev/null; then
    echo "ERROR: kubectl is not configured or cluster is not accessible"
    exit 1
fi

echo "✓ kubectl is configured"

# Destroy old service if requested
if [ "$1" == "destroy-old" ]; then
    echo ""
    echo "Checking for old 'secops' service..."
    if kubectl get namespace ${OLD_SERVICE} &> /dev/null; then
        echo "Found old namespace '${OLD_SERVICE}', destroying..."
        kubectl delete namespace ${OLD_SERVICE} --wait=true --timeout=300s || true
        echo "✓ Old service destroyed"
    else
        echo "No old service found"
    fi
fi

# Apply manifests in order
echo ""
echo "Deploying SecOps Scanner..."

echo "1. Creating namespace..."
kubectl apply -f namespace.yaml

echo "2. Creating service account..."
kubectl apply -f serviceaccount.yaml

echo "3. Creating config map..."
kubectl apply -f configmap.yaml

echo "4. Creating deployment..."
kubectl apply -f deployment.yaml

echo "5. Creating ClusterIP service..."
kubectl apply -f service-clusterip.yaml

echo "6. Creating external service..."
kubectl apply -f service-external.yaml

echo "7. Creating ingress (if ALB controller is installed)..."
kubectl apply -f ingress.yaml || echo "⚠ Ingress creation skipped (ALB controller may not be installed)"

echo ""
echo "=========================================="
echo "Deployment completed!"
echo "=========================================="
echo ""
echo "Checking deployment status..."
kubectl get pods -n ${NAMESPACE} -w

echo ""
echo "To check logs:"
echo "  kubectl logs -f -n ${NAMESPACE} deployment/secops-scanner -c scanner-api"
echo "  kubectl logs -f -n ${NAMESPACE} deployment/secops-scanner -c s3-sync"
echo ""
echo "To get service endpoints:"
echo "  kubectl get svc -n ${NAMESPACE}"
echo "  kubectl get ingress -n ${NAMESPACE}"

