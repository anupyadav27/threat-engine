#!/bin/bash
# Deploy Onboarding Engine to EKS

set -e

NAMESPACE="threat-engine-engines"
DOCKER_USERNAME="yadavanup84"
IMAGE_NAME="threat-engine-onboarding"

echo "=========================================="
echo "Deploying Onboarding Engine to EKS"
echo "=========================================="
echo ""

# Check kubectl connection
echo "🔍 Checking kubectl connection..."
if ! kubectl cluster-info > /dev/null 2>&1; then
    echo "❌ Cannot connect to Kubernetes cluster"
    exit 1
fi

echo "✅ Connected to cluster"
kubectl config current-context
echo ""

# Check namespace
echo "🔍 Checking namespace: $NAMESPACE..."
if ! kubectl get namespace $NAMESPACE > /dev/null 2>&1; then
    echo "⚠️  Namespace $NAMESPACE not found. Creating..."
    kubectl create namespace $NAMESPACE
fi
echo "✅ Namespace ready"
echo ""

# Apply ConfigMaps
echo "📋 Applying ConfigMaps..."
if [ -f "engine_onboarding/deployment/kubernetes/threat-engine-db-config.yaml" ]; then
    kubectl apply -f engine_onboarding/deployment/kubernetes/threat-engine-db-config.yaml
    echo "✅ ConfigMap applied"
else
    echo "⚠️  ConfigMap not found, skipping"
fi
echo ""

# Apply Deployment
echo "🚀 Applying Deployment..."
kubectl apply -f engine_onboarding/deployment/kubernetes/engine-onboarding.yaml

echo ""
echo "⏳ Waiting for deployment to be ready..."
kubectl rollout status deployment/engine-onboarding -n $NAMESPACE --timeout=5m

echo ""
echo "=========================================="
echo "✅ Deployment Complete!"
echo "=========================================="
echo ""

# Show pod status
echo "📊 Pod Status:"
kubectl get pods -n $NAMESPACE -l app=engine-onboarding

echo ""
echo "📊 Service Status:"
kubectl get svc -n $NAMESPACE -l app=engine-onboarding

echo ""
echo "📋 Recent Events:"
kubectl get events -n $NAMESPACE --field-selector involvedObject.name=engine-onboarding --sort-by='.lastTimestamp' | tail -10

echo ""
echo "=========================================="
echo "Access the API:"
echo "=========================================="
echo ""
echo "1. Port Forward (local testing):"
echo "   kubectl port-forward -n $NAMESPACE svc/engine-onboarding 8008:80"
echo "   Then access: http://localhost:8008"
echo ""
echo "2. Service Endpoint (internal):"
echo "   http://engine-onboarding.threat-engine-engines.svc.cluster.local"
echo ""
echo "3. Get pod logs:"
echo "   kubectl logs -f deployment/engine-onboarding -n $NAMESPACE"
echo ""
