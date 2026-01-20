#!/bin/bash

# Rebuild images and redeploy to EKS
# Usage: ./rebuild-and-redeploy.sh

set -e

echo "=========================================="
echo "Rebuilding Images and Redeploying"
echo "=========================================="

# Check Docker login
if ! docker info | grep -q "Username"; then
    echo "❌ Not logged in to Docker Hub"
    echo "Please run: docker login -u yadavanup84"
    exit 1
fi

# Build and push
echo ""
echo "Step 1: Building and pushing images..."
./build-and-push-engines.sh

# Wait a moment for images to be available
echo ""
echo "Step 2: Waiting for images to be available..."
sleep 10

# Restart deployments
echo ""
echo "Step 3: Restarting deployments..."
kubectl rollout restart deployment/aws-compliance-engine -n threat-engine-engines
kubectl rollout restart deployment/azure-compliance-engine -n threat-engine-engines
kubectl rollout restart deployment/gcp-compliance-engine -n threat-engine-engines
kubectl rollout restart deployment/alicloud-compliance-engine -n threat-engine-engines
kubectl rollout restart deployment/oci-compliance-engine -n threat-engine-engines
kubectl rollout restart deployment/ibm-compliance-engine -n threat-engine-engines
kubectl rollout restart deployment/yaml-rule-builder -n threat-engine-engines

echo ""
echo "Step 4: Waiting for rollouts to complete..."
kubectl rollout status deployment/aws-compliance-engine -n threat-engine-engines --timeout=300s
kubectl rollout status deployment/azure-compliance-engine -n threat-engine-engines --timeout=300s
kubectl rollout status deployment/gcp-compliance-engine -n threat-engine-engines --timeout=300s
kubectl rollout status deployment/alicloud-compliance-engine -n threat-engine-engines --timeout=300s
kubectl rollout status deployment/oci-compliance-engine -n threat-engine-engines --timeout=300s
kubectl rollout status deployment/ibm-compliance-engine -n threat-engine-engines --timeout=300s
kubectl rollout status deployment/yaml-rule-builder -n threat-engine-engines --timeout=300s

echo ""
echo "=========================================="
echo "✅ Rebuild and Redeploy Complete!"
echo "=========================================="
echo ""
echo "New image sizes:"
docker images | grep threat-engine | awk '{print $1, $2, $7}'
echo ""
echo "Pod status:"
kubectl get pods -n threat-engine-engines -l tier=engine
kubectl get pods -n threat-engine-engines -l app=yaml-rule-builder

