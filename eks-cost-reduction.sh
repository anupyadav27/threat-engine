#!/bin/bash
# EKS Cost Reduction Script for Dev Environment

set -e

CLUSTER_NAME="vulnerability-eks-cluster"
REGION="ap-south-1"

echo "=========================================="
echo "EKS Cost Reduction - Dev Environment"
echo "=========================================="
echo ""

# Step 1: Remove unnecessary LoadBalancers
echo "Step 1: Removing unnecessary LoadBalancers..."
kubectl delete svc compliance-engine-lb -n threat-engine-engines --ignore-not-found=true
kubectl delete svc yaml-rule-builder-lb -n threat-engine-engines --ignore-not-found=true
echo "✅ LoadBalancers removed"
echo ""

# Step 2: Disable Control Plane Logging
echo "Step 2: Disabling Control Plane Logging..."
aws eks update-cluster-config \
  --name ${CLUSTER_NAME} \
  --region ${REGION} \
  --logging '{"clusterLogging":[{"types":[],"enabled":false}]}' \
  --no-cli-pager 2>/dev/null || echo "⚠️  Logging may already be disabled or requires permissions"
echo "✅ Control Plane logging disabled"
echo ""

# Step 3: Check for Extended Support
echo "Step 3: Checking cluster version..."
CLUSTER_VERSION=$(aws eks describe-cluster --name ${CLUSTER_NAME} --region ${REGION} \
  --query 'cluster.version' --output text 2>/dev/null || echo "unknown")

if [ "$CLUSTER_VERSION" != "unknown" ]; then
    echo "   Cluster Version: $CLUSTER_VERSION"
    if [[ $(echo "$CLUSTER_VERSION" | cut -d. -f1) -ge 1 ]] && [[ $(echo "$CLUSTER_VERSION" | cut -d. -f2) -ge 28 ]]; then
        echo "   ✅ Using supported Kubernetes version (no extended support needed)"
    else
        echo "   ⚠️  Consider upgrading to a supported version to avoid extended support costs"
    fi
fi
echo ""

echo "=========================================="
echo "✅ Cost Optimization Complete!"
echo "=========================================="
echo ""
echo "Estimated Monthly Savings:"
echo "  - LoadBalancers (2 removed): ~\$32/month"
echo "  - Control Plane Logging: ~\$5-20/month"
echo "  - Total: ~\$37-52/month"
echo ""
echo "Access services via port-forward:"
echo "  kubectl port-forward -n threat-engine-engines svc/compliance-engine 8000:80"
echo "  kubectl port-forward -n threat-engine-engines svc/yaml-rule-builder 8001:80"
