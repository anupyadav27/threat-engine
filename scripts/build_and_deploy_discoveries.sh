#!/bin/bash
# Build and Deploy Discovery Engine to EKS
# Date: 2026-02-20
# Changes: Database-driven filters, removed 178 lines of hardcoded logic

set -e  # Exit on error

echo "================================================================================"
echo "Building and Deploying Discovery Engine with Database-Driven Filters"
echo "================================================================================"

# Configuration
DOCKER_IMAGE="yadavanup84/engine-discoveries"
TAG="latest"
BUILD_CONTEXT="/Users/apple/Desktop/threat-engine"
DOCKERFILE="$BUILD_CONTEXT/engine_discoveries/Dockerfile"
NAMESPACE="threat-engine-engines"
DEPLOYMENT="engine-discoveries"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo ""
echo "${YELLOW}Step 1: Building Docker Image${NC}"
echo "================================================================================"
echo "Image: $DOCKER_IMAGE:$TAG"
echo "Build Context: $BUILD_CONTEXT"
echo "Dockerfile: $DOCKERFILE"
echo ""

# Build Docker image from threat-engine root directory
cd "$BUILD_CONTEXT"
docker build -f "$DOCKERFILE" -t "$DOCKER_IMAGE:$TAG" .

if [ $? -eq 0 ]; then
    echo "${GREEN}✅ Docker build successful${NC}"
else
    echo "❌ Docker build failed"
    exit 1
fi

echo ""
echo "${YELLOW}Step 2: Pushing to Docker Hub${NC}"
echo "================================================================================"
echo "Pushing: $DOCKER_IMAGE:$TAG"
echo ""

docker push "$DOCKER_IMAGE:$TAG"

if [ $? -eq 0 ]; then
    echo "${GREEN}✅ Docker push successful${NC}"
else
    echo "❌ Docker push failed"
    exit 1
fi

echo ""
echo "${YELLOW}Step 3: Restarting Deployment in EKS${NC}"
echo "================================================================================"
echo "Namespace: $NAMESPACE"
echo "Deployment: $DEPLOYMENT"
echo ""

# Force pull latest image by restarting deployment
kubectl rollout restart deployment/$DEPLOYMENT -n $NAMESPACE

if [ $? -eq 0 ]; then
    echo "${GREEN}✅ Deployment restart initiated${NC}"
else
    echo "❌ Deployment restart failed"
    exit 1
fi

echo ""
echo "${YELLOW}Step 4: Waiting for Rollout${NC}"
echo "================================================================================"

kubectl rollout status deployment/$DEPLOYMENT -n $NAMESPACE --timeout=5m

if [ $? -eq 0 ]; then
    echo "${GREEN}✅ Deployment rollout successful${NC}"
else
    echo "❌ Deployment rollout failed"
    exit 1
fi

echo ""
echo "${YELLOW}Step 5: Verifying Deployment${NC}"
echo "================================================================================"

# Get pod status
kubectl get pods -n $NAMESPACE -l app=engine-discoveries

echo ""
echo "Recent pod logs:"
POD_NAME=$(kubectl get pods -n $NAMESPACE -l app=engine-discoveries -o jsonpath='{.items[0].metadata.name}')
kubectl logs $POD_NAME -n $NAMESPACE --tail=20

echo ""
echo "================================================================================"
echo "${GREEN}✅ DEPLOYMENT COMPLETE${NC}"
echo "================================================================================"
echo ""
echo "Summary:"
echo "  - Image: $DOCKER_IMAGE:$TAG"
echo "  - Namespace: $NAMESPACE"
echo "  - Deployment: $DEPLOYMENT"
echo "  - Pod: $POD_NAME"
echo ""
echo "Changes in this deployment:"
echo "  ✅ Database-driven filter rules (filter_rules column)"
echo "  ✅ Migrated 13 AWS services with 26 filters to database"
echo "  ✅ Removed 178 lines of hardcoded filter logic"
echo "  ✅ FilterEngine now reads from rule_discoveries table"
echo "  ✅ Multi-CSP architecture (common/ + providers/)"
echo ""
echo "Next steps:"
echo "  1. Test discovery scan with: POST /api/v1/discovery"
echo "  2. Verify filters work correctly"
echo "  3. Check database for filter_rules in rule_discoveries table"
echo ""
echo "To view logs: kubectl logs -f $POD_NAME -n $NAMESPACE"
echo "To check deployment: kubectl get deployment $DEPLOYMENT -n $NAMESPACE"
echo "================================================================================"
