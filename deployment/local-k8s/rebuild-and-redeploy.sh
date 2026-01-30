#!/bin/bash
#
# Rebuild and redeploy engines with API changes
# Usage: ./rebuild-and-redeploy.sh [DOCKERHUB_USERNAME] [TAG]
#
# This script:
# 1. Builds onboarding and configscan-aws images
# 2. Pushes to DockerHub
# 3. Forces pod restart to pick up new images
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Get DockerHub username
DOCKERHUB_USER="${1:-yadavanup84}"
TAG="${2:-latest}"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Rebuild and Redeploy Engines${NC}"
echo -e "${BLUE}========================================${NC}"
echo -e "DockerHub User: ${GREEN}${DOCKERHUB_USER}${NC}"
echo -e "Tag: ${GREEN}${TAG}${NC}"
echo ""

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$PROJECT_ROOT"

# Check Docker
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running${NC}"
    exit 1
fi

# Engines to rebuild (only changed ones)
declare -a ENGINES=(
    "engine_onboarding/Dockerfile:onboarding-service"
    "engine_configscan/engine_configscan_aws/Dockerfile:configscan-aws-service"
)

echo -e "${YELLOW}Building and pushing changed engines...${NC}"
echo ""

# Build and push
for ENGINE_SPEC in "${ENGINES[@]}"; do
    DOCKERFILE_PATH="${ENGINE_SPEC%%:*}"
    IMAGE_NAME="${ENGINE_SPEC##*:}"
    IMAGE_TAG="${DOCKERHUB_USER}/${IMAGE_NAME}:${TAG}"
    
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}Building: ${IMAGE_NAME}${NC}"
    echo -e "Dockerfile: ${DOCKERFILE_PATH}"
    echo -e "Image: ${IMAGE_TAG}"
    echo -e "${GREEN}========================================${NC}"
    
    # Build for linux/amd64 (Kubernetes compatibility)
    if docker build --platform linux/amd64 -t "${IMAGE_TAG}" -f "${DOCKERFILE_PATH}" .; then
        echo -e "${GREEN}✓ Build successful${NC}"
        
        # Push to DockerHub
        echo -e "${YELLOW}Pushing to DockerHub...${NC}"
        if docker push "${IMAGE_TAG}"; then
            echo -e "${GREEN}✓ Push successful${NC}"
        else
            echo -e "${RED}✗ Push failed${NC}"
            exit 1
        fi
    else
        echo -e "${RED}✗ Build failed${NC}"
        exit 1
    fi
    echo ""
done

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All images built and pushed!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo -e "${YELLOW}Warning: kubectl not found. Skipping deployment.${NC}"
    echo "Manually restart pods with:"
    echo "  kubectl rollout restart deployment/onboarding-service -n threat-engine-local"
    echo "  kubectl rollout restart deployment/configscan-aws-service -n threat-engine-local"
    exit 0
fi

# Check if namespace exists
if ! kubectl get namespace threat-engine-local &> /dev/null; then
    echo -e "${YELLOW}Namespace threat-engine-local not found. Creating...${NC}"
    kubectl create namespace threat-engine-local
fi

# Force pod restart to pick up new images
echo -e "${YELLOW}Restarting deployments to pick up new images...${NC}"
echo ""

# Restart onboarding
if kubectl get deployment onboarding-service -n threat-engine-local &> /dev/null; then
    echo -e "${BLUE}Restarting onboarding-service...${NC}"
    kubectl rollout restart deployment/onboarding-service -n threat-engine-local
    echo -e "${GREEN}✓ Onboarding restart initiated${NC}"
else
    echo -e "${YELLOW}⚠ onboarding-service deployment not found${NC}"
    echo "Deploy with: kubectl apply -f ${SCRIPT_DIR}/onboarding-deployment.yaml"
fi

# Restart configscan
if kubectl get deployment configscan-aws-service -n threat-engine-local &> /dev/null; then
    echo -e "${BLUE}Restarting configscan-aws-service...${NC}"
    kubectl rollout restart deployment/configscan-aws-service -n threat-engine-local
    echo -e "${GREEN}✓ ConfigScan restart initiated${NC}"
else
    echo -e "${YELLOW}⚠ configscan-aws-service deployment not found${NC}"
    echo "Deploy with: kubectl apply -f ${SCRIPT_DIR}/configscan-aws-deployment.yaml"
fi

echo ""
echo -e "${YELLOW}Waiting for pods to be ready...${NC}"
echo ""

# Wait for deployments
if kubectl get deployment onboarding-service -n threat-engine-local &> /dev/null; then
    kubectl rollout status deployment/onboarding-service -n threat-engine-local --timeout=120s || true
fi

if kubectl get deployment configscan-aws-service -n threat-engine-local &> /dev/null; then
    kubectl rollout status deployment/configscan-aws-service -n threat-engine-local --timeout=120s || true
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Check pod status:"
echo "  kubectl get pods -n threat-engine-local"
echo ""
echo "View logs:"
echo "  kubectl logs -f deployment/onboarding-service -n threat-engine-local"
echo "  kubectl logs -f deployment/configscan-aws-service -n threat-engine-local"
echo ""
echo "Test API changes:"
echo "  curl http://localhost:30010/api/v1/onboarding/aws/auth-methods"
echo "  curl -X DELETE http://localhost:30002/api/v1/scan/{scan_id}"
