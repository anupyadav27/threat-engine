#!/bin/bash
# Build and push Docker images to DockerHub for local K8s deployment
# Usage: ./build-and-push-dockerhub.sh [DOCKERHUB_USERNAME] [TAG]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Get DockerHub username from argument or prompt
DOCKERHUB_USER="${1:-}"
if [ -z "$DOCKERHUB_USER" ]; then
    echo -e "${YELLOW}DockerHub username not provided.${NC}"
    read -p "Enter your DockerHub username: " DOCKERHUB_USER
fi

# Get tag from argument or use 'latest'
TAG="${2:-latest}"

echo -e "${GREEN}Building and pushing images to DockerHub...${NC}"
echo -e "DockerHub User: ${GREEN}${DOCKERHUB_USER}${NC}"
echo -e "Tag: ${GREEN}${TAG}${NC}"
echo ""

# Get script directory (should be in deployment/local-k8s)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$PROJECT_ROOT"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running. Please start Docker Desktop.${NC}"
    exit 1
fi

# Check if logged into DockerHub (Docker Desktop stores credentials differently)
# Try to verify by checking if we can access DockerHub
if ! docker pull hello-world:latest > /dev/null 2>&1; then
    echo -e "${YELLOW}Warning: Cannot verify DockerHub access.${NC}"
    echo -e "${YELLOW}If push fails, run 'docker login' first.${NC}"
    echo -e "${YELLOW}Continuing with build...${NC}"
fi

# Engines to build (with their Dockerfile paths and image names)
declare -a ENGINES=(
    "engine_onboarding/Dockerfile:onboarding-service"
    "engine_configscan/engine_configscan_aws/Dockerfile:configscan-aws-service"
    "engine_secops/scanner_engine/Dockerfile:secops-service"
    "engine_compliance/Dockerfile:compliance-service"
    "engine_inventory/Dockerfile:inventory-service"
)

# Build and push each engine
for ENGINE_SPEC in "${ENGINES[@]}"; do
    DOCKERFILE_PATH="${ENGINE_SPEC%%:*}"
    IMAGE_NAME="${ENGINE_SPEC##*:}"
    IMAGE_TAG="${DOCKERHUB_USER}/${IMAGE_NAME}:${TAG}"
    
    echo -e "\n${GREEN}========================================${NC}"
    echo -e "${GREEN}Building: ${IMAGE_NAME}${NC}"
    echo -e "Dockerfile: ${DOCKERFILE_PATH}"
    echo -e "Image: ${IMAGE_TAG}"
    echo -e "${GREEN}========================================${NC}"
    
    # Build image
    if docker build -t "${IMAGE_TAG}" -f "${DOCKERFILE_PATH}" .; then
        echo -e "${GREEN}✓ Build successful${NC}"
        
        # Also tag as 'latest' if different tag was provided
        if [ "$TAG" != "latest" ]; then
            docker tag "${IMAGE_TAG}" "${DOCKERHUB_USER}/${IMAGE_NAME}:latest"
            echo -e "${GREEN}✓ Tagged as latest${NC}"
        fi
        
        # Push to DockerHub
        echo -e "${YELLOW}Pushing to DockerHub...${NC}"
        if docker push "${IMAGE_TAG}"; then
            echo -e "${GREEN}✓ Push successful${NC}"
            
            # Push latest tag if different
            if [ "$TAG" != "latest" ]; then
                docker push "${DOCKERHUB_USER}/${IMAGE_NAME}:latest"
            fi
        else
            echo -e "${RED}✗ Push failed${NC}"
            exit 1
        fi
    else
        echo -e "${RED}✗ Build failed${NC}"
        exit 1
    fi
done

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}All images built and pushed successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Images pushed:"
for ENGINE_SPEC in "${ENGINES[@]}"; do
    IMAGE_NAME="${ENGINE_SPEC##*:}"
    echo "  - ${DOCKERHUB_USER}/${IMAGE_NAME}:${TAG}"
    if [ "$TAG" != "latest" ]; then
        echo "  - ${DOCKERHUB_USER}/${IMAGE_NAME}:latest"
    fi
done
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Update K8s manifests to use DockerHub images"
echo "2. Run: kubectl apply -f deployment/local-k8s/"
echo "3. Verify: kubectl get pods -n threat-engine-local"
