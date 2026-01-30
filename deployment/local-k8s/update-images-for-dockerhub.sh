#!/bin/bash
# Update K8s manifests to use DockerHub images
# Usage: ./update-images-for-dockerhub.sh [DOCKERHUB_USERNAME] [TAG]

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Get DockerHub username
DOCKERHUB_USER="${1:-}"
if [ -z "$DOCKERHUB_USER" ]; then
    echo -e "${YELLOW}DockerHub username not provided.${NC}"
    read -p "Enter your DockerHub username: " DOCKERHUB_USER
fi

TAG="${2:-latest}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${GREEN}Updating K8s manifests to use DockerHub images...${NC}"
echo "DockerHub User: ${DOCKERHUB_USER}"
echo "Tag: ${TAG}"
echo ""

# Update onboarding deployment
if [ -f "${SCRIPT_DIR}/onboarding-deployment.yaml" ]; then
    sed -i.bak "s|image: threat-engine/onboarding-service:local|image: ${DOCKERHUB_USER}/onboarding-service:${TAG}|g" \
        "${SCRIPT_DIR}/onboarding-deployment.yaml"
    sed -i.bak "s|imagePullPolicy: IfNotPresent|imagePullPolicy: Always|g" \
        "${SCRIPT_DIR}/onboarding-deployment.yaml"
    rm -f "${SCRIPT_DIR}/onboarding-deployment.yaml.bak"
    echo "✓ Updated onboarding-deployment.yaml"
fi

# Update configscan-aws deployment
if [ -f "${SCRIPT_DIR}/configscan-aws-deployment.yaml" ]; then
    sed -i.bak "s|image: threat-engine/configscan-aws-service:local|image: ${DOCKERHUB_USER}/configscan-aws-service:${TAG}|g" \
        "${SCRIPT_DIR}/configscan-aws-deployment.yaml"
    sed -i.bak "s|image: threat-engine/configscan-aws-service:local|image: ${DOCKERHUB_USER}/configscan-aws-service:${TAG}|g" \
        "${SCRIPT_DIR}/configscan-aws-deployment.yaml"
    sed -i.bak "s|imagePullPolicy: IfNotPresent|imagePullPolicy: Always|g" \
        "${SCRIPT_DIR}/configscan-aws-deployment.yaml"
    rm -f "${SCRIPT_DIR}/configscan-aws-deployment.yaml.bak"
    echo "✓ Updated configscan-aws-deployment.yaml"
fi

echo -e "\n${GREEN}All manifests updated!${NC}"
echo ""
echo "To deploy:"
echo "  kubectl apply -f ${SCRIPT_DIR}/"
