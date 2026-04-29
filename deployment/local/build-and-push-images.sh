#!/bin/bash
# Build and push all Threat Engine images to Docker Hub
# Usage: ./build-and-push-images.sh YOUR_DOCKERHUB_USERNAME

set -e

DOCKERHUB_USER="${1:-YOUR_DOCKERHUB_USERNAME}"

if [ "$DOCKERHUB_USER" == "YOUR_DOCKERHUB_USERNAME" ]; then
    echo "Error: Please provide your Docker Hub username"
    echo "Usage: $0 YOUR_DOCKERHUB_USERNAME"
    exit 1
fi

echo "Building and pushing images to Docker Hub as: $DOCKERHUB_USER"
echo "Make sure you're logged in: docker login"

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Base directory
THREAT_ENGINE_DIR="/Users/apple/Desktop/threat-engine"
ONBOARDING_DIR="/Users/apple/Desktop/onboarding"

# Build and push onboarding API
echo -e "${BLUE}Building onboarding-api...${NC}"
cd "$ONBOARDING_DIR"
docker build -t "$DOCKERHUB_USER/threat-engine-onboarding-api:latest" -f Dockerfile .
docker push "$DOCKERHUB_USER/threat-engine-onboarding-api:latest"
echo -e "${GREEN}✓ onboarding-api pushed${NC}"

# Build and push scheduler
echo -e "${BLUE}Building scheduler-service...${NC}"
docker build -t "$DOCKERHUB_USER/threat-engine-scheduler:latest" -f scheduler/Dockerfile .
docker push "$DOCKERHUB_USER/threat-engine-scheduler:latest"
echo -e "${GREEN}✓ scheduler-service pushed${NC}"

# Build and push AWS engine
cd "$THREAT_ENGINE_DIR"
echo -e "${BLUE}Building aws-compliance-engine...${NC}"
docker build -t "$DOCKERHUB_USER/threat-engine-aws-compliance:latest" -f aws_compliance_python_engine/Dockerfile .
docker push "$DOCKERHUB_USER/threat-engine-aws-compliance:latest"
echo -e "${GREEN}✓ aws-compliance-engine pushed${NC}"

# Build and push Azure engine
echo -e "${BLUE}Building azure-compliance-engine...${NC}"
docker build -t "$DOCKERHUB_USER/threat-engine-azure-compliance:latest" -f azure_compliance_python_engine/Dockerfile .
docker push "$DOCKERHUB_USER/threat-engine-azure-compliance:latest"
echo -e "${GREEN}✓ azure-compliance-engine pushed${NC}"

# Build and push GCP engine
echo -e "${BLUE}Building gcp-compliance-engine...${NC}"
docker build -t "$DOCKERHUB_USER/threat-engine-gcp-compliance:latest" -f gcp_compliance_python_engine/Dockerfile .
docker push "$DOCKERHUB_USER/threat-engine-gcp-compliance:latest"
echo -e "${GREEN}✓ gcp-compliance-engine pushed${NC}"

# Build and push AliCloud engine
echo -e "${BLUE}Building alicloud-compliance-engine...${NC}"
docker build -t "$DOCKERHUB_USER/threat-engine-alicloud-compliance:latest" -f alicloud_compliance_python_engine/Dockerfile .
docker push "$DOCKERHUB_USER/threat-engine-alicloud-compliance:latest"
echo -e "${GREEN}✓ alicloud-compliance-engine pushed${NC}"

# Build and push OCI engine
echo -e "${BLUE}Building oci-compliance-engine...${NC}"
docker build -t "$DOCKERHUB_USER/threat-engine-oci-compliance:latest" -f oci_compliance_python_engine/Dockerfile .
docker push "$DOCKERHUB_USER/threat-engine-oci-compliance:latest"
echo -e "${GREEN}✓ oci-compliance-engine pushed${NC}"

# Build and push IBM engine
echo -e "${BLUE}Building ibm-compliance-engine...${NC}"
docker build -t "$DOCKERHUB_USER/threat-engine-ibm-compliance:latest" -f ibm_compliance_python_engine/Dockerfile .
docker push "$DOCKERHUB_USER/threat-engine-ibm-compliance:latest"
echo -e "${GREEN}✓ ibm-compliance-engine pushed${NC}"

# Build and push YAML Rule Builder
echo -e "${BLUE}Building yaml-rule-builder...${NC}"
docker build -t "$DOCKERHUB_USER/threat-engine-yaml-rule-builder:latest" -f yaml-rule-builder/Dockerfile .
docker push "$DOCKERHUB_USER/threat-engine-yaml-rule-builder:latest"
echo -e "${GREEN}✓ yaml-rule-builder pushed${NC}"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}All images built and pushed successfully!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Next steps:"
echo "1. Update kubernetes/*/deployment.yaml files: Replace YOUR_DOCKERHUB_USERNAME with $DOCKERHUB_USER"
echo "2. Or use: sed -i '' 's/YOUR_DOCKERHUB_USERNAME/$DOCKERHUB_USER/g' kubernetes/**/*.yaml"
echo "3. Deploy: kubectl apply -f kubernetes/"

