#!/bin/bash

# Build and push all threat engine Docker images
# Usage: ./build-and-push-engines.sh

set -e

DOCKER_USERNAME="yadavanup84"
BASE_DIR="/Users/apple/Desktop/threat-engine"

echo "=========================================="
echo "Building and Pushing Threat Engine Images"
echo "=========================================="

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if logged in to Docker Hub
if ! docker info | grep -q "Username"; then
    echo -e "${YELLOW}⚠️  Not logged in to Docker Hub${NC}"
    echo "Please run: docker login -u $DOCKER_USERNAME"
    exit 1
fi

# Build and push AWS Engine
echo -e "\n${YELLOW}Building AWS ConfigScan Engine...${NC}"
cd "$BASE_DIR"
docker build -f configScan_engines/aws-configScan-engine/Dockerfile -t $DOCKER_USERNAME/threat-engine-aws-compliance:latest .
docker push $DOCKER_USERNAME/threat-engine-aws-compliance:latest
echo -e "${GREEN}✅ AWS Engine pushed${NC}"

# Build and push Azure Engine
echo -e "\n${YELLOW}Building Azure ConfigScan Engine...${NC}"
docker build -f configScan_engines/azure-configScan-engine/Dockerfile -t $DOCKER_USERNAME/threat-engine-azure-compliance:latest .
docker push $DOCKER_USERNAME/threat-engine-azure-compliance:latest
echo -e "${GREEN}✅ Azure Engine pushed${NC}"

# Build and push GCP Engine
echo -e "\n${YELLOW}Building GCP ConfigScan Engine...${NC}"
docker build -f configScan_engines/gcp-configScan-engine/Dockerfile -t $DOCKER_USERNAME/threat-engine-gcp-compliance:latest .
docker push $DOCKER_USERNAME/threat-engine-gcp-compliance:latest
echo -e "${GREEN}✅ GCP Engine pushed${NC}"

# Build and push AliCloud Engine
echo -e "\n${YELLOW}Building AliCloud ConfigScan Engine...${NC}"
docker build -f configScan_engines/alicloud-configScan-engine/Dockerfile -t $DOCKER_USERNAME/threat-engine-alicloud-compliance:latest .
docker push $DOCKER_USERNAME/threat-engine-alicloud-compliance:latest
echo -e "${GREEN}✅ AliCloud Engine pushed${NC}"

# Build and push OCI Engine
echo -e "\n${YELLOW}Building OCI ConfigScan Engine...${NC}"
docker build -f configScan_engines/oci-configScan-engine/Dockerfile -t $DOCKER_USERNAME/threat-engine-oci-compliance:latest .
docker push $DOCKER_USERNAME/threat-engine-oci-compliance:latest
echo -e "${GREEN}✅ OCI Engine pushed${NC}"

# Build and push IBM Engine
echo -e "\n${YELLOW}Building IBM ConfigScan Engine...${NC}"
docker build -f configScan_engines/ibm-configScan-engine/Dockerfile -t $DOCKER_USERNAME/threat-engine-ibm-compliance:latest .
docker push $DOCKER_USERNAME/threat-engine-ibm-compliance:latest
echo -e "${GREEN}✅ IBM Engine pushed${NC}"

# Build and push Rule Engine
echo -e "\n${YELLOW}Building Rule Engine...${NC}"
docker build -f rule_engine/Dockerfile -t $DOCKER_USERNAME/threat-engine-rule-engine:latest .
docker push $DOCKER_USERNAME/threat-engine-rule-engine:latest
echo -e "${GREEN}✅ Rule Engine pushed${NC}"

# Build and push Compliance Engine
echo -e "\n${YELLOW}Building Compliance Engine...${NC}"
docker build -f compliance-engine/Dockerfile -t $DOCKER_USERNAME/threat-engine-compliance:latest .
docker push $DOCKER_USERNAME/threat-engine-compliance:latest
echo -e "${GREEN}✅ Compliance Engine pushed${NC}"

# Build and push Threat Engine
echo -e "\n${YELLOW}Building Threat Engine...${NC}"
docker build -f threat-engine/Dockerfile -t $DOCKER_USERNAME/threat-engine:latest .
docker push $DOCKER_USERNAME/threat-engine:latest
echo -e "${GREEN}✅ Threat Engine pushed${NC}"

# Build and push Inventory Engine
echo -e "\n${YELLOW}Building Inventory Engine...${NC}"
docker build -f inventory-engine/Dockerfile -t $DOCKER_USERNAME/inventory-engine:latest .
docker push $DOCKER_USERNAME/inventory-engine:latest
echo -e "${GREEN}✅ Inventory Engine pushed${NC}"

echo ""
echo "=========================================="
echo -e "${GREEN}✅ All images built and pushed!${NC}"
echo "=========================================="
echo ""
echo "Images:"
echo "  - $DOCKER_USERNAME/threat-engine-aws-compliance:latest"
echo "  - $DOCKER_USERNAME/threat-engine-azure-compliance:latest"
echo "  - $DOCKER_USERNAME/threat-engine-gcp-compliance:latest"
echo "  - $DOCKER_USERNAME/threat-engine-alicloud-compliance:latest"
echo "  - $DOCKER_USERNAME/threat-engine-oci-compliance:latest"
echo "  - $DOCKER_USERNAME/threat-engine-ibm-compliance:latest"
echo "  - $DOCKER_USERNAME/threat-engine-rule-engine:latest"
echo "  - $DOCKER_USERNAME/threat-engine-compliance:latest"
echo "  - $DOCKER_USERNAME/threat-engine:latest"
echo "  - $DOCKER_USERNAME/inventory-engine:latest"
echo ""

