#!/bin/bash

# Deploy all threat engines to EKS
# Usage: ./deploy-all-engines.sh

set -e

KUBECTL_NAMESPACE="threat-engine-engines"
KUBECTL_DIR="/Users/apple/Desktop/threat-engine/kubernetes"

echo "=========================================="
echo "Deploying All Threat Engines to EKS"
echo "=========================================="

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if namespace exists
if ! kubectl get namespace $KUBECTL_NAMESPACE &>/dev/null; then
    echo -e "${YELLOW}Creating namespace: $KUBECTL_NAMESPACE${NC}"
    kubectl create namespace $KUBECTL_NAMESPACE
fi

# Deploy AWS Engine
echo -e "\n${YELLOW}Deploying AWS Compliance Engine...${NC}"
kubectl apply -f $KUBECTL_DIR/engines/aws-engine-deployment.yaml
echo -e "${GREEN}✅ AWS Engine deployed${NC}"

# Deploy Azure Engine
echo -e "\n${YELLOW}Deploying Azure Compliance Engine...${NC}"
kubectl apply -f $KUBECTL_DIR/engines/azure-engine-deployment.yaml
echo -e "${GREEN}✅ Azure Engine deployed${NC}"

# Deploy GCP Engine
echo -e "\n${YELLOW}Deploying GCP Compliance Engine...${NC}"
kubectl apply -f $KUBECTL_DIR/engines/gcp-engine-deployment.yaml
echo -e "${GREEN}✅ GCP Engine deployed${NC}"

# Deploy AliCloud Engine
echo -e "\n${YELLOW}Deploying AliCloud Compliance Engine...${NC}"
kubectl apply -f $KUBECTL_DIR/engines/alicloud-engine-deployment.yaml
echo -e "${GREEN}✅ AliCloud Engine deployed${NC}"

# Deploy OCI Engine
echo -e "\n${YELLOW}Deploying OCI Compliance Engine...${NC}"
kubectl apply -f $KUBECTL_DIR/engines/oci-engine-deployment.yaml
echo -e "${GREEN}✅ OCI Engine deployed${NC}"

# Deploy IBM Engine
echo -e "\n${YELLOW}Deploying IBM Compliance Engine...${NC}"
kubectl apply -f $KUBECTL_DIR/engines/ibm-engine-deployment.yaml
echo -e "${GREEN}✅ IBM Engine deployed${NC}"

# Deploy YAML Rule Builder
echo -e "\n${YELLOW}Deploying YAML Rule Builder...${NC}"
kubectl apply -f $KUBECTL_DIR/engines/yaml-rule-builder-deployment.yaml
echo -e "${GREEN}✅ YAML Rule Builder deployed${NC}"

echo ""
echo "=========================================="
echo -e "${GREEN}✅ All engines deployed!${NC}"
echo "=========================================="
echo ""
echo "Checking pod status..."
kubectl get pods -n $KUBECTL_NAMESPACE -l tier=engine
kubectl get pods -n $KUBECTL_NAMESPACE -l app=yaml-rule-builder
echo ""
echo "To check all services:"
echo "  kubectl get svc -n $KUBECTL_NAMESPACE"
echo ""
echo "To check pod logs:"
echo "  kubectl logs -n $KUBECTL_NAMESPACE -l app=aws-compliance-engine"
echo ""

