#!/bin/bash
# CSPM EKS Deployment Script

set -e

echo "=========================================="
echo "CSPM EKS Deployment"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    echo -e "${RED}❌ kubectl is not installed${NC}"
    exit 1
fi

# Check if namespace exists
if ! kubectl get namespace cspm &> /dev/null; then
    echo -e "${YELLOW}Creating namespace...${NC}"
    kubectl apply -f kubernetes/namespace.yaml
    echo -e "${GREEN}✅ Namespace created${NC}"
else
    echo -e "${GREEN}✅ Namespace exists${NC}"
fi

# Apply ConfigMaps
echo -e "${YELLOW}Applying ConfigMaps...${NC}"
kubectl apply -f kubernetes/configmaps/cspm-config.yaml
kubectl apply -f kubernetes/configmaps/django-config.yaml
echo -e "${GREEN}✅ ConfigMaps applied${NC}"

# Apply Secrets (user needs to update values first)
echo -e "${YELLOW}Applying Secrets...${NC}"
if kubectl get secret database-secret -n cspm &> /dev/null; then
    echo -e "${YELLOW}⚠️  Secret exists. Update it manually if needed:${NC}"
    echo "   kubectl edit secret database-secret -n cspm"
else
    echo -e "${YELLOW}⚠️  Please update database-secret.yaml with your values first!${NC}"
    echo -e "${YELLOW}   Then run: kubectl apply -f kubernetes/secrets/database-secret.yaml${NC}"
fi

# Apply ServiceAccount
echo -e "${YELLOW}Applying ServiceAccount...${NC}"
kubectl apply -f kubernetes/serviceaccounts/cspm-sa.yaml
echo -e "${GREEN}✅ ServiceAccount applied${NC}"

# Apply Services
echo -e "${YELLOW}Applying Services...${NC}"
kubectl apply -f kubernetes/services/django-backend-service.yaml
kubectl apply -f kubernetes/services/onboarding-api-service.yaml
echo -e "${GREEN}✅ Services applied${NC}"

# Apply Deployments
echo -e "${YELLOW}Applying Deployments...${NC}"
kubectl apply -f kubernetes/deployments/django-backend-deployment.yaml
kubectl apply -f kubernetes/deployments/onboarding-api-deployment.yaml
kubectl apply -f kubernetes/deployments/scheduler-deployment.yaml
echo -e "${GREEN}✅ Deployments applied${NC}"

# Wait for deployments
echo -e "${YELLOW}Waiting for deployments to be ready...${NC}"
kubectl rollout status deployment/django-backend -n cspm --timeout=5m
kubectl rollout status deployment/onboarding-api -n cspm --timeout=5m
kubectl rollout status deployment/scheduler-service -n cspm --timeout=5m

echo ""
echo -e "${GREEN}=========================================="
echo "✅ Deployment Complete!"
echo "==========================================${NC}"
echo ""
echo "Check status:"
echo "  kubectl get pods -n cspm"
echo "  kubectl get svc -n cspm"
echo ""
echo "View logs:"
echo "  kubectl logs -f deployment/django-backend -n cspm"
echo "  kubectl logs -f deployment/onboarding-api -n cspm"
echo "  kubectl logs -f deployment/scheduler-service -n cspm"
echo ""

