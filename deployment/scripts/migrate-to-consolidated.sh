#!/bin/bash
#
# Migration Script: Legacy to Consolidated Architecture
# Safely migrates from individual engine services to consolidated services
#

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

NAMESPACE=${NAMESPACE:-"threat-engine"}
BACKUP_NAMESPACE="threat-engine-backup"

echo -e "${BLUE}🚀 Threat Engine Migration to Consolidated Architecture${NC}"
echo "Namespace: ${NAMESPACE}"
echo "Backup Namespace: ${BACKUP_NAMESPACE}"

# Function to backup existing deployment
backup_existing() {
    echo -e "${YELLOW}Creating backup of existing deployment...${NC}"
    
    kubectl create namespace "${BACKUP_NAMESPACE}" --dry-run=client -o yaml | kubectl apply -f -
    
    # Backup all resources
    kubectl get all -n "${NAMESPACE}" -o yaml > "backup-$(date +%Y%m%d-%H%M%S).yaml"
    
    echo -e "${GREEN}✓ Backup created${NC}"
}

# Function to scale down legacy services
scale_down_legacy() {
    echo -e "${YELLOW}Scaling down legacy services...${NC}"
    
    local legacy_services=(
        "engine-threat"
        "engine-compliance" 
        "engine-rule"
        "engine-inventory"
        "engine-onboarding"
        "engine-datasec"
        "engine-secops"
    )
    
    for service in "${legacy_services[@]}"; do
        if kubectl get deployment "${service}" -n "${NAMESPACE}" &>/dev/null; then
            kubectl scale deployment "${service}" --replicas=0 -n "${NAMESPACE}"
            echo -e "${GREEN}✓ Scaled down ${service}${NC}"
        fi
    done
}

# Function to deploy consolidated services
deploy_consolidated() {
    echo -e "${YELLOW}Deploying consolidated services...${NC}"
    
    # Run the main deployment script
    ./deploy-consolidated.sh deploy
}

# Function to verify migration
verify_migration() {
    echo -e "${YELLOW}Verifying migration...${NC}"
    
    # Check API Gateway health
    kubectl port-forward -n "${NAMESPACE}" service/api-gateway 8080:8000 &
    sleep 5
    
    if curl -f http://localhost:8080/health &>/dev/null; then
        echo -e "${GREEN}✓ API Gateway is healthy${NC}"
    else
        echo -e "${RED}✗ API Gateway health check failed${NC}"
        return 1
    fi
    
    # Test service routing
    for endpoint in core platform configscan data-secops; do
        if curl -f "http://localhost:8080/api/v1/${endpoint}/health" &>/dev/null; then
            echo -e "${GREEN}✓ ${endpoint} service is accessible${NC}"
        else
            echo -e "${RED}✗ ${endpoint} service not accessible${NC}"
        fi
    done
    
    pkill kubectl || true
}

# Main migration process
main() {
    echo -e "${BLUE}Starting migration process...${NC}"
    
    backup_existing
    scale_down_legacy
    deploy_consolidated
    verify_migration
    
    echo -e "${GREEN}🎉 Migration completed successfully!${NC}"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "1. Monitor the new services for stability"
    echo "2. Update DNS/load balancer to point to API Gateway"
    echo "3. Clean up legacy deployments when confident"
    echo "4. Remove backup namespace after verification period"
}

case "${1:-migrate}" in
    "migrate")
        main
        ;;
    "rollback")
        echo -e "${YELLOW}Rolling back to legacy architecture...${NC}"
        kubectl apply -f "backup-*.yaml" -n "${NAMESPACE}"
        echo -e "${GREEN}✓ Rollback completed${NC}"
        ;;
    "cleanup")
        echo -e "${YELLOW}Cleaning up legacy resources...${NC}"
        kubectl delete namespace "${BACKUP_NAMESPACE}"
        rm -f backup-*.yaml
        echo -e "${GREEN}✓ Cleanup completed${NC}"
        ;;
    "help")
        echo "Usage: $0 [migrate|rollback|cleanup|help]"
        ;;
esac