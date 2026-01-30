#!/bin/bash
#
# Deploy Consolidated Threat Engine Architecture
# Deploys all consolidated services to Kubernetes cluster
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
NAMESPACE=${NAMESPACE:-"threat-engine"}
ENVIRONMENT=${ENVIRONMENT:-"production"}
VERSION=${VERSION:-"latest"}
REGISTRY_PREFIX=${REGISTRY_PREFIX:-"threat-engine"}
DRY_RUN=${DRY_RUN:-"false"}
WAIT_FOR_ROLLOUT=${WAIT_FOR_ROLLOUT:-"true"}

# Script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
K8S_DIR="$(dirname "$SCRIPT_DIR")/kubernetes"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo -e "${BLUE}Threat Engine Consolidated Deployment${NC}"
echo "Namespace: ${NAMESPACE}"
echo "Environment: ${ENVIRONMENT}"
echo "Version: ${VERSION}"
echo "Registry: ${REGISTRY_PREFIX}"
echo "Kubernetes Manifests: ${K8S_DIR}"
echo ""

# Function to check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        echo -e "${RED}✗ kubectl is not installed or not in PATH${NC}"
        exit 1
    fi
    
    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        echo -e "${RED}✗ Cannot connect to Kubernetes cluster${NC}"
        exit 1
    fi
    
    # Check if manifests directory exists
    if [ ! -d "${K8S_DIR}" ]; then
        echo -e "${RED}✗ Kubernetes manifests directory not found: ${K8S_DIR}${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Prerequisites check passed${NC}"
    
    # Show current context
    echo -e "${BLUE}Current cluster context:${NC}"
    kubectl config current-context
    echo ""
}

# Function to create namespace if it doesn't exist
create_namespace() {
    echo -e "${YELLOW}Setting up namespace: ${NAMESPACE}${NC}"
    
    if kubectl get namespace "${NAMESPACE}" &> /dev/null; then
        echo -e "${GREEN}✓ Namespace ${NAMESPACE} already exists${NC}"
    else
        if [ "${DRY_RUN}" == "true" ]; then
            echo -e "${PURPLE}[DRY RUN] Would create namespace: ${NAMESPACE}${NC}"
        else
            kubectl create namespace "${NAMESPACE}"
            echo -e "${GREEN}✓ Created namespace: ${NAMESPACE}${NC}"
        fi
    fi
    
    # Label the namespace
    if [ "${DRY_RUN}" != "true" ]; then
        kubectl label namespace "${NAMESPACE}" environment="${ENVIRONMENT}" --overwrite
        kubectl label namespace "${NAMESPACE}" app=threat-engine --overwrite
    fi
}

# Function to deploy a manifest
deploy_manifest() {
    local manifest_file=$1
    local manifest_name=$(basename "${manifest_file}" .yaml)
    
    echo -e "${YELLOW}Deploying ${manifest_name}...${NC}"
    
    if [ ! -f "${manifest_file}" ]; then
        echo -e "${RED}✗ Manifest file not found: ${manifest_file}${NC}"
        return 1
    fi
    
    if [ "${DRY_RUN}" == "true" ]; then
        echo -e "${PURPLE}[DRY RUN] Would apply: ${manifest_file}${NC}"
        kubectl apply --dry-run=client -f "${manifest_file}" -n "${NAMESPACE}"
    else
        kubectl apply -f "${manifest_file}" -n "${NAMESPACE}"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ ${manifest_name} deployed successfully${NC}"
        else
            echo -e "${RED}✗ Failed to deploy ${manifest_name}${NC}"
            return 1
        fi
    fi
}

# Function to wait for deployment rollout
wait_for_rollout() {
    local deployment_name=$1
    
    if [ "${WAIT_FOR_ROLLOUT}" == "true" ] && [ "${DRY_RUN}" != "true" ]; then
        echo -e "${YELLOW}Waiting for ${deployment_name} rollout...${NC}"
        
        if kubectl rollout status deployment/"${deployment_name}" -n "${NAMESPACE}" --timeout=300s; then
            echo -e "${GREEN}✓ ${deployment_name} rolled out successfully${NC}"
        else
            echo -e "${RED}✗ ${deployment_name} rollout failed or timed out${NC}"
            return 1
        fi
    fi
}

# Function to update image tags in manifests
update_image_tags() {
    if [ "${VERSION}" != "latest" ]; then
        echo -e "${YELLOW}Updating image tags to version: ${VERSION}${NC}"
        
        # Create temporary directory for modified manifests
        TEMP_DIR=$(mktemp -d)
        
        for manifest in "${K8S_DIR}"/*-deployment.yaml; do
            if [ -f "$manifest" ]; then
                local temp_manifest="${TEMP_DIR}/$(basename "$manifest")"
                sed "s/:latest/:${VERSION}/g" "$manifest" > "$temp_manifest"
                cp "$temp_manifest" "$manifest.versioned"
            fi
        done
        
        echo -e "${GREEN}✓ Image tags updated${NC}"
    fi
}

# Function to deploy secrets (placeholder - customize based on your secret management)
deploy_secrets() {
    echo -e "${YELLOW}Deploying secrets...${NC}"
    
    # Check if secret manifests exist
    local secret_files=(
        "${K8S_DIR}/secrets/database-secret.yaml"
        "${K8S_DIR}/secrets/cloud-credentials-secret.yaml"
    )
    
    for secret_file in "${secret_files[@]}"; do
        if [ -f "$secret_file" ]; then
            deploy_manifest "$secret_file"
        else
            echo -e "${YELLOW}⚠ Secret file not found: $secret_file${NC}"
            echo -e "${YELLOW}  Please create secrets manually or use your secret management system${NC}"
        fi
    done
}

# Function to deploy configuration
deploy_config() {
    echo -e "${YELLOW}Deploying configuration...${NC}"
    
    # Deploy ConfigMaps if they exist
    for config_file in "${K8S_DIR}"/configmaps/*.yaml; do
        if [ -f "$config_file" ]; then
            deploy_manifest "$config_file"
        fi
    done
    
    # Deploy data-security-rules ConfigMap from the data-secops deployment
    echo -e "${BLUE}ConfigMaps deployed with service manifests${NC}"
}

# Function to deploy storage
deploy_storage() {
    echo -e "${YELLOW}Deploying storage...${NC}"
    
    # PVCs are included in service deployment manifests
    echo -e "${BLUE}PVCs will be deployed with services${NC}"
}

# Function to deploy services in correct order
deploy_services() {
    echo -e "${BLUE}Deploying consolidated services...${NC}"
    
    # Service deployment order (dependencies first)
    local services=(
        "api-gateway-deployment.yaml"
        "core-engine-service-deployment.yaml"
        "configscan-service-deployment.yaml" 
        "platform-service-deployment.yaml"
        "data-secops-service-deployment.yaml"
    )
    
    for service in "${services[@]}"; do
        local service_file="${K8S_DIR}/${service}"
        
        if [ -f "$service_file" ]; then
            deploy_manifest "$service_file"
            
            # Extract deployment name from file
            local deployment_name=$(echo "$service" | sed 's/-deployment.yaml$//')
            
            # Wait for rollout
            wait_for_rollout "$deployment_name"
        else
            echo -e "${RED}✗ Service manifest not found: $service_file${NC}"
            exit 1
        fi
    done
}

# Function to verify deployment
verify_deployment() {
    echo -e "${YELLOW}Verifying deployment...${NC}"
    
    if [ "${DRY_RUN}" == "true" ]; then
        echo -e "${PURPLE}[DRY RUN] Would verify deployment${NC}"
        return 0
    fi
    
    # Check all deployments
    echo -e "${BLUE}Deployment status:${NC}"
    kubectl get deployments -n "${NAMESPACE}" -o wide
    
    echo ""
    echo -e "${BLUE}Pod status:${NC}"
    kubectl get pods -n "${NAMESPACE}" -o wide
    
    echo ""
    echo -e "${BLUE}Service status:${NC}"
    kubectl get services -n "${NAMESPACE}" -o wide
    
    # Check if all deployments are ready
    local failed_deployments=()
    
    while IFS= read -r deployment; do
        if ! kubectl rollout status deployment/"$deployment" -n "${NAMESPACE}" --timeout=10s &> /dev/null; then
            failed_deployments+=("$deployment")
        fi
    done < <(kubectl get deployments -n "${NAMESPACE}" -o jsonpath='{.items[*].metadata.name}')
    
    if [ ${#failed_deployments[@]} -eq 0 ]; then
        echo -e "${GREEN}✓ All deployments are ready${NC}"
        return 0
    else
        echo -e "${RED}✗ The following deployments are not ready:${NC}"
        printf '%s\n' "${failed_deployments[@]}"
        return 1
    fi
}

# Function to show access information
show_access_info() {
    if [ "${DRY_RUN}" == "true" ]; then
        return 0
    fi
    
    echo ""
    echo -e "${GREEN}🎉 Deployment completed successfully!${NC}"
    echo ""
    echo -e "${BLUE}Access Information:${NC}"
    
    # Get API Gateway service details
    local api_gateway_service=$(kubectl get service api-gateway -n "${NAMESPACE}" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")
    
    if [ "$api_gateway_service" != "pending" ] && [ -n "$api_gateway_service" ]; then
        echo "API Gateway: http://${api_gateway_service}:8000"
    else
        echo "API Gateway: kubectl port-forward -n ${NAMESPACE} service/api-gateway 8000:8000"
    fi
    
    echo ""
    echo -e "${BLUE}Service Endpoints (internal):${NC}"
    echo "• API Gateway: http://api-gateway:8000"
    echo "• Core Engine: http://core-engine-service:8001" 
    echo "• ConfigScan: http://configscan-service:8002"
    echo "• Platform: http://platform-service:8003"
    echo "• Data SecOps: http://data-secops-service:8004"
    
    echo ""
    echo -e "${BLUE}Useful Commands:${NC}"
    echo "• View logs: kubectl logs -f -l app=<service-name> -n ${NAMESPACE}"
    echo "• Scale deployment: kubectl scale deployment <deployment-name> --replicas=<count> -n ${NAMESPACE}"
    echo "• Port forward: kubectl port-forward -n ${NAMESPACE} service/<service-name> <local-port>:<service-port>"
    echo "• Delete deployment: kubectl delete -f ${K8S_DIR}/<manifest>.yaml -n ${NAMESPACE}"
}

# Main deployment process
main() {
    check_prerequisites
    create_namespace
    
    # Update image tags if version specified
    update_image_tags
    
    # Deploy in order
    deploy_secrets
    deploy_config  
    deploy_storage
    deploy_services
    
    # Verify deployment
    if verify_deployment; then
        show_access_info
    else
        echo -e "${RED}Deployment verification failed${NC}"
        exit 1
    fi
}

# Rollback function
rollback() {
    echo -e "${YELLOW}Rolling back deployment...${NC}"
    
    local deployments=(
        "api-gateway"
        "core-engine-service" 
        "configscan-service"
        "platform-service"
        "data-secops-service"
    )
    
    for deployment in "${deployments[@]}"; do
        if kubectl get deployment "$deployment" -n "${NAMESPACE}" &> /dev/null; then
            echo -e "${YELLOW}Rolling back ${deployment}...${NC}"
            kubectl rollout undo deployment/"$deployment" -n "${NAMESPACE}"
        fi
    done
    
    echo -e "${GREEN}✓ Rollback completed${NC}"
}

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning up deployment...${NC}"
    
    if [ "${DRY_RUN}" == "true" ]; then
        echo -e "${PURPLE}[DRY RUN] Would delete all resources in namespace: ${NAMESPACE}${NC}"
        kubectl get all -n "${NAMESPACE}"
    else
        read -p "Are you sure you want to delete all resources in namespace '${NAMESPACE}'? (yes/no): " confirm
        if [ "$confirm" == "yes" ]; then
            kubectl delete all --all -n "${NAMESPACE}"
            kubectl delete namespace "${NAMESPACE}"
            echo -e "${GREEN}✓ Cleanup completed${NC}"
        else
            echo "Cleanup cancelled"
        fi
    fi
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "rollback")
        rollback
        ;;
    "cleanup"|"clean")
        cleanup
        ;;
    "verify")
        verify_deployment
        show_access_info
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [deploy|rollback|cleanup|verify|help]"
        echo ""
        echo "Commands:"
        echo "  deploy   - Deploy all consolidated services (default)"
        echo "  rollback - Rollback all deployments to previous version"
        echo "  cleanup  - Delete all resources (DESTRUCTIVE)"
        echo "  verify   - Verify current deployment status"
        echo "  help     - Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  NAMESPACE           - Kubernetes namespace (default: threat-engine)"
        echo "  ENVIRONMENT         - Environment label (default: production)"
        echo "  VERSION             - Image version tag (default: latest)"
        echo "  REGISTRY_PREFIX     - Docker registry prefix (default: threat-engine)"
        echo "  DRY_RUN            - Show what would be done without applying (default: false)"
        echo "  WAIT_FOR_ROLLOUT   - Wait for deployment rollouts (default: true)"
        echo ""
        echo "Examples:"
        echo "  $0 deploy                              # Deploy with defaults"
        echo "  NAMESPACE=staging $0 deploy            # Deploy to staging namespace"
        echo "  VERSION=v1.2.3 $0 deploy             # Deploy specific version"
        echo "  DRY_RUN=true $0 deploy                # Show what would be deployed"
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo "Use '$0 help' for usage information."
        exit 1
        ;;
esac