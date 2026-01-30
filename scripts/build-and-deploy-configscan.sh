#!/bin/bash
#
# Build and Deploy ConfigScan Service to Docker Desktop Kubernetes
#

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)"
CONFIGSCAN_DIR="${PROJECT_ROOT}/consolidated_services/configscan_service"
K8S_MANIFESTS="${PROJECT_ROOT}/deployment/local-k8s"

IMAGE_TAG="threat-engine/configscan-service:local"

echo -e "${BLUE}Building and Deploying ConfigScan Service to Docker Desktop K8s${NC}"
echo "Project Root: ${PROJECT_ROOT}"
echo "Service Directory: ${CONFIGSCAN_DIR}"
echo "Image Tag: ${IMAGE_TAG}"
echo ""

# Function to check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}Docker is required but not installed${NC}"
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        echo -e "${RED}Docker daemon is not running${NC}"
        exit 1
    fi
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        echo -e "${RED}kubectl is required but not installed${NC}"
        exit 1
    fi
    
    # Check if kubectl can connect
    if ! kubectl cluster-info &> /dev/null; then
        echo -e "${RED}Cannot connect to Kubernetes cluster${NC}"
        echo "Make sure Docker Desktop Kubernetes is enabled"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Prerequisites check passed${NC}"
}

# Function to build Docker image
build_docker_image() {
    echo -e "${YELLOW}Building Docker image...${NC}"
    
    cd "${CONFIGSCAN_DIR}"
    
    # Check if Dockerfile exists
    if [ ! -f "Dockerfile" ]; then
        echo -e "${RED}Dockerfile not found in ${CONFIGSCAN_DIR}${NC}"
        exit 1
    fi
    
    # Build the image
    docker build -t "${IMAGE_TAG}" . \
        --build-arg VERSION="local" \
        --build-arg BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --build-arg GIT_COMMIT="$(git rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
        --label "environment=local" \
        --label "service=configscan-service"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Docker image built successfully: ${IMAGE_TAG}${NC}"
    else
        echo -e "${RED}✗ Failed to build Docker image${NC}"
        exit 1
    fi
    
    # Show image info
    echo -e "${BLUE}Image details:${NC}"
    docker images "${IMAGE_TAG}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
}

# Function to deploy to Kubernetes
deploy_to_kubernetes() {
    echo -e "${YELLOW}Deploying to Kubernetes...${NC}"
    
    local manifest_file="${K8S_MANIFESTS}/configscan-local-deployment.yaml"
    
    if [ ! -f "$manifest_file" ]; then
        echo -e "${RED}Kubernetes manifest not found: $manifest_file${NC}"
        exit 1
    fi
    
    # Apply the manifests
    kubectl apply -f "$manifest_file"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Kubernetes manifests applied successfully${NC}"
    else
        echo -e "${RED}✗ Failed to apply Kubernetes manifests${NC}"
        exit 1
    fi
}

# Function to wait for deployment
wait_for_deployment() {
    echo -e "${YELLOW}Waiting for deployment to be ready...${NC}"
    
    # Wait for deployment to be available
    if kubectl wait --for=condition=available --timeout=300s deployment/configscan-service -n threat-engine-local; then
        echo -e "${GREEN}✓ Deployment is ready${NC}"
    else
        echo -e "${RED}✗ Deployment failed or timed out${NC}"
        
        # Show debug information
        echo -e "${YELLOW}Debug information:${NC}"
        kubectl get pods -n threat-engine-local
        echo ""
        kubectl describe deployment configscan-service -n threat-engine-local
        exit 1
    fi
}

# Function to show deployment status
show_deployment_status() {
    echo -e "${YELLOW}Deployment status...${NC}"
    
    echo -e "${BLUE}Namespace resources:${NC}"
    kubectl get all -n threat-engine-local
    
    echo ""
    echo -e "${BLUE}Pod status:${NC}"
    kubectl get pods -n threat-engine-local -o wide
    
    echo ""
    echo -e "${BLUE}Service endpoints:${NC}"
    kubectl get services -n threat-engine-local
}

# Function to test the deployment
test_deployment() {
    echo -e "${YELLOW}Testing deployment...${NC}"
    
    # Get NodePort for testing
    local node_port=$(kubectl get service configscan-external -n threat-engine-local -o jsonpath='{.spec.ports[0].nodePort}')
    
    if [ -n "$node_port" ]; then
        echo -e "${BLUE}Testing service at localhost:${node_port}${NC}"
        
        # Wait for service to be ready
        sleep 5
        
        # Test health endpoint
        if curl -f -s "http://localhost:${node_port}/health" > /dev/null; then
            echo -e "${GREEN}✅ Service is responding to health checks${NC}"
            
            # Show health response
            echo -e "${BLUE}Health check response:${NC}"
            curl -s "http://localhost:${node_port}/health" | python3 -m json.tool 2>/dev/null || echo "Could not format JSON response"
        else
            echo -e "${RED}❌ Service is not responding${NC}"
            
            # Show pod logs for debugging
            echo -e "${YELLOW}Pod logs:${NC}"
            kubectl logs -l app=configscan-service -n threat-engine-local --tail=20
            return 1
        fi
    else
        echo -e "${RED}Could not get NodePort for external service${NC}"
        return 1
    fi
}

# Function to show access information
show_access_info() {
    local node_port=$(kubectl get service configscan-external -n threat-engine-local -o jsonpath='{.spec.ports[0].nodePort}')
    
    echo ""
    echo -e "${GREEN}🎉 ConfigScan Service deployed successfully!${NC}"
    echo ""
    echo -e "${BLUE}Access Information:${NC}"
    echo "External URL: http://localhost:${node_port}"
    echo "Health Check: http://localhost:${node_port}/health" 
    echo "API Documentation: http://localhost:${node_port}/docs"
    echo "Internal Service: configscan-service.threat-engine-local.svc.cluster.local:8002"
    echo ""
    echo -e "${BLUE}Useful Commands:${NC}"
    echo "• View pods: kubectl get pods -n threat-engine-local"
    echo "• View logs: kubectl logs -l app=configscan-service -n threat-engine-local"
    echo "• Port forward: kubectl port-forward -n threat-engine-local service/configscan-service 8002:8002"
    echo "• Scale deployment: kubectl scale deployment configscan-service --replicas=2 -n threat-engine-local"
    echo "• Delete deployment: kubectl delete -f ${K8S_MANIFESTS}/configscan-local-deployment.yaml"
    echo ""
    echo -e "${YELLOW}Test the deployment:${NC}"
    echo "curl http://localhost:${node_port}/health"
    echo "curl http://localhost:${node_port}/"
}

# Function to cleanup deployment
cleanup_deployment() {
    echo -e "${YELLOW}Cleaning up deployment...${NC}"
    
    local manifest_file="${K8S_MANIFESTS}/configscan-local-deployment.yaml"
    
    if [ -f "$manifest_file" ]; then
        kubectl delete -f "$manifest_file"
        echo -e "${GREEN}✓ Deployment cleaned up${NC}"
    else
        echo -e "${YELLOW}No manifest file found for cleanup${NC}"
    fi
    
    # Remove Docker image
    if docker images -q "${IMAGE_TAG}" &> /dev/null; then
        docker rmi "${IMAGE_TAG}" -f
        echo -e "${GREEN}✓ Docker image removed${NC}"
    fi
}

# Function to show logs
show_logs() {
    echo -e "${YELLOW}Showing ConfigScan service logs...${NC}"
    kubectl logs -l app=configscan-service -n threat-engine-local --tail=50 -f
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  deploy    - Build and deploy ConfigScan service (default)"
    echo "  build     - Build Docker image only"
    echo "  test      - Test the deployed service"
    echo "  status    - Show deployment status"
    echo "  logs      - Show service logs"
    echo "  cleanup   - Remove the deployment and image"
    echo "  help      - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 deploy    # Build and deploy"
    echo "  $0 test      # Test deployed service"
    echo "  $0 logs      # View service logs"
    echo "  $0 cleanup   # Remove deployment"
}

# Main deployment process
main() {
    case "${1:-deploy}" in
        "deploy")
            check_prerequisites
            build_docker_image
            deploy_to_kubernetes
            wait_for_deployment
            show_deployment_status
            test_deployment
            show_access_info
            ;;
        "build")
            check_prerequisites
            build_docker_image
            ;;
        "test")
            test_deployment
            ;;
        "status")
            show_deployment_status
            ;;
        "logs")
            show_logs
            ;;
        "cleanup")
            cleanup_deployment
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            echo -e "${RED}Unknown command: $1${NC}"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"