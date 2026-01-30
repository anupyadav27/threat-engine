#!/bin/bash
# Deploy All Orchestration Engines to Local Kubernetes (Docker Desktop)
# Uses existing PostgreSQL database

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

NAMESPACE="threat-engine-local"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

print_header() {
    echo -e "\n${BLUE}===================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}===================================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

check_prerequisites() {
    print_header "Checking Prerequisites"
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        print_error "kubectl not found. Please install kubectl."
        exit 1
    fi
    print_success "kubectl found"
    
    # Check Kubernetes connection
    if ! kubectl cluster-info &> /dev/null; then
        print_error "Cannot connect to Kubernetes cluster. Please ensure Docker Desktop Kubernetes is running."
        exit 1
    fi
    print_success "Kubernetes cluster accessible"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker not found. Please install Docker Desktop."
        exit 1
    fi
    print_success "Docker found"
    
    # Check if Docker is running
    if ! docker info &> /dev/null; then
        print_error "Docker is not running. Please start Docker Desktop."
        exit 1
    fi
    print_success "Docker is running"
}

build_images() {
    print_header "Building Docker Images"
    
    cd "$PROJECT_ROOT"
    
    # Build API Gateway
    print_warning "Building API Gateway..."
    docker build -t threat-engine/api-gateway:local \
        -f api_gateway/Dockerfile . || print_warning "API Gateway Dockerfile not found, skipping..."
    
    # Build Discovery Engine
    print_warning "Building Discovery Engine..."
    docker build -t threat-engine/discovery:local \
        -f engine_discovery/Dockerfile . || print_warning "Discovery Dockerfile not found, skipping..."
    
    # Build Check Engine
    print_warning "Building Check Engine..."
    docker build -t threat-engine/check:local \
        -f engine_check/Dockerfile . || print_warning "Check Dockerfile not found, skipping..."
    
    # Build Threat Engine
    print_warning "Building Threat Engine..."
    docker build -t threat-engine/threat:local \
        -f engine_threat/Dockerfile . || print_warning "Threat Dockerfile not found, skipping..."
    
    # Build Compliance Engine
    print_warning "Building Compliance Engine..."
    docker build -t threat-engine/compliance:local \
        -f engine_compliance/Dockerfile . || print_warning "Compliance Dockerfile not found, skipping..."
    
    # Build IAM Engine
    print_warning "Building IAM Engine..."
    docker build -t threat-engine/iam:local \
        -f engine_iam/Dockerfile . || print_warning "IAM Dockerfile not found, skipping..."
    
    # Build DataSec Engine
    print_warning "Building DataSec Engine..."
    docker build -t threat-engine/datasec:local \
        -f engine_datasec/Dockerfile . || print_warning "DataSec Dockerfile not found, skipping..."
    
    # Build Inventory Engine
    print_warning "Building Inventory Engine..."
    docker build -t threat-engine/inventory:local \
        -f engine_inventory/Dockerfile . || print_warning "Inventory Dockerfile not found, skipping..."
    
    print_success "Docker images built (or skipped if Dockerfiles not found)"
}

deploy_to_k8s() {
    print_header "Deploying to Kubernetes"
    
    cd "$SCRIPT_DIR"
    
    # Apply namespace and deployments
    kubectl apply -f orchestration-deployments.yaml
    
    print_success "Deployments applied"
}

wait_for_pods() {
    print_header "Waiting for Pods to be Ready"
    
    print_warning "Waiting up to 5 minutes for all pods to be ready..."
    
    kubectl wait --for=condition=ready pod \
        -l app=api-gateway \
        -n "$NAMESPACE" \
        --timeout=300s || print_warning "API Gateway not ready yet"
    
    kubectl wait --for=condition=ready pod \
        -l app=discovery-service \
        -n "$NAMESPACE" \
        --timeout=300s || print_warning "Discovery not ready yet"
    
    kubectl wait --for=condition=ready pod \
        -l app=check-service \
        -n "$NAMESPACE" \
        --timeout=300s || print_warning "Check not ready yet"
    
    kubectl wait --for=condition=ready pod \
        -l app=threat-service \
        -n "$NAMESPACE" \
        --timeout=300s || print_warning "Threat not ready yet"
    
    kubectl wait --for=condition=ready pod \
        -l app=compliance-service \
        -n "$NAMESPACE" \
        --timeout=300s || print_warning "Compliance not ready yet"
    
    kubectl wait --for=condition=ready pod \
        -l app=iam-service \
        -n "$NAMESPACE" \
        --timeout=300s || print_warning "IAM not ready yet"
    
    kubectl wait --for=condition=ready pod \
        -l app=datasec-service \
        -n "$NAMESPACE" \
        --timeout=300s || print_warning "DataSec not ready yet"
    
    kubectl wait --for=condition=ready pod \
        -l app=inventory-service \
        -n "$NAMESPACE" \
        --timeout=300s || print_warning "Inventory not ready yet"
    
    print_success "Pods are ready (or still starting)"
}

show_status() {
    print_header "Deployment Status"
    
    echo -e "\n${BLUE}Pods:${NC}"
    kubectl get pods -n "$NAMESPACE"
    
    echo -e "\n${BLUE}Services:${NC}"
    kubectl get services -n "$NAMESPACE"
    
    echo -e "\n${BLUE}API Gateway NodePort:${NC}"
    NODEPORT=$(kubectl get service api-gateway -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || echo "N/A")
    if [ "$NODEPORT" != "N/A" ]; then
        echo "  http://localhost:$NODEPORT"
    fi
}

check_health() {
    print_header "Checking Service Health"
    
    # Get API Gateway port
    NODEPORT=$(kubectl get service api-gateway -n "$NAMESPACE" -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || echo "")
    
    if [ -n "$NODEPORT" ]; then
        print_warning "Testing API Gateway health endpoint..."
        if curl -s -f "http://localhost:$NODEPORT/gateway/health" > /dev/null; then
            print_success "API Gateway is healthy"
        else
            print_warning "API Gateway health check failed (may still be starting)"
        fi
    fi
}

cleanup() {
    print_header "Cleaning Up"
    
    kubectl delete -f orchestration-deployments.yaml --ignore-not-found=true
    
    print_success "Cleanup complete"
}

main() {
    case "${1:-deploy}" in
        build)
            check_prerequisites
            build_images
            ;;
        deploy)
            check_prerequisites
            build_images
            deploy_to_k8s
            wait_for_pods
            show_status
            check_health
            ;;
        status)
            show_status
            ;;
        health)
            check_health
            ;;
        cleanup)
            cleanup
            ;;
        *)
            echo "Usage: $0 [build|deploy|status|health|cleanup]"
            echo "  build   - Build Docker images only"
            echo "  deploy  - Build and deploy everything (default)"
            echo "  status  - Show deployment status"
            echo "  health  - Check service health"
            echo "  cleanup - Remove all deployments"
            exit 1
            ;;
    esac
}

main "$@"
