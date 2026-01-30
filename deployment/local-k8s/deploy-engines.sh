#!/bin/bash

# Deploy Threat Engine Services to Local Kubernetes
# Supports Docker Desktop Kubernetes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

NAMESPACE="threat-engine-local"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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
    
    # Check if namespace exists or will be created
    if kubectl get namespace "$NAMESPACE" &> /dev/null; then
        print_success "Namespace $NAMESPACE exists"
    else
        print_warning "Namespace $NAMESPACE will be created"
    fi
}

build_images() {
    print_header "Building Docker Images"
    
    cd "$SCRIPT_DIR/../.."
    
    # Build onboarding image
    print_header "Building Onboarding Engine Image"
    docker build -t threat-engine/onboarding-service:local \
        -f engine_onboarding/Dockerfile \
        .
    
    if [ $? -eq 0 ]; then
        print_success "Onboarding image built successfully"
    else
        print_error "Failed to build onboarding image"
        exit 1
    fi
    
    # Build configscan AWS image
    print_header "Building ConfigScan AWS Engine Image"
    docker build -t threat-engine/configscan-aws-service:local \
        -f engine_configscan/engine_configscan_aws/Dockerfile \
        .
    
    if [ $? -eq 0 ]; then
        print_success "ConfigScan AWS image built successfully"
    else
        print_error "Failed to build configscan AWS image"
        exit 1
    fi
}

deploy_services() {
    print_header "Deploying Services to Kubernetes"
    
    cd "$SCRIPT_DIR"
    
    # Deploy onboarding
    print_header "Deploying Onboarding Engine"
    kubectl apply -f onboarding-deployment.yaml
    
    if [ $? -eq 0 ]; then
        print_success "Onboarding deployment applied"
    else
        print_error "Failed to deploy onboarding"
        exit 1
    fi
    
    # Deploy configscan AWS
    print_header "Deploying ConfigScan AWS Engine"
    kubectl apply -f configscan-aws-deployment.yaml
    
    if [ $? -eq 0 ]; then
        print_success "ConfigScan AWS deployment applied"
    else
        print_error "Failed to deploy configscan AWS"
        exit 1
    fi
}

wait_for_deployments() {
    print_header "Waiting for Deployments to be Ready"
    
    echo "Waiting for onboarding-service..."
    kubectl wait --for=condition=available --timeout=300s \
        deployment/onboarding-service -n "$NAMESPACE" || {
        print_error "Onboarding service failed to become ready"
        kubectl describe deployment onboarding-service -n "$NAMESPACE"
        kubectl logs -l app=onboarding-service -n "$NAMESPACE" --tail=50
        exit 1
    }
    print_success "Onboarding service is ready"
    
    echo "Waiting for configscan-aws-service..."
    kubectl wait --for=condition=available --timeout=300s \
        deployment/configscan-aws-service -n "$NAMESPACE" || {
        print_error "ConfigScan AWS service failed to become ready"
        kubectl describe deployment configscan-aws-service -n "$NAMESPACE"
        kubectl logs -l app=configscan-aws-service -n "$NAMESPACE" --tail=50
        exit 1
    }
    print_success "ConfigScan AWS service is ready"
}

check_health() {
    print_header "Checking Service Health"
    
    # Get pod names
    ONBOARDING_POD=$(kubectl get pods -n "$NAMESPACE" -l app=onboarding-service -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    CONFIGSCAN_POD=$(kubectl get pods -n "$NAMESPACE" -l app=configscan-aws-service -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    
    if [ -n "$ONBOARDING_POD" ]; then
        echo "Testing Onboarding health endpoint..."
        kubectl exec -n "$NAMESPACE" "$ONBOARDING_POD" -- \
            curl -s http://localhost:8010/api/v1/health | python3 -m json.tool || {
            print_warning "Onboarding health check failed (may still be starting)"
        }
    fi
    
    if [ -n "$CONFIGSCAN_POD" ]; then
        echo "Testing ConfigScan AWS health endpoint..."
        kubectl exec -n "$NAMESPACE" "$CONFIGSCAN_POD" -- \
            curl -s http://localhost:8002/api/v1/health | python3 -m json.tool || {
            print_warning "ConfigScan AWS health check failed (may still be starting)"
        }
    fi
}

show_status() {
    print_header "Deployment Status"
    
    echo "Services:"
    kubectl get services -n "$NAMESPACE"
    
    echo -e "\nDeployments:"
    kubectl get deployments -n "$NAMESPACE"
    
    echo -e "\nPods:"
    kubectl get pods -n "$NAMESPACE"
    
    echo -e "\n\nAccess URLs:"
    echo "Onboarding API:"
    echo "  - ClusterIP: http://onboarding-service.$NAMESPACE.svc.cluster.local:8010"
    echo "  - NodePort: http://localhost:30010"
    echo "  - Health: http://localhost:30010/api/v1/health"
    
    echo -e "\nConfigScan AWS API:"
    echo "  - ClusterIP: http://configscan-aws-service.$NAMESPACE.svc.cluster.local:8002"
    echo "  - NodePort: http://localhost:30002"
    echo "  - Health: http://localhost:30002/api/v1/health"
}

cleanup() {
    print_header "Cleaning Up Deployments"
    
    read -p "This will delete all deployments in $NAMESPACE. Continue? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        kubectl delete -f onboarding-deployment.yaml --ignore-not-found=true
        kubectl delete -f configscan-aws-deployment.yaml --ignore-not-found=true
        print_success "Deployments cleaned up"
    else
        echo "Cleanup cancelled"
    fi
}

main() {
    case "${1:-}" in
        "build")
            check_prerequisites
            build_images
            ;;
        "deploy")
            check_prerequisites
            deploy_services
            wait_for_deployments
            check_health
            show_status
            ;;
        "status")
            show_status
            ;;
        "health")
            check_health
            ;;
        "cleanup")
            cleanup
            ;;
        "all"|"")
            check_prerequisites
            build_images
            deploy_services
            wait_for_deployments
            check_health
            show_status
            ;;
        "--help"|"-h")
            echo "Usage: $0 [command]"
            echo ""
            echo "Commands:"
            echo "  (no args) - Full deployment (build + deploy)"
            echo "  all       - Full deployment (build + deploy)"
            echo "  build     - Build Docker images only"
            echo "  deploy    - Deploy to Kubernetes (assumes images exist)"
            echo "  status    - Show deployment status"
            echo "  health    - Check service health"
            echo "  cleanup   - Remove all deployments"
            echo ""
            exit 0
            ;;
        *)
            echo "Unknown command: $1"
            echo "Run '$0 --help' for usage"
            exit 1
            ;;
    esac
}

main "$@"
