#!/bin/bash
# Deploy all services locally using Docker Compose or Kubernetes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOYMENT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

echo "=========================================="
echo "Local Deployment"
echo "=========================================="
echo ""

# Check deployment method
DEPLOY_METHOD="${1:-docker-compose}"

if [ "$DEPLOY_METHOD" == "kubernetes" ]; then
    echo "Deploying to Kubernetes (Docker Desktop)..."
    echo ""
    
    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        echo "❌ kubectl not found"
        exit 1
    fi
    
    # Check Docker Desktop context
    if ! kubectl config current-context | grep -q "docker-desktop"; then
        echo "⚠️  Not using docker-desktop context"
        echo "Switching to docker-desktop..."
        kubectl config use-context docker-desktop
    fi
    
    # Create namespace
    kubectl create namespace threat-engine-local --dry-run=client -o yaml | kubectl apply -f -
    
    # Deploy services
    cd "$DEPLOYMENT_DIR/kubernetes"
    kubectl apply -f .
    
    echo ""
    echo "✅ Deployed to Kubernetes"
    echo ""
    echo "To access services:"
    echo "  kubectl port-forward -n threat-engine-local svc/compliance-engine 8001:80"
    echo "  kubectl port-forward -n threat-engine-local svc/rule-engine 8002:80"
    
else
    echo "Deploying with Docker Compose..."
    echo ""
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo "❌ Docker not found"
        exit 1
    fi
    
    # Setup PostgreSQL first
    echo "Setting up PostgreSQL..."
    cd "$DEPLOYMENT_DIR/postgres"
    ./setup-postgres.sh
    
    # Start services
    echo ""
    echo "Starting Docker Compose services..."
    cd "$DEPLOYMENT_DIR/docker-compose"
    docker-compose up -d
    
    echo ""
    echo "✅ Services started"
    echo ""
    echo "Services available at:"
    echo "  Compliance Engine: http://localhost:8001"
    echo "  Rule Engine: http://localhost:8002"
    echo "  Onboarding Engine: http://localhost:8003"
    echo "  AWS ConfigScan Engine: http://localhost:8000"
    echo ""
    echo "To view logs:"
    echo "  docker-compose logs -f"
    echo ""
    echo "To stop:"
    echo "  docker-compose down"
fi

echo ""
echo "=========================================="
echo "✅ Local Deployment Complete!"
echo "=========================================="

