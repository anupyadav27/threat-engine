#!/bin/bash
# Build all orchestration engine Docker images

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

cd "$PROJECT_ROOT"

print_header "Building All Orchestration Engine Images"

# Image tag
IMAGE_TAG="${1:-local}"
REGISTRY="${2:-threat-engine}"

print_warning "Building images with tag: $IMAGE_TAG"
print_warning "Using registry prefix: $REGISTRY"

# Build API Gateway
print_header "Building API Gateway"
if [ -f "api_gateway/Dockerfile" ]; then
    docker build -t "$REGISTRY/api-gateway:$IMAGE_TAG" \
        -f api_gateway/Dockerfile . && print_success "API Gateway built" || print_warning "API Gateway build failed"
else
    print_warning "API Gateway Dockerfile not found, skipping..."
fi

# Build Discovery Engine
print_header "Building Discovery Engine"
if [ -f "engine_discoveries/engine_discoveries_aws/Dockerfile" ]; then
    docker build -t "$REGISTRY/discovery:$IMAGE_TAG" \
        -f engine_discoveries/engine_discoveries_aws/Dockerfile . && print_success "Discovery Engine built" || print_warning "Discovery build failed"
else
    print_warning "Discovery Dockerfile not found, skipping..."
fi

# Build Check Engine
print_header "Building Check Engine"
if [ -f "engine_check/engine_check_aws/Dockerfile" ]; then
    docker build -t "$REGISTRY/check:$IMAGE_TAG" \
        -f engine_check/engine_check_aws/Dockerfile . && print_success "Check Engine built" || print_warning "Check build failed"
else
    print_warning "Check Dockerfile not found, skipping..."
fi

# Build Threat Engine
print_header "Building Threat Engine"
if [ -f "engine_threat/Dockerfile" ]; then
    docker build -t "$REGISTRY/threat:$IMAGE_TAG" \
        -f engine_threat/Dockerfile . && print_success "Threat Engine built" || print_warning "Threat build failed"
else
    print_warning "Threat Dockerfile not found, skipping..."
fi

# Build Compliance Engine
print_header "Building Compliance Engine"
if [ -f "engine_compliance/Dockerfile" ]; then
    docker build -t "$REGISTRY/compliance:$IMAGE_TAG" \
        -f engine_compliance/Dockerfile . && print_success "Compliance Engine built" || print_warning "Compliance build failed"
else
    print_warning "Compliance Dockerfile not found, skipping..."
fi

# Build IAM Engine
print_header "Building IAM Engine"
if [ -f "engine_iam/Dockerfile" ]; then
    docker build -t "$REGISTRY/iam:$IMAGE_TAG" \
        -f engine_iam/Dockerfile . && print_success "IAM Engine built" || print_warning "IAM build failed"
else
    print_warning "IAM Dockerfile not found, skipping..."
fi

# Build DataSec Engine
print_header "Building DataSec Engine"
if [ -f "engine_datasec/Dockerfile" ]; then
    docker build -t "$REGISTRY/datasec:$IMAGE_TAG" \
        -f engine_datasec/Dockerfile . && print_success "DataSec Engine built" || print_warning "DataSec build failed"
else
    print_warning "DataSec Dockerfile not found, skipping..."
fi

# Build Inventory Engine
print_header "Building Inventory Engine"
if [ -f "engine_inventory/Dockerfile" ]; then
    docker build -t "$REGISTRY/inventory:$IMAGE_TAG" \
        -f engine_inventory/Dockerfile . && print_success "Inventory Engine built" || print_warning "Inventory build failed"
else
    print_warning "Inventory Dockerfile not found, skipping..."
fi

print_header "Build Summary"
echo "Built images with tag: $IMAGE_TAG"
echo ""
echo "To view images:"
echo "  docker images | grep $REGISTRY"
echo ""
echo "To push to registry (if needed):"
echo "  docker push $REGISTRY/api-gateway:$IMAGE_TAG"
echo "  docker push $REGISTRY/discovery:$IMAGE_TAG"
echo "  # ... etc"
