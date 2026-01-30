#!/bin/bash
#
# Build All Consolidated Services
# Builds Docker images for all consolidated services in the correct order
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REGISTRY_PREFIX=${REGISTRY_PREFIX:-"threat-engine"}
VERSION=${VERSION:-"latest"}
BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Build context
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

echo -e "${BLUE}Starting build process for Threat Engine Consolidated Services${NC}"
echo "Registry: ${REGISTRY_PREFIX}"
echo "Version: ${VERSION}"
echo "Build Date: ${BUILD_DATE}"
echo "Git Commit: ${GIT_COMMIT}"
echo "Project Root: ${PROJECT_ROOT}"
echo ""

# Function to build a service
build_service() {
    local service_name=$1
    local service_path=$2
    local dockerfile_path=${3:-"Dockerfile"}
    
    echo -e "${YELLOW}Building ${service_name}...${NC}"
    
    cd "${PROJECT_ROOT}"
    
    # Build the Docker image
    docker build \
        --file "${service_path}/${dockerfile_path}" \
        --tag "${REGISTRY_PREFIX}/${service_name}:${VERSION}" \
        --tag "${REGISTRY_PREFIX}/${service_name}:latest" \
        --label "org.opencontainers.image.title=${service_name}" \
        --label "org.opencontainers.image.version=${VERSION}" \
        --label "org.opencontainers.image.created=${BUILD_DATE}" \
        --label "org.opencontainers.image.revision=${GIT_COMMIT}" \
        --label "org.opencontainers.image.source=https://github.com/company/threat-engine" \
        --build-arg VERSION="${VERSION}" \
        --build-arg BUILD_DATE="${BUILD_DATE}" \
        --build-arg GIT_COMMIT="${GIT_COMMIT}" \
        "${service_path}"
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ ${service_name} built successfully${NC}"
    else
        echo -e "${RED}✗ Failed to build ${service_name}${NC}"
        exit 1
    fi
}

# Function to check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}✗ Docker is not installed or not in PATH${NC}"
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        echo -e "${RED}✗ Docker daemon is not running${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Prerequisites check passed${NC}"
}

# Function to cleanup old images (optional)
cleanup_old_images() {
    if [ "${CLEANUP_OLD_IMAGES:-false}" == "true" ]; then
        echo -e "${YELLOW}Cleaning up old images...${NC}"
        docker image prune -f --filter "label=org.opencontainers.image.title"
        echo -e "${GREEN}✓ Old images cleaned up${NC}"
    fi
}

# Main build process
main() {
    check_prerequisites
    
    echo -e "${BLUE}Building consolidated services...${NC}"
    
    # Build services in dependency order
    # 1. API Gateway (no dependencies)
    build_service "api-gateway" "api_gateway"
    
    # 2. Core services (can be built in parallel)
    build_service "core-engine-service" "consolidated_services/core_engine_service"
    build_service "configscan-service" "consolidated_services/configscan_service"
    build_service "platform-service" "consolidated_services/platform_service"
    build_service "data-secops-service" "consolidated_services/data_secops_service"
    
    # Optional cleanup
    cleanup_old_images
    
    echo ""
    echo -e "${GREEN}🎉 All services built successfully!${NC}"
    echo ""
    echo "Built images:"
    docker images --filter "label=org.opencontainers.image.version=${VERSION}" --format "table {{.Repository}}:{{.Tag}}\t{{.CreatedAt}}\t{{.Size}}"
}

# Handle script arguments
case "${1:-build}" in
    "build")
        main
        ;;
    "clean")
        echo -e "${YELLOW}Cleaning up all threat-engine images...${NC}"
        docker images "${REGISTRY_PREFIX}/*" --format "{{.Repository}}:{{.Tag}}" | xargs -r docker rmi -f
        echo -e "${GREEN}✓ Cleanup completed${NC}"
        ;;
    "list")
        echo "Current threat-engine images:"
        docker images --filter "reference=${REGISTRY_PREFIX}/*" --format "table {{.Repository}}:{{.Tag}}\t{{.CreatedAt}}\t{{.Size}}"
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [build|clean|list|help]"
        echo ""
        echo "Commands:"
        echo "  build  - Build all consolidated services (default)"
        echo "  clean  - Remove all threat-engine Docker images"
        echo "  list   - List all current threat-engine images"
        echo "  help   - Show this help message"
        echo ""
        echo "Environment Variables:"
        echo "  REGISTRY_PREFIX     - Docker registry prefix (default: threat-engine)"
        echo "  VERSION            - Image version tag (default: latest)"
        echo "  CLEANUP_OLD_IMAGES - Clean up old images after build (default: false)"
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo "Use '$0 help' for usage information."
        exit 1
        ;;
esac