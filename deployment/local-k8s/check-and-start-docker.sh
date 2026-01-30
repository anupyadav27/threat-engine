#!/bin/bash
# Check Docker status and provide instructions to start

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

print_header "Checking Docker Status"

# Check if Docker daemon is running
if docker info > /dev/null 2>&1; then
    print_success "Docker daemon is running"
    
    # Check Docker Desktop
    if docker ps > /dev/null 2>&1; then
        print_success "Docker is fully operational"
        echo ""
        echo "Docker containers:"
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        echo ""
        exit 0
    else
        print_warning "Docker daemon accessible but containers not responding"
    fi
else
    print_error "Docker daemon is not running"
    echo ""
    echo "To start Docker:"
    echo "  1. Open Docker Desktop application"
    echo "  2. Wait for Docker to start (whale icon in menu bar)"
    echo "  3. Run this script again: ./check-and-start-docker.sh"
    echo ""
    
    # Try to open Docker Desktop on macOS
    if [[ "$OSTYPE" == "darwin"* ]]; then
        print_warning "Attempting to open Docker Desktop..."
        open -a Docker 2>/dev/null || print_warning "Could not auto-open Docker Desktop. Please open it manually."
        echo ""
        echo "Waiting 10 seconds for Docker to start..."
        sleep 10
        
        # Check again
        if docker info > /dev/null 2>&1; then
            print_success "Docker started successfully!"
            exit 0
        else
            print_error "Docker did not start. Please start Docker Desktop manually."
            exit 1
        fi
    else
        exit 1
    fi
fi
