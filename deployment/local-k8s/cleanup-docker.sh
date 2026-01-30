#!/bin/bash
# Clean up Docker Desktop - Remove all threat-engine images/containers except PostgreSQL
# Usage: ./cleanup-docker.sh [--dry-run]

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

DRY_RUN=false
SKIP_CONFIRM=false

for arg in "$@"; do
    case $arg in
        --dry-run)
            DRY_RUN=true
            echo -e "${YELLOW}DRY RUN MODE - No changes will be made${NC}\n"
            ;;
        --yes|-y)
            SKIP_CONFIRM=true
            ;;
    esac
done

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Docker Cleanup - Threat Engine${NC}"
echo -e "${BLUE}Keeping: PostgreSQL images/containers${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running. Please start Docker Desktop.${NC}"
    exit 1
fi

# Function to remove containers
cleanup_containers() {
    echo -e "${YELLOW}Cleaning up containers...${NC}"
    
    # Get all threat-engine related containers (excluding postgres)
    CONTAINERS=$(docker ps -a --format "{{.ID}} {{.Names}} {{.Image}}" | \
        grep -E "(threat-engine|onboarding|configscan|secops|compliance|inventory|cspm)" | \
        grep -v -E "(postgres|postgresql)" | \
        awk '{print $1}')
    
    if [ -z "$CONTAINERS" ]; then
        echo -e "${GREEN}No threat-engine containers found${NC}"
    else
        COUNT=$(echo "$CONTAINERS" | wc -l | tr -d ' ')
        echo -e "Found ${COUNT} container(s) to remove:"
        for CONTAINER_ID in $CONTAINERS; do
            CONTAINER_NAME=$(docker ps -a --format "{{.Names}}" --filter "id=$CONTAINER_ID" | head -1)
            echo "  - $CONTAINER_NAME ($CONTAINER_ID)"
        done
        
        if [ "$DRY_RUN" = false ]; then
            echo "$CONTAINERS" | xargs -r docker rm -f 2>/dev/null || true
            echo -e "${GREEN}✓ Containers removed${NC}"
        else
            echo -e "${YELLOW}[DRY RUN] Would remove containers${NC}"
        fi
    fi
    echo ""
}

# Function to remove images
cleanup_images() {
    echo -e "${YELLOW}Cleaning up images...${NC}"
    
    # Get all threat-engine related images (excluding postgres)
    IMAGE_LIST=$(docker images --format "{{.ID}}|{{.Repository}}:{{.Tag}}" | \
        grep -E "(threat-engine|onboarding|configscan|secops|compliance|inventory|cspm|lgtechharsh|yadavanup84)" | \
        grep -v -E "(postgres|postgresql)")
    
    if [ -z "$IMAGE_LIST" ]; then
        echo -e "${GREEN}No threat-engine images found${NC}"
    else
        COUNT=$(echo "$IMAGE_LIST" | wc -l | tr -d ' ')
        echo -e "Found ${COUNT} image(s) to remove:"
        echo "$IMAGE_LIST" | while IFS='|' read -r IMAGE_ID IMAGE_NAME; do
            echo "  - $IMAGE_NAME ($IMAGE_ID)"
        done
        
        if [ "$DRY_RUN" = false ]; then
            IMAGE_IDS=$(echo "$IMAGE_LIST" | cut -d'|' -f1)
            echo "$IMAGE_IDS" | xargs -r docker rmi -f 2>/dev/null || true
            echo -e "${GREEN}✓ Images removed${NC}"
        else
            echo -e "${YELLOW}[DRY RUN] Would remove images${NC}"
        fi
    fi
    echo ""
}

# Function to clean up dangling images and build cache
cleanup_dangling() {
    echo -e "${YELLOW}Cleaning up dangling images and build cache...${NC}"
    
    if [ "$DRY_RUN" = false ]; then
        docker image prune -f
        docker builder prune -f --filter "until=24h"
        echo -e "${GREEN}✓ Dangling resources cleaned${NC}"
    else
        echo -e "${YELLOW}[DRY RUN] Would clean dangling resources${NC}"
    fi
    echo ""
}

# Function to show what will be kept
show_kept() {
    echo -e "${BLUE}PostgreSQL images/containers (KEPT):${NC}"
    
    POSTGRES_IMAGES=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -E "(postgres|postgresql)" || true)
    if [ -n "$POSTGRES_IMAGES" ]; then
        echo "$POSTGRES_IMAGES" | while read -r img; do
            echo "  ✓ $img"
        done
    else
        echo "  (none found)"
    fi
    
    POSTGRES_CONTAINERS=$(docker ps -a --format "{{.Names}}" | grep -E "(postgres|postgresql)" || true)
    if [ -n "$POSTGRES_CONTAINERS" ]; then
        echo "$POSTGRES_CONTAINERS" | while read -r cont; do
            echo "  ✓ $cont"
        done
    else
        echo "  (none found)"
    fi
    echo ""
}

# Main execution
show_kept

if [ "$DRY_RUN" = false ] && [ "$SKIP_CONFIRM" = false ]; then
    read -p "Continue with cleanup? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Cleanup cancelled${NC}"
        exit 0
    fi
fi

cleanup_containers
cleanup_images
cleanup_dangling

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Cleanup completed!${NC}"
echo -e "${GREEN}========================================${NC}"
