#!/bin/bash
# Complete workflow: Cleanup Docker, Build and Push all engines to DockerHub
# Usage: ./cleanup-and-build.sh [DOCKERHUB_USERNAME] [TAG]

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Complete Workflow${NC}"
echo -e "${BLUE}1. Cleanup Docker (keep PostgreSQL)${NC}"
echo -e "${BLUE}2. Build all engine images${NC}"
echo -e "${BLUE}3. Push to DockerHub${NC}"
echo -e "${BLUE}========================================${NC}\n"

# Step 1: Cleanup
echo -e "${YELLOW}Step 1: Cleaning up Docker...${NC}"
"$SCRIPT_DIR/cleanup-docker.sh"

# Step 2: Build and Push
echo -e "\n${YELLOW}Step 2: Building and pushing images...${NC}"
"$SCRIPT_DIR/build-and-push-dockerhub.sh" "$@"

echo -e "\n${GREEN}========================================${NC}"
echo -e "${GREEN}All done!${NC}"
echo -e "${GREEN}========================================${NC}"
