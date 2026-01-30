#!/bin/bash
# Access services locally - Sets up port forwarding for all engines

set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Setting up port forwarding for services...${NC}"
echo ""

# Kill existing port forwards
pkill -f "kubectl port-forward" 2>/dev/null || true
sleep 2

# Port forwarding mappings
declare -a SERVICES=(
    "onboarding-external:30010:8010:Onboarding"
    "configscan-aws-external:30002:8002:ConfigScan AWS"
)

echo "Starting port forwards..."
for SERVICE_SPEC in "${SERVICES[@]}"; do
    IFS=':' read -r SERVICE_NAME LOCAL_PORT REMOTE_PORT SERVICE_LABEL <<< "$SERVICE_SPEC"
    
    echo -e "${YELLOW}Forwarding ${SERVICE_LABEL}: localhost:${LOCAL_PORT} -> ${SERVICE_NAME}:${REMOTE_PORT}${NC}"
    kubectl port-forward -n threat-engine-local svc/${SERVICE_NAME} ${LOCAL_PORT}:${REMOTE_PORT} > /dev/null 2>&1 &
    sleep 1
done

echo ""
echo -e "${GREEN}Port forwarding active!${NC}"
echo ""
echo "Services available at:"
echo "  - Onboarding: http://localhost:30010/api/v1/health"
echo "  - ConfigScan AWS: http://localhost:30002/api/v1/health"
echo ""
echo "Press Ctrl+C to stop port forwarding"
echo ""

# Wait for interrupt
trap "pkill -f 'kubectl port-forward'; exit" INT TERM
wait
