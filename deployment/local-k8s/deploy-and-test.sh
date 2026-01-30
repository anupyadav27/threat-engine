#!/bin/bash
# Deploy engines one by one and test health/database connections
# Usage: ./deploy-and-test.sh [engine_name]

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Deploy and Test Engine${NC}"
echo -e "${BLUE}========================================${NC}\n"

ENGINE="${1:-onboarding}"

# Engine configurations
case $ENGINE in
    onboarding)
        DEPLOYMENT_FILE="onboarding-deployment.yaml"
        SERVICE_NAME="onboarding-service"
        NAMESPACE="threat-engine-local"
        PORT=30010
        HEALTH_PATH="/api/v1/health"
        ;;
    configscan|configscan-aws)
        DEPLOYMENT_FILE="configscan-aws-deployment.yaml"
        SERVICE_NAME="configscan-aws-service"
        NAMESPACE="threat-engine-local"
        PORT=30002
        HEALTH_PATH="/api/v1/health"
        ;;
    *)
        echo -e "${RED}Unknown engine: $ENGINE${NC}"
        echo "Available: onboarding, configscan"
        exit 1
        ;;
esac

echo -e "${YELLOW}Deploying: ${ENGINE}${NC}"
echo -e "Deployment file: ${DEPLOYMENT_FILE}"
echo -e "Service: ${SERVICE_NAME}"
echo ""

# Check if namespace exists
if ! kubectl get namespace "$NAMESPACE" > /dev/null 2>&1; then
    echo -e "${YELLOW}Creating namespace...${NC}"
    kubectl create namespace "$NAMESPACE"
fi

# Apply deployment
echo -e "${YELLOW}Applying deployment...${NC}"
kubectl apply -f "${SCRIPT_DIR}/${DEPLOYMENT_FILE}"

# Wait for deployment
echo -e "${YELLOW}Waiting for deployment to be ready...${NC}"
kubectl wait --for=condition=available --timeout=300s deployment/${SERVICE_NAME} -n ${NAMESPACE} || {
    echo -e "${RED}Deployment failed to become ready${NC}"
    echo "Checking pod status:"
    kubectl get pods -n ${NAMESPACE} -l app=${SERVICE_NAME}
    kubectl describe pod -n ${NAMESPACE} -l app=${SERVICE_NAME} | tail -30
    exit 1
}

echo -e "${GREEN}✓ Deployment ready${NC}\n"

# Get pod name
POD_NAME=$(kubectl get pods -n ${NAMESPACE} -l app=${SERVICE_NAME} -o jsonpath='{.items[0].metadata.name}')

if [ -z "$POD_NAME" ]; then
    echo -e "${RED}✗ Pod not found${NC}"
    exit 1
fi

echo -e "${BLUE}Pod: ${POD_NAME}${NC}\n"

# Wait a bit for service to start
echo -e "${YELLOW}Waiting for service to start...${NC}"
sleep 10

# Check health endpoint
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}1. Health Check${NC}"
echo -e "${BLUE}========================================${NC}\n"

HEALTH_URL="http://localhost:${PORT}${HEALTH_PATH}"
echo -e "Checking: ${HEALTH_URL}"

for i in {1..10}; do
    if curl -s -f "${HEALTH_URL}" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Health endpoint responding${NC}"
        HEALTH_RESPONSE=$(curl -s "${HEALTH_URL}" | python3 -m json.tool 2>/dev/null || curl -s "${HEALTH_URL}")
        echo -e "\n${YELLOW}Health Response:${NC}"
        echo "$HEALTH_RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$HEALTH_RESPONSE"
        break
    else
        if [ $i -eq 10 ]; then
            echo -e "${RED}✗ Health endpoint not responding after 10 attempts${NC}"
            echo "Checking pod logs:"
            kubectl logs -n ${NAMESPACE} ${POD_NAME} --tail=20
            exit 1
        fi
        echo -e "${YELLOW}Waiting... (attempt $i/10)${NC}"
        sleep 5
    fi
done

echo ""

# Check database connection from pod
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}2. Database Connection Check${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${YELLOW}Testing database connection from pod...${NC}"

# Test database connectivity
DB_TEST=$(kubectl exec -n ${NAMESPACE} ${POD_NAME} -- python3 -c "
import os
import sys
try:
    if '${ENGINE}' == 'onboarding':
        from engine_onboarding.database.connection import check_connection, get_database_config
        from engine_onboarding.database.connection.database_config import get_shared_config
        config = get_shared_config()
        result = check_connection()
        print(f'Database: {config.database}')
        print(f'Host: {config.host}')
        print(f'Connection: {\"OK\" if result else \"FAILED\"}')
    elif '${ENGINE}' == 'configscan' or '${ENGINE}' == 'configscan-aws':
        from database.connection.database_config import get_configscan_config
        import psycopg2
        config = get_configscan_config()
        conn = psycopg2.connect(
            host=config.host,
            port=config.port,
            database=config.database,
            user=config.username,
            password=config.password
        )
        conn.close()
        print(f'Database: {config.database}')
        print(f'Host: {config.host}')
        print(f'Connection: OK')
    sys.exit(0)
except Exception as e:
    print(f'Error: {str(e)}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
" 2>&1)

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✓ Database connection successful${NC}"
    echo "$DB_TEST"
else
    echo -e "${RED}✗ Database connection failed${NC}"
    echo "$DB_TEST"
    echo ""
    echo "Checking pod logs:"
    kubectl logs -n ${NAMESPACE} ${POD_NAME} --tail=30
    exit 1
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}✓ ${ENGINE} engine deployed and verified!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Service URL: http://localhost:${PORT}"
echo "Health: http://localhost:${PORT}${HEALTH_PATH}"
echo ""
echo "Next: Test individual endpoints or deploy next engine"
