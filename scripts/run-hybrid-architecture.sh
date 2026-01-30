#!/bin/bash

# Hybrid Architecture Startup Script  
# Starts: API Gateway → Battle-tested Engines → Centralized Database
# Architecture: API Gateway + ConfigScan Engines + Centralized Database Management

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo -e "${CYAN}🚀 Starting Hybrid Architecture${NC}"
echo -e "${CYAN}==============================${NC}"
echo "Architecture: API Gateway → Battle-tested Engines → Centralized Database"
echo ""

# Function to check if a port is in use
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null; then
        echo -e "${YELLOW}⚠️  Port $port is already in use${NC}"
        return 1
    else
        return 0
    fi
}

# Function to wait for service to be ready
wait_for_service() {
    local url=$1
    local service_name=$2
    local max_attempts=15
    local attempt=1
    
    echo -e "${YELLOW}Waiting for $service_name to be ready...${NC}"
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q "200\|404"; then
            echo -e "${GREEN}✅ $service_name is ready${NC}"
            return 0
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    echo -e "${RED}❌ $service_name failed to start within expected time${NC}"
    return 1
}

# Check if database is ready (single-DB, engine_* schemas)
echo -e "${BLUE}Step 1: Checking Database${NC}"
echo "========================"

ok=$(psql -h localhost -p 5432 -U "$(whoami)" -d postgres -tAc "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='engine_configscan';" 2>/dev/null || echo "0")
if [ "${ok}" -ge 1 ]; then
    echo -e "${GREEN}✅ Database ready (single-DB, engine_* schemas)${NC}"
else
    echo -e "${RED}❌ Database not ready${NC}"
    echo "Run: psql -U \$(whoami) -d postgres -f scripts/init-databases.sql"
    exit 1
fi

# Check required ports
echo -e "\n${BLUE}Step 2: Checking Ports${NC}"
echo "======================"

REQUIRED_PORTS=(8000 8001 8002 8010)
for port in "${REQUIRED_PORTS[@]}"; do
    if ! check_port $port; then
        echo -e "${YELLOW}Attempting to free port $port...${NC}"
        lsof -ti:$port | xargs kill -9 2>/dev/null || true
        sleep 2
        if ! check_port $port; then
            echo -e "${RED}❌ Could not free port $port${NC}"
            exit 1
        fi
    fi
    echo -e "${GREEN}✅ Port $port is available${NC}"
done

# Start API Gateway
echo -e "\n${BLUE}Step 3: Starting API Gateway${NC}"
echo "============================"

cd "$PROJECT_ROOT/api_gateway"
echo -e "${YELLOW}Starting API Gateway on port 8000...${NC}"

export PORT=8000
export USE_CENTRALIZED_DB=true

nohup python3 main.py > api_gateway.log 2>&1 &
GATEWAY_PID=$!
echo -e "${GREEN}✅ API Gateway started (PID: $GATEWAY_PID)${NC}"

# Wait for API Gateway
wait_for_service "http://localhost:8000/" "API Gateway"

# Start ConfigScan AWS Engine  
echo -e "\n${BLUE}Step 4: Starting ConfigScan AWS Engine${NC}"
echo "======================================"

cd "$PROJECT_ROOT/engine_configscan/engine_configscan_aws"
echo -e "${YELLOW}Starting ConfigScan AWS Engine on port 8001...${NC}"

export PORT=8001
export USE_CENTRALIZED_DB=true
export CONFIGSCAN_DB_HOST=localhost
export CONFIGSCAN_DB_NAME=postgres
export CONFIGSCAN_DB_USER=postgres
export CONFIGSCAN_DB_PASSWORD=postgres
export DB_SCHEMA=engine_configscan,engine_shared

nohup python3 api_server.py > configscan_aws.log 2>&1 &
CONFIGSCAN_AWS_PID=$!
echo -e "${GREEN}✅ ConfigScan AWS Engine started (PID: $CONFIGSCAN_AWS_PID)${NC}"

# Wait for ConfigScan AWS
wait_for_service "http://localhost:8001/health" "ConfigScan AWS Engine" || echo -e "${YELLOW}⚠️  ConfigScan AWS might not have /health endpoint${NC}"

# Start Onboarding Engine  
echo -e "\n${BLUE}Step 5: Starting Onboarding Engine${NC}"
echo "=================================="

cd "$PROJECT_ROOT/engine_onboarding"
echo -e "${YELLOW}Starting Onboarding Engine on port 8010...${NC}"

export API_PORT=8010
export USE_CENTRALIZED_DB=true

nohup python3 main.py > onboarding.log 2>&1 &
ONBOARDING_PID=$!
echo -e "${GREEN}✅ Onboarding Engine started (PID: $ONBOARDING_PID)${NC}"

# Wait for Onboarding Engine
wait_for_service "http://localhost:8010/health" "Onboarding Engine"

# Test the hybrid architecture
echo -e "\n${BLUE}Step 6: Testing Hybrid Architecture${NC}"
echo "===================================="

sleep 3  # Let services settle
python3 "$PROJECT_ROOT/scripts/test-hybrid-architecture.py"

echo -e "\n${GREEN}🎉 Hybrid Architecture Started Successfully!${NC}"
echo -e "${GREEN}===========================================${NC}"
echo ""
echo -e "${BLUE}Service URLs:${NC}"
echo "• API Gateway:              http://localhost:8000"
echo "• ConfigScan AWS Engine:    http://localhost:8001" 
echo "• Onboarding Engine:        http://localhost:8010"
echo ""
echo -e "${BLUE}API Documentation:${NC}"
echo "• API Gateway:              http://localhost:8000/docs"
echo "• ConfigScan AWS:           http://localhost:8001/docs"
echo "• Onboarding:               http://localhost:8010/docs"
echo ""
echo -e "${BLUE}Gateway Endpoints:${NC}"
echo "• Service Status:           http://localhost:8000/gateway/health"
echo "• CSP Discovery:            http://localhost:8000/gateway/configscan/csps"
echo "• Unified ConfigScan:       http://localhost:8000/api/v1/configscan"
echo ""
echo -e "${BLUE}Database Info:${NC}"
echo "• Database (single-DB):     postgresql://postgres:postgres@localhost:5432/postgres (schemas: engine_configscan, ...)"
echo ""
echo -e "${BLUE}Process IDs:${NC}"
echo "• API Gateway PID:          $GATEWAY_PID"
echo "• ConfigScan AWS PID:       $CONFIGSCAN_AWS_PID" 
echo "• Onboarding PID:           $ONBOARDING_PID"
echo ""
echo -e "${BLUE}Log Files:${NC}"
echo "• API Gateway:              $PROJECT_ROOT/api_gateway/api_gateway.log"
echo "• ConfigScan AWS:           $PROJECT_ROOT/engine_configscan/engine_configscan_aws/configscan_aws.log"
echo "• Onboarding:               $PROJECT_ROOT/engine_onboarding/onboarding.log"
echo ""
echo -e "${BLUE}To stop all services:${NC}"
echo "kill $GATEWAY_PID $CONFIGSCAN_AWS_PID $ONBOARDING_PID"
echo ""
echo -e "${GREEN}✅ Hybrid architecture is ready for testing!${NC}"