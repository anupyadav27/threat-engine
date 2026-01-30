#!/bin/bash

# Complete Flow Setup Script
# Sets up and runs: Database -> Onboarding Engine -> Enhanced ConfigScan Service
# For end-to-end testing of the complete workflow

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPTS_DIR="${PROJECT_ROOT}/scripts"

echo -e "${BLUE}🚀 Starting Complete Flow Setup${NC}"
echo -e "${BLUE}=================================${NC}"
echo "Project Root: $PROJECT_ROOT"

# Function to check if a command exists
check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo -e "${RED}✗ $1 is not installed${NC}"
        exit 1
    else
        echo -e "${GREEN}✓ $1 is available${NC}"
    fi
}

# Function to check if a port is in use
check_port() {
    local port=$1
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null; then
        echo -e "${YELLOW}⚠️  Port $port is already in use${NC}"
        return 1
    else
        echo -e "${GREEN}✓ Port $port is available${NC}"
        return 0
    fi
}

# Function to wait for service to be ready
wait_for_service() {
    local url=$1
    local service_name=$2
    local max_attempts=30
    local attempt=1
    
    echo -e "${YELLOW}Waiting for $service_name to be ready...${NC}"
    
    while [ $attempt -le $max_attempts ]; do
        if curl -s -o /dev/null -w "%{http_code}" "$url" | grep -q "200\|404"; then
            echo -e "${GREEN}✓ $service_name is ready${NC}"
            return 0
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    echo -e "${RED}✗ $service_name failed to start within expected time${NC}"
    return 1
}

echo -e "\n${BLUE}Step 1: Checking Prerequisites${NC}"
echo "==============================="

# Check required commands
check_command "python3"
check_command "pip3"
check_command "psql"
check_command "curl"

# Check Python version
PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${GREEN}✓ Python version: $PYTHON_VERSION${NC}"

# Check PostgreSQL connection
if psql -U "$(whoami)" -d postgres -c "SELECT 1" &>/dev/null; then
    echo -e "${GREEN}✓ PostgreSQL connection successful${NC}"
else
    echo -e "${RED}✗ PostgreSQL connection failed${NC}"
    echo "Please ensure PostgreSQL is running and user '$(whoami)' can connect"
    exit 1
fi

# Check required ports
REQUIRED_PORTS=(8005 8002)
for port in "${REQUIRED_PORTS[@]}"; do
    if ! check_port $port; then
        echo -e "${YELLOW}⚠️  Attempting to kill processes on port $port${NC}"
        lsof -ti:$port | xargs kill -9 2>/dev/null || true
        sleep 2
        if ! check_port $port; then
            echo -e "${RED}✗ Could not free port $port${NC}"
            exit 1
        fi
    fi
done

echo -e "\n${BLUE}Step 2: Setting Up Database (single-DB)${NC}"
echo "=========================================="

echo -e "${YELLOW}Running init-databases.sql...${NC}"
if psql -U "$(whoami)" -d postgres -f "$SCRIPTS_DIR/init-databases.sql" -v ON_ERROR_STOP=1; then
    echo -e "${GREEN}✓ Database setup completed (engine_* schemas)${NC}"
else
    echo -e "${RED}✗ Database setup failed${NC}"
    exit 1
fi

echo -e "${YELLOW}Testing database connectivity...${NC}"
ok=$(psql -h localhost -p 5432 -U "$(whoami)" -d postgres -tAc "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='engine_configscan';" 2>/dev/null || echo "0")
if [ "${ok}" -ge 1 ]; then
    echo -e "${GREEN}✓ Database connection test successful${NC}"
else
    echo -e "${RED}✗ Database connection test failed${NC}"
    exit 1
fi

echo -e "\n${BLUE}Step 3: Setting Up Onboarding Engine${NC}"
echo "===================================="

# Setup onboarding engine virtual environment
ONBOARDING_VENV_DIR="${PROJECT_ROOT}/engine_onboarding/venv"
if [ ! -d "$ONBOARDING_VENV_DIR" ]; then
    echo -e "${YELLOW}Creating onboarding engine virtual environment...${NC}"
    cd "${PROJECT_ROOT}/engine_onboarding"
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}✓ Virtual environment exists${NC}"
fi

# Install onboarding engine dependencies
echo -e "${YELLOW}Installing onboarding engine dependencies...${NC}"
cd "${PROJECT_ROOT}/engine_onboarding"
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo -e "${GREEN}✓ Onboarding engine dependencies installed${NC}"

# Set up onboarding engine (single-DB: postgres, engine_onboarding schema)
echo -e "${YELLOW}Setting up onboarding engine database...${NC}"
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/postgres"
export DB_SCHEMA="engine_onboarding,engine_shared"

echo -e "${GREEN}✓ Onboarding engine database ready (single-DB)${NC}"

echo -e "\n${BLUE}Step 4: Setting Up Enhanced ConfigScan Service${NC}"
echo "=============================================="

# Setup ConfigScan service virtual environment
CONFIGSCAN_VENV_DIR="${PROJECT_ROOT}/consolidated_services/configscan_service/venv"
if [ ! -d "$CONFIGSCAN_VENV_DIR" ]; then
    echo -e "${YELLOW}Creating ConfigScan service virtual environment...${NC}"
    cd "${PROJECT_ROOT}/consolidated_services/configscan_service"
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}✓ Virtual environment exists${NC}"
fi

# Install ConfigScan service dependencies
echo -e "${YELLOW}Installing ConfigScan service dependencies...${NC}"
cd "${PROJECT_ROOT}/consolidated_services/configscan_service"
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
echo -e "${GREEN}✓ ConfigScan service dependencies installed${NC}"

echo -e "\n${BLUE}Step 5: Starting Services${NC}"
echo "========================="

# Start onboarding engine
echo -e "${YELLOW}Starting Onboarding Engine on port 8005...${NC}"
cd "${PROJECT_ROOT}/engine_onboarding"
source venv/bin/activate
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/postgres"
export DB_SCHEMA="engine_onboarding,engine_shared"
export API_PORT=8005

nohup python -m uvicorn main:app --host 0.0.0.0 --port 8005 > onboarding.log 2>&1 &
ONBOARDING_PID=$!
echo -e "${GREEN}✓ Onboarding Engine started (PID: $ONBOARDING_PID)${NC}"

# Wait for onboarding engine to be ready
wait_for_service "http://localhost:8005/health" "Onboarding Engine"

# Start enhanced ConfigScan service
echo -e "${YELLOW}Starting Enhanced ConfigScan Service on port 8002...${NC}"
cd "${PROJECT_ROOT}/consolidated_services/configscan_service"
source venv/bin/activate
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/postgres"
export DB_SCHEMA="engine_configscan,engine_shared"
export PORT=8002
export ONBOARDING_ENGINE_URL="http://localhost:8005"

nohup python main_enhanced.py > configscan.log 2>&1 &
CONFIGSCAN_PID=$!
echo -e "${GREEN}✓ Enhanced ConfigScan Service started (PID: $CONFIGSCAN_PID)${NC}"

# Wait for ConfigScan service to be ready
wait_for_service "http://localhost:8002/health" "Enhanced ConfigScan Service"

echo -e "\n${BLUE}Step 6: Testing Service Integration${NC}"
echo "==================================="

# Test onboarding engine health
echo -e "${YELLOW}Testing Onboarding Engine...${NC}"
if curl -s http://localhost:8005/health | python3 -c "import sys, json; data=json.load(sys.stdin); print(f'Status: {data.get(\"status\", \"unknown\")}')"; then
    echo -e "${GREEN}✓ Onboarding Engine health check passed${NC}"
else
    echo -e "${RED}✗ Onboarding Engine health check failed${NC}"
fi

# Test ConfigScan service health
echo -e "${YELLOW}Testing Enhanced ConfigScan Service...${NC}"
if curl -s http://localhost:8002/health | python3 -c "import sys, json; data=json.load(sys.stdin); print(f'Status: {data.get(\"status\", \"unknown\")}')"; then
    echo -e "${GREEN}✓ Enhanced ConfigScan Service health check passed${NC}"
else
    echo -e "${RED}✗ Enhanced ConfigScan Service health check failed${NC}"
fi

# Test CSP availability
echo -e "${YELLOW}Testing CSP availability...${NC}"
curl -s http://localhost:8002/csps | python3 -c "
import sys, json
data = json.load(sys.stdin)
csps = data.get('csps', {})
print(f'Available CSPs: {len([csp for csp, info in csps.items() if info.get(\"available\")])}/{len(csps)}')
for csp, info in csps.items():
    status = '✓' if info.get('available') else '✗'
    print(f'  {status} {csp.upper()}: {info.get(\"services\", 0)} services, {info.get(\"regions\", 0)} regions')
"

echo -e "\n${GREEN}🎉 Complete Flow Setup Completed Successfully!${NC}"
echo -e "${GREEN}=============================================${NC}"
echo ""
echo -e "${BLUE}Service URLs:${NC}"
echo "• Onboarding Engine:       http://localhost:8005"
echo "• Enhanced ConfigScan:     http://localhost:8002"
echo "• API Documentation:"
echo "  - Onboarding:            http://localhost:8005/docs"
echo "  - ConfigScan:            http://localhost:8002/docs"
echo ""
echo -e "${BLUE}Log Files:${NC}"
echo "• Onboarding Engine:       ${PROJECT_ROOT}/engine_onboarding/onboarding.log"
echo "• ConfigScan Service:      ${PROJECT_ROOT}/consolidated_services/configscan_service/configscan.log"
echo ""
echo -e "${BLUE}Database Info (single-DB):${NC}"
echo "• Database:                postgresql://postgres:postgres@localhost:5432/postgres"
echo "• Schemas:                 engine_configscan, engine_onboarding, engine_shared, ..."
echo ""
echo -e "${BLUE}Process IDs:${NC}"
echo "• Onboarding Engine PID:   $ONBOARDING_PID"
echo "• ConfigScan Service PID:  $CONFIGSCAN_PID"
echo ""
echo -e "${BLUE}To stop services:${NC}"
echo "kill $ONBOARDING_PID $CONFIGSCAN_PID"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Test tenant onboarding: POST http://localhost:8005/api/v1/tenants"
echo "2. Test credential storage: POST http://localhost:8005/api/v1/credentials"  
echo "3. Test ConfigScan with tenant credentials: POST http://localhost:8002/api/v1/scans"
echo "4. Monitor logs for any issues"
echo ""
echo -e "${GREEN}✅ Ready for end-to-end testing!${NC}"