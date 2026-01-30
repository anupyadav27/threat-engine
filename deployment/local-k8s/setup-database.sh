#!/bin/bash
# Setup local PostgreSQL for Threat Engine (single-DB layout)
# Runs scripts/init-databases.sql to create engine_* schemas in postgres.

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INIT_SQL="${PROJECT_ROOT}/scripts/init-databases.sql"

cd "$PROJECT_ROOT"

echo -e "${GREEN}Setting up local PostgreSQL (single DB)...${NC}"
echo ""

if ! command -v psql &> /dev/null; then
    echo -e "${RED}Error: psql not found. Please install PostgreSQL.${NC}"
    exit 1
fi

if ! psql -h localhost -p 5432 -U "$(whoami)" -d postgres -c "SELECT 1;" > /dev/null 2>&1; then
    echo -e "${YELLOW}Warning: Cannot connect to PostgreSQL.${NC}"
    echo "Ensure PostgreSQL is running on localhost:5432."
    exit 1
fi

if [ ! -f "$INIT_SQL" ]; then
    echo -e "${RED}Error: Init script not found: ${INIT_SQL}${NC}"
    exit 1
fi

echo -e "${GREEN}Running init-databases.sql...${NC}"
if psql -h localhost -p 5432 -U "$(whoami)" -d postgres -f "$INIT_SQL" -v ON_ERROR_STOP=1; then
    echo ""
    echo -e "${GREEN}✓ Single-DB setup completed.${NC}"
    echo "  Database: postgres (schemas: engine_shared, engine_configscan, engine_compliance, engine_inventory, engine_threat, ...)"
    echo ""
    echo "Next: deploy engines, e.g. kubectl apply -f deployment/local-k8s/"
else
    echo -e "${RED}✗ Init failed. Check errors above.${NC}"
    exit 1
fi
