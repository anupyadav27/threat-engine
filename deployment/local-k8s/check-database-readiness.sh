#!/bin/bash
# Check single-DB setup: postgres reachable and engine_* schemas exist.

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$PROJECT_ROOT"

echo -e "${BLUE}Database Readiness Check (single-DB)${NC}"
echo ""

if ! psql -h localhost -p 5432 -U "$(whoami)" -d postgres -c "SELECT 1;" > /dev/null 2>&1; then
    echo -e "${RED}✗ Cannot connect to PostgreSQL (localhost:5432)${NC}"
    exit 1
fi
echo -e "${GREEN}✓ PostgreSQL reachable${NC}"

SCHEMAS=$(psql -h localhost -p 5432 -U "$(whoami)" -d postgres -tAc "
  SELECT COUNT(*) FROM information_schema.schemata
  WHERE schema_name IN ('engine_shared','engine_configscan','engine_compliance','engine_inventory','engine_threat');
" 2>/dev/null || echo "0")

if [ "${SCHEMAS}" -ge "5" ]; then
    echo -e "${GREEN}✓ engine_* schemas present${NC}"
else
    echo -e "${YELLOW}⚠ engine_* schemas missing or incomplete. Run: psql -U \$(whoami) -d postgres -f scripts/init-databases.sql${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}✓ Database ready.${NC}"
