#!/bin/bash
#
# Run ConfigScan Service Locally
# Sets up environment and starts the consolidated ConfigScan service
#

set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." &> /dev/null && pwd)"
CONFIGSCAN_DIR="${PROJECT_ROOT}/consolidated_services/configscan_service"

echo -e "${BLUE}Starting ConfigScan Service Locally${NC}"
echo "Project Root: ${PROJECT_ROOT}"
echo "Service Directory: ${CONFIGSCAN_DIR}"
echo ""

# Function to check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}Python 3 is required but not installed${NC}"
        exit 1
    fi
    
    # Check PostgreSQL
    if ! command -v psql &> /dev/null; then
        echo -e "${RED}PostgreSQL client (psql) is required but not installed${NC}"
        exit 1
    fi
    
    # Check if PostgreSQL is running
    if ! pg_isready -h localhost -p 5432 &> /dev/null; then
        echo -e "${RED}PostgreSQL server is not running on localhost:5432${NC}"
        echo "Start PostgreSQL with: brew services start postgresql"
        echo "Please start PostgreSQL first"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Prerequisites check passed${NC}"
}

# Function to setup database (single-DB, engine_* schemas)
setup_database() {
    echo -e "${YELLOW}Setting up database (init-databases)...${NC}"
    
    local db_script="${PROJECT_ROOT}/scripts/init-databases.sql"
    
    if [ ! -f "$db_script" ]; then
        echo -e "${RED}Database setup script not found: $db_script${NC}"
        exit 1
    fi
    
    if psql -U "$(whoami)" -d postgres -f "$db_script" -v ON_ERROR_STOP=1; then
        echo -e "${GREEN}✓ Database setup completed (single-DB, engine_* schemas)${NC}"
    else
        echo -e "${RED}✗ Database setup failed${NC}"
        exit 1
    fi
}

# Function to install dependencies
install_dependencies() {
    echo -e "${YELLOW}Installing service dependencies...${NC}"
    
    cd "${CONFIGSCAN_DIR}"
    
    if [ ! -f "requirements.txt" ]; then
        echo -e "${RED}requirements.txt not found in ${CONFIGSCAN_DIR}${NC}"
        exit 1
    fi
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        echo "Creating virtual environment..."
        python3 -m venv venv
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Install dependencies
    pip install --upgrade pip
    pip install -r requirements.txt
    
    # Install additional development dependencies
    pip install python-dotenv uvicorn[standard]
    
    echo -e "${GREEN}✓ Dependencies installed${NC}"
}

# Function to setup environment
setup_environment() {
    echo -e "${YELLOW}Setting up environment variables...${NC}"
    
    cd "${CONFIGSCAN_DIR}"
    
    # Create .env file
    cat > .env << EOF
# ConfigScan Service Local Environment (single-DB)
# Database Configuration — postgres DB, engine_configscan schema
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres
DB_SCHEMA=engine_configscan,engine_shared

# Service Configuration
PORT=8002
HOST=0.0.0.0
ENVIRONMENT=development
LOG_LEVEL=DEBUG

# CSP Configuration
AWS_REGION=us-east-1
# AWS_ACCESS_KEY_ID=your-access-key  # Add your AWS credentials if testing real scans
# AWS_SECRET_ACCESS_KEY=your-secret-key

# Azure Configuration
# AZURE_SUBSCRIPTION_ID=your-subscription-id
# AZURE_TENANT_ID=your-tenant-id
# AZURE_CLIENT_ID=your-client-id
# AZURE_CLIENT_SECRET=your-client-secret

# GCP Configuration  
# GOOGLE_APPLICATION_CREDENTIALS=/path/to/credentials.json
# GCP_PROJECT_ID=your-project-id

# Scanner Configuration
MAX_CONCURRENT_SCANS=3
SCAN_TIMEOUT_SECONDS=3600
ENABLE_DRIFT_DETECTION=true

# Output Configuration
SCAN_RESULTS_DIR=${PROJECT_ROOT}/scan_results
ENABLE_RESULT_CACHING=true

# Monitoring
PROMETHEUS_ENABLED=false
METRICS_PORT=9002
EOF
    
    echo -e "${GREEN}✓ Environment configuration created (.env file)${NC}"
}

# Function to create output directories
setup_directories() {
    echo -e "${YELLOW}Creating output directories...${NC}"
    
    mkdir -p "${PROJECT_ROOT}/scan_results"
    mkdir -p "${PROJECT_ROOT}/logs"
    
    echo -e "${GREEN}✓ Directories created${NC}"
}

# Function to check database connection (single-DB, engine_* schemas)
test_database_connection() {
    echo -e "${YELLOW}Testing database connection...${NC}"
    
    local ok
    ok=$(psql -h localhost -p 5432 -U "$(whoami)" -d postgres -tAc "SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name='engine_configscan';" 2>/dev/null || echo "0")
    if [ "${ok}" -ge 1 ]; then
        echo -e "${GREEN}✓ Database connection successful (single-DB)${NC}"
        echo -e "${BLUE}Database Info:${NC}"
        psql -h localhost -p 5432 -U "$(whoami)" -d postgres -c "
            SELECT 'engine_shared.customers' AS table_name, COUNT(*) AS record_count FROM engine_shared.customers
            UNION ALL SELECT 'engine_shared.tenants', COUNT(*) FROM engine_shared.tenants
            UNION ALL SELECT 'engine_configscan.csp_hierarchies', COUNT(*) FROM engine_configscan.csp_hierarchies
            UNION ALL SELECT 'engine_configscan.scans', COUNT(*) FROM engine_configscan.scans;
        " 2>/dev/null || echo "  (No test data yet)"
    else
        echo -e "${RED}✗ Database connection failed or engine_* schemas missing${NC}"
        echo "Run: psql -U \$(whoami) -d postgres -f scripts/init-databases.sql"
        exit 1
    fi
}

# Function to start the service
start_service() {
    echo -e "${YELLOW}Starting ConfigScan service...${NC}"
    
    cd "${CONFIGSCAN_DIR}"
    
    # Activate virtual environment
    source venv/bin/activate
    
    echo ""
    echo -e "${GREEN}🚀 ConfigScan Service Starting...${NC}"
    echo ""
    echo -e "${BLUE}Service URL: http://localhost:8002${NC}"
    echo -e "${BLUE}Health Check: http://localhost:8002/health${NC}"
    echo -e "${BLUE}API Docs: http://localhost:8002/docs${NC}"
    echo ""
    echo -e "${YELLOW}Press Ctrl+C to stop${NC}"
    echo ""
    
    # Start the service with auto-reload for development
    python -c "
import os
from dotenv import load_dotenv
load_dotenv()

import uvicorn
uvicorn.run(
    'main:app',
    host=os.getenv('HOST', '0.0.0.0'),
    port=int(os.getenv('PORT', 8002)),
    reload=True,
    reload_dirs=['.'],
    log_level=os.getenv('LOG_LEVEL', 'info').lower()
)
"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  setup    - Set up database and environment (run first time)"
    echo "  start    - Start the ConfigScan service"
    echo "  test-db  - Test database connection only"
    echo "  reset-db - Reset the database (drops and recreates)"
    echo "  help     - Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 setup    # First time setup"
    echo "  $0 start    # Start the service"
    echo "  $0 test-db  # Test database connection"
}

# Function to reset database
reset_database() {
    echo -e "${YELLOW}Resetting ConfigScan database...${NC}"
    echo -e "${RED}This will delete ALL data in the database!${NC}"
    
    read -p "Are you sure? (yes/no): " confirm
    if [ "$confirm" != "yes" ]; then
        echo "Database reset cancelled"
        exit 0
    fi
    
    setup_database
    echo -e "${GREEN}✓ Database reset completed${NC}"
}

# Main function
main() {
    case "${1:-start}" in
        "setup")
            check_prerequisites
            setup_database
            install_dependencies
            setup_environment
            setup_directories
            test_database_connection
            echo ""
            echo -e "${GREEN}🎉 ConfigScan service setup completed!${NC}"
            echo ""
            echo "Next steps:"
            echo "  1. Review .env file in ${CONFIGSCAN_DIR}/.env"
            echo "  2. Add your CSP credentials if testing real scans"
            echo "  3. Run: $0 start"
            ;;
        "start")
            check_prerequisites
            test_database_connection
            start_service
            ;;
        "test-db")
            check_prerequisites
            test_database_connection
            ;;
        "reset-db")
            check_prerequisites
            reset_database
            ;;
        "help"|"-h"|"--help")
            show_usage
            ;;
        *)
            echo -e "${RED}Unknown command: $1${NC}"
            show_usage
            exit 1
            ;;
    esac
}

# Run main function
main "$@"