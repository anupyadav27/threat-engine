#!/bin/bash

# Centralized Database Management Demo Script
# Demonstrates the benefits of the new consolidated database architecture

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

echo -e "${CYAN}🏗️  Centralized Database Management Demo${NC}"
echo -e "${CYAN}=======================================${NC}"
echo ""
echo "This demo shows the benefits of the new centralized database architecture"
echo "vs the scattered approach across individual engines."
echo ""

# Function to print section headers
print_section() {
    echo -e "\n${BLUE}$1${NC}"
    echo -e "${BLUE}$(printf '=%.0s' $(seq 1 ${#1}))${NC}"
}

# Function to print comparison
print_comparison() {
    echo -e "${RED}❌ Before (Scattered):${NC} $1"
    echo -e "${GREEN}✅ After (Centralized):${NC} $2"
    echo ""
}

print_section "1. Database File Organization"

echo -e "${YELLOW}Previous scattered approach:${NC}"
echo "📁 engine_configscan/engine_configscan_aws/database/"
echo "📁 engine_configscan/engine_configscan_azure/database/" 
echo "📁 engine_configscan/engine_configscan_gcp/database/"
echo "📁 engine_compliance/database/"
echo "📁 engine_inventory/database/"
echo "📁 engine_threat/database/"
echo "📁 scripts/ (random database files)"
echo ""

echo -e "${GREEN}New centralized structure:${NC}"
echo "📁 consolidated_services/database/"
echo "  ├── 📄 README.md                    # Central documentation"
echo "  ├── 📁 schemas/                     # All schemas in one place"
echo "  │   ├── 📄 configscan_schema.sql   # From proven engine_configscan_aws"
echo "  │   ├── 📄 compliance_schema.sql   # Consolidated compliance schema"
echo "  │   ├── 📄 inventory_schema.sql    # Consolidated inventory schema"
echo "  │   ├── 📄 threat_schema.sql       # Consolidated threat schema"
echo "  │   └── 📄 shared_schema.sql       # Cross-engine shared tables"
echo "  ├── 📁 connections/                # Unified connection management"
echo "  │   ├── 📄 connection_factory.py   # Single entry point for all DBs"
echo "  │   ├── 📄 postgres_connection.py  # Optimized PostgreSQL handling"
echo "  │   └── 📄 connection_pool.py      # Shared connection pooling"
echo "  ├── 📁 config/                     # Centralized configuration"
echo "  │   └── 📄 database_config.py      # All DB configs in one place"
echo "  └── 📁 migrations/                 # Unified migration management"
echo "      └── 📄 migration_runner.py     # Single migration tool"
echo ""

print_comparison \
    "Database files scattered across 6+ locations, hard to find and maintain" \
    "All database files centralized in one location with clear organization"

print_section "2. Connection Management Comparison"

echo -e "${RED}❌ Previous approach (scattered connections):${NC}"
echo "• Each engine has its own database connection logic"
echo "• Duplicated connection code across engines"  
echo "• Inconsistent connection pooling"
echo "• Different error handling approaches"
echo "• Hard to monitor and debug connection issues"
echo ""

echo -e "${GREEN}✅ New centralized approach:${NC}"
echo "• Single connection factory for all engines"
echo "• Shared connection pooling across all services"
echo "• Consistent error handling and logging"
echo "• Easy monitoring and health checks"
echo "• Optimized performance with proper pooling"
echo ""

print_section "3. Configuration Management Benefits"

echo -e "${YELLOW}Example: Getting a database connection${NC}"
echo ""

echo -e "${RED}Before (scattered):${NC}"
echo 'import psycopg2'
echo 'import os'
echo 'def get_db_connection():'
echo '    return psycopg2.connect('
echo '        host=os.getenv("CONFIGSCAN_DB_HOST", "localhost"),'
echo '        database=os.getenv("CONFIGSCAN_DB_NAME", "configscan"),'
echo '        user=os.getenv("CONFIGSCAN_DB_USER", "user"),'
echo '        password=os.getenv("CONFIGSCAN_DB_PASS", "pass")'
echo '    )'
echo ""

echo -e "${GREEN}After (centralized):${NC}"
echo 'from consolidated_services.database import get_configscan_connection'
echo ''
echo 'async def my_function():'
echo '    async with get_configscan_connection() as db:'
echo '        result = await db.fetch_all("SELECT * FROM scans")'
echo '        return result'
echo ""

print_comparison \
    "Each engine reimplements database connection logic" \
    "Single import provides optimized, pooled connections"

print_section "4. Schema Management Benefits"

echo -e "${YELLOW}Using the proven schema from engine_configscan_aws:${NC}"

# Show that we're using the original, battle-tested schema
if [ -f "$PROJECT_ROOT/consolidated_services/database/schemas/configscan_schema.sql" ]; then
    echo -e "${GREEN}✅ Copied proven schema:${NC}"
    echo "   Original: engine_configscan/engine_configscan_aws/database/schema.sql"
    echo "   Centralized: consolidated_services/database/schemas/configscan_schema.sql"
    
    # Show line counts to prove it's comprehensive
    original_lines=$(wc -l < "$PROJECT_ROOT/engine_configscan/engine_configscan_aws/database/schema.sql")
    centralized_lines=$(wc -l < "$PROJECT_ROOT/consolidated_services/database/schemas/configscan_schema.sql")
    
    echo "   Lines: $original_lines (original) = $centralized_lines (centralized)"
    echo ""
    
    echo -e "${GREEN}Schema includes:${NC}"
    grep -E "CREATE TABLE.*(" "$PROJECT_ROOT/consolidated_services/database/schemas/configscan_schema.sql" | \
        sed 's/CREATE TABLE IF NOT EXISTS /• /' | \
        sed 's/ (.*$//' | \
        head -10
else
    echo -e "${RED}❌ Schema not found${NC}"
fi

print_section "5. Migration Management"

echo -e "${YELLOW}Centralized migration runner:${NC}"
echo ""

echo -e "${GREEN}Single command to manage all databases:${NC}"
echo "# Initialize specific engine"
echo "python -m consolidated_services.database.migrations.migration_runner --engine configscan"
echo ""
echo "# Initialize all engines"
echo "python -m consolidated_services.database.migrations.migration_runner --engine all"
echo ""
echo "# Check migration status"
echo "python -m consolidated_services.database.migrations.migration_runner --status"
echo ""
echo "# Check database connections"
echo "python -m consolidated_services.database.migrations.migration_runner --check-connections"

print_section "6. Real Benefits Demonstration"

echo -e "${YELLOW}Let's show the practical benefits:${NC}"
echo ""

# Check if the centralized structure exists
if [ -d "$PROJECT_ROOT/consolidated_services/database" ]; then
    echo -e "${GREEN}✅ Centralized database structure created${NC}"
    
    # Count files in centralized vs scattered
    centralized_files=$(find "$PROJECT_ROOT/consolidated_services/database" -name "*.py" -o -name "*.sql" | wc -l)
    scattered_files=$(find "$PROJECT_ROOT" -path "*/engine_*/database/*" -name "*.py" -o -name "*.sql" 2>/dev/null | wc -l)
    
    echo "   Centralized files: $centralized_files"
    echo "   Previously scattered files: $scattered_files"
    echo ""
    
    echo -e "${GREEN}Directory structure:${NC}"
    tree "$PROJECT_ROOT/consolidated_services/database" -I "__pycache__" 2>/dev/null || \
        find "$PROJECT_ROOT/consolidated_services/database" -type d | sed 's/^/  /'
else
    echo -e "${RED}❌ Centralized structure not found${NC}"
fi

print_section "7. Developer Experience Improvements"

echo -e "${YELLOW}How this improves developer workflow:${NC}"
echo ""

print_comparison \
    "Developer needs to find database files across multiple engine directories" \
    "Developer goes to one place: consolidated_services/database/"

print_comparison \
    "Each engine has different connection patterns and configurations" \
    "Single, consistent API across all engines and services"

print_comparison \
    "Database issues require debugging across multiple engines" \
    "Centralized logging and monitoring for all database operations"

print_comparison \
    "Adding new engine requires implementing database logic from scratch" \
    "New engines automatically get optimized database connectivity"

print_section "8. Production Benefits"

echo -e "${GREEN}Performance Benefits:${NC}"
echo "• Shared connection pooling reduces overall database connections"
echo "• Optimized query patterns across all engines"
echo "• Centralized monitoring and performance metrics"
echo "• Easier database optimization and tuning"
echo ""

echo -e "${GREEN}Operational Benefits:${NC}"
echo "• Single place to update database credentials"
echo "• Unified migration and deployment processes"
echo "• Consistent backup and recovery procedures" 
echo "• Easier compliance and security auditing"
echo ""

echo -e "${GREEN}Maintenance Benefits:${NC}"
echo "• Bug fixes benefit all engines simultaneously"
echo "• Performance optimizations apply across the platform"
echo "• Easier to add new database features"
echo "• Simplified testing and validation"

print_section "9. Migration Path from Old to New"

echo -e "${YELLOW}For existing engines:${NC}"
echo ""
echo "1. Copy proven schemas to consolidated_services/database/schemas/"
echo "2. Update engine imports:"
echo "   ${RED}FROM:${NC} from engine_xyz.database import get_connection"
echo "   ${GREEN}TO:${NC}   from consolidated_services.database import get_xyz_connection"
echo ""
echo "3. Update configuration:"
echo "   ${RED}FROM:${NC} XYZ_DB_HOST, XYZ_DB_PORT, etc."
echo "   ${GREEN}TO:${NC}   Centralized config in database_config.py"
echo ""
echo "4. Remove old database directories after migration"

print_section "10. Next Steps"

echo -e "${YELLOW}To use the centralized database system:${NC}"
echo ""
echo "1. Initialize the ConfigScan database:"
echo "   cd $PROJECT_ROOT"
echo "   python -m consolidated_services.database.migrations.migration_runner --engine configscan"
echo ""
echo "2. Test the centralized ConfigScan service:"
echo "   cd consolidated_services/configscan_service"
echo "   python main_with_centralized_db.py"
echo ""
echo "3. Migrate other engines one by one to use centralized database"
echo ""
echo "4. Remove old scattered database files after successful migration"

echo ""
echo -e "${CYAN}🎉 Centralized Database Architecture Benefits Summary:${NC}"
echo -e "${GREEN}• Single source of truth for all database schemas${NC}"
echo -e "${GREEN}• Optimized connection pooling and performance${NC}"
echo -e "${GREEN}• Consistent configuration and credential management${NC}"  
echo -e "${GREEN}• Unified migration and deployment processes${NC}"
echo -e "${GREEN}• Better developer experience and maintainability${NC}"
echo -e "${GREEN}• Easier monitoring, debugging, and operations${NC}"
echo ""
echo -e "${CYAN}The centralized approach is clearly superior to scattered database files!${NC}"