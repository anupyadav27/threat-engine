#!/bin/bash
# Quick database inspection script

echo "=========================================="
echo "PostgreSQL Database Inspection"
echo "=========================================="
echo ""

# Get current user
DB_USER=${DB_USER:-$(whoami)}

echo "📚 Available Databases:"
echo "----------------------------------------"
psql -U $DB_USER -d postgres -c "SELECT datname, pg_size_pretty(pg_database_size(datname)) as size FROM pg_database WHERE datistemplate = false ORDER BY datname;" 2>/dev/null || echo "Error connecting to PostgreSQL"

echo ""
echo "📊 threat_engine_configscan Tables:"
echo "----------------------------------------"
psql -U $DB_USER -d threat_engine_configscan -c "\dt" 2>/dev/null || echo "Database not accessible"

echo ""
echo "📊 cspm_db Tables:"
echo "----------------------------------------"
psql -U $DB_USER -d cspm_db -c "\dt" 2>/dev/null || echo "Database not accessible"

echo ""
echo "📈 Data Summary (threat_engine_configscan):"
echo "----------------------------------------"
psql -U $DB_USER -d threat_engine_configscan -c "
SELECT 
    'customers' as table_name, COUNT(*) as rows FROM customers
UNION ALL SELECT 'tenants', COUNT(*) FROM tenants
UNION ALL SELECT 'csp_hierarchies', COUNT(*) FROM csp_hierarchies
UNION ALL SELECT 'schedules', COUNT(*) FROM schedules
UNION ALL SELECT 'scans', COUNT(*) FROM scans
UNION ALL SELECT 'check_results', COUNT(*) FROM check_results
UNION ALL SELECT 'discoveries', COUNT(*) FROM discoveries
ORDER BY table_name;
" 2>/dev/null || echo "Error querying data"

echo ""
echo "📈 Data Summary (cspm_db):"
echo "----------------------------------------"
psql -U $DB_USER -d cspm_db -c "
SELECT 
    'customers' as table_name, COUNT(*) as rows FROM customers
UNION ALL SELECT 'tenants', COUNT(*) FROM tenants
UNION ALL SELECT 'csp_hierarchies', COUNT(*) FROM csp_hierarchies
UNION ALL SELECT 'scans', COUNT(*) FROM scans
UNION ALL SELECT 'discoveries', COUNT(*) FROM discoveries
ORDER BY table_name;
" 2>/dev/null || echo "Error querying data"

echo ""
echo "=========================================="
