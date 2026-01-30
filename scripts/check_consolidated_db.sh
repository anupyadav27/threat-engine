#!/bin/bash
# Check consolidated database setup - schemas and tables

DB_USER=${DB_USER:-$(whoami)}
DB_NAME=${DB_NAME:-postgres}

echo "=========================================="
echo "Consolidated Database Inspection"
echo "=========================================="
echo ""

echo "📋 Checking for engine schemas in database: $DB_NAME"
echo "----------------------------------------"
SCHEMAS=$(psql -U $DB_USER -d $DB_NAME -t -c "SELECT schema_name FROM information_schema.schemata WHERE schema_name LIKE 'engine_%' ORDER BY schema_name;" 2>/dev/null)

if [ -z "$SCHEMAS" ]; then
    echo "❌ No engine schemas found!"
    echo ""
    echo "Expected schemas:"
    echo "  - engine_shared"
    echo "  - engine_onboarding"
    echo "  - engine_configscan"
    echo "  - engine_compliance"
    echo "  - engine_inventory"
    echo "  - engine_userportal"
    echo "  - engine_adminportal"
    echo "  - engine_secops"
    echo ""
    echo "💡 To initialize, run:"
    echo "   psql -U $DB_USER -d $DB_NAME -f scripts/init-databases.sql"
else
    echo "✅ Found schemas:"
    echo "$SCHEMAS" | sed 's/^/   - /'
    echo ""
    
    # Check tables in each schema
    for schema in $SCHEMAS; do
        schema=$(echo $schema | xargs)  # trim whitespace
        echo "📊 Tables in $schema:"
        TABLES=$(psql -U $DB_USER -d $DB_NAME -t -c "SELECT table_name FROM information_schema.tables WHERE table_schema = '$schema' AND table_type = 'BASE TABLE' ORDER BY table_name;" 2>/dev/null)
        if [ -z "$TABLES" ]; then
            echo "   ⚠️  No tables found"
        else
            echo "$TABLES" | sed 's/^/   - /'
        fi
        echo ""
    done
fi

echo "=========================================="
