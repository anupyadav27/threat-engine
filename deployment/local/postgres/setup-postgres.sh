#!/bin/bash
# Setup Local PostgreSQL for Local Deployment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

echo "=========================================="
echo "Local PostgreSQL Setup"
echo "=========================================="
echo ""

# Check if PostgreSQL is running
if ! pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
    echo "⚠️  PostgreSQL is not running"
    echo ""
    echo "Starting PostgreSQL..."
    
    # Try to start via Homebrew
    if command -v brew &> /dev/null; then
        brew services start postgresql@14 2>/dev/null || brew services start postgresql 2>/dev/null
        sleep 3
    else
        echo "Please start PostgreSQL manually and run this script again"
        exit 1
    fi
fi

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL..."
for i in {1..10}; do
    if pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
        echo "✅ PostgreSQL is ready!"
        break
    fi
    sleep 2
done

if ! pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
    echo "❌ PostgreSQL failed to start"
    exit 1
fi

echo ""
echo "Running database setup..."
cd "$WORKSPACE_ROOT"
./setup-local-databases.sh

echo ""
echo "=========================================="
echo "✅ Local PostgreSQL Setup Complete!"
echo "=========================================="
echo ""
echo "Connection strings:"
echo "  Compliance Engine: postgresql://postgres:postgres@localhost:5432/compliance_engine"
echo "  Onboarding Engine: postgresql://postgres:postgres@localhost:5432/threat_engine"
echo ""

