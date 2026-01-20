#!/bin/bash
# Start PostgreSQL and setup databases

echo "=== Starting PostgreSQL ==="
echo ""

# Try to start PostgreSQL
if command -v brew &> /dev/null; then
    echo "Starting PostgreSQL via Homebrew..."
    brew services start postgresql@14 2>/dev/null || brew services start postgresql 2>/dev/null
    sleep 3
else
    echo "Homebrew not found. Please start PostgreSQL manually."
    exit 1
fi

# Wait for PostgreSQL to be ready
echo "Waiting for PostgreSQL to be ready..."
for i in {1..10}; do
    if pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
        echo "✅ PostgreSQL is ready!"
        break
    fi
    echo "  Attempt $i/10..."
    sleep 2
done

if ! pg_isready -h localhost -p 5432 >/dev/null 2>&1; then
    echo "❌ PostgreSQL failed to start"
    exit 1
fi

echo ""
echo "=== Running Database Setup ==="
./setup-local-databases.sh
