#!/bin/bash

# Script to load vulnerability database schema from within EKS cluster

set -e

echo "========================================"
echo "Vulnerability DB Schema Loader"
echo "========================================"

# Check if secrets exist
echo "Step 1: Checking if secrets exist..."
if ! kubectl get secret vulnerability-db-secret -n default &> /dev/null; then
    echo "❌ Secret 'vulnerability-db-secret' not found. Please apply vulnerability-secrets.yaml first."
    exit 1
fi
echo "✅ Secrets found"

# Create verification pod
echo ""
echo "Step 2: Creating database verification pod..."
kubectl apply -f verify-db-schema.yaml

# Wait for pod to be ready
echo "Waiting for pod to be ready..."
kubectl wait --for=condition=Ready pod/vulnerability-db-check -n default --timeout=120s

# Check if tables exist
echo ""
echo "Step 3: Checking existing tables in database..."
kubectl exec vulnerability-db-check -n default -- psql -c "\dt" || true

# Ask user if they want to load schema
echo ""
read -p "Do you want to load the vulnerability schema? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "Step 4: Loading schema..."

    # Copy schema file to pod
    kubectl cp ../vul_engine/schemas_and_config/vulnerability_schema.sql \
        vulnerability-db-check:/tmp/vulnerability_schema.sql -n default

    # Execute schema
    kubectl exec vulnerability-db-check -n default -- \
        psql -f /tmp/vulnerability_schema.sql

    echo "✅ Schema loaded successfully"

    # Verify tables
    echo ""
    echo "Step 5: Verifying tables..."
    kubectl exec vulnerability-db-check -n default -- psql -c "\dt"
else
    echo "Schema loading skipped."
fi

# Cleanup
echo ""
read -p "Delete verification pod? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    kubectl delete pod vulnerability-db-check -n default
    echo "✅ Cleanup completed"
fi

echo ""
echo "========================================"
echo "Database verification completed!"
echo "========================================"
