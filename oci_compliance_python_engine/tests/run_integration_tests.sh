#!/bin/bash

# OCI Engine Integration Test Runner
# Tests the refactored OCI SDK engine with YAML service definitions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENGINE_DIR="$(dirname "$SCRIPT_DIR")"
PROJECT_ROOT="$(dirname "$ENGINE_DIR")"

echo "========================================================================"
echo "OCI Engine Integration Test Suite"
echo "========================================================================"
echo ""
echo "Engine Directory: $ENGINE_DIR"
echo "Test Directory: $SCRIPT_DIR"
echo ""

# Setup Python path
export PYTHONPATH="$ENGINE_DIR:$PROJECT_ROOT:$PYTHONPATH"

# Run integration tests
echo "Running integration tests..."
echo "------------------------------------------------------------------------"
python3 "$SCRIPT_DIR/test_oci_engine_integration.py"

TEST_EXIT_CODE=$?

echo ""
echo "========================================================================"
if [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ All integration tests passed!"
else
    echo "❌ Some integration tests failed"
fi
echo "========================================================================"

exit $TEST_EXIT_CODE
