#!/bin/bash
# Run full integration tests

set -e

echo "=========================================="
echo "Running Full Integration Tests"
echo "=========================================="
echo ""

# Activate virtual environment
source ../../venv/bin/activate

# Set PYTHONPATH
export PYTHONPATH="/Users/apple/Desktop/threat-engine:/Users/apple/Desktop/threat-engine/onboarding_engine"

# Run integration tests
echo "Running integration workflow tests..."
python3 -m pytest \
    tests/integration/test_integration_workflow.py \
    tests/integration/test_configscan_api_integration.py \
    tests/integration/test_mock_server_integration.py \
    -v \
    --tb=short

echo ""
echo "=========================================="
echo "Integration Tests Complete"
echo "=========================================="
