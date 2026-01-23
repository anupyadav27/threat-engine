#!/bin/bash
# Run all integration and unit tests

set -e

echo "=========================================="
echo "Running All Integration Tests"
echo "=========================================="
echo ""

# Activate virtual environment
cd "$(dirname "$0")/.."
source venv/bin/activate

# Set PYTHONPATH
export PYTHONPATH="$(pwd):$(pwd)/onboarding_engine"

echo "Running unit tests..."
python3 -m pytest \
    tests/test_integration_simple.py \
    tests/test_storage_paths.py \
    tests/test_api_models.py \
    tests/test_retry_handler.py \
    tests/test_circuit_breaker.py \
    tests/test_webhook_sender.py \
    -v --tb=short

echo ""
echo "Running integration tests..."
python3 -m pytest \
    tests/integration/test_integration_workflow.py \
    tests/integration/test_configscan_api_integration.py \
    tests/integration/test_mock_server_integration.py \
    -v --tb=short

echo ""
echo "=========================================="
echo "All Tests Complete"
echo "=========================================="
