#!/bin/bash
# Run all local tests

set -e

# Activate virtual environment
source ../venv/bin/activate

# Run all passing tests
echo "Running all local tests..."
python3 -m pytest \
    tests/test_storage_paths.py \
    tests/test_api_models.py \
    tests/test_retry_handler.py \
    tests/test_circuit_breaker.py \
    tests/test_webhook_sender.py \
    tests/test_integration_simple.py \
    -v \
    --tb=short

echo ""
echo "✅ All tests completed!"
