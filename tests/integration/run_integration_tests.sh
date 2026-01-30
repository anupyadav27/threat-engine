#!/bin/bash
# Run full integration tests (use project-root–relative paths)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$ROOT"

echo "=========================================="
echo "Running Full Integration Tests"
echo "=========================================="
echo ""

[ -d "$ROOT/venv" ] && source "$ROOT/venv/bin/activate"
export PYTHONPATH="${ROOT}:${ROOT}/engine_onboarding"

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
