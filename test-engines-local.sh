#!/bin/bash
# Test all CSP engines locally

set -e

WORKSPACE_ROOT="/Users/apple/Desktop/threat-engine"
ENGINES_DIR="${WORKSPACE_ROOT}/configScan_engines"
OUTPUT_DIR="${WORKSPACE_ROOT}/engines-output"

echo "=== Testing CSP Engines Locally ==="
echo ""

# Test AWS Engine
if [ -d "${ENGINES_DIR}/aws-configScan-engine" ]; then
    echo "Testing AWS ConfigScan Engine..."
    cd "${ENGINES_DIR}/aws-configScan-engine"
    
    # Set output directory
    export OUTPUT_DIR="${OUTPUT_DIR}/aws-configScan-engine/output"
    export PYTHONPATH="${ENGINES_DIR}/aws-configScan-engine:${PYTHONPATH}"
    
    # Test health endpoint if API server exists
    if [ -f "api_server.py" ]; then
        echo "  Starting API server..."
        python3 api_server.py &
        SERVER_PID=$!
        sleep 3
        
        # Test health
        if curl -s http://localhost:8000/api/v1/health > /dev/null; then
            echo "  ✅ AWS Engine API is running"
        else
            echo "  ⚠️  AWS Engine API not responding"
        fi
        
        kill $SERVER_PID 2>/dev/null || true
    fi
    
    echo ""
fi

# Test Azure Engine
if [ -d "${ENGINES_DIR}/azure-configScan-engine" ]; then
    echo "Testing Azure ConfigScan Engine..."
    cd "${ENGINES_DIR}/azure-configScan-engine"
    
    export OUTPUT_DIR="${OUTPUT_DIR}/azure-configScan-engine/output"
    export PYTHONPATH="${ENGINES_DIR}/azure-configScan-engine:${PYTHONPATH}"
    
    if [ -f "api_server.py" ]; then
        echo "  ✅ Azure Engine found"
    fi
    
    echo ""
fi

# Test GCP Engine
if [ -d "${ENGINES_DIR}/gcp-configScan-engine" ]; then
    echo "Testing GCP ConfigScan Engine..."
    cd "${ENGINES_DIR}/gcp-configScan-engine"
    
    export OUTPUT_DIR="${OUTPUT_DIR}/gcp-configScan-engine/output"
    export PYTHONPATH="${ENGINES_DIR}/gcp-configScan-engine:${PYTHONPATH}"
    
    if [ -f "api_server.py" ]; then
        echo "  ✅ GCP Engine found"
    fi
    
    echo ""
fi

echo "=== Engine Structure ==="
echo "Engines: ${ENGINES_DIR}"
echo "Output: ${OUTPUT_DIR}"
echo ""
echo "Available engines:"
ls -1 "${ENGINES_DIR}" | grep -v README

