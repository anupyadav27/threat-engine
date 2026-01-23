#!/bin/bash
# Test Inventory Engine Locally
# Runs a small AWS inventory scan and displays results

set -e

WORKSPACE_ROOT="/Users/apple/Desktop/threat-engine"
INVENTORY_DIR="${WORKSPACE_ROOT}/inventory-engine"
OUTPUT_DIR="${WORKSPACE_ROOT}/engines-output/inventory-engine/output"

echo "=========================================="
echo "Testing Inventory Engine Locally"
echo "=========================================="
echo ""

# Check if Python dependencies are installed
echo "Checking dependencies..."
cd "$INVENTORY_DIR"
if ! python3 -c "import fastapi, boto3, pydantic" 2>/dev/null; then
    echo "Installing dependencies..."
    pip3 install --user -r requirements.txt || pip3 install -r requirements.txt
fi

# Set environment variables
export USE_S3="false"
export INVENTORY_OUTPUT_DIR="$OUTPUT_DIR"
export DATABASE_URL="postgresql://postgres:postgres@localhost:5432/inventory_engine"
export PORT=8005

# Get AWS account ID
echo "Getting AWS account ID..."
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "123456789012")
REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")

echo "Account ID: $ACCOUNT_ID"
echo "Region: $REGION"
echo ""

# Start API server in background
echo "Starting Inventory Engine API server..."
cd "$INVENTORY_DIR"
python3 -m uvicorn inventory_engine.api.api_server:app --host 0.0.0.0 --port 8005 &
SERVER_PID=$!
sleep 3

# Wait for server to be ready
echo "Waiting for server to be ready..."
for i in {1..10}; do
    if curl -s http://localhost:8005/health > /dev/null 2>&1; then
        echo "✅ Server is ready"
        break
    fi
    echo "  Attempt $i/10..."
    sleep 1
done

# Run inventory scan
echo ""
echo "Running inventory scan..."
echo "  Tenant: test-tenant"
echo "  Providers: aws"
echo "  Accounts: $ACCOUNT_ID"
echo "  Regions: $REGION"
echo "  Services: s3, ec2"
echo ""

SCAN_RESPONSE=$(curl -s -X POST http://localhost:8005/api/v1/inventory/scan \
  -H "Content-Type: application/json" \
  -d "{
    \"tenant_id\": \"test-tenant\",
    \"providers\": [\"aws\"],
    \"accounts\": [\"$ACCOUNT_ID\"],
    \"regions\": [\"$REGION\"],
    \"services\": [\"s3\", \"ec2\"]
  }")

SCAN_RUN_ID=$(echo "$SCAN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('scan_run_id', ''))" 2>/dev/null || echo "")

if [ -z "$SCAN_RUN_ID" ]; then
    echo "❌ Scan failed"
    echo "Response: $SCAN_RESPONSE"
    kill $SERVER_PID 2>/dev/null || true
    exit 1
fi

echo "✅ Scan started: $SCAN_RUN_ID"
echo ""

# Wait for scan to complete (with timeout)
echo "Waiting for scan to complete..."
MAX_WAIT=300
WAIT_TIME=0
while [ $WAIT_TIME -lt $MAX_WAIT ]; do
    SUMMARY=$(curl -s "http://localhost:8005/api/v1/inventory/runs/$SCAN_RUN_ID/summary?tenant_id=test-tenant" 2>/dev/null || echo "")
    if [ -n "$SUMMARY" ] && echo "$SUMMARY" | python3 -c "import sys, json; d=json.load(sys.stdin); exit(0 if d.get('status') == 'completed' else 1)" 2>/dev/null; then
        echo "✅ Scan completed!"
        break
    fi
    sleep 5
    WAIT_TIME=$((WAIT_TIME + 5))
done

# Display summary
echo ""
echo "Scan Summary:"
echo "$SUMMARY" | python3 -m json.tool 2>/dev/null || echo "$SUMMARY"

# Display sample assets
echo ""
echo "Sample Assets (first 5):"
ASSETS_FILE="$OUTPUT_DIR/test-tenant/$SCAN_RUN_ID/normalized/assets.ndjson"
if [ -f "$ASSETS_FILE" ]; then
    head -5 "$ASSETS_FILE" | python3 -m json.tool
else
    echo "  Assets file not found at: $ASSETS_FILE"
fi

# Display sample relationships
echo ""
echo "Sample Relationships (first 5):"
RELS_FILE="$OUTPUT_DIR/test-tenant/$SCAN_RUN_ID/normalized/relationships.ndjson"
if [ -f "$RELS_FILE" ]; then
    head -5 "$RELS_FILE" | python3 -m json.tool
else
    echo "  Relationships file not found at: $RELS_FILE"
fi

# Stop server
echo ""
echo "Stopping server..."
kill $SERVER_PID 2>/dev/null || true

echo ""
echo "=========================================="
echo "✅ Test Complete!"
echo "=========================================="
echo ""
echo "Scan artifacts:"
echo "  $OUTPUT_DIR/test-tenant/$SCAN_RUN_ID/"
echo ""

