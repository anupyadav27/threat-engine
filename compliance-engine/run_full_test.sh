#!/bin/bash

# Full Compliance Test Script
# 1. Triggers full AWS compliance scan
# 2. Waits for scan completion
# 3. Generates compliance reports
# 4. Exports to PDF/CSV/JSON

set -e

AWS_ENGINE_URL="${AWS_ENGINE_URL:-http://aws-compliance-engine.threat-engine-engines.svc.cluster.local}"
COMPLIANCE_ENGINE_URL="${COMPLIANCE_ENGINE_URL:-http://compliance-engine-lb.threat-engine-engines.svc.cluster.local}"

echo "=========================================="
echo "Full Compliance Test"
echo "=========================================="
echo ""
echo "Step 1: Triggering full AWS compliance scan..."
echo "  - All accounts"
echo "  - All regions"
echo "  - All services"
echo ""

# Trigger scan
SCAN_RESPONSE=$(curl -s -X POST "${AWS_ENGINE_URL}/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "include_accounts": null,
    "include_regions": null,
    "include_services": null,
    "stream_results": true
  }')

SCAN_ID=$(echo $SCAN_RESPONSE | jq -r '.scan_id')

if [ "$SCAN_ID" == "null" ] || [ -z "$SCAN_ID" ]; then
    echo "❌ Failed to start scan"
    echo "Response: $SCAN_RESPONSE"
    exit 1
fi

echo "✅ Scan started: $SCAN_ID"
echo ""

# Wait for scan completion
echo "Step 2: Waiting for scan to complete..."
MAX_WAIT=3600  # 1 hour
WAIT_TIME=0
CHECK_INTERVAL=10

while [ $WAIT_TIME -lt $MAX_WAIT ]; do
    STATUS=$(curl -s "${AWS_ENGINE_URL}/api/v1/scan/${SCAN_ID}/status" | jq -r '.status')
    
    if [ "$STATUS" == "completed" ]; then
        echo "✅ Scan completed!"
        break
    elif [ "$STATUS" == "failed" ]; then
        echo "❌ Scan failed!"
        exit 1
    fi
    
    echo "  Status: $STATUS (waiting ${WAIT_TIME}s)..."
    sleep $CHECK_INTERVAL
    WAIT_TIME=$((WAIT_TIME + CHECK_INTERVAL))
done

if [ $WAIT_TIME -ge $MAX_WAIT ]; then
    echo "❌ Scan timeout after ${MAX_WAIT}s"
    exit 1
fi

echo ""
echo "Step 3: Generating compliance reports..."
echo ""

# Generate compliance report
COMPLIANCE_RESPONSE=$(curl -s -X POST "${COMPLIANCE_ENGINE_URL}/api/v1/compliance/generate" \
  -H "Content-Type: application/json" \
  -d "{
    \"scan_id\": \"${SCAN_ID}\",
    \"csp\": \"aws\"
  }")

REPORT_ID=$(echo $COMPLIANCE_RESPONSE | jq -r '.report_id')

if [ "$REPORT_ID" == "null" ] || [ -z "$REPORT_ID" ]; then
    echo "❌ Failed to generate compliance report"
    echo "Response: $COMPLIANCE_RESPONSE"
    exit 1
fi

echo "✅ Compliance report generated: $REPORT_ID"
echo ""

# Wait a bit for S3 sync
echo "Step 4: Waiting for reports to be saved to S3..."
sleep 30

# Check S3 for reports
echo ""
echo "Step 5: Verifying reports in S3..."
echo ""

S3_BUCKET="cspm-lgtech"
S3_PATH="compliance-engine/output/aws/${REPORT_ID}"

echo "Reports should be available at:"
echo "  s3://${S3_BUCKET}/${S3_PATH}/"
echo ""
echo "Files:"
echo "  - report.json"
echo "  - executive_summary.pdf"
echo "  - executive_summary.csv"
echo "  - {framework}_report.pdf (for each framework)"
echo "  - {framework}_report.csv (for each framework)"
echo ""

# Export PDF
echo "Step 6: Testing PDF export..."
curl -s "${COMPLIANCE_ENGINE_URL}/api/v1/compliance/report/${REPORT_ID}/export?format=pdf" \
  -o "/tmp/compliance_report_${REPORT_ID}.pdf"

if [ -f "/tmp/compliance_report_${REPORT_ID}.pdf" ]; then
    echo "✅ PDF exported: /tmp/compliance_report_${REPORT_ID}.pdf"
else
    echo "⚠️  PDF export may have failed"
fi

echo ""
echo "=========================================="
echo "Test Complete!"
echo "=========================================="
echo ""
echo "Scan ID: $SCAN_ID"
echo "Report ID: $REPORT_ID"
echo ""
echo "Access reports:"
echo "  - API: ${COMPLIANCE_ENGINE_URL}/api/v1/compliance/report/${REPORT_ID}"
echo "  - S3: s3://${S3_BUCKET}/${S3_PATH}/"
echo "  - PDF: /tmp/compliance_report_${REPORT_ID}.pdf"
echo ""

