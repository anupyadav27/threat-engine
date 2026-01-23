#!/bin/bash

# Trigger Full AWS Scan and Generate Compliance Reports
# This script:
# 1. Triggers a full AWS compliance scan (all accounts, regions, services)
# 2. Waits for completion
# 3. Generates compliance reports
# 4. Exports to PDF/CSV/JSON
# 5. Saves everything to S3

set -e

# Get service URLs (use LoadBalancer if available, otherwise ClusterIP)
AWS_ENGINE_LB=$(kubectl get svc aws-compliance-engine-lb -n threat-engine-engines -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "")
COMPLIANCE_ENGINE_LB=$(kubectl get svc compliance-engine-lb -n threat-engine-engines -o jsonpath='{.status.loadBalancer.ingress[0].hostname}' 2>/dev/null || echo "")

if [ -n "$AWS_ENGINE_LB" ]; then
    AWS_ENGINE_URL="http://${AWS_ENGINE_LB}"
else
    AWS_ENGINE_URL="http://aws-compliance-engine.threat-engine-engines.svc.cluster.local"
fi

if [ -n "$COMPLIANCE_ENGINE_LB" ]; then
    COMPLIANCE_ENGINE_URL="http://${COMPLIANCE_ENGINE_LB}"
else
    COMPLIANCE_ENGINE_URL="http://compliance-engine.threat-engine-engines.svc.cluster.local"
fi

echo "=========================================="
echo "Full Compliance Scan & Report Generation"
echo "=========================================="
echo ""
echo "AWS Engine URL: $AWS_ENGINE_URL"
echo "Compliance Engine URL: $COMPLIANCE_ENGINE_URL"
echo ""

# Step 1: Trigger full scan
echo "Step 1: Triggering full AWS compliance scan..."
echo "  Scope: All accounts, all regions, all services"
echo ""

SCAN_RESPONSE=$(curl -s -X POST "${AWS_ENGINE_URL}/api/v1/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "account": null,
    "include_accounts": null,
    "include_regions": null,
    "include_services": null,
    "stream_results": true
  }')

SCAN_ID=$(echo $SCAN_RESPONSE | jq -r '.scan_id // empty')

if [ -z "$SCAN_ID" ] || [ "$SCAN_ID" == "null" ]; then
    echo "❌ Failed to start scan"
    echo "Response: $SCAN_RESPONSE"
    exit 1
fi

echo "✅ Scan started successfully!"
echo "   Scan ID: $SCAN_ID"
echo ""

# Step 2: Monitor scan progress
echo "Step 2: Monitoring scan progress..."
echo "   (This may take a while for a full scan)"
echo ""

MAX_WAIT=7200  # 2 hours
WAIT_TIME=0
CHECK_INTERVAL=30
LAST_STATUS=""

while [ $WAIT_TIME -lt $MAX_WAIT ]; do
    STATUS_RESPONSE=$(curl -s "${AWS_ENGINE_URL}/api/v1/scan/${SCAN_ID}/status")
    STATUS=$(echo $STATUS_RESPONSE | jq -r '.status // "unknown"')
    
    if [ "$STATUS" != "$LAST_STATUS" ]; then
        echo "   Status: $STATUS"
        LAST_STATUS=$STATUS
    fi
    
    if [ "$STATUS" == "completed" ]; then
        echo "✅ Scan completed successfully!"
        break
    elif [ "$STATUS" == "failed" ]; then
        ERROR=$(echo $STATUS_RESPONSE | jq -r '.error // "Unknown error"')
        echo "❌ Scan failed: $ERROR"
        exit 1
    fi
    
    # Show progress if available
    PROGRESS=$(echo $STATUS_RESPONSE | jq -r '.progress.percentage // 0')
    if [ "$PROGRESS" != "0" ] && [ "$PROGRESS" != "null" ]; then
        echo "   Progress: ${PROGRESS}%"
    fi
    
    sleep $CHECK_INTERVAL
    WAIT_TIME=$((WAIT_TIME + CHECK_INTERVAL))
done

if [ $WAIT_TIME -ge $MAX_WAIT ]; then
    echo "⚠️  Scan timeout after ${MAX_WAIT}s, proceeding anyway..."
fi

echo ""
echo "Step 3: Generating compliance reports..."
echo ""

# Step 3: Generate compliance report
COMPLIANCE_RESPONSE=$(curl -s -X POST "${COMPLIANCE_ENGINE_URL}/api/v1/compliance/generate" \
  -H "Content-Type: application/json" \
  -d "{
    \"scan_id\": \"${SCAN_ID}\",
    \"csp\": \"aws\"
  }")

REPORT_ID=$(echo $COMPLIANCE_RESPONSE | jq -r '.report_id // empty')

if [ -z "$REPORT_ID" ] || [ "$REPORT_ID" == "null" ]; then
    echo "❌ Failed to generate compliance report"
    echo "Response: $COMPLIANCE_RESPONSE"
    exit 1
fi

echo "✅ Compliance report generated!"
echo "   Report ID: $REPORT_ID"
echo ""

# Step 4: Wait for S3 sync
echo "Step 4: Waiting for reports to sync to S3..."
sleep 60

# Step 5: Export formats
echo "Step 5: Testing report exports..."
echo ""

# Export PDF
echo "   Exporting PDF..."
curl -s "${COMPLIANCE_ENGINE_URL}/api/v1/compliance/report/${REPORT_ID}/export?format=pdf" \
  -o "/tmp/compliance_report_${REPORT_ID}.pdf" 2>&1

if [ -f "/tmp/compliance_report_${REPORT_ID}.pdf" ]; then
    PDF_SIZE=$(ls -lh "/tmp/compliance_report_${REPORT_ID}.pdf" | awk '{print $5}')
    echo "   ✅ PDF exported: /tmp/compliance_report_${REPORT_ID}.pdf (${PDF_SIZE})"
else
    echo "   ⚠️  PDF export may have failed"
fi

# Export CSV
echo "   Exporting CSV..."
curl -s "${COMPLIANCE_ENGINE_URL}/api/v1/compliance/report/${REPORT_ID}/export?format=csv" \
  -o "/tmp/compliance_report_${REPORT_ID}.csv" 2>&1

if [ -f "/tmp/compliance_report_${REPORT_ID}.csv" ]; then
    CSV_SIZE=$(ls -lh "/tmp/compliance_report_${REPORT_ID}.csv" | awk '{print $5}')
    echo "   ✅ CSV exported: /tmp/compliance_report_${REPORT_ID}.csv (${CSV_SIZE})"
else
    echo "   ⚠️  CSV export may have failed"
fi

# Step 6: Verify S3
echo ""
echo "Step 6: Verifying S3 storage..."
echo ""

S3_BUCKET="cspm-lgtech"
S3_PATH="compliance-engine/output/aws/${REPORT_ID}"

echo "Reports should be available at:"
echo "   s3://${S3_BUCKET}/${S3_PATH}/"
echo ""
echo "Expected files:"
echo "   - report.json"
echo "   - executive_summary.pdf"
echo "   - executive_summary.csv"
echo "   - {framework}_report.pdf (for each framework)"
echo "   - {framework}_report.csv (for each framework)"
echo ""

# Check S3
if command -v aws &> /dev/null; then
    echo "Checking S3..."
    aws s3 ls "s3://${S3_BUCKET}/${S3_PATH}/" 2>/dev/null | head -n 10 || echo "   (S3 check requires AWS CLI credentials)"
fi

echo ""
echo "=========================================="
echo "✅ Complete!"
echo "=========================================="
echo ""
echo "Summary:"
echo "   Scan ID: $SCAN_ID"
echo "   Report ID: $REPORT_ID"
echo ""
echo "Access Reports:"
echo "   - API: ${COMPLIANCE_ENGINE_URL}/api/v1/compliance/report/${REPORT_ID}"
echo "   - PDF: ${COMPLIANCE_ENGINE_URL}/api/v1/compliance/report/${REPORT_ID}/export?format=pdf"
echo "   - CSV: ${COMPLIANCE_ENGINE_URL}/api/v1/compliance/report/${REPORT_ID}/export?format=csv"
echo "   - S3: s3://${S3_BUCKET}/${S3_PATH}/"
echo ""

