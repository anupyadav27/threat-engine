#!/bin/bash
# Full AWS Compliance Scan Script
# Scans all accounts, all regions, all services

set -e

AWS_ENGINE_URL="${AWS_ENGINE_URL:-http://aws-compliance-engine.threat-engine-engines.svc.cluster.local}"

echo "=========================================="
echo "Full AWS Compliance Scan"
echo "=========================================="
echo ""
echo "Scope:"
echo "  - All accounts"
echo "  - All regions"
echo "  - All services"
echo ""

# Step 1: Trigger scan
echo "Step 1: Triggering scan..."
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

# Step 2: Monitor progress
echo "Step 2: Monitoring scan progress..."
echo "   (This may take 30-60 minutes for a full scan)"
echo ""

MAX_WAIT=7200  # 2 hours
WAIT_TIME=0
CHECK_INTERVAL=30
LAST_STATUS=""
LAST_PROGRESS=0

while [ $WAIT_TIME -lt $MAX_WAIT ]; do
    STATUS_RESPONSE=$(curl -s "${AWS_ENGINE_URL}/api/v1/scan/${SCAN_ID}/status")
    STATUS=$(echo $STATUS_RESPONSE | jq -r '.status // "unknown"')
    PROGRESS=$(echo $STATUS_RESPONSE | jq -r '.progress.percentage // 0')
    
    # Only print when status or progress changes
    if [ "$STATUS" != "$LAST_STATUS" ] || [ "$PROGRESS" != "$LAST_PROGRESS" ]; then
        TIMESTAMP=$(date +"%H:%M:%S")
        echo "[$TIMESTAMP] Status: $STATUS | Progress: ${PROGRESS}%"
        LAST_STATUS=$STATUS
        LAST_PROGRESS=$PROGRESS
    fi
    
    if [ "$STATUS" == "completed" ]; then
        echo ""
        echo "✅ Scan completed successfully!"
        
        # Get summary
        SUMMARY=$(curl -s "${AWS_ENGINE_URL}/api/v1/scan/${SCAN_ID}/summary" | jq '.')
        echo ""
        echo "Scan Summary:"
        echo "$SUMMARY" | jq '{total_checks, passed_checks, failed_checks, report_folder}'
        break
    elif [ "$STATUS" == "failed" ]; then
        ERROR=$(echo $STATUS_RESPONSE | jq -r '.error // "Unknown error"')
        echo ""
        echo "❌ Scan failed: $ERROR"
        exit 1
    fi
    
    sleep $CHECK_INTERVAL
    WAIT_TIME=$((WAIT_TIME + CHECK_INTERVAL))
done

if [ $WAIT_TIME -ge $MAX_WAIT ]; then
    echo ""
    echo "⚠️  Scan timeout after ${MAX_WAIT}s"
    echo "   Scan may still be running. Check status manually:"
    echo "   curl ${AWS_ENGINE_URL}/api/v1/scan/${SCAN_ID}/status"
    exit 1
fi

echo ""
echo "=========================================="
echo "✅ Scan Complete!"
echo "=========================================="
echo ""
echo "Scan ID: $SCAN_ID"
echo ""
echo "Results available at:"
echo "  - S3: s3://cspm-lgtech/aws-compliance-engine/output/${SCAN_ID}/"
echo "  - API: ${AWS_ENGINE_URL}/api/v1/scan/${SCAN_ID}/results"
echo ""
echo "To generate compliance report:"
echo "  ./compliance-engine/trigger_full_scan_and_report.sh"
echo "  OR"
echo "  curl -X POST http://compliance-engine.threat-engine-engines.svc.cluster.local/api/v1/compliance/generate \\"
echo "    -H \"Content-Type: application/json\" \\"
echo "    -d '{\"scan_id\": \"${SCAN_ID}\", \"csp\": \"aws\"}'"
echo ""

