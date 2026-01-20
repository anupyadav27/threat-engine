#!/bin/bash
# Monitor AWS Compliance Scan Progress

SCAN_ID="${1:-$(cat /tmp/current_scan_id.txt 2>/dev/null)}"

if [ -z "$SCAN_ID" ]; then
    echo "Usage: $0 <scan_id>"
    echo "Or set scan ID in /tmp/current_scan_id.txt"
    exit 1
fi

AWS_ENGINE_URL="${AWS_ENGINE_URL:-http://localhost:8080}"

echo "Monitoring Scan: $SCAN_ID"
echo ""

while true; do
    STATUS_RESPONSE=$(curl -s "${AWS_ENGINE_URL}/api/v1/scan/${SCAN_ID}/status")
    STATUS=$(echo $STATUS_RESPONSE | jq -r '.status // "unknown"')
    PROGRESS=$(echo $STATUS_RESPONSE | jq -r '.progress.percentage // 0')
    SERVICES_COMPLETED=$(echo $STATUS_RESPONSE | jq -r '.progress.services_completed // 0')
    SERVICES_TOTAL=$(echo $STATUS_RESPONSE | jq -r '.progress.services_total // 0')
    
    TIMESTAMP=$(date +"%H:%M:%S")
    echo "[$TIMESTAMP] Status: $STATUS | Progress: ${PROGRESS}% | Services: ${SERVICES_COMPLETED}/${SERVICES_TOTAL}"
    
    if [ "$STATUS" == "completed" ]; then
        echo ""
        echo "✅ Scan completed!"
        echo ""
        echo "Getting summary..."
        curl -s "${AWS_ENGINE_URL}/api/v1/scan/${SCAN_ID}/summary" | jq '{total_checks, passed_checks, failed_checks, report_folder}'
        break
    elif [ "$STATUS" == "failed" ]; then
        echo ""
        echo "❌ Scan failed!"
        echo "$STATUS_RESPONSE" | jq '.error'
        break
    fi
    
    sleep 30
done

