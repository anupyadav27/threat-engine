#!/bin/bash
# Real-time performance monitoring for test scan

echo "=========================================="
echo "TEST SCAN PERFORMANCE MONITOR"
echo "=========================================="
echo ""

# Find latest scan folder
LATEST_SCAN=$(find engines-output/aws-configScan-engine/output -name "test_performance_*" -type d -mmin -30 2>/dev/null | sort -r | head -1)

if [ -z "$LATEST_SCAN" ]; then
    echo "⏳ No recent scan found. Waiting for scan to start..."
    exit 1
fi

SCAN_NAME=$(basename "$LATEST_SCAN")
LOG_FILE="$LATEST_SCAN/logs/scan.log"
ERROR_FILE="$LATEST_SCAN/logs/errors.log"

echo "📁 Scan: $SCAN_NAME"
echo ""

# Check if scan is running
if pgrep -f "test_performance_optimized.py" > /dev/null; then
    echo "✅ Scan is RUNNING"
else
    echo "⚠️  Scan process NOT running (may have completed)"
fi

echo ""
echo "📊 Progress:"
echo ""

# Count discoveries processed
if [ -f "$LOG_FILE" ]; then
    TOTAL_DISCOVERIES=$(grep -c "Processing discovery:" "$LOG_FILE" 2>/dev/null || echo "0")
    COMPLETED_DISCOVERIES=$(grep -c "Completed discovery" "$LOG_FILE" 2>/dev/null || echo "0")
    ERRORS=$(grep -c "WARNING\|ERROR" "$LOG_FILE" 2>/dev/null || echo "0")
    
    echo "   Discoveries processed: $TOTAL_DISCOVERIES"
    echo "   Completed: $COMPLETED_DISCOVERIES"
    echo "   Warnings/Errors: $ERRORS"
    echo ""
    
    # Show recent activity
    echo "📝 Recent activity (last 5 lines):"
    tail -5 "$LOG_FILE" 2>/dev/null | sed 's/^/   /'
    echo ""
    
    # Check for SageMaker errors (should be fixed)
    SAGEMAKER_ERRORS=$(grep -c "ValidationException.*maxResults.*100" "$LOG_FILE" 2>/dev/null || echo "0")
    if [ "$SAGEMAKER_ERRORS" -gt 0 ]; then
        echo "⚠️  SageMaker MaxResults errors detected: $SAGEMAKER_ERRORS"
        echo "   (These should be fixed in the new scan)"
    else
        echo "✅ No SageMaker MaxResults errors (fix working!)"
    fi
fi

# Count output files
RESULTS=$(ls -1 "$LATEST_SCAN"/results_*.ndjson 2>/dev/null | wc -l | tr -d ' ')
INVENTORY=$(ls -1 "$LATEST_SCAN"/inventory_*.ndjson 2>/dev/null | wc -l | tr -d ' ')

echo ""
echo "📦 Output files:"
echo "   Results: $RESULTS files"
echo "   Inventory: $INVENTORY files"

if [ "$RESULTS" -gt 0 ]; then
    echo ""
    echo "   Sample results:"
    ls -lht "$LATEST_SCAN"/results_*.ndjson 2>/dev/null | head -3 | awk '{print "      " $9 " (" $5 ")"}'
fi

echo ""
echo "=========================================="
echo "💡 Run this script again to see updates"
echo "=========================================="

