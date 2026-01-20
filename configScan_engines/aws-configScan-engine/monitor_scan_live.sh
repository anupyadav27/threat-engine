#!/bin/bash
# Live scan monitoring - refreshes every 5 seconds

SCAN_FOLDER="engines-output/aws-configScan-engine/output/test_performance_20260119_170130"
LOG_FILE="$SCAN_FOLDER/logs/scan.log"

if [ ! -f "$LOG_FILE" ]; then
    echo "⏳ Waiting for scan to start..."
    exit 1
fi

while true; do
    clear
    echo "=========================================="
    echo "LIVE SCAN MONITOR"
    echo "=========================================="
    echo "Time: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    
    # Check if running
    if pgrep -f "test_performance_optimized.py" > /dev/null; then
        echo "✅ Status: RUNNING"
    else
        echo "⚠️  Status: COMPLETED or STOPPED"
    fi
    
    echo ""
    echo "📊 Statistics:"
    
    if [ -f "$LOG_FILE" ]; then
        TOTAL=$(wc -l < "$LOG_FILE" 2>/dev/null | tr -d ' ')
        PROCESSING=$(grep -c "Processing discovery:" "$LOG_FILE" 2>/dev/null || echo "0")
        COMPLETED=$(grep -c "Completed discovery" "$LOG_FILE" 2>/dev/null || echo "0")
        ERRORS=$(grep -c "ValidationException.*maxResults" "$LOG_FILE" 2>/dev/null || echo "0")
        WARNINGS=$(grep -c "WARNING" "$LOG_FILE" 2>/dev/null || echo "0")
        
        echo "   Log lines: $TOTAL"
        echo "   Discoveries: $PROCESSING processed, $COMPLETED completed"
        echo "   SageMaker errors: $ERRORS"
        echo "   Warnings: $WARNINGS"
    fi
    
    echo ""
    echo "📦 Output Files:"
    RESULTS=$(ls -1 "$SCAN_FOLDER"/results_*.ndjson 2>/dev/null | wc -l | tr -d ' ')
    INVENTORY=$(ls -1 "$SCAN_FOLDER"/inventory_*.ndjson 2>/dev/null | wc -l | tr -d ' ')
    echo "   Results: $RESULTS files"
    echo "   Inventory: $INVENTORY files"
    
    echo ""
    echo "📝 Recent Activity (last 5 lines):"
    tail -5 "$LOG_FILE" 2>/dev/null | sed 's/^/   /'
    
    echo ""
    echo "=========================================="
    echo "Press Ctrl+C to stop monitoring"
    echo "Refreshing in 5 seconds..."
    sleep 5
done

