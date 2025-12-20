#!/bin/bash
# Monitor full scan progress

LOG_FILE="full_scan_all_services.log"
SCAN_DIR="../output/scan_20251213_152007"

echo "=" | tr -d '\n' | head -c 80; echo
echo "FULL SCAN PROGRESS MONITOR"
echo "=" | tr -d '\n' | head -c 80; echo
echo

# Check if scan is running
if ps aux | grep -q "[m]ain_scanner"; then
    echo "✅ Scan is running"
else
    echo "⏸️  Scan completed or not running"
fi

echo

# Count completed services
if [ -d "$SCAN_DIR" ]; then
    COMPLETED=$(find "$SCAN_DIR" -name "*_checks.json" 2>/dev/null | wc -l | tr -d ' ')
    echo "📊 Services completed: $COMPLETED/114"
else
    echo "📊 Scan directory not found yet"
fi

echo

# Show recent activity
if [ -f "$LOG_FILE" ]; then
    echo "Recent activity (last 10 lines):"
    echo "-" | tr -d '\n' | head -c 80; echo
    tail -10 "$LOG_FILE" | grep -E "(INFO|ERROR|WARNING)" | tail -5
    echo
    echo "Total log lines: $(wc -l < "$LOG_FILE")"
else
    echo "Log file not found"
fi

echo

# Check for errors
if [ -f "$LOG_FILE" ]; then
    ERROR_COUNT=$(grep -c "ERROR.*failed" "$LOG_FILE" 2>/dev/null || echo "0")
    echo "⚠️  Services with errors: $ERROR_COUNT"
    
    if [ "$ERROR_COUNT" -gt 0 ]; then
        echo
        echo "Recent errors:"
        grep "ERROR.*failed" "$LOG_FILE" | tail -5 | sed 's/^/  /'
    fi
fi

echo
echo "=" | tr -d '\n' | head -c 80; echo
