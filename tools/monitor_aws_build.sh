#!/bin/bash
# Monitor AWS dependency index build progress

PROVIDER="aws"
ROOT_PATH="pythonsdk-database/aws"
INTERVAL=10  # Check every 10 seconds

# Auto-detect AWS process PID
get_aws_pid() {
    ps aux | grep "build_all_dependency_indexes.*aws" | grep -v grep | awk '{print $2}' | head -1
}

PID=$(get_aws_pid)

if [ -z "$PID" ]; then
    echo "⚠️  AWS build process not found. It may have completed or crashed."
    exit 1
fi

echo "Monitoring AWS dependency index build (PID: $PID)"
echo "Press Ctrl+C to stop"
echo ""

while true; do
    # Re-detect PID in case it changes
    PID=$(get_aws_pid)
    
    clear
    echo "============================================================"
    echo "AWS DEPENDENCY INDEX BUILD MONITOR"
    echo "============================================================"
    echo "Time: $(date '+%Y-%m-%d %H:%M:%S')"
    echo ""
    
    # Check if process is still running
    if [ -n "$PID" ] && ps -p $PID > /dev/null 2>&1; then
        echo "✓ Process is RUNNING"
        # Use ps without --no-headers flag (macOS compatible)
        RUNTIME=$(ps -p $PID -o etime= 2>/dev/null | tr -d ' ')
        CPU=$(ps -p $PID -o pcpu= 2>/dev/null | tr -d ' ')
        MEM=$(ps -p $PID -o pmem= 2>/dev/null | tr -d ' ')
        if [ -n "$RUNTIME" ]; then
            echo "  PID: $PID | Runtime: $RUNTIME | CPU: ${CPU}% | Memory: ${MEM}%"
        else
            echo "  PID: $PID (process info unavailable)"
        fi
    else
        echo "⚠️  Process is NOT running (may have completed or crashed)"
    fi
    echo ""
    
    # Count completed files
    COMPLETED=$(find "$ROOT_PATH" -name "dependency_index.json" -type f 2>/dev/null | wc -l | tr -d ' ')
    TOTAL=$(find "$ROOT_PATH" -type d -maxdepth 1 ! -name "$(basename "$ROOT_PATH")" 2>/dev/null | wc -l | tr -d ' ')
    
    if [ "$TOTAL" -gt 0 ]; then
        PERCENT=$(awk "BEGIN {printf \"%.1f\", ($COMPLETED/$TOTAL)*100}")
        PROGRESS_BAR_WIDTH=40
        FILLED=$(awk "BEGIN {printf \"%.0f\", ($COMPLETED/$TOTAL)*$PROGRESS_BAR_WIDTH}")
        
        echo "PROGRESS:"
        echo "  Services: $COMPLETED / $TOTAL ($PERCENT%)"
        printf "  ["
        for ((i=0; i<$PROGRESS_BAR_WIDTH; i++)); do
            if [ $i -lt $FILLED ]; then
                printf "="
            else
                printf " "
            fi
        done
        printf "] $PERCENT%%\n"
        echo ""
        
        # Show last completed service
        LAST_SERVICE=$(find "$ROOT_PATH" -name "dependency_index.json" -type f 2>/dev/null | sed 's|.*/\([^/]*\)/dependency_index.json|\1|' | sort | tail -1)
        if [ -n "$LAST_SERVICE" ]; then
            echo "Last completed: $LAST_SERVICE"
        fi
        echo ""
        
        # Estimate time remaining
        if [ -n "$PID" ] && ps -p $PID > /dev/null 2>&1 && [ "$COMPLETED" -gt 0 ]; then
            RUNTIME=$(ps -p $PID -o etime= | tr -d ' ')
            # Parse runtime (format: HH:MM:SS or MM:SS)
            if [[ $RUNTIME =~ ^([0-9]+):([0-9]+):([0-9]+)$ ]]; then
                HOURS=${BASH_REMATCH[1]}
                MINUTES=${BASH_REMATCH[2]}
                SECONDS=${BASH_REMATCH[3]}
                ELAPSED_SECONDS=$((HOURS*3600 + MINUTES*60 + SECONDS))
            elif [[ $RUNTIME =~ ^([0-9]+):([0-9]+)$ ]]; then
                MINUTES=${BASH_REMATCH[1]}
                SECONDS=${BASH_REMATCH[2]}
                ELAPSED_SECONDS=$((MINUTES*60 + SECONDS))
            else
                ELAPSED_SECONDS=0
            fi
            
            if [ "$ELAPSED_SECONDS" -gt 0 ] && [ "$COMPLETED" -gt 0 ]; then
                AVG_TIME=$((ELAPSED_SECONDS / COMPLETED))
                REMAINING=$((TOTAL - COMPLETED))
                ESTIMATED=$((AVG_TIME * REMAINING))
                EST_HOURS=$((ESTIMATED / 3600))
                EST_MINUTES=$(((ESTIMATED % 3600) / 60))
                echo "Estimated time remaining: ${EST_HOURS}h ${EST_MINUTES}m"
            fi
        fi
    fi
    
    echo ""
    echo "============================================================"
    echo "Next update in $INTERVAL seconds... (Ctrl+C to stop)"
    sleep $INTERVAL
done

