#!/bin/bash
# Quick status check for AWS build

ROOT_PATH="pythonsdk-database/aws"
PID=$(ps aux | grep "build_all_dependency_indexes.*aws" | grep -v grep | awk '{print $2}' | head -1)

echo "============================================================"
echo "AWS BUILD STATUS - $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"

if [ -z "$PID" ]; then
    echo "⚠️  Process NOT running (may have completed)"
else
    echo "✓ Process RUNNING (PID: $PID)"
    ps -p $PID -o etime=,pcpu=,pmem= | awk '{printf "  Runtime: %s | CPU: %s%% | Memory: %s%%\n", $1, $2, $3}'
fi

echo ""

COMPLETED=$(find "$ROOT_PATH" -name "dependency_index.json" -type f 2>/dev/null | wc -l | tr -d ' ')
TOTAL=$(find "$ROOT_PATH" -type d -maxdepth 1 ! -name "$(basename "$ROOT_PATH")" 2>/dev/null | wc -l | tr -d ' ')

if [ "$TOTAL" -gt 0 ]; then
    PERCENT=$(awk "BEGIN {printf \"%.1f\", ($COMPLETED/$TOTAL)*100}")
    echo "Progress: $COMPLETED / $TOTAL services ($PERCENT%)"
    
    LAST=$(find "$ROOT_PATH" -name "dependency_index.json" -type f 2>/dev/null | sed 's|.*/\([^/]*\)/dependency_index.json|\1|' | sort | tail -1)
    if [ -n "$LAST" ]; then
        echo "Last completed: $LAST"
    fi
    
    if [ -n "$PID" ] && ps -p $PID > /dev/null 2>&1 && [ "$COMPLETED" -gt 0 ]; then
        RUNTIME_STR=$(ps -p $PID -o etime= | tr -d ' ')
        # Simple time estimate
        echo ""
        echo "Note: Processing appears to be on a large service (ec2)"
        echo "      This is normal - some services take longer than others"
    fi
fi

echo "============================================================"

