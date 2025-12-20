#!/bin/bash
# Monitor dependency index build progress

LOG_FILE="/tmp/dep_index_build.log"

if [ ! -f "$LOG_FILE" ]; then
    echo "Log file not found: $LOG_FILE"
    echo "Build may not be running. Start with:"
    echo "  nohup python3 tools/build_all_dependency_indexes.py pythonsdk-database/aws --provider aws --validate > $LOG_FILE 2>&1 &"
    exit 1
fi

echo "Monitoring build progress..."
echo "Press Ctrl+C to stop monitoring"
echo ""

# Show current progress
tail -f "$LOG_FILE" | while IFS= read -r line; do
    echo "$line"
    # Extract progress if it matches [X/Y] format
    if [[ $line =~ \[([0-9]+)/([0-9]+)\] ]]; then
        current="${BASH_REMATCH[1]}"
        total="${BASH_REMATCH[2]}"
        if [ -n "$current" ] && [ -n "$total" ]; then
            percent=$((current * 100 / total))
            echo ">>> Progress: $current/$total ($percent%)"
        fi
    fi
done

