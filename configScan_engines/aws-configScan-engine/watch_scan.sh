#!/bin/bash
# Watch scan performance continuously
# Usage: ./watch_scan.sh [interval_seconds]

INTERVAL=${1:-60}  # Default: 60 seconds

echo "=" | tr -d '\n'
echo "Watching scan performance (checking every ${INTERVAL}s)"
echo "Press Ctrl+C to stop"
echo "=" | tr -d '\n'
echo ""

while true; do
    clear
    python3 configScan_engines/aws-configScan-engine/monitor_scan_performance.py
    echo ""
    echo "Next check in ${INTERVAL} seconds... (Ctrl+C to stop)"
    sleep $INTERVAL
done

