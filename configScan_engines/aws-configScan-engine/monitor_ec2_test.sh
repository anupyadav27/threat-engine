#!/bin/bash
# Monitor EC2 Mumbai test scan

OUTPUT_DIR="/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output"

echo "Monitoring EC2 Mumbai test scan..."
echo "Checking for scan folders..."
echo ""

# Find latest test_ec2_mumbai folder
LATEST_SCAN=$(find "$OUTPUT_DIR" -type d -name "test_ec2_mumbai_*" | sort | tail -1)

if [ -z "$LATEST_SCAN" ]; then
    echo "⚠️  No scan folder found yet. Scan may still be initializing..."
    echo "Checking for running processes..."
    ps aux | grep -E "test_ec2_mumbai|python.*scan" | grep -v grep || echo "No scan processes found"
else
    echo "✅ Found scan folder: $(basename $LATEST_SCAN)"
    echo ""
    
    # Check logs
    if [ -f "$LATEST_SCAN/logs/scan.log" ]; then
        echo "📋 Latest log entries:"
        tail -30 "$LATEST_SCAN/logs/scan.log"
        echo ""
    fi
    
    # Check for results
    echo "📁 Output files:"
    ls -lh "$LATEST_SCAN"/*.ndjson 2>/dev/null | head -10 || echo "No .ndjson files yet"
    echo ""
    
    # Check for per-account+region files
    echo "📁 Per-account+region files:"
    ls -lh "$LATEST_SCAN"/results_*.ndjson 2>/dev/null | head -5 || echo "No results files yet"
    ls -lh "$LATEST_SCAN"/inventory_*.ndjson 2>/dev/null | head -5 || echo "No inventory files yet"
fi


