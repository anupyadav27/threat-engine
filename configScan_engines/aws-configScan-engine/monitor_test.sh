#!/bin/bash
# Monitor test scan progress

echo "=========================================="
echo "TEST SCAN MONITOR"
echo "=========================================="
echo ""

# Check if scan is running
if pgrep -f "test_performance_optimized.py" > /dev/null; then
    echo "✅ Scan is RUNNING"
    echo ""
    ps aux | grep "[p]ython.*test_performance" | head -2
else
    echo "⚠️  Scan is NOT running"
fi

echo ""
echo "Output files:"
find engines-output/aws-configScan-engine/output -name "test_performance_*" -type d -mmin -10 2>/dev/null | head -1 | while read folder; do
    echo "  Folder: $(basename $folder)"
    echo "  Results: $(ls -1 $folder/results_*.ndjson 2>/dev/null | wc -l) files"
    echo "  Inventory: $(ls -1 $folder/inventory_*.ndjson 2>/dev/null | wc -l) files"
    echo ""
    echo "  Recent files:"
    ls -lht $folder/*.ndjson 2>/dev/null | head -5 | awk '{print "    " $9 " (" $5 ")"}'
done

echo ""
echo "=========================================="

