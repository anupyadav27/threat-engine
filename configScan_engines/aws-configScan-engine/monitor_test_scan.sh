#!/bin/bash
# Monitor test scan progress and show file creation

SCAN_FOLDER="engines-output/aws-configScan-engine/output"
LATEST_SCAN=$(ls -t $SCAN_FOLDER/test_performance_* 2>/dev/null | head -1)

if [ -z "$LATEST_SCAN" ]; then
    echo "No test scan folder found"
    exit 1
fi

echo "Monitoring: $LATEST_SCAN"
echo "Services: EC2, Inspector, SageMaker"
echo "Regions: All enabled regions"
echo "Filters: Customer-managed resources only"
echo "Press Ctrl+C to stop"
echo ""

while true; do
    # Check if scan is running
    if ps aux | grep -E "test_performance" | grep -v grep > /dev/null; then
        echo "[$(date +%H:%M:%S)] Scan running..."
        
        # Count results files
        RESULTS_COUNT=$(find $LATEST_SCAN -name "results_*.ndjson" 2>/dev/null | wc -l | tr -d ' ')
        INVENTORY_COUNT=$(find $LATEST_SCAN -name "inventory_*.ndjson" 2>/dev/null | wc -l | tr -d ' ')
        RAW_COUNT=$(find $LATEST_SCAN/raw -name "*.json" 2>/dev/null | wc -l | tr -d ' ')
        
        echo "  Results files: $RESULTS_COUNT"
        echo "  Inventory files: $INVENTORY_COUNT"
        echo "  Raw data files: $RAW_COUNT"
        
        # Show latest results file
        if [ $RESULTS_COUNT -gt 0 ]; then
            LATEST_RESULTS=$(find $LATEST_SCAN -name "results_*.ndjson" 2>/dev/null | xargs ls -t | head -1)
            if [ -n "$LATEST_RESULTS" ]; then
                LINES=$(wc -l < "$LATEST_RESULTS" 2>/dev/null | tr -d ' ')
                SIZE=$(ls -lh "$LATEST_RESULTS" 2>/dev/null | awk '{print $5}')
                echo "  Latest: $(basename $LATEST_RESULTS) - $LINES lines, $SIZE"
            fi
        fi
        
        # Show FPGA image count (to verify filter)
        if [ -f "$LATEST_SCAN/inventory.ndjson" ]; then
            FPGA_COUNT=$(grep -c "fpga-image" "$LATEST_SCAN/inventory.ndjson" 2>/dev/null || echo "0")
            echo "  FPGA images in inventory: $FPGA_COUNT (should be customer-managed only)"
        fi
    else
        echo "[$(date +%H:%M:%S)] Scan completed"
        break
    fi
    
    sleep 10
done

echo ""
echo "Final status:"
find $LATEST_SCAN -name "*.ndjson" 2>/dev/null | wc -l | xargs echo "Total .ndjson files:"
