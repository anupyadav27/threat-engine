#!/bin/bash
# Monitor OCI enhancement progress and auto-retry failed rules

PROGRESS_FILE="enhancement_progress_oci.json"
CHECK_INTERVAL=600  # 10 minutes in seconds

echo "=========================================="
echo "OCI Enhancement Monitor & Auto-Retry"
echo "=========================================="
echo ""
echo "Monitoring progress every 10 minutes..."
echo "Will automatically retry failed rules when complete."
echo ""

while true; do
    if [ ! -f "$PROGRESS_FILE" ]; then
        echo "❌ Progress file not found. Exiting."
        exit 1
    fi
    
    # Get current progress
    LAST_INDEX=$(cat $PROGRESS_FILE | grep last_index | awk -F': ' '{print $2}' | tr -d ',')
    ENHANCED=$(cat $PROGRESS_FILE | grep enhanced_count | awk -F': ' '{print $2}' | tr -d ',')
    FAILED_COUNT=$(cat $PROGRESS_FILE | grep -o '"oci\.' | wc -l | tr -d ' ')
    TOTAL=1914
    
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    PERCENT=$(echo "scale=1; ($ENHANCED / $TOTAL) * 100" | bc)
    
    echo "[$TIMESTAMP] Progress: $ENHANCED/$TOTAL enhanced ($PERCENT%) | Index: $LAST_INDEX | Failed: $FAILED_COUNT"
    
    # Check if complete
    if [ "$LAST_INDEX" -ge "$TOTAL" ]; then
        echo ""
        echo "=========================================="
        echo "✅ FIRST PASS COMPLETE!"
        echo "=========================================="
        echo "Total Enhanced: $ENHANCED"
        echo "Total Failed: $FAILED_COUNT"
        echo ""
        
        if [ "$FAILED_COUNT" -gt 0 ]; then
            echo "🔄 Starting retry for $FAILED_COUNT failed rules..."
            echo ""
            python3 retry_failed_rules.py
            
            echo ""
            echo "=========================================="
            echo "✅ RETRY COMPLETE!"
            echo "=========================================="
        else
            echo "✅ No failed rules to retry!"
        fi
        
        exit 0
    fi
    
    # Wait 10 minutes before next check
    sleep $CHECK_INTERVAL
done

