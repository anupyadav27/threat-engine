#!/bin/bash

clear

cat << 'HEADER'
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║              🔍 ALICLOUD URL VALIDATION - LIVE MONITOR 🔍                   ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
HEADER

echo ""
date
echo ""

# Progress
total=1400
processed=$(grep -c "📚 Using fallback\|✅ MATCH" alicloud_intelligent.log 2>/dev/null || echo "0")
pct=$(echo "scale=2; ($processed / $total) * 100" | bc 2>/dev/null || echo "0.00")
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 OVERALL PROGRESS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Rules Processed:  $processed / $total ($pct%)"

# Calculate time estimate
if [ "$processed" -gt 5 ]; then
    # Estimate based on current rate
    rate=$(echo "scale=2; $processed / 10" | bc)  # rules per minute (10 min elapsed)
    remaining=$(echo "scale=0; ($total - $processed) / $rate" | bc 2>/dev/null || echo "N/A")
    echo "  Est. Remaining:   ~$remaining minutes"
fi

echo ""

# Outcomes
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📈 VALIDATION OUTCOMES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
fake=$(grep -c "❌ Contains:" alicloud_intelligent.log 2>/dev/null || echo "0")
matches=$(grep -c "✅ MATCH!" alicloud_intelligent.log 2>/dev/null || echo "0")
fallback=$(grep -c "📚 Using fallback:" alicloud_intelligent.log 2>/dev/null || echo "0")
low_rel=$(grep -c "⚠️  Valid page but low relevance" alicloud_intelligent.log 2>/dev/null || echo "0")

echo "  ❌ Fake 404 Pages Detected:  $fake"
echo "  ✅ Real Matches Found:       $matches"
echo "  ⚠️  Low Relevance Pages:     $low_rel"
echo "  📚 Fallback URLs Used:       $fallback"
echo ""

# Current activity
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔄 CURRENTLY PROCESSING"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
tail -15 alicloud_intelligent.log | grep -E "🔍 alicloud\.|🧪 Testing:|✅ MATCH|❌|📚" | tail -10
echo ""

# Process status
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
if ps aux | grep '[a]licloud_intelligent' >/dev/null; then
    echo "Status: ✅ RUNNING"
else
    echo "Status: ⏸️  STOPPED"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Commands:"
echo "  • Re-run this:           ./monitor_validation.sh"
echo "  • View verified URLs:    cat alicloud/final/VERIFIED_URLS_SO_FAR.json | jq"
echo "  • Extract latest:        python3 extract_verified_urls.py"
echo "  • Live log:              tail -f alicloud_intelligent.log"
echo ""

