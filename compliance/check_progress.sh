#!/bin/bash

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║                    📊 REAL-TIME PROGRESS TRACKER 📊                         ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Count processed rules
echo "📈 PROGRESS:"
echo "============"
total=1400
processed=$(grep -c "🔍.*searching for real pages\|Using fallback" alicloud_intelligent.log 2>/dev/null || echo "0")
pct=$(echo "scale=1; ($processed / $total) * 100" | bc 2>/dev/null || echo "0")
echo "Rules Processed: $processed / $total ($pct%)"
echo ""

# Count outcomes
echo "📊 OUTCOMES:"
echo "============"
fake_404=$(grep -c "❌ Contains:" alicloud_intelligent.log 2>/dev/null || echo "0")
matches=$(grep -c "✅ MATCH!" alicloud_intelligent.log 2>/dev/null || echo "0")
fallbacks=$(grep -c "📚 Using fallback:" alicloud_intelligent.log 2>/dev/null || echo "0")
echo "Fake 404 Pages Detected: $fake_404"
echo "Real Matches Found:      $matches"
echo "Fallback URLs Used:      $fallbacks"
echo ""

# Show last 10 processed rules
echo "📋 LAST 10 PROCESSED RULES:"
echo "============================"
grep -E "🔍 alicloud\." alicloud_intelligent.log 2>/dev/null | tail -10 | sed 's/.*🔍 //' | sed 's/:.*//'
echo ""

# Show any successful matches
echo "✅ SUCCESSFUL MATCHES FOUND:"
echo "============================="
grep -B 2 "✅ MATCH!" alicloud_intelligent.log 2>/dev/null | grep "alicloud\." | tail -5 || echo "None yet"
echo ""

echo "🔄 Process Status: $(ps aux | grep '[a]licloud_intelligent' >/dev/null && echo 'RUNNING ✅' || echo 'STOPPED ❌')"
echo ""
echo "Monitor live: tail -f alicloud_intelligent.log"

