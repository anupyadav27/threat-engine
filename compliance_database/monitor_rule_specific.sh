#!/bin/bash
clear
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║            🎯 RULE-SPECIFIC CONTENT SEARCH - MONITOR 🎯                     ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

total=1400
processed=$(grep -c "🔍 alicloud\." alicloud_rule_specific.log 2>/dev/null || echo "0")
pct=$(echo "scale=1; ($processed / $total) * 100" | bc 2>/dev/null || echo "0")

echo "📊 PROGRESS: $processed / $total ($pct%)"
echo ""

exact=$(grep -c "✅ Exact match found!" alicloud_rule_specific.log 2>/dev/null || echo "0")
partial=$(grep -c "✅ Partial match found!" alicloud_rule_specific.log 2>/dev/null || echo "0")
fallback=$(grep -c "📚 No match, using fallback" alicloud_rule_specific.log 2>/dev/null || echo "0")
content_matches=$(grep -c "✅ Match" alicloud_rule_specific.log 2>/dev/null || echo "0")

echo "📈 RESULTS:"
echo "  ✅ Exact matches (≥70%):   $exact"
echo "  ⚠️  Partial matches (30-70%): $partial"
echo "  📚 Fallback (<30%):        $fallback"
echo "  🎯 Content-matched URLs:   $content_matches"
echo ""

if [ "$processed" -gt 0 ]; then
    match_rate=$(echo "scale=1; (($exact + $partial) / $processed) * 100" | bc)
    echo "🎯 Match Rate: $match_rate%"
    echo ""
fi

echo "🔍 Recent activity:"
grep -E "🔍 alicloud\.|✅ Match|✅ Exact|📚 No match" alicloud_rule_specific.log | tail -10
echo ""

if ps aux | grep '[a]licloud_rule_specific' >/dev/null; then
    echo "Status: ✅ RUNNING"
else
    echo "Status: ⏸️  STOPPED"
fi

