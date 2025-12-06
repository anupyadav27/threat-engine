#!/bin/bash
clear
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║             🔍 DEEP SEARCH MONITOR - Live Progress 🔍                       ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

total=1400
processed=$(grep -c "Deep search: alicloud\." alicloud_deep_search.log 2>/dev/null || echo "0")
pct=$(echo "scale=1; ($processed / $total) * 100" | bc 2>/dev/null || echo "0")

echo "📊 PROGRESS: $processed / $total ($pct%)"
echo ""

found=$(grep -c "✅.*Found.*high-quality" alicloud_deep_search.log 2>/dev/null || echo "0")
fallback=$(grep -c "📚.*Using fallback" alicloud_deep_search.log 2>/dev/null || echo "0")
fake_404=$(grep -c "❌ Fake 404:" alicloud_deep_search.log 2>/dev/null || echo "0")

echo "📈 RESULTS:"
echo "  ✅ High-quality found: $found"
echo "  📚 Fallback used:      $fallback"
echo "  ❌ Fake 404s caught:   $fake_404"
echo ""

echo "🔍 Last 5 processed:"
grep "Deep search: alicloud\." alicloud_deep_search.log | tail -5 | sed 's/.*Deep search: /  /'
echo ""

# Show any successful finds
echo "✅ Recent successful finds:"
grep -A 2 "Selected TOP 2 URLs:" alicloud_deep_search.log | tail -10 | grep "Score:" | tail -3 || echo "  None in recent batch"
echo ""

if ps aux | grep '[a]licloud_deep_search' >/dev/null; then
    echo "Status: ✅ RUNNING"
else
    echo "Status: ⏸️  STOPPED"
fi

