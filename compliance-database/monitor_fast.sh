#!/bin/bash
clear
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                  ⚡ FAST GENERATOR - LIVE MONITOR ⚡                         ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Progress
total=1400
processed=$(grep -c "🔧.*Generating" alicloud_fast.log 2>/dev/null || echo "0")
pct=$(echo "scale=1; ($processed / $total) * 100" | bc 2>/dev/null || echo "0")

echo "📊 PROGRESS: $processed / $total ($pct%)"
echo ""

# Outcomes
generated=$(grep -c "✅ Working:" alicloud_fast.log 2>/dev/null || echo "0")
fake=$(grep -c "❌ Fake 404:" alicloud_fast.log 2>/dev/null || echo "0")
fallback=$(grep -c "📚 Fallback:" alicloud_fast.log 2>/dev/null || echo "0")

echo "📈 OUTCOMES:"
echo "  ✅ Generated working: $generated"
echo "  ❌ Fake 404s caught:  $fake"
echo "  📚 Fallback used:     $fallback"
echo ""

# Speed estimate
if [ "$processed" -gt 10 ]; then
    elapsed=2  # minutes elapsed
    rate=$(echo "scale=0; $processed / $elapsed" | bc)
    remaining=$(echo "scale=0; ($total - $processed) / $rate" | bc 2>/dev/null || echo "N/A")
    echo "⏱️  Speed: ~$rate rules/min | Est. remaining: ~$remaining minutes"
    echo ""
fi

echo "🔄 Last 10 processed:"
grep "🔧 alicloud\." alicloud_fast.log | tail -10 | sed 's/.*🔧 /  /'
echo ""

# Status
if ps aux | grep '[a]licloud_fast_smart' >/dev/null; then
    echo "Status: ✅ RUNNING"
else
    echo "Status: ⏸️  STOPPED or COMPLETE"
fi

