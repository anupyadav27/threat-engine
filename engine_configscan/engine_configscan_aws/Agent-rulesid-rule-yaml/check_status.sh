#!/bin/bash
# Quick status checker for sequential run

cd /Users/apple/Desktop/threat-engine/aws_compliance_python_engine/Agent-rulesid-rule-yaml

echo "══════════════════════════════════════════"
echo "SEQUENTIAL RUN STATUS"
echo "══════════════════════════════════════════"
echo ""

# Check if running
if ps aux | grep "run_sequential_all" | grep -v grep > /dev/null; then
    echo "✅ Process: RUNNING"
    PID=$(ps aux | grep "run_sequential_all" | grep -v grep | head -1 | awk '{print $2}')
    echo "   PID: $PID"
else
    echo "❌ Process: NOT RUNNING"
fi

# Check Python
if ps aux | grep "agent1_requirements" | grep -v grep > /dev/null; then
    echo "✅ Agent1: ACTIVE"
else
    echo "⏸  Agent1: Not started or between agents"
fi

# Check caffeinate
if ps aux | grep "caffeinate" | grep -v grep > /dev/null; then
    echo "✅ Sleep prevention: ACTIVE"
else
    echo "⚠️  Sleep prevention: Not active"
fi

echo ""
echo "══════════════════════════════════════════"
echo "PROGRESS"
echo "══════════════════════════════════════════"
echo ""

# Count processed services from log
if [ -f "sequential_run.log" ]; then
    LINES=$(wc -l < sequential_run.log)
    echo "Log lines: $LINES"
    echo ""
    echo "Last 15 lines of log:"
    echo "────────────────────────────────────────"
    tail -15 sequential_run.log
else
    echo "No log file yet"
fi

echo ""
echo "══════════════════════════════════════════"
echo "OUTPUT FILES"
echo "══════════════════════════════════════════"
echo ""

if [ -d "output" ] && [ "$(ls -A output 2>/dev/null)" ]; then
    ls -lh output/
    echo ""
    
    # Try to count rules if validated file exists
    if [ -f "output/requirements_validated.json" ]; then
        echo "Current stats:"
        python3 << 'PYEOF'
import json
try:
    with open('output/requirements_validated.json') as f:
        data = json.load(f)
    services = len(data)
    total = sum(len(rules) for rules in data.values())
    validated = sum(1 for svc in data.values() for r in svc if r.get('all_fields_valid'))
    print(f"  Services: {services}/101")
    print(f"  Rules: {total}")
    if total > 0:
        print(f"  Validated: {validated} ({validated/total*100:.1f}%)")
except Exception as e:
    print(f"  Processing... ({e})")
PYEOF
    fi
else
    echo "Output directory empty (agents not finished yet)"
fi

echo ""
echo "══════════════════════════════════════════"
echo "To watch live: tail -f sequential_run.log"
echo "══════════════════════════════════════════"

