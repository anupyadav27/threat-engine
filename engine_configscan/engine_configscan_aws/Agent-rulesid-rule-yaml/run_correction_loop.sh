#!/bin/bash
# Recursive correction loop: Agents 5 → 6 → 7 → 5 (repeat until no errors)

set -e

MAX_ITERATIONS=3

echo "════════════════════════════════════════════════════════════"
echo "CORRECTION LOOP - AGENTS 5, 6, 7 (Max $MAX_ITERATIONS iterations)"
echo "════════════════════════════════════════════════════════════"
echo ""

for i in $(seq 1 $MAX_ITERATIONS); do
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "ITERATION $i/$MAX_ITERATIONS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    
    # Agent 5: Test (skip copy on iterations > 1)
    if [ $i -eq 1 ]; then
        echo "Agent 5: Copy YAMLs & Test"
        python3 agent5_engine_tester.py
    else
        echo "Agent 5: Re-test (YAMLs already copied)"
        # TODO: Create agent5_retest.py that only tests, doesn't copy
        python3 agent5_engine_tester.py
    fi
    
    if [ $? -ne 0 ]; then
        echo "⚠️  Agent 5 had issues"
    fi
    echo ""
    
    # Check if test results exist
    if [ ! -f "output/engine_test_results.json" ]; then
        echo "⏭️  No test results, stopping loop"
        break
    fi
    
    # Agent 6: Analyze errors
    echo "Agent 6: Analyze errors"
    python3 agent6_error_analyzer.py
    
    if [ $? -ne 0 ]; then
        echo "❌ Agent 6 failed"
        break
    fi
    echo ""
    
    # Check if fixes exist
    if [ ! -f "output/error_analysis_and_fixes.json" ]; then
        echo "✅ No errors found - all tests passed!"
        break
    fi
    
    # Count fixes
    FIX_COUNT=$(python3 -c "import json; data=json.load(open('output/error_analysis_and_fixes.json')); print(sum(len(fixes) for fixes in data.values()))")
    
    if [ "$FIX_COUNT" -eq "0" ]; then
        echo "✅ No fixes needed - tests passed!"
        break
    fi
    
    echo "Found $FIX_COUNT issues to fix"
    echo ""
    
    # Agent 7: Apply fixes
    echo "Agent 7: Apply auto-corrections"
    python3 agent7_auto_corrector.py
    
    if [ $? -ne 0 ]; then
        echo "❌ Agent 7 failed"
        break
    fi
    echo ""
    
    echo "✅ Iteration $i complete - $FIX_COUNT fixes applied"
    
    if [ $i -lt $MAX_ITERATIONS ]; then
        echo "   Re-testing in next iteration..."
    fi
done

echo ""
echo "════════════════════════════════════════════════════════════"
echo "✅ CORRECTION LOOP COMPLETE"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Final status in: output/engine_test_results.json"
echo "YAMLs deployed to: ../services/*/rules/"

