#!/bin/bash
# Sequential runner for all 101 services
# Runs agents 1-4 in sequence for all services
# Prevents system sleep during execution

set -e

echo "========================================"
echo "SEQUENTIAL AGENT RUNNER - ALL SERVICES"
echo "========================================"
echo ""
echo "Processing 101 AWS services"
echo "Estimated time: 1-2 hours"
echo ""

# Check for API key
if [ -z "$OPENAI_API_KEY" ]; then
    echo "❌ Error: OPENAI_API_KEY not set"
    echo "Set it with: export OPENAI_API_KEY='your-key'"
    exit 1
fi

# Prevent system sleep during execution (macOS)
echo "⏰ Preventing system sleep during execution..."
caffeinate -dims -w $$ &
CAFFEINATE_PID=$!

# Cleanup function
cleanup() {
    echo ""
    echo "🔓 Re-enabling system sleep..."
    kill $CAFFEINATE_PID 2>/dev/null || true
}

# Set trap to cleanup on exit
trap cleanup EXIT INT TERM

# Create output directory
mkdir -p output

START_TIME=$(date +%s)

echo "Step 1/4: AI Requirements Generator (GPT-4o)"
echo "--------------------------------------------"
python3 agent1_requirements_generator.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 1 failed"
    exit 1
fi
echo "✅ Agent 1 complete"
echo ""

echo "Step 2/4: Function Name Validator"
echo "----------------------------------"
python3 agent2_function_validator.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 2 failed"
    exit 1
fi
echo "✅ Agent 2 complete"
echo ""

echo "Step 3/4: Field Name Validator"
echo "-------------------------------"
python3 agent3_field_validator.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 3 failed"
    exit 1
fi
echo "✅ Agent 3 complete"
echo ""

echo "Step 4/7: YAML Generator"
echo "------------------------"
python3 agent4_yaml_generator.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 4 failed"
    exit 1
fi
echo "✅ Agent 4 complete"
echo ""

echo "Step 5/7: Copy YAMLs to Services & Engine Testing"
echo "--------------------------------------------------"
python3 agent5_engine_tester.py
if [ $? -ne 0 ]; then
    echo "⚠️  Agent 5 had issues (may be expected if AWS creds not available)"
fi
echo "✅ Agent 5 complete"
echo ""

echo "Step 6/7: Error Analysis"
echo "------------------------"
if [ -f "output/engine_test_results.json" ]; then
    python3 agent6_error_analyzer.py
    echo "✅ Agent 6 complete"
else
    echo "⏭️  Skipping Agent 6 (no test results)"
fi
echo ""

echo "Step 7/7: Auto-Correction"
echo "-------------------------"
if [ -f "output/error_analysis_and_fixes.json" ]; then
    python3 agent7_auto_corrector.py
    echo "✅ Agent 7 complete"
else
    echo "⏭️  Skipping Agent 7 (no fixes needed)"
fi
echo ""

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))
MINUTES=$((DURATION / 60))
SECONDS=$((DURATION % 60))

echo "========================================"
echo "✅ COMPLETE 7-AGENT PIPELINE FINISHED"
echo "========================================"
echo ""
echo "Duration: ${MINUTES}m ${SECONDS}s"
echo ""

# Count results
if [ -f "output/requirements_validated.json" ]; then
    SERVICES=$(cat output/requirements_validated.json | python3 -c "import sys, json; data=json.load(sys.stdin); print(len(data))")
    TOTAL_RULES=$(cat output/requirements_validated.json | python3 -c "import sys, json; data=json.load(sys.stdin); print(sum(len(rules) for rules in data.values()))")
    VALIDATED=$(cat output/requirements_validated.json | python3 -c "import sys, json; data=json.load(sys.stdin); print(sum(1 for svc in data.values() for r in svc if r.get('all_fields_valid')))")
    YAML_COUNT=$(ls output/*.yaml 2>/dev/null | wc -l | tr -d ' ')
    
    echo "📊 GENERATION RESULTS:"
    echo "  Services processed: $SERVICES"
    echo "  Total rules: $TOTAL_RULES"
    echo "  Validated rules: $VALIDATED"
    echo "  YAML files created: $YAML_COUNT"
    
    if [ $TOTAL_RULES -gt 0 ]; then
        RATE=$(python3 -c "print(f'{$VALIDATED/$TOTAL_RULES*100:.1f}%')")
        echo "  Validation rate: $RATE"
    fi
    echo ""
fi

# Test results
if [ -f "output/engine_test_results.json" ]; then
    echo "🔬 ENGINE TEST RESULTS:"
    python3 << 'EOF'
import json
try:
    with open('output/engine_test_results.json') as f:
        results = json.load(f)
    tested = len(results)
    passed = sum(1 for r in results.values() if r.get('success'))
    total_checks = sum(r.get('checks_count', 0) for r in results.values())
    print(f"  Services tested: {tested}")
    print(f"  Tests passed: {passed}/{tested}")
    print(f"  Total checks executed: {total_checks}")
except:
    print("  No test results available")
EOF
    echo ""
fi

echo "📁 OUTPUT LOCATIONS:"
echo "  Generated YAMLs: output/*.yaml"
echo "  Validated requirements: output/requirements_validated.json"
if [ -f "output/engine_test_results.json" ]; then
    echo "  Test results: output/engine_test_results.json"
fi
echo ""

echo "📋 NEXT STEPS:"
echo "  1. Review: output/requirements_validated.json"
echo "  2. Check YAMLs: ls output/*.yaml"
if [ -f "output/engine_test_results.json" ]; then
    echo "  3. Review test results: output/engine_test_results.json"
    echo "  4. YAMLs copied to: ../services/*/rules/*.yaml"
else
    echo "  3. To test with real AWS account, ensure AWS credentials configured"
    echo "  4. Then re-run agents 5-7 for testing & correction"
fi

