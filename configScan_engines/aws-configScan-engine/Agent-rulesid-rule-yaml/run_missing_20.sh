#!/bin/bash
# Run agents 1-4 for the 20 missing services

set -e

echo "════════════════════════════════════════════════════════════"
echo "PROCESSING 20 MISSING SERVICES"
echo "════════════════════════════════════════════════════════════"
echo ""
echo "Services: cognito, vpc, eventbridge, fargate, macie, and 15 more"
echo "Estimated time: 15-20 minutes"
echo ""

# Check API key
if [ -z "$OPENAI_API_KEY" ]; then
    echo "❌ OPENAI_API_KEY not set"
    exit 1
fi

#  Prevent sleep
caffeinate -dims -w $$ &
CAFFEINATE_PID=$!
trap "kill $CAFFEINATE_PID 2>/dev/null || true" EXIT INT TERM

START=$(date +%s)

echo "Agent 1: AI Requirements Generator"
python3 agent1_requirements_generator.py
echo "✅ Agent 1 done"
echo ""

echo "Agent 2: Function Validator"
python3 agent2_function_validator.py
echo "✅ Agent 2 done"
echo ""

echo "Agent 3: Field Validator"
python3 agent3_field_validator.py
echo "✅ Agent 3 done"
echo ""

echo "Agent 4: YAML Generator"
python3 agent4_yaml_generator.py
echo "✅ Agent 4 done"
echo ""

END=$(date +%s)
DURATION=$((END - START))
MIN=$((DURATION / 60))
SEC=$((DURATION % 60))

echo "════════════════════════════════════════════════════════════"
echo "✅ COMPLETE - 20 Missing Services Processed"
echo "════════════════════════════════════════════════════════════"
echo "Duration: ${MIN}m ${SEC}s"
echo ""

# Count new YAMLs
NEW_YAMLS=$(ls output/*_generated.yaml 2>/dev/null | wc -l | tr -d ' ')
echo "New YAML files: $NEW_YAMLS"
echo ""

echo "Next steps:"
echo "  1. Check: ls output/*.yaml"
echo "  2. Copy to services: python3 agent5_engine_tester.py"
echo "  3. Combine with previous 80 YAMLs"

