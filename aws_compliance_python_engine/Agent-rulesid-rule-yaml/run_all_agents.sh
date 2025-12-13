#!/bin/bash
# Run all 3 agents in sequence

set -e  # Exit on error

echo "========================================"
echo "3-AGENT PIPELINE"
echo "Processing 5 services: accessanalyzer, acm, athena, apigateway, s3"
echo "========================================"
echo ""

# Check for API key
if [ -z "$OPENAI_API_KEY" ]; then
    echo "❌ Error: OPENAI_API_KEY not set"
    echo "Set it with: export OPENAI_API_KEY='your-key'"
    exit 1
fi

# Create output directory
mkdir -p agents/output

echo "Step 1/3: AI Requirements Generator"
echo "------------------------------------"
python3 agents/agent1_requirements_generator.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 1 failed"
    exit 1
fi
echo ""

echo "Step 2/3: Function Name Validator"
echo "------------------------------------"
python3 agents/agent2_function_validator.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 2 failed"
    exit 1
fi
echo ""

echo "Step 3/3: Field Name Validator"
echo "------------------------------------"
python3 agents/agent3_field_validator.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 3 failed"
    exit 1
fi
echo ""

echo "========================================"
echo "✅ PIPELINE COMPLETE"
echo "========================================"
echo ""
echo "Output files created:"
echo "  1. agents/output/requirements_initial.json"
echo "  2. agents/output/requirements_with_functions.json"
echo "  3. agents/output/requirements_validated.json ← FINAL"
echo ""
echo "Use requirements_validated.json as single source of truth!"
