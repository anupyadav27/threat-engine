#!/bin/bash
# Run all Azure compliance agents in sequence

set -e  # Exit on error

echo "========================================"
echo "AZURE AGENTIC AI PIPELINE"
echo "Processing Azure Services"
echo "========================================"
echo ""

# Check for API key
if [ -z "$ANTHROPIC_API_KEY" ]; then
    echo "❌ Error: ANTHROPIC_API_KEY not set"
    echo "Set it with: export ANTHROPIC_API_KEY='your-key'"
    exit 1
fi

# Create output and logs directories
mkdir -p Agent-ruleid-rule-yaml/output
mkdir -p Agent-ruleid-rule-yaml/logs

echo "📋 Pipeline Configuration"
echo "------------------------------------"
echo "Working Directory: $(pwd)"
echo "Azure SDK Catalog: Agent-ruleid-rule-yaml/azure_sdk_dependencies_with_python_names.json"
echo "Output Directory: Agent-ruleid-rule-yaml/output"
echo "Logs Directory: Agent-ruleid-rule-yaml/logs"
echo ""

echo "Step 1/7: AI Requirements Generator"
echo "------------------------------------"
echo "Generating compliance requirements from metadata..."
python3 Agent-ruleid-rule-yaml/agent1_requirements_generator.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 1 failed"
    exit 1
fi
echo "✅ Requirements generated"
echo ""

echo "Step 2/7: Azure SDK Operation Validator"
echo "------------------------------------"
echo "Validating Azure SDK operations..."
python3 Agent-ruleid-rule-yaml/agent2_function_validator.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 2 failed"
    exit 1
fi
echo "✅ Operations validated"
echo ""

echo "Step 3/7: Field Name Validator"
echo "------------------------------------"
echo "Validating field names against Azure SDK..."
python3 Agent-ruleid-rule-yaml/agent3_field_validator.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 3 failed"
    exit 1
fi
echo "✅ Fields validated"
echo ""

echo "Step 4/7: YAML Generator"
echo "------------------------------------"
echo "Generating YAML rule files..."
python3 Agent-ruleid-rule-yaml/agent4_yaml_generator.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 4 failed"
    exit 1
fi
echo "✅ YAML files generated"
echo ""

echo "Step 5/7: Compliance Engine Tester"
echo "------------------------------------"
echo "Testing generated rules with engine..."
python3 Agent-ruleid-rule-yaml/agent5_engine_tester.py
if [ $? -ne 0 ]; then
    echo "⚠️  Agent 5 had errors (continuing...)"
fi
echo "✅ Engine tests completed"
echo ""

echo "Step 6/7: Error Analyzer"
echo "------------------------------------"
echo "Analyzing test errors..."
python3 Agent-ruleid-rule-yaml/agent6_error_analyzer.py
if [ $? -ne 0 ]; then
    echo "⚠️  Agent 6 had errors (continuing...)"
fi
echo "✅ Error analysis completed"
echo ""

echo "Step 7/7: Auto Corrector"
echo "------------------------------------"
echo "Auto-correcting errors..."
python3 Agent-ruleid-rule-yaml/agent7_auto_corrector.py
if [ $? -ne 0 ]; then
    echo "⚠️  Agent 7 had errors (continuing...)"
fi
echo "✅ Auto-correction completed"
echo ""

echo "========================================"
echo "✅ PIPELINE COMPLETE"
echo "========================================"
echo ""
echo "📁 Output Files Created:"
echo "  1. Agent-ruleid-rule-yaml/output/requirements_initial.json"
echo "  2. Agent-ruleid-rule-yaml/output/requirements_with_functions.json"
echo "  3. Agent-ruleid-rule-yaml/output/requirements_validated.json ← FINAL"
echo "  4. Agent-ruleid-rule-yaml/output/{service}_generated.yaml"
echo "  5. Agent-ruleid-rule-yaml/output/engine_test_results.json"
echo ""
echo "📊 Pipeline Statistics:"
if [ -f "Agent-ruleid-rule-yaml/output/requirements_validated.json" ]; then
    total_rules=$(python3 -c "import json; d=json.load(open('Agent-ruleid-rule-yaml/output/requirements_validated.json')); print(sum(len(v) for v in d.values()))" 2>/dev/null || echo "N/A")
    echo "  - Total Rules Processed: $total_rules"
fi

if [ -f "Agent-ruleid-rule-yaml/output/engine_test_results.json" ]; then
    passed=$(python3 -c "import json; d=json.load(open('Agent-ruleid-rule-yaml/output/engine_test_results.json')); print(d.get('passed', 0))" 2>/dev/null || echo "N/A")
    failed=$(python3 -c "import json; d=json.load(open('Agent-ruleid-rule-yaml/output/engine_test_results.json')); print(d.get('failed', 0))" 2>/dev/null || echo "N/A")
    echo "  - Tests Passed: $passed"
    echo "  - Tests Failed: $failed"
fi

echo ""
echo "📝 Logs:"
echo "  - Pipeline Log: Agent-ruleid-rule-yaml/logs/pipeline.log"
echo ""
echo "🎯 Next Steps:"
echo "  1. Review requirements_validated.json"
echo "  2. Check generated YAML files in output/"
echo "  3. Review engine_test_results.json for any failures"
echo "  4. Deploy validated YAMLs to services/ directory"
echo ""
echo "Use requirements_validated.json as single source of truth!"

