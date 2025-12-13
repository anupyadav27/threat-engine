#!/bin/bash

echo "================================================================================"
echo "GCP Agentic AI Pipeline - Complete Run"
echo "================================================================================"
echo ""

# Check OPENAI_API_KEY
if [ -z "$OPENAI_API_KEY" ]; then
    echo "❌ Error: OPENAI_API_KEY not set"
    echo "Set it with: export OPENAI_API_KEY='your-key'"
    exit 1
fi

# Create output directory
mkdir -p output

# Run Agent 1
echo "Step 1/4: Running Agent 1 (Requirements Generator)..."
python3 agent1_requirements_generator.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 1 failed"
    exit 1
fi
echo ""

# Run Agent 2
echo "Step 2/4: Running Agent 2 (Operation Validator)..."
python3 agent2_operation_validator.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 2 failed"
    exit 1
fi
echo ""

# Run Agent 3
echo "Step 3/4: Running Agent 3 (Field Validator)..."
python3 agent3_field_validator.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 3 failed"
    exit 1
fi
echo ""

# Run Agent 4
echo "Step 4/4: Running Agent 4 (YAML Generator)..."
python3 agent4_yaml_generator.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 4 failed"
    exit 1
fi
echo ""

echo "================================================================================"
echo "✅ GCP Agentic AI Pipeline Complete!"
echo "================================================================================"
echo ""
echo "Output files:"
echo "  - output/requirements_initial.json"
echo "  - output/requirements_with_operations.json"
echo "  - output/requirements_validated.json"
echo "  - output/{service}_generated.yaml"
echo ""
echo "================================================================================"

