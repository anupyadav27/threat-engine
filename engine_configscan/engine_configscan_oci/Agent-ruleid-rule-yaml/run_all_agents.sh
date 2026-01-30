#!/bin/bash

echo "================================================================================"
echo "OCI Agentic AI Pipeline"
echo "================================================================================"

if [ -z "$OPENAI_API_KEY" ]; then
    echo "❌ Error: OPENAI_API_KEY not set"
    exit 1
fi

mkdir -p output

echo "Step 1/4: Agent 1 (Requirements Generator)..."
python3 agent1_requirements_generator.py || exit 1

echo "Step 2/4: Agent 2 (Operation Validator)..."
python3 agent2_operation_validator.py || exit 1

echo "Step 3/4: Agent 3 (Field Validator)..."
python3 agent3_field_validator.py || exit 1

echo "Step 4/4: Agent 4 (YAML Generator)..."
python3 agent4_yaml_generator.py || exit 1

echo ""
echo "================================================================================"
echo "✅ OCI Pipeline Complete!"
echo "================================================================================"

