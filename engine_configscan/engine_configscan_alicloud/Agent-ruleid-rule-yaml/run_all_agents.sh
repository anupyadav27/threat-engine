#!/bin/bash

echo "================================================================================"
echo "Alibaba Cloud Agentic AI Pipeline"
echo "================================================================================"

if [ -z "$OPENAI_API_KEY" ]; then
    echo "❌ Error: OPENAI_API_KEY not set"
    exit 1
fi

mkdir -p output

echo "Step 1/4: Agent 1..."
python3 agent1_requirements_generator.py || exit 1

echo "Step 2/4: Agent 2..."
python3 agent2_operation_validator.py || exit 1

echo "Step 3/4: Agent 3..."
python3 agent3_field_validator.py || exit 1

echo "Step 4/4: Agent 4..."
python3 agent4_yaml_generator.py || exit 1

echo ""
echo "================================================================================"
echo "✅ Alibaba Cloud Pipeline Complete!"
echo "================================================================================"
