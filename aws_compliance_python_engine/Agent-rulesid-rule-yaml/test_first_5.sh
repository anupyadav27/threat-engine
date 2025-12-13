#!/bin/bash
# Test with first 5 services only

set -e

echo "========================================"
echo "TEST RUN - FIRST 5 SERVICES"
echo "========================================"
echo ""

# Backup original agent1
cp agent1_requirements_generator.py agent1_requirements_generator.py.backup

# Create test version with only 5 services
cat > agent1_requirements_generator_test.py << 'AGENT1'
"""
Agent 1: Simple Requirements Generator - TEST VERSION (5 services)
"""

import yaml
import json
import os
import sys
from openai import OpenAI


SERVICES_TO_PROCESS = ['accessanalyzer', 'acm', 'apigateway', 'apigatewayv2', 'appstream']


def get_metadata_files(service: str):
    """Get all metadata YAML files for a service"""
    metadata_dir = f"../services/{service}/metadata"
    if not os.path.exists(metadata_dir):
        return []
    
    files = []
    for file in os.listdir(metadata_dir):
        if file.endswith('.yaml') and file.startswith('aws.'):
            files.append(os.path.join(metadata_dir, file))
    
    return files
AGENT1

# Copy rest of agent1 (skip first 40 lines)
tail -n +41 agent1_requirements_generator.py >> agent1_requirements_generator_test.py

# Replace agent1 temporarily
mv agent1_requirements_generator.py agent1_requirements_generator_full.py
mv agent1_requirements_generator_test.py agent1_requirements_generator.py

# Run the pipeline
echo "Running 4-agent pipeline on 5 services..."
echo ""

START=$(date +%s)

python3 agent1_requirements_generator.py && \
python3 agent2_function_validator.py && \
python3 agent3_field_validator.py && \
python3 agent4_yaml_generator.py

END=$(date +%s)
DURATION=$((END - START))

# Restore original
mv agent1_requirements_generator_full.py agent1_requirements_generator.py
rm -f agent1_requirements_generator.py.backup

echo ""
echo "========================================"
echo "✅ TEST COMPLETE"
echo "========================================"
echo "Duration: ${DURATION}s"
echo ""

if [ -f "output/requirements_validated.json" ]; then
    echo "Results:"
    python3 << 'PYEOF'
import json
with open('output/requirements_validated.json') as f:
    data = json.load(f)
    
services = len(data)
total_rules = sum(len(rules) for rules in data.values())
validated = sum(1 for svc in data.values() for r in svc if r.get('all_fields_valid'))

print(f"  Services: {services}")
print(f"  Total rules: {total_rules}")
print(f"  Validated: {validated}")
if total_rules > 0:
    print(f"  Rate: {validated/total_rules*100:.1f}%")

# Show per-service
print("\nPer service:")
for svc, rules in sorted(data.items()):
    if rules:
        svc_validated = sum(1 for r in rules if r.get('all_fields_valid'))
        print(f"  {svc}: {svc_validated}/{len(rules)} validated")
PYEOF
fi

