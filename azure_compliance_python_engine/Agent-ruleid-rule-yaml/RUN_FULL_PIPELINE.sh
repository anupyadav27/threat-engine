#!/bin/bash
# Run complete Azure agentic AI pipeline for ALL services

set -e

cd "$(dirname "$0")"

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                            ║"
echo "║     AZURE AGENTIC AI PIPELINE - FULL RUN FOR ALL SERVICES                 ║"
echo "║                                                                            ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Clean previous outputs
echo "🧹 Cleaning previous outputs..."
rm -f output/requirements_*.json
rm -f output/*_generated.yaml
echo "✅ Clean"
echo ""

# Step 1: Generate requirements (rule-based for now)
echo "Step 1/4: Generate Requirements (Rule-Based)"
echo "────────────────────────────────────────────────────────────────────────────"
python3 generate_requirements_auto.py
if [ $? -ne 0 ]; then
    echo "❌ Agent 1 failed"
    exit 1
fi
echo ""

# Step 2: Validate functions
echo "Step 2/4: Validate Azure SDK Operations"
echo "────────────────────────────────────────────────────────────────────────────"
python3 agent2_function_validator.py | tail -20
if [ $? -ne 0 ]; then
    echo "❌ Agent 2 failed"
    exit 1
fi
echo ""

# Step 3: Validate fields  
echo "Step 3/4: Validate Field Names"
echo "────────────────────────────────────────────────────────────────────────────"
python3 agent3_field_validator.py | tail -20
if [ $? -ne 0 ]; then
    echo "❌ Agent 3 failed"
    exit 1
fi
echo ""

# Step 4: Generate YAMLs
echo "Step 4/4: Generate YAML Files"
echo "────────────────────────────────────────────────────────────────────────────"
python3 agent4_yaml_generator.py | tail -30
if [ $? -ne 0 ]; then
    echo "❌ Agent 4 failed"
    exit 1
fi
echo ""

echo "╔════════════════════════════════════════════════════════════════════════════╗"
echo "║                        PIPELINE COMPLETE                                    ║"
echo "╚════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Summary
echo "📊 Summary:"
python3 << 'PYEOF'
import json

# Load results
with open('output/requirements_validated.json') as f:
    validated = json.load(f)

total_services = len(validated)
total_rules = sum(len(rules) for rules in validated.values())
valid_rules = sum(len([r for r in rules if r.get('all_fields_valid')]) for rules in validated.values())

print(f"  Total Services:    {total_services}")
print(f"  Total Rules:       {total_rules}")
print(f"  Valid Rules:       {valid_rules}")
print(f"  Success Rate:      {100*valid_rules/total_rules if total_rules > 0 else 0:.1f}%")
print()
print("Services with valid rules:")
for service, rules in sorted(validated.items(), key=lambda x: len([r for r in x[1] if r.get('all_fields_valid')]), reverse=True):
    valid = len([r for r in rules if r.get('all_fields_valid')])
    if valid > 0:
        print(f"  ✅ {service:25s}: {valid:3d} valid checks")
PYEOF

echo ""
echo "📁 Generated YAMLs:"
ls -lh output/*_generated.yaml 2>/dev/null | awk '{print "  ✅", $9, "(" $5 ")"}'

echo ""
echo "🎯 Next: Deploy YAMLs and run engine test"
echo "   ./deploy_and_test.sh"
echo ""

