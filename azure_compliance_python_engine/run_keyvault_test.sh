#!/bin/bash
# Quick test of Azure compliance engine with keyvault service

set -e

echo "════════════════════════════════════════════════════════════════════════════════"
echo "  Azure Compliance Engine - KeyVault Service Test"
echo "════════════════════════════════════════════════════════════════════════════════"
echo ""

# Check if Azure credentials are set
if [ -z "$AZURE_SUBSCRIPTION_ID" ]; then
    echo "⚠️  AZURE_SUBSCRIPTION_ID not set, trying to get from Azure CLI..."
    if command -v az &> /dev/null; then
        export AZURE_SUBSCRIPTION_ID=$(az account show --query id -o tsv 2>/dev/null || echo "")
    fi
    
    if [ -z "$AZURE_SUBSCRIPTION_ID" ]; then
        echo "❌ Could not determine subscription ID"
        echo ""
        echo "Please set Azure credentials:"
        echo "  export AZURE_SUBSCRIPTION_ID='your-subscription-id'"
        echo "  OR run: az login"
        exit 1
    fi
fi

echo "✅ Azure Subscription: $AZURE_SUBSCRIPTION_ID"
echo ""

# Navigate to directory
cd "$(dirname "$0")"

echo "Step 1: Validate KeyVault YAML"
echo "────────────────────────────────────────────────────────────────────────────────"
python3 << 'EOF'
import yaml
try:
    with open('services/keyvault/keyvault_rules.yaml') as f:
        data = yaml.safe_load(f)
    print(f"✅ YAML valid")
    print(f"   - Service: {data['service']}")
    print(f"   - Discoveries: {len(data['discovery'])}")
    print(f"   - Checks: {len(data['checks'])}")
except Exception as e:
    print(f"❌ YAML error: {e}")
    exit(1)
EOF

if [ $? -ne 0 ]; then
    echo ""
    echo "❌ YAML validation failed"
    exit 1
fi

echo ""
echo "Step 2: Run Engine Test"
echo "────────────────────────────────────────────────────────────────────────────────"
echo "Command: python3 engine/main_scanner.py --service keyvault --location eastus"
echo ""

# Run the engine
python3 engine/main_scanner.py \
  --service keyvault \
  --subscription $AZURE_SUBSCRIPTION_ID \
  --location eastus \
  --max-workers 5 \
  2>&1 | tee /tmp/azure_keyvault_test.log

TEST_EXIT=$?

echo ""
echo "════════════════════════════════════════════════════════════════════════════════"
echo "  Test Results"
echo "════════════════════════════════════════════════════════════════════════════════"

if [ $TEST_EXIT -eq 0 ]; then
    echo "✅ Engine execution successful"
else
    echo "⚠️  Engine execution had issues (exit code: $TEST_EXIT)"
fi

echo ""
echo "📊 Output Files:"
if [ -d "output/latest" ]; then
    echo "  - output/latest/"
    ls -lh output/latest/ 2>/dev/null | tail -n +2 | awk '{print "    " $9 " (" $5 ")"}'
    
    if [ -f "output/latest/checks/keyvault_checks.json" ]; then
        echo ""
        echo "📋 Check Results Summary:"
        python3 << 'EOF'
import json
try:
    with open('output/latest/checks/keyvault_checks.json') as f:
        data = json.load(f)
    
    if 'summary' in data:
        s = data['summary']
        print(f"  Total checks: {s.get('total', 0)}")
        print(f"  ✅ Passed: {s.get('passed', 0)}")
        print(f"  ❌ Failed: {s.get('failed', 0)}")
        print(f"  ⚠️  Errors: {s.get('errors', 0)}")
    elif 'checks' in data:
        checks = data['checks']
        total = len(checks)
        passed = sum(1 for c in checks if c.get('result') == 'PASS')
        failed = sum(1 for c in checks if c.get('result') == 'FAIL')
        errors = sum(1 for c in checks if c.get('result') == 'ERROR')
        print(f"  Total checks: {total}")
        print(f"  ✅ Passed: {passed}")
        print(f"  ❌ Failed: {failed}")
        print(f"  ⚠️  Errors: {errors}")
except Exception as e:
    print(f"  Could not parse results: {e}")
EOF
    fi
    
    if [ -f "output/latest/inventory/keyvault_inventory.json" ]; then
        echo ""
        echo "📦 Inventory Summary:"
        python3 << 'EOF'
import json
try:
    with open('output/latest/inventory/keyvault_inventory.json') as f:
        data = json.load(f)
    count = data.get('count', len(data.get('discovered', [])))
    print(f"  Resources discovered: {count}")
    if count > 0:
        print(f"  Sample resource: {data['discovered'][0].get('name', 'N/A')}")
except Exception as e:
    print(f"  Could not parse inventory: {e}")
EOF
    fi
else
    echo "  ⚠️  No output directory found"
fi

echo ""
echo "📝 Full log: /tmp/azure_keyvault_test.log"
echo ""

if [ $TEST_EXIT -eq 0 ]; then
    echo "✅ TEST PASSED"
else
    echo "⚠️  TEST COMPLETED WITH WARNINGS"
    echo ""
    echo "Check the log for details:"
    echo "  tail -100 /tmp/azure_keyvault_test.log"
fi

echo "════════════════════════════════════════════════════════════════════════════════"

