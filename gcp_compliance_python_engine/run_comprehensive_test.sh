#!/bin/bash
# Comprehensive GCP Compliance Testing
# Provisions resources → Runs compliance scan → Reports results → Cleans up
# Usage: ./run_comprehensive_test.sh <project_id> <region>

set -e

PROJECT_ID=${1:-test-2277}
REGION=${2:-us-central1}
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="test_results_${TIMESTAMP}"

mkdir -p $RESULTS_DIR

echo "=========================================="
echo "GCP COMPREHENSIVE COMPLIANCE TEST"
echo "=========================================="
echo "Project: $PROJECT_ID"
echo "Region: $REGION"
echo "Results dir: $RESULTS_DIR"
echo ""

# Step 1: Provision test resources
echo "STEP 1: Provisioning test resources..."
echo "=========================================="
./provision_test_resources.sh $PROJECT_ID $REGION 2>&1 | tee $RESULTS_DIR/provision.log

echo ""
echo "⏳ Waiting 60s for resources to be fully ready..."
sleep 60

# Step 2: Run compliance scan
echo ""
echo "STEP 2: Running compliance scan..."
echo "=========================================="

source venv/bin/activate
export PYTHONPATH="$(pwd)/..:$PYTHONPATH"
export GCP_PROJECTS="$PROJECT_ID"
export GCP_ENGINE_FILTER_REGIONS="$REGION"

python -c "
from engine.gcp_engine import run
import json
from datetime import datetime

print(f'🔍 Starting scan at {datetime.now().strftime(\"%H:%M:%S\")}')
print()

results = run()

# Analyze results
service_summary = {}
total_checks = 0
total_pass = 0
total_fail = 0

for r in results:
    svc = r.get('service', 'unknown')
    checks = r.get('checks', [])
    inventory = r.get('inventory', {})
    
    p = sum(1 for c in checks if c.get('result') == 'PASS')
    f = sum(1 for c in checks if c.get('result') == 'FAIL')
    
    total_checks += len(checks)
    total_pass += p
    total_fail += f
    
    if svc not in service_summary:
        service_summary[svc] = {'checks': 0, 'pass': 0, 'fail': 0, 'inventory': 0}
    
    service_summary[svc]['checks'] += len(checks)
    service_summary[svc]['pass'] += p
    service_summary[svc]['fail'] += f
    service_summary[svc]['inventory'] += sum(len(v) if isinstance(v, list) else 1 for v in inventory.values() if v)

print(f'✅ Scan completed at {datetime.now().strftime(\"%H:%M:%S\")}')
print()
print('='*60)
print('SCAN RESULTS')
print('='*60)

print(f'\nServices with checks executed:')
for svc, data in sorted(service_summary.items(), key=lambda x: x[1]['checks'], reverse=True):
    if data['checks'] > 0:
        rate = round(data['pass']/data['checks']*100, 1)
        print(f'  {svc}: {data[\"pass\"]}/{data[\"checks\"]} ({rate}%) | {data[\"inventory\"]} inventory items')

print(f'\n🎯 OVERALL:')
print(f'  Total checks: {total_checks}')
print(f'  ✅ PASS: {total_pass} ({round(total_pass/total_checks*100, 1) if total_checks > 0 else 0}%)')
print(f'  ❌ FAIL: {total_fail}')
print()

# Save detailed results
with open('$RESULTS_DIR/scan_results.json', 'w') as f:
    json.dump(results, f, indent=2)
    
print(f'📄 Detailed results saved to: $RESULTS_DIR/scan_results.json')
" 2>&1 | tee $RESULTS_DIR/scan.log

# Step 3: Generate report
echo ""
echo "STEP 3: Generating test report..."
echo "=========================================="

cat > $RESULTS_DIR/TEST_REPORT.md << EOF
# GCP Compliance Test Report

**Date:** $(date)
**Project:** $PROJECT_ID
**Region:** $REGION

## Test Summary

$(cat $RESULTS_DIR/scan.log | grep -A 20 "OVERALL:")

## Files Generated

- \`provision.log\` - Resource provisioning log
- \`scan.log\` - Compliance scan log
- \`scan_results.json\` - Detailed JSON results
- \`TEST_REPORT.md\` - This report

## Next Steps

1. Review scan results in scan_results.json
2. Fix any failing checks by adjusting GCP configurations
3. Run cleanup: \`./cleanup_test_resources.sh $PROJECT_ID\`

EOF

echo "✅ Report generated: $RESULTS_DIR/TEST_REPORT.md"

# Step 4: Cleanup (optional)
echo ""
echo "=========================================="
echo "Test complete! Results in: $RESULTS_DIR"
echo "=========================================="
echo ""
echo "To cleanup test resources, run:"
echo "  ./cleanup_test_resources.sh $PROJECT_ID"
echo ""
echo "Or to keep resources for further testing, leave them as-is."

