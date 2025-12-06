#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Get services from command line or use default batch
if [ $# -gt 0 ]; then
    SERVICES=("$@")
else
    # Default: next 5 services from manifest
    SERVICES=("billing" "databricks" "database" "databox" "databricks")
fi

echo "================================================================================
🚀 BATCH VALIDATION OF SERVICES
================================================================================
Services: ${SERVICES[*]}
================================================================================
"

source venv/bin/activate 2>/dev/null || true

for service in "${SERVICES[@]}"; do
    echo "
================================================================================
📋 VALIDATING: $service
================================================================================
"
    
    # Add to service list if not exists
    python3 << PYTHON
import json
import sys

with open('config/service_list.json', 'r') as f:
    data = json.load(f)

service_name = "$service"
exists = any(s['name'] == service_name for s in data['services'])

if not exists:
    data['services'].append({
        "name": service_name,
        "enabled": True,
        "scope": "subscription"
    })
    
    with open('config/service_list.json', 'w') as f:
        json.dump(data, f, indent=2)
    print(f"✅ Added {service_name} to service list")
else:
    print(f"ℹ️  {service_name} already in service list")
PYTHON
    
    # Run test
    export AZURE_ENGINE_FILTER_SERVICES="$service"
    export LOG_LEVEL=WARNING
    
    OUTPUT_FILE="/tmp/test_${service}_batch.json"
    python3 engine/azure_generic_engine.py > "$OUTPUT_FILE" 2>&1
    
    # Parse results
    python3 << PYTHON
import json

output_file = "$OUTPUT_FILE"
service_name = "$service"

try:
    with open(output_file, 'r') as f:
        content = f.read()
        if 'Saved results' in content:
            content = content[:content.index('Saved results')].strip()
        
        # Skip if empty
        if not content.strip() or content.strip() == '[]':
            print(f"⚠️  {service_name}: Empty result - may need SDK or config")
            exit(0)
        
        data = json.loads(content)
        
        if isinstance(data, list) and len(data) > 0:
            result = data[0]
            
            # Check for errors in service
            if 'error' in result:
                print(f"❌ {service_name}: Service error - {result['error'][:80]}")
                exit(1)
            
            inventory = result.get('inventory', {})
            checks = result.get('checks', [])
            
            total_found = sum(len(v) if isinstance(v, list) else 0 for v in inventory.values())
            
            if checks:
                error_count = sum(1 for c in checks if c.get('result') == 'ERROR')
                
                if error_count > 0:
                    print(f"❌ {service_name}: {error_count} errors found")
                    errors = [c for c in checks if c.get('result') == 'ERROR'][:2]
                    for err in errors:
                        print(f"   - {err.get('check_id', 'Unknown')}: {err.get('error', 'Unknown')[:80]}")
                    exit(1)
                else:
                    print(f"✅ {service_name}: {len(checks)} checks, {total_found} resources, 0 errors")
            else:
                # Check for warnings in output
                with open(output_file, 'r') as f:
                    full_output = f.read()
                    if 'WARNING' in full_output and 'Method not found' in full_output:
                        print(f"❌ {service_name}: Action method issue - need to fix YAML")
                        exit(1)
                    elif 'Failed to create client' in full_output:
                        print(f"❌ {service_name}: Client creation failed - need SDK/config")
                        exit(1)
                    else:
                        print(f"✅ {service_name}: No errors, {total_found} resources")
        else:
            print(f"⚠️  {service_name}: Empty result")
except json.JSONDecodeError as e:
    # Check if it's just empty or has real errors
    if '[]' in content or not content.strip():
        print(f"⚠️  {service_name}: Empty JSON - no resources found (OK)")
    else:
        print(f"❌ {service_name}: JSON parse error - {str(e)[:80]}")
        exit(1)
except Exception as e:
    print(f"❌ {service_name}: Error - {str(e)[:80]}")
    exit(1)
PYTHON
    
    # Only mark as done if test passed
    if [ $? -eq 0 ]; then
        python3 sequential_service_validator.py --mark-done "$service" 2>/dev/null || true
        echo "✅ Marked $service as validated"
    else
        echo "❌ Skipping validation mark for $service due to errors"
    fi
    
    sleep 1
done

echo "
================================================================================
✅ BATCH VALIDATION COMPLETE
================================================================================
"
python3 sequential_service_validator.py --status

