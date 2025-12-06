#!/bin/bash
set -e

RESOURCE_GROUP="threat-engine-test-rg"
APIM_NAME="threat-test-apim-$(date +%s)"
LOCATION="eastus"
SKU="Developer"  # Developer tier is free/cheap for testing
PUBLISHER_EMAIL="test@example.com"
PUBLISHER_NAME="Test User"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "================================================================================
🚀 PROVISIONING API MANAGEMENT INSTANCE FOR TESTING
================================================================================
APIM Name: $APIM_NAME
Resource Group: $RESOURCE_GROUP
Location: $LOCATION
SKU: $SKU (Developer tier - free/low cost)
================================================================================
"

# Refresh Azure auth if needed
echo "Checking Azure authentication..."
if ! az account get-access-token --resource https://management.azure.com/ > /dev/null 2>&1; then
    echo "⚠️  Token expired, refreshing..."
    az account get-access-token --resource https://management.azure.com/ > /dev/null
fi

# Check if resource group exists
if ! az group show --name "$RESOURCE_GROUP" &>/dev/null; then
    echo "Creating resource group..."
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION"
fi

# Check if API Management provider is registered
echo "Checking API Management provider registration..."
REGISTRATION_STATE=$(az provider show --namespace Microsoft.ApiManagement --query "registrationState" -o tsv 2>/dev/null || echo "NotRegistered")
if [ "$REGISTRATION_STATE" != "Registered" ]; then
    echo "Registering API Management provider..."
    az provider register --namespace Microsoft.ApiManagement --wait
    echo "Waiting 30 seconds for registration to complete..."
    sleep 30
else
    echo "✅ API Management provider already registered"
fi

echo "
Creating API Management instance (this will take 5-10 minutes)..."
az apim create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$APIM_NAME" \
  --location "$LOCATION" \
  --publisher-email "$PUBLISHER_EMAIL" \
  --publisher-name "$PUBLISHER_NAME" \
  --sku-name "$SKU" \
  --output table

if [ $? -eq 0 ]; then
    echo "
✅ API Management instance created! Waiting 60 seconds for it to be fully ready..."
    sleep 60
    
    echo "
================================================================================
🧪 TESTING API MANAGEMENT SERVICE WITH ENGINE
================================================================================
"
    
    cd "$SCRIPT_DIR"
    
    # Activate venv if it exists
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi
    
    export AZURE_ENGINE_FILTER_SERVICES="api"
    export LOG_LEVEL=WARNING
    
    OUTPUT_FILE="/tmp/apim_test_$(date +%s).json"
    
    echo "Running engine test..."
    python3 engine/azure_generic_engine.py > "$OUTPUT_FILE" 2>&1
    
    # Parse and display results
    python3 << PYTHON
import json
import sys
import os

output_file = "$OUTPUT_FILE"

try:
    with open(output_file, 'r') as f:
        content = f.read()
        if 'Saved results' in content:
            content = content[:content.index('Saved results')].strip()
        
        data = json.loads(content)
        
        if isinstance(data, list) and len(data) > 0:
            result = data[0]
            print("\n" + "="*70)
            print("📊 API MANAGEMENT SERVICE TEST RESULTS")
            print("="*70)
            print(f"Service: {result.get('service')}")
            print(f"Scope: {result.get('scope')}")
            
            inventory = result.get('inventory', {})
            print(f"\n📦 INVENTORY:")
            total_found = 0
            for key, value in inventory.items():
                count = len(value) if isinstance(value, list) else 0
                total_found += count
                status = "✅" if count > 0 else "⚠️ "
                print(f"  {status} {key}: {count} items")
                if count > 0 and isinstance(value, list):
                    first = value[0]
                    if isinstance(first, dict):
                        name = first.get('name') or first.get('id', 'N/A')[:60]
                        print(f"      → {name}")
            
            checks = result.get('checks', [])
            print(f"\n🔍 CHECKS: {len(checks)} executed")
            
            if checks:
                pass_count = sum(1 for c in checks if c.get('result') == 'PASS')
                fail_count = sum(1 for c in checks if c.get('result') == 'FAIL')
                error_count = sum(1 for c in checks if c.get('result') == 'ERROR')
                
                print(f"  ✅ PASS: {pass_count}")
                print(f"  ❌ FAIL: {fail_count}")
                print(f"  ⚠️  ERROR: {error_count}")
                
                if error_count > 0:
                    print(f"\n❌ ERRORS FOUND ({error_count}):")
                    for i, c in enumerate([c for c in checks if c.get('result') == 'ERROR'][:5], 1):
                        print(f"{i}. {c.get('check_id', 'Unknown')}")
                        error_msg = c.get('error', 'Unknown error')[:150]
                        print(f"   {error_msg}")
                elif total_found > 0:
                    print(f"\n✅ SUCCESS! Engine working correctly")
                    print(f"   Found {total_found} resource(s) and executed {len(checks)} checks")
                    if fail_count > 0:
                        print(f"   Note: {fail_count} FAIL results indicate compliance violations (expected)")
                else:
                    print(f"\n⚠️  No resources found in inventory")
            
            print("="*70)
            print(f"\n📁 Full results saved to: {output_file}")
        else:
            print("\n⚠️  Empty result - possible issue")
            print("Check the output file for details:", output_file)
            
except json.JSONDecodeError as e:
    print(f"\n❌ JSON parse error: {e}")
    print("Raw output preview:")
    try:
        with open(output_file, 'r') as f:
            content = f.read()[:500]
            print(content)
    except:
        pass
except Exception as e:
    print(f"\n❌ Error processing results: {e}")
    import traceback
    traceback.print_exc()

PYTHON
    
    echo "
================================================================================
🧹 CLEANUP OPTIONS
================================================================================
"
    read -p "Delete the API Management instance now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Deleting API Management instance..."
        az apim delete \
          --resource-group "$RESOURCE_GROUP" \
          --name "$APIM_NAME" \
          --yes \
          --no-wait
        
        echo "✅ API Management deletion initiated (running in background)"
        echo "   To check status: az apim show --resource-group $RESOURCE_GROUP --name $APIM_NAME"
    else
        echo "API Management instance kept alive."
        echo "   To delete manually:"
        echo "   az apim delete --resource-group $RESOURCE_GROUP --name $APIM_NAME --yes"
    fi
    
    echo "
================================================================================
✅ TEST COMPLETE
================================================================================
"
else
    echo "❌ Failed to create API Management instance"
    exit 1
fi

