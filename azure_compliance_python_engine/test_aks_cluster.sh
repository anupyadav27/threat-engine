#!/bin/bash
set -e

RESOURCE_GROUP="threat-engine-test-rg"
CLUSTER_NAME="threat-test-aks-$(date +%s)"
LOCATION="eastus"
NODE_COUNT=1
NODE_SIZE="Standard_D2s_v3"

echo "================================================================================
🚀 PROVISIONING AKS CLUSTER FOR TESTING
================================================================================
Cluster Name: $CLUSTER_NAME
Resource Group: $RESOURCE_GROUP
Location: $LOCATION
Node Count: $NODE_COUNT
Node Size: $NODE_SIZE
================================================================================
"

# Check if ContainerService provider is registered
echo "Checking ContainerService provider registration..."
REGISTRATION_STATE=$(az provider show --namespace Microsoft.ContainerService --query "registrationState" -o tsv 2>/dev/null || echo "NotRegistered")
if [ "$REGISTRATION_STATE" != "Registered" ]; then
    echo "Registering ContainerService provider..."
    az provider register --namespace Microsoft.ContainerService --wait
    echo "Waiting 30 seconds for registration to complete..."
    sleep 30
else
    echo "✅ ContainerService provider already registered"
fi

# Check if resource group exists, create if not
if ! az group show --name "$RESOURCE_GROUP" &>/dev/null; then
    echo "Creating resource group..."
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION"
fi

echo "
Creating AKS cluster (this will take 5-10 minutes)..."
az aks create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CLUSTER_NAME" \
  --node-count "$NODE_COUNT" \
  --node-vm-size "$NODE_SIZE" \
  --enable-managed-identity \
  --generate-ssh-keys \
  --output table

if [ $? -eq 0 ]; then
    echo "
✅ Cluster created! Waiting 60 seconds for cluster to be fully ready..."
    sleep 60
    
    echo "
================================================================================
🧪 TESTING AKS SERVICE WITH ENGINE
================================================================================
"
    
    cd /Users/apple/Desktop/threat-engine/azure_compliance_python_engine
    export AZURE_ENGINE_FILTER_SERVICES="aks"
    export LOG_LEVEL=WARNING
    
    echo "Running engine..."
    python engine/azure_generic_engine.py > /tmp/aks_test_with_cluster.json 2>&1
    
    echo "
Results saved to: /tmp/aks_test_with_cluster.json"
    
    # Show summary
    python3 << PYTHON
import json
import sys

try:
    with open('/tmp/aks_test_with_cluster.json', 'r') as f:
        content = f.read()
        if 'Saved results' in content:
            content = content[:content.index('Saved results')].strip()
        data = json.loads(content)
        
        if isinstance(data, list) and len(data) > 0:
            result = data[0]
            print("\n📊 RESULTS:")
            inventory = result.get('inventory', {})
            for key, value in inventory.items():
                count = len(value) if isinstance(value, list) else 0
                print(f"  - {key}: {count} items")
            
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
                    print(f"\n❌ ERRORS:")
                    for i, c in enumerate([c for c in checks if c.get('result') == 'ERROR'][:3], 1):
                        print(f"{i}. {c.get('check_id')}")
                        print(f"   {c.get('error', 'Unknown')[:100]}")
except Exception as e:
    print(f"Error parsing results: {e}")
PYTHON
    
    echo "
================================================================================
🧹 CLEANUP - DELETING AKS CLUSTER
================================================================================
"
    
    echo "Deleting AKS cluster (auto-delete enabled)..."
    az aks delete \
      --resource-group "$RESOURCE_GROUP" \
      --name "$CLUSTER_NAME" \
      --yes \
      --no-wait
    
    echo "✅ Cluster deletion initiated (running in background)"
    echo "
================================================================================
✅ TEST COMPLETE
================================================================================
"
else
    echo "❌ Failed to create cluster"
    exit 1
fi
