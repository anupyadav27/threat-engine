#!/bin/bash
set -e

RESOURCE_GROUP="threat-engine-test-rg"
CLUSTER_NAME="threat-test-aks-1765016610"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "================================================================================
🔄 AUTO-REFRESH & TEST AKS CLUSTER
================================================================================
"

# Function to refresh Azure authentication
refresh_azure_auth() {
    echo "Checking Azure CLI authentication..."
    
    # Try to get access token to refresh
    if az account get-access-token --resource https://management.azure.com/ > /dev/null 2>&1; then
        echo "✅ Azure CLI token is valid"
        return 0
    else
        echo "⚠️  Azure CLI token expired or invalid"
        echo "Refreshing authentication..."
        
        # Try to use existing account first
        if az account show > /dev/null 2>&1; then
            echo "Account found, refreshing token..."
            az account get-access-token --resource https://management.azure.com/ > /dev/null
            if [ $? -eq 0 ]; then
                echo "✅ Token refreshed successfully"
                return 0
            fi
        fi
        
        # If that fails, need interactive login
        echo "⚠️  Interactive login required..."
        az login
        if [ $? -eq 0 ]; then
            echo "✅ Login successful"
            return 0
        else
            echo "❌ Login failed"
            return 1
        fi
    fi
}

# Function to verify cluster exists
verify_cluster() {
    echo "Verifying AKS cluster exists..."
    
    CLUSTER_STATUS=$(az aks show --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" --query "provisioningState" -o tsv 2>/dev/null || echo "NotFound")
    
    if [ "$CLUSTER_STATUS" == "Succeeded" ]; then
        echo "✅ Cluster found and ready: $CLUSTER_NAME"
        return 0
    elif [ "$CLUSTER_STATUS" == "Creating" ]; then
        echo "⏳ Cluster is still being created..."
        echo "Waiting for cluster to be ready (this may take a few minutes)..."
        
        # Wait up to 10 minutes for cluster to be ready
        for i in {1..20}; do
            sleep 30
            STATUS=$(az aks show --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" --query "provisioningState" -o tsv 2>/dev/null || echo "NotFound")
            if [ "$STATUS" == "Succeeded" ]; then
                echo "✅ Cluster is now ready!"
                return 0
            fi
            echo "   Still creating... ($i/20)"
        done
        
        echo "⚠️  Cluster creation taking longer than expected"
        return 1
    else
        echo "❌ Cluster not found or not ready (Status: $CLUSTER_STATUS)"
        return 1
    fi
}

# Function to run AKS engine test
run_aks_test() {
    echo "
================================================================================
🧪 RUNNING AKS ENGINE TEST
================================================================================
"
    
    cd "$SCRIPT_DIR"
    
    # Activate venv if it exists
    if [ -d "venv" ]; then
        source venv/bin/activate
    fi
    
    export AZURE_ENGINE_FILTER_SERVICES="aks"
    export LOG_LEVEL=WARNING
    
    OUTPUT_FILE="/tmp/aks_test_$(date +%s).json"
    
    echo "Running engine test..."
    python3 engine/azure_generic_engine.py > "$OUTPUT_FILE" 2>&1
    
    if [ $? -ne 0 ]; then
        echo "⚠️  Engine returned non-zero exit code"
    fi
    
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
            print("📊 AKS SERVICE TEST RESULTS")
            print("="*70)
            print(f"Service: {result.get('service')}")
            print(f"Scope: {result.get('scope')}")
            print(f"Subscription: {result.get('subscription', 'N/A')[:36]}...")
            
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
                    print(f"   This might indicate:")
                    print(f"   - Cluster not discovered (authentication/timing issue)")
                    print(f"   - Subscription/region mismatch")
            
            print("="*70)
            print(f"\n📁 Full results saved to: {output_file}")
        else:
            print("\n⚠️  Empty result - possible authentication issue")
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
    
    echo "$OUTPUT_FILE"
}

# Function to cleanup cluster
cleanup_cluster() {
    echo "
================================================================================
🧹 CLEANUP OPTIONS
================================================================================
"
    read -p "Delete the AKS cluster now? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Deleting cluster..."
        az aks delete \
          --resource-group "$RESOURCE_GROUP" \
          --name "$CLUSTER_NAME" \
          --yes \
          --no-wait
        
        echo "✅ Cluster deletion initiated (running in background)"
        echo "   To check status: az aks show --resource-group $RESOURCE_GROUP --name $CLUSTER_NAME"
    else
        echo "Cluster kept alive."
        echo "   To delete manually:"
        echo "   az aks delete --resource-group $RESOURCE_GROUP --name $CLUSTER_NAME --yes"
    fi
}

# Main execution
main() {
    # Step 1: Refresh authentication
    if ! refresh_azure_auth; then
        echo "❌ Failed to refresh Azure authentication"
        exit 1
    fi
    
    sleep 2  # Give token time to propagate
    
    # Step 2: Verify cluster
    if ! verify_cluster; then
        echo "❌ Cluster verification failed"
        exit 1
    fi
    
    # Step 3: Run test
    OUTPUT_FILE=$(run_aks_test)
    
    # Step 4: Offer cleanup
    cleanup_cluster
    
    echo "
================================================================================
✅ TEST COMPLETE
================================================================================
"
}

# Run main function
main

