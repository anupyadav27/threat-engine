#!/bin/bash
set -e

RESOURCE_GROUP="threat-engine-test-rg"
LOCATION="eastus"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "================================================================================
🚀 PROVISION AND TEST RESOURCES FOR SERVICES
================================================================================
"

# Ensure resource group exists
if ! az group show --name "$RESOURCE_GROUP" &>/dev/null; then
    echo "Creating resource group..."
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION"
fi

# Function to register provider if needed
register_provider() {
    local namespace=$1
    local state=$(az provider show --namespace "$namespace" --query "registrationState" -o tsv 2>/dev/null || echo "NotRegistered")
    if [ "$state" != "Registered" ]; then
        echo "Registering provider $namespace..."
        az provider register --namespace "$namespace" --wait
        sleep 10
    fi
}

# Function to provision and test a service
provision_and_test() {
    local service=$1
    local provider=$2
    local provision_cmd=$3
    
    echo "
================================================================================
📦 PROVISIONING: $service
================================================================================
"
    
    # Register provider if specified
    if [ -n "$provider" ]; then
        register_provider "$provider"
    fi
    
    # Provision resource
    eval "$provision_cmd"
    
    if [ $? -eq 0 ]; then
        echo "✅ Resource provisioned, waiting 30 seconds..."
        sleep 30
        
        echo "
================================================================================
🧪 TESTING: $service
================================================================================
"
        
        cd "$SCRIPT_DIR"
        source venv/bin/activate 2>/dev/null || true
        
        export AZURE_ENGINE_FILTER_SERVICES="$service"
        export LOG_LEVEL=WARNING
        
        OUTPUT_FILE="/tmp/test_${service}_provisioned.json"
        python3 engine/azure_generic_engine.py > "$OUTPUT_FILE" 2>&1
        
        # Check results
        python3 << PYTHON
import json

output_file = "$OUTPUT_FILE"
service_name = "$service"

try:
    with open(output_file, 'r') as f:
        content = f.read()
        if 'Saved results' in content:
            content = content[:content.index('Saved results')].strip()
        
        if content.strip() and content.strip() != '[]':
            data = json.loads(content)
            if isinstance(data, list) and len(data) > 0:
                result = data[0]
                inventory = result.get('inventory', {})
                checks = result.get('checks', [])
                
                total_resources = sum(len(v) if isinstance(v, list) else 0 for v in inventory.values())
                error_count = sum(1 for c in checks if c.get('result') == 'ERROR') if checks else 0
                
                if total_resources > 0:
                    print(f"✅ {service_name}: {total_resources} resource(s) found")
                    if checks:
                        print(f"   {len(checks)} checks executed, {error_count} errors")
                        if error_count == 0:
                            print(f"   ✅ SUCCESS - All checks working!")
                        else:
                            print(f"   ⚠️  {error_count} check errors found")
                    else:
                        print(f"   ⚠️  No checks executed")
                else:
                    print(f"⚠️  {service_name}: No resources discovered")
except Exception as e:
    print(f"❌ {service_name}: Error - {str(e)[:100]}")
PYTHON
    else
        echo "❌ Failed to provision $service"
    fi
}

# Test services that are quick to provision
echo "Starting resource provisioning and testing..."

# 1. Storage Account (blob)
STORAGE_NAME="threattest$(date +%s | tail -c 9)"
provision_and_test "blob" "" "az storage account create --resource-group $RESOURCE_GROUP --name $STORAGE_NAME --location $LOCATION --sku Standard_LRS"

# 2. Container Registry
ACR_NAME="threattest$(date +%s | tail -c 9)"
provision_and_test "containerregistry" "Microsoft.ContainerRegistry" "az acr create --resource-group $RESOURCE_GROUP --name $ACR_NAME --sku Basic --location $LOCATION"

# 3. Function App (requires storage)
FUNC_STORAGE="threatfunc$(date +%s | tail -c 9)"
FUNC_APP="threat-func-$(date +%s | tail -c 9)"
az storage account create --resource-group "$RESOURCE_GROUP" --name "$FUNC_STORAGE" --location "$LOCATION" --sku Standard_LRS > /dev/null
sleep 10
provision_and_test "function" "Microsoft.Web" "az functionapp create --resource-group $RESOURCE_GROUP --name $FUNC_APP --storage-account $FUNC_STORAGE --consumption-plan-location $LOCATION --runtime python --runtime-version 3.9 --os-type Linux"

# 4. Event Hub Namespace
EH_NAMESPACE="threat-eh-$(date +%s | tail -c 9)"
provision_and_test "event" "Microsoft.EventHub" "az eventhubs namespace create --resource-group $RESOURCE_GROUP --name $EH_NAMESPACE --location $LOCATION --sku Basic"

# 5. Service Bus Namespace
SB_NAMESPACE="threat-sb-$(date +%s | tail -c 9)"
provision_and_test "servicebus" "Microsoft.ServiceBus" "az servicebus namespace create --resource-group $RESOURCE_GROUP --name $SB_NAMESPACE --location $LOCATION --sku Basic"

echo "
================================================================================
✅ PROVISIONING AND TESTING COMPLETE
================================================================================
"

# Offer cleanup
read -p "Delete all test resources? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "Cleaning up resources..."
    az group delete --name "$RESOURCE_GROUP" --yes --no-wait
    echo "✅ Cleanup initiated"
else
    echo "Resources kept in: $RESOURCE_GROUP"
fi

