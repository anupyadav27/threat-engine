#!/bin/bash
set -e

RESOURCE_GROUP="threat-engine-test-rg"
LOCATION="eastus"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "================================================================================
🚀 BATCH 2: PROVISION AND TEST MORE SERVICES
================================================================================
"

# Refresh token
echo "Refreshing Azure authentication..."
az account get-access-token --resource https://management.azure.com/ > /dev/null 2>&1
sleep 2

# Ensure resource group exists
if ! az group show --name "$RESOURCE_GROUP" &>/dev/null; then
    az group create --name "$RESOURCE_GROUP" --location "$LOCATION"
fi

register_provider() {
    local namespace=$1
    local state=$(az provider show --namespace "$namespace" --query "registrationState" -o tsv 2>/dev/null || echo "NotRegistered")
    if [ "$state" != "Registered" ]; then
        echo "Registering provider $namespace..."
        az provider register --namespace "$namespace" --wait
        sleep 10
    fi
}

provision_and_test() {
    local service=$1
    local provider=$2
    local provision_cmd=$3
    
    echo "
================================================================================
📦 PROVISIONING: $service
================================================================================
"
    
    if [ -n "$provider" ]; then
        register_provider "$provider"
    fi
    
    eval "$provision_cmd" > /dev/null 2>&1
    
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
        
        OUTPUT_FILE="/tmp/test_${service}_batch2.json"
        python3 engine/azure_generic_engine.py > "$OUTPUT_FILE" 2>&1
        
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
                    print(f"✅ {service_name}: {total_resources} resource(s), {len(checks)} checks, {error_count} errors")
                else:
                    print(f"⚠️  {service_name}: No resources discovered")
except:
    pass
PYTHON
    fi
}

# Continue with more services
echo "Starting Batch 2 provisioning..."

# Redis Cache
REDIS_NAME="threatredis$(date +%s | tail -c 8)"
provision_and_test "redis" "Microsoft.Cache" "az redis create --resource-group $RESOURCE_GROUP --name $REDIS_NAME --location $LOCATION --sku Basic --vm-size c0"

# Cosmos DB
COSMOS_NAME="threat-cosmos-$(date +%s | tail -c 8)"
provision_and_test "cosmosdb" "Microsoft.DocumentDB" "az cosmosdb create --resource-group $RESOURCE_GROUP --name $COSMOS_NAME --locations regionName=$LOCATION"

# PostgreSQL (Basic tier)
POSTGRES_NAME="threatpostgres$(date +%s | tail -c 8)"
provision_and_test "postgresql" "Microsoft.DBforPostgreSQL" "az postgres flexible-server create --resource-group $RESOURCE_GROUP --name $POSTGRES_NAME --location $LOCATION --sku-name Standard_B1ms --tier Burstable --admin-user testadmin --admin-password Test@12345 --version 14 --public-access 0.0.0.0"

# MySQL (Basic tier)  
MYSQL_NAME="threatmysql$(date +%s | tail -c 8)"
provision_and_test "mysql" "Microsoft.DBforMySQL" "az mysql flexible-server create --resource-group $RESOURCE_GROUP --name $MYSQL_NAME --location $LOCATION --sku-name Standard_B1ms --tier Burstable --admin-user testadmin --admin-password Test@12345 --version 8.0.21 --public-access 0.0.0.0"

echo "
================================================================================
✅ BATCH 2 PROVISIONING COMPLETE
================================================================================
"
