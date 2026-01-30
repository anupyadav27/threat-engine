#!/bin/bash
# Provision free/low-cost Azure resources for compliance testing

set -e

SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-$(az account show --query id -o tsv)}"
RESOURCE_GROUP="compliance-test-rg-$(date +%s)"
LOCATION="${AZURE_LOCATION:-eastus}"

echo "================================================================================"
echo "PROVISIONING FREE/LOW-COST AZURE RESOURCES"
echo "================================================================================"
echo "Subscription: $SUBSCRIPTION_ID"
echo "Resource Group: $RESOURCE_GROUP"
echo "Location: $LOCATION"
echo ""

# Create resource group
echo "Creating resource group..."
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --output none
echo "$RESOURCE_GROUP" > /tmp/azure_compliance_test_rg.txt
echo "✅ Resource group created: $RESOURCE_GROUP"
echo ""

# Function to provision with error handling
provision_service() {
    local service_name=$1
    local cmd=$2
    echo -n "Provisioning $service_name... "
    if eval "$cmd" > /dev/null 2>&1; then
        echo "✅"
    else
        echo "❌ (skipped - may already exist or quota limit)"
    fi
}

echo "Provisioning free/low-cost services..."
echo ""

# FREE TIER SERVICES

# 1. Storage Account (Free tier - 5GB)
provision_service "Storage Account (Free)" \
    "az storage account create --name stcompliance$(date +%s | cut -c1-10) --resource-group $RESOURCE_GROUP --location $LOCATION --sku Standard_LRS --kind StorageV2"

# 2. Key Vault (Free - first 10,000 operations/month)
provision_service "Key Vault (Free tier)" \
    "az keyvault create --name kv-compliance-$(date +%s | cut -c1-10) --resource-group $RESOURCE_GROUP --location $LOCATION --sku standard"

# 3. Virtual Network (Free)
provision_service "Virtual Network (Free)" \
    "az network vnet create --name vnet-compliance-test --resource-group $RESOURCE_GROUP --location $LOCATION --address-prefix 10.0.0.0/16 --subnet-name default --subnet-prefix 10.0.1.0/24"

# 4. Network Security Group (Free)
provision_service "Network Security Group (Free)" \
    "az network nsg create --name nsg-compliance-test --resource-group $RESOURCE_GROUP --location $LOCATION"

# 5. API Management (Consumption tier - pay per use, very low cost)
provision_service "API Management (Consumption)" \
    "az apim create --name apim-compliance-$(date +%s | cut -c1-10) --resource-group $RESOURCE_GROUP --location $LOCATION --sku-name Consumption --publisher-email test@example.com --publisher-name ComplianceTest"

# 6. Container Registry (Basic tier - $5/month but free for first month)
provision_service "Container Registry (Basic)" \
    "az acr create --name acrcompliance$(date +%s | cut -c1-10) --resource-group $RESOURCE_GROUP --location $LOCATION --sku Basic"

# 7. Log Analytics Workspace (Free tier - 5GB/month)
provision_service "Log Analytics Workspace (Free)" \
    "az monitor log-analytics workspace create --name law-compliance-$(date +%s | cut -c1-10) --resource-group $RESOURCE_GROUP --location $LOCATION"

# 8. App Service Plan (Free tier)
APP_SERVICE_PLAN="asp-compliance-$(date +%s | cut -c1-10)"
provision_service "App Service Plan (Free)" \
    "az appservice plan create --name $APP_SERVICE_PLAN --resource-group $RESOURCE_GROUP --location $LOCATION --sku FREE"
provision_service "Web App (Free)" \
    "az webapp create --name web-compliance-$(date +%s | cut -c1-10) --resource-group $RESOURCE_GROUP --plan $APP_SERVICE_PLAN"

# 9. Automation Account (Free tier)
provision_service "Automation Account (Free)" \
    "az automation account create --name auto-compliance-$(date +%s | cut -c1-10) --resource-group $RESOURCE_GROUP --location $LOCATION --sku Free"

echo ""
echo "================================================================================"
echo "✅ PROVISIONING COMPLETE"
echo "================================================================================"
echo "Resource Group: $RESOURCE_GROUP"
echo ""
echo "📝 Note: Most services are FREE tier or very low cost"
echo ""
echo "Next steps:"
echo "1. Run compliance scan:"
echo "   python3 -m azure_compliance_python_engine.engine.main_scanner \\"
echo "     --subscription $SUBSCRIPTION_ID --location $LOCATION"
echo ""
echo "2. Clean up resources:"
echo "   az group delete --name $RESOURCE_GROUP --yes --no-wait"
echo ""

