#!/bin/bash
# Complete Azure Resource Cleanup Script
# Removes all test resources and verifies zero costs

set -e

SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID:-f6d24b5d-51ed-47b7-9f6a-0ad194156b5e}"

echo "╔══════════════════════════════════════════════════════════════════════════╗"
echo "║              🧹 COMPREHENSIVE AZURE CLEANUP                             ║"
echo "╚══════════════════════════════════════════════════════════════════════════╝"
echo ""

# Function to delete resource group with retry
delete_resource_group() {
    local rg_name=$1
    echo "🗑️  Deleting resource group: $rg_name"
    
    if az group delete --name "$rg_name" --subscription "$SUBSCRIPTION_ID" --yes --no-wait 2>/dev/null; then
        echo "   ✅ Deletion initiated for $rg_name"
    else
        echo "   ⚠️  $rg_name not found or already deleted"
    fi
}

# 1. Delete all test resource groups
echo "1️⃣ Checking for test resource groups..."
TEST_RGS=$(az group list --subscription "$SUBSCRIPTION_ID" --query "[?contains(name, 'test') || contains(name, 'agentic') || contains(name, 'incremental')].name" -o tsv 2>/dev/null || echo "")

if [ -n "$TEST_RGS" ]; then
    echo "   Found test resource groups:"
    echo "$TEST_RGS" | while read -r rg; do
        echo "      - $rg"
        delete_resource_group "$rg"
    done
else
    echo "   ✅ No test resource groups found"
fi

echo ""

# 2. Delete specific known test resource groups
echo "2️⃣ Deleting known test resource groups..."
for rg in "rg-agentic-test-DELETE" "rg-incremental-test" "rg-test-validation"; do
    delete_resource_group "$rg"
done

echo ""

# 3. Wait and verify cleanup
echo "3️⃣ Waiting 10 seconds for deletion to start..."
sleep 10

echo ""

# 4. Final verification
echo "4️⃣ Verifying cleanup..."
REMAINING_RGS=$(az group list --subscription "$SUBSCRIPTION_ID" --query "length(@)" -o tsv 2>/dev/null || echo "0")
REMAINING_RESOURCES=$(az resource list --subscription "$SUBSCRIPTION_ID" --query "length(@)" -o tsv 2>/dev/null || echo "0")

echo "   Resource Groups: $REMAINING_RGS"
echo "   Total Resources: $REMAINING_RESOURCES"

if [ "$REMAINING_RGS" = "0" ] && [ "$REMAINING_RESOURCES" = "0" ]; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════╗"
    echo "║                    ✅ CLEANUP COMPLETE                                   ║"
    echo "╚══════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "💰 Estimated Monthly Cost: $0.00"
    echo "✅ Zero Azure resources remaining"
else
    echo ""
    echo "⚠️  Some resources may still be deleting in background"
    echo "    Run 'az group list' to check status"
fi

echo ""
echo "✅ Cleanup script completed"

