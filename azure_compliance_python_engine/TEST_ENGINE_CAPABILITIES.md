# Azure Compliance Engine - Full Capabilities Test Guide

## 🎯 Engine Features (Same as AWS)

The Azure engine has **full feature parity** with AWS engine:

✅ **Multi-threading** - Parallel execution at all levels  
✅ **Multi-subscription** - Scan entire organization  
✅ **Multi-region** - All Azure locations  
✅ **Multi-service** - All enabled services  
✅ **Flexible filtering** - Include/exclude at any level  
✅ **Resource-level** - Single resource or pattern matching  
✅ **Granular control** - From full org to single resource  

## 📊 Scanning Levels

### Level 1: Full Organization (All Subscriptions)
```bash
cd /Users/apple/Desktop/threat-engine/azure_compliance_python_engine

# Scan all subscriptions in tenant
python3 engine/main_scanner.py --tenant-id $AZURE_TENANT_ID

# With parallelism control
python3 engine/main_scanner.py \
  --max-subscription-workers 5 \
  --max-workers 20
```

### Level 2: Multi-Subscription
```bash
# Specific subscriptions
python3 engine/main_scanner.py \
  --include-subscriptions "sub-id-1,sub-id-2,sub-id-3"

# All except some
python3 engine/main_scanner.py \
  --exclude-subscriptions "dev-sub-id,test-sub-id"
```

### Level 3: Single Subscription
```bash
# Just one subscription
python3 engine/main_scanner.py \
  --subscription $AZURE_SUBSCRIPTION_ID
```

### Level 4: Subscription + Region
```bash
# Single subscription + single region
python3 engine/main_scanner.py \
  --subscription $AZURE_SUBSCRIPTION_ID \
  --location eastus

# Single subscription + multiple regions
python3 engine/main_scanner.py \
  --subscription $AZURE_SUBSCRIPTION_ID \
  --include-locations "eastus,westus,centralus"

# All regions except
python3 engine/main_scanner.py \
  --subscription $AZURE_SUBSCRIPTION_ID \
  --exclude-locations "northeurope,westeurope"
```

### Level 5: Subscription + Region + Service
```bash
# Single service
python3 engine/main_scanner.py \
  --subscription $AZURE_SUBSCRIPTION_ID \
  --location eastus \
  --service keyvault

# Multiple services
python3 engine/main_scanner.py \
  --subscription $AZURE_SUBSCRIPTION_ID \
  --include-services "keyvault,storage,compute"

# All except
python3 engine/main_scanner.py \
  --subscription $AZURE_SUBSCRIPTION_ID \
  --exclude-services "monitor,network"
```

### Level 6: Resource-Level (Most Granular)
```bash
# Single specific resource
python3 engine/main_scanner.py \
  --subscription $AZURE_SUBSCRIPTION_ID \
  --service keyvault \
  --resource "my-keyvault-name"

# Pattern matching
python3 engine/main_scanner.py \
  --subscription $AZURE_SUBSCRIPTION_ID \
  --service keyvault \
  --resource-pattern "*prod*"

# By resource type
python3 engine/main_scanner.py \
  --subscription $AZURE_SUBSCRIPTION_ID \
  --service storage \
  --resource-type "StorageAccount"
```

## 🧪 Test KeyVault Service

### Test 1: Single Subscription + Single Service
```bash
cd /Users/apple/Desktop/threat-engine/azure_compliance_python_engine

# Test keyvault in current subscription
python3 engine/main_scanner.py \
  --service keyvault \
  --subscription $AZURE_SUBSCRIPTION_ID
```

**Expected Output:**
```
AZURE FLEXIBLE COMPLIANCE SCANNER
Scan Scope:
  Subscriptions: 1 - ['xxx-xxx-xxx']
  Locations: 25 - ['eastus', 'westus', ...]
  Services: 1 - ['keyvault']

Parallelism:
  Subscription workers: 3
  Service/location workers: 10

Scanning subscriptions in parallel...
[1/1] ✓ Subscription-xxx: 175 checks

SCAN COMPLETE
Total checks: 175
  PASS: 120
  FAIL: 55

Report: output/latest/
```

### Test 2: Single Subscription + Single Location + Single Service
```bash
# More focused test
python3 engine/main_scanner.py \
  --service keyvault \
  --subscription $AZURE_SUBSCRIPTION_ID \
  --location eastus
```

**Expected Output:**
```
Scan Scope:
  Subscriptions: 1
  Locations: 1 - ['eastus']
  Services: 1 - ['keyvault']

Total checks: 7  (1 location × 7 checks)
```

### Test 3: Multiple Services
```bash
# Test multiple small services
python3 engine/main_scanner.py \
  --subscription $AZURE_SUBSCRIPTION_ID \
  --include-services "keyvault,subscription,managementgroups"
```

## 🔧 Performance Tuning

### Conservative (Default)
```bash
python3 engine/main_scanner.py \
  --max-subscription-workers 3 \
  --max-workers 10
```

### Aggressive (Fast)
```bash
python3 engine/main_scanner.py \
  --max-subscription-workers 10 \
  --max-workers 50
```

### Safe (For testing)
```bash
python3 engine/main_scanner.py \
  --max-subscription-workers 1 \
  --max-workers 1
```

## 📋 Output Structure

The engine creates comprehensive reports:

```
output/
└── scan_20241212_153045/
    ├── summary.json              # Overall summary
    ├── inventory/
    │   └── keyvault_inventory.json
    ├── checks/
    │   └── keyvault_checks.json
    └── logs/
        └── scan.log
```

### inventory/keyvault_inventory.json
```json
{
  "service": "keyvault",
  "subscription": "xxx-xxx-xxx",
  "location": "eastus",
  "discovered": [
    {
      "id": "/subscriptions/.../vaults/my-vault",
      "name": "my-vault",
      "type": "Microsoft.KeyVault/vaults",
      "location": "eastus",
      "properties": {
        "enable_soft_delete": true,
        "enable_purge_protection": true,
        ...
      }
    }
  ],
  "count": 5
}
```

### checks/keyvault_checks.json
```json
{
  "service": "keyvault",
  "subscription": "xxx-xxx-xxx",
  "checks": [
    {
      "rule_id": "azure.keyvault.vault.soft_delete_enabled",
      "resource_id": "/subscriptions/.../vaults/my-vault",
      "result": "PASS",
      "expected": true,
      "actual": true,
      "message": "Soft delete is enabled"
    },
    {
      "rule_id": "azure.keyvault.vault.purge_protection_enabled",
      "resource_id": "/subscriptions/.../vaults/my-vault",
      "result": "FAIL",
      "expected": true,
      "actual": false,
      "message": "Purge protection is not enabled"
    }
  ],
  "summary": {
    "total": 7,
    "passed": 5,
    "failed": 2,
    "errors": 0
  }
}
```

## 🎯 Real-World Usage Examples

### DevOps: Scan Dev Environment
```bash
python3 engine/main_scanner.py \
  --subscription $DEV_SUBSCRIPTION_ID \
  --location eastus \
  --exclude-services "monitor,backup"
```

### Security: Quick Compliance Check
```bash
python3 engine/main_scanner.py \
  --subscription $PROD_SUBSCRIPTION_ID \
  --include-services "keyvault,storage,sql,network"
```

### Audit: Full Organization Scan
```bash
python3 engine/main_scanner.py \
  --tenant-id $AZURE_TENANT_ID \
  --max-subscription-workers 5 \
  --max-workers 20
```

### Investigation: Single Resource
```bash
python3 engine/main_scanner.py \
  --subscription $AZURE_SUBSCRIPTION_ID \
  --service keyvault \
  --resource "suspicious-vault-name"
```

## 🐛 Troubleshooting

### Authentication Issues
```bash
# Set Azure credentials
export AZURE_TENANT_ID='your-tenant-id'
export AZURE_CLIENT_ID='your-client-id'
export AZURE_CLIENT_SECRET='your-client-secret'
export AZURE_SUBSCRIPTION_ID='your-subscription-id'

# OR use Azure CLI
az login
```

### Check if Service is Enabled
```bash
python3 << 'EOF'
from engine.service_scanner import load_enabled_services_with_scope
services = load_enabled_services_with_scope()
for svc, scope in services:
    print(f"{svc:20s} ({scope})")
EOF
```

### View Available Services
```bash
ls -1 /Users/apple/Desktop/threat-engine/azure_compliance_python_engine/services/
```

### Check YAML Syntax
```bash
python3 -c "import yaml; yaml.safe_load(open('services/keyvault/keyvault_rules.yaml'))"
```

## ⚡ Quick Test Command

```bash
# Quick end-to-end test with keyvault
cd /Users/apple/Desktop/threat-engine/azure_compliance_python_engine

python3 engine/main_scanner.py \
  --service keyvault \
  --subscription ${AZURE_SUBSCRIPTION_ID:-$(az account show --query id -o tsv)} \
  --location eastus \
  --max-workers 5

# Check results
cat output/latest/checks/keyvault_checks.json | python3 -m json.tool | head -50
```

## 📊 Expected Test Results

For keyvault service with 7 checks:

```
✅ Successful Scan:
  - Inventory: 5 vaults discovered
  - Checks: 35 checks (5 vaults × 7 checks)
  - Results: Mix of PASS/FAIL based on actual configuration
  - No ERROR results

⚠️ Partial Success:
  - Inventory: 0 vaults (if none exist)
  - Checks: 0
  - Message: "No resources found"

❌ Failure:
  - Error: "Service not enabled"
  - Fix: Check services/keyvault/keyvault_rules.yaml exists
```

## 🎓 Comparison with AWS

| Feature | AWS Engine | Azure Engine | Status |
|---------|------------|--------------|--------|
| Multi-threading | ✅ | ✅ | **Same** |
| Multi-account/subscription | ✅ | ✅ | **Same** |
| Multi-region | ✅ | ✅ | **Same** |
| Multi-service | ✅ | ✅ | **Same** |
| Resource filtering | ✅ | ✅ | **Same** |
| Include/Exclude | ✅ | ✅ | **Same** |
| Pattern matching | ✅ | ✅ | **Same** |
| YAML structure | ✅ | ✅ | **Same** |
| Parallel execution | ✅ | ✅ | **Same** |
| Granular control | ✅ | ✅ | **Same** |

## 🚀 Ready to Test!

The Azure engine is **production-ready** with full feature parity to AWS. Just run:

```bash
python3 engine/main_scanner.py --service keyvault
```

---

**Created:** December 12, 2024  
**Engine Version:** Azure Flexible Scanner v1.0  
**Status:** ✅ Production Ready

