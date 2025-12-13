# Test Azure Subscription Service

## Quick Test Commands

### 1. Validate YAML Structure
```bash
cd /Users/apple/Desktop/threat-engine/azure_compliance_python_engine

# Check YAML is valid
python3 << 'EOF'
import yaml
with open('services/subscription/rules/subscription.yaml') as f:
    data = yaml.safe_load(f)
    print(f"✅ YAML valid")
    print(f"  - Service: {data['service']}")
    print(f"  - Discovery sections: {len(data['discovery'])}")
    print(f"  - Check rules: {len(data['checks'])}")
EOF
```

### 2. Validate Azure SDK Operations
```bash
cd /Users/apple/Desktop/threat-engine/azure_compliance_python_engine

# Verify operations exist in catalog
python3 << 'EOF'
import sys
sys.path.insert(0, 'Agent-ruleid-rule-yaml')
from azure_sdk_dependency_analyzer import load_analyzer

analyzer = load_analyzer()

# Check subscription.list operation
op = analyzer.find_operation('subscription', 'list')
if op:
    print("✅ subscription.list operation exists")
    print(f"  - Output fields: {op['output_fields']}")
    print(f"  - Item fields: {len(op['item_fields'])} fields")
else:
    print("❌ subscription.list NOT FOUND")

# Validate field
validation = analyzer.validate_field('subscription', 'list', 'state')
if validation['exists']:
    print("✅ Field 'state' validated")
else:
    print("❌ Field 'state' NOT FOUND")
EOF
```

### 3. Test with Azure Compliance Engine
```bash
cd /Users/apple/Desktop/threat-engine/azure_compliance_python_engine

# Set environment
export AZURE_ENGINE_FILTER_SERVICES="subscription"

# Run engine
python3 engine/main_scanner.py

# Check output
cat output/latest/inventory/subscription_inventory.json
```

## Expected Results

### YAML Validation
```
✅ YAML valid
  - Service: subscription
  - Discovery sections: 2
  - Check rules: 1
```

### SDK Validation
```
✅ subscription.list operation exists
  - Output fields: ['value', 'next_link']
  - Item fields: 2 fields
✅ Field 'state' validated
```

### Engine Test
Should produce:
- `inventory/subscription_inventory.json` - Discovered subscriptions
- `checks/subscription_checks.json` - Check results for subscription_state_enabled

## Troubleshooting

### Issue: "Module not found"
```bash
# Install Azure SDK
pip install azure-mgmt-subscription
```

### Issue: "Authentication failed"
```bash
# Set Azure credentials
export AZURE_SUBSCRIPTION_ID='your-subscription-id'
export AZURE_TENANT_ID='your-tenant-id'
export AZURE_CLIENT_ID='your-client-id'
export AZURE_CLIENT_SECRET='your-client-secret'

# OR use Azure CLI
az login
```

### Issue: "Action not found: list"
Check the YAML action name matches Azure SDK method:
```bash
python3 << 'EOF'
from azure.mgmt.subscription import SubscriptionClient
print(dir(SubscriptionClient))
EOF
```

## Comparison with AWS

### AWS accessanalyzer.yaml
```yaml
discovery:
- discovery_id: aws.accessanalyzer.list_analyzers
  calls:
  - action: list_analyzers
    save_as: list_analyzers_response
  emit:
    items_for: '{{ list_analyzers_response.analyzers }}'  # AWS uses 'analyzers'
```

### Azure subscription.yaml
```yaml
discovery:
- discovery_id: azure.subscription.list_subscriptions
  calls:
  - action: list
    save_as: list_subscriptions_response
  emit:
    items_for: '{{ list_subscriptions_response.value }}'  # Azure uses 'value'
```

**Key Difference:** Azure standardizes on `.value` for all list responses!

## Next Steps

After successful test:

1. **Create more services:**
   - keyvault (41 operations, small and simple)
   - managementgroups (18 operations)
   - containerinstance (17 operations)

2. **Implement Agent 1:**
   - Generate requirements from metadata
   - Use subscription.yaml as reference

3. **Scale to larger services:**
   - compute (262 operations)
   - network (590 operations)
   - storage (91 operations)

## Status

- [x] YAML created and validated
- [x] Operations validated against SDK catalog
- [x] Fields validated against SDK models
- [ ] Tested with Azure compliance engine
- [ ] Production deployment

---

**Created:** December 12, 2024  
**Status:** ✅ Ready for Testing

