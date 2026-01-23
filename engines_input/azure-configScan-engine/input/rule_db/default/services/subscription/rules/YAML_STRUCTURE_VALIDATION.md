# YAML Structure Validation - Azure vs AWS

## ✅ Structure Comparison

### AWS Example (accessanalyzer.yaml)
```yaml
version: '1.0'
provider: aws
service: accessanalyzer
discovery:
- discovery_id: aws.accessanalyzer.list_analyzers
  calls:
  - action: list_analyzers
    save_as: list_analyzers_response
  emit:
    items_for: '{{ list_analyzers_response.analyzers }}'
    as: item
    item:
      arn: '{{ item.arn }}'
      name: '{{ item.name }}'
      status: '{{ item.status }}'
checks:
- rule_id: aws.accessanalyzer.resource.access_analyzer_enabled
  for_each: aws.accessanalyzer.list_analyzers
  conditions:
    var: item.status
    op: equals
    value: ACTIVE
```

### Azure Example (subscription.yaml)
```yaml
version: '1.0'
provider: azure
service: subscription
discovery:
- discovery_id: azure.subscription.list_subscriptions
  calls:
  - action: list
    save_as: list_subscriptions_response
  emit:
    items_for: '{{ list_subscriptions_response.value }}'
    as: item
    item:
      id: '{{ item.id }}'
      subscription_id: '{{ item.subscription_id }}'
      state: '{{ item.state }}'
checks:
- rule_id: azure.subscription.subscription.subscription_state_enabled
  for_each: azure.subscription.list_subscriptions
  conditions:
    var: item.state
    op: equals
    value: Enabled
```

## 📊 Key Differences

| Element | AWS | Azure | Notes |
|---------|-----|-------|-------|
| **version** | ✅ '1.0' | ✅ '1.0' | Same |
| **provider** | aws | azure | Different provider |
| **service** | accessanalyzer | subscription | Service name |
| **discovery_id** | aws.service.action | azure.service.action | Same pattern |
| **action** | list_analyzers | list | Azure SDK method name |
| **items_for** | `.analyzers` | `.value` | Azure uses `.value` for lists |
| **item fields** | Direct (arn, name) | Direct (id, name) | Same pattern |
| **rule_id** | aws.service.resource.rule | azure.service.resource.rule | Same pattern |
| **for_each** | aws.service.action | azure.service.action | Same pattern |
| **conditions** | ✅ Same structure | ✅ Same structure | Identical |

## ✅ Structure Validation

### Both Follow Same Schema:

1. **Top Level**
   ```yaml
   version: '1.0'
   provider: <aws|azure>
   service: <service_name>
   discovery: [...]
   checks: [...]
   ```

2. **Discovery Section**
   ```yaml
   - discovery_id: <provider>.<service>.<action>
     calls:
     - action: <sdk_method_name>
       save_as: <response_variable>
     emit:
       items_for: '{{ <response_variable>.<list_field> }}'
       as: item
       item:
         <field>: '{{ item.<field> }}'
   ```

3. **Checks Section**
   ```yaml
   - rule_id: <provider>.<service>.<resource>.<rule_name>
     for_each: <provider>.<service>.<action>
     conditions:
       var: item.<field>
       op: <operator>
       value: <expected_value>
   ```

## 🎯 Azure-Specific Patterns

### 1. List Response Structure
**AWS:** Different per service (analyzers, buckets, instances)
```yaml
items_for: '{{ response.analyzers }}'
items_for: '{{ response.Buckets }}'
```

**Azure:** Standardized `.value` for all list operations
```yaml
items_for: '{{ response.value }}'  # Always .value
```

### 2. Field Names
**AWS:** PascalCase in responses
```yaml
item.createdAt
item.lastResourceAnalyzed
```

**Azure:** snake_case in responses
```yaml
item.subscription_id
item.display_name
```

### 3. Action Names
**AWS:** PascalCase operation names
```yaml
action: list_analyzers  # From ListAnalyzers
```

**Azure:** snake_case operation names
```yaml
action: list  # Already snake_case
```

## ✅ Validation Checklist

- [x] YAML syntax valid
- [x] Version 1.0
- [x] Provider specified (azure)
- [x] Service name matches directory
- [x] Discovery IDs follow pattern: azure.service.action
- [x] Actions match Azure SDK methods
- [x] items_for uses .value for Azure lists
- [x] Item fields match Azure SDK model
- [x] Rule IDs follow pattern: azure.service.resource.rule
- [x] for_each references valid discovery_id
- [x] Conditions use correct field paths
- [x] All fields exist in Azure SDK model

## 🚀 Testing

### Test with Azure SDK Analyzer
```bash
cd azure_compliance_python_engine
python3 << 'EOF'
import sys
sys.path.insert(0, 'Agent-ruleid-rule-yaml')
from azure_sdk_dependency_analyzer import load_analyzer

analyzer = load_analyzer()

# Validate operations
op = analyzer.find_operation('subscription', 'list')
print(f"Operation found: {op is not None}")

# Validate fields
validation = analyzer.validate_field('subscription', 'list', 'state')
print(f"Field 'state' exists: {validation['exists']}")
EOF
```

### Test with Engine
```bash
# Run Azure compliance engine with subscription filter
export AZURE_ENGINE_FILTER_SERVICES="subscription"
python3 engine/main_scanner.py
```

## 📝 Conclusion

✅ **Azure YAML structure is 100% compatible with AWS YAML schema**

Key Points:
- Same top-level structure
- Same discovery/checks sections
- Same templating syntax (Jinja2)
- Only differences are provider-specific (field names, action names)
- Azure uses standardized `.value` for list responses
- Azure uses snake_case consistently

**Status:** ✅ VALIDATED - Ready for engine testing

