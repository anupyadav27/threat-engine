# Azure SDK Dependencies - Quick Start Guide

## 🚀 What is This?

A comprehensive JSON mapping of all Azure Python SDK operations, similar to AWS boto3 dependencies. This file enables dynamic compliance rule execution in the Azure compliance engine.

## 📋 Quick Facts

- **File:** `azure_sdk_dependencies_with_python_names.json`
- **Size:** 2.9 MB
- **Services:** 23 Azure services
- **Operations:** 3,377 total
- **Format:** JSON

## 💡 How to Use

### 1. Load the Dependencies

```python
import json

with open('framework/azure_sdk_dependencies_with_python_names.json') as f:
    azure_deps = json.load(f)
```

### 2. Explore Available Services

```python
# List all services
services = azure_deps.keys()
print(f"Available services: {list(services)}")

# Get service info
compute = azure_deps['compute']
print(f"Compute has {compute['total_operations']} operations")
```

### 3. Find List Operations (Independent)

```python
# Get all independent operations for storage
storage_list_ops = azure_deps['storage']['independent']

for op in storage_list_ops:
    print(f"Operation: {op['operation']}")
    print(f"  Python Method: {op['python_method']}")
    print(f"  Required Params: {op['required_params']}")
    print()
```

### 4. Find Operations by Category

```python
# Get VM operations from compute service
compute_ops = azure_deps['compute']['operations_by_category']

# List all categories
print("Compute categories:", list(compute_ops.keys()))

# Get specific category
vm_ops = compute_ops['virtualmachines']
print(f"VM operations: {len(vm_ops['independent']) + len(vm_ops['dependent'])}")
```

### 5. Use in Compliance Rules

```yaml
# Example YAML rule using the dependencies
- rule_id: azure.storage.account.https_only
  for_each: azure.storage.list_storage_accounts  # From independent operations
  conditions:
    var: item.enable_https_traffic_only
    op: equals
    value: true
```

## 🔍 Common Queries

### Find All List Operations

```python
all_list_ops = []
for service, data in azure_deps.items():
    for op in data['independent']:
        all_list_ops.append({
            'service': service,
            'operation': op['operation'],
            'params': op['required_params']
        })

print(f"Total list operations: {len(all_list_ops)}")
```

### Find Operations by Name Pattern

```python
def find_operations(pattern):
    results = []
    for service, data in azure_deps.items():
        all_ops = data['independent'] + data['dependent']
        for op in all_ops:
            if pattern.lower() in op['operation'].lower():
                results.append({
                    'service': service,
                    'operation': op['operation'],
                    'type': 'independent' if op in data['independent'] else 'dependent'
                })
    return results

# Find all encryption-related operations
encryption_ops = find_operations('encrypt')
```

### Get Service Statistics

```python
def service_stats(service_name):
    service = azure_deps[service_name]
    return {
        'service': service_name,
        'module': service['module'],
        'total_operations': service['total_operations'],
        'independent': len(service['independent']),
        'dependent': len(service['dependent']),
        'categories': len(service['operations_by_category'])
    }

stats = service_stats('network')
print(json.dumps(stats, indent=2))
```

## 📊 Top Services by Operations

1. **web** - 699 operations (App Service, Functions)
2. **network** - 590 operations (VNets, NSGs, Load Balancers)
3. **apimanagement** - 516 operations (API Management)
4. **sql** - 334 operations (Azure SQL)
5. **compute** - 262 operations (VMs, Disks, Images)

## 🛠️ Regenerate the File

If you need to update with latest Azure SDK:

```bash
cd azure_compliance_python_engine
source venv/bin/activate
python3 framework/generate_azure_dependencies_final.py
```

## 📖 More Information

- **Full Documentation:** See `README.md`
- **AWS Comparison:** See `AWS_AZURE_COMPARISON.md`
- **Implementation Details:** See `IMPLEMENTATION_SUMMARY.md`

## 💬 Common Use Cases

### Use Case 1: Build Dynamic Scanner

```python
def scan_service(service_name):
    """Dynamically scan a service using independent operations"""
    service = azure_deps[service_name]
    
    for op in service['independent']:
        method_name = op['python_method']
        required_params = op['required_params']
        
        print(f"Scanning with {method_name}...")
        # Execute operation dynamically
        # results = execute_operation(service_name, method_name, params)
```

### Use Case 2: Generate Rule Templates

```python
def generate_rule_template(service_name, operation):
    """Generate YAML rule template from operation"""
    template = f"""
- rule_id: {service_name}.resource.check_name
  for_each: {service_name}.{operation['python_method']}
  conditions:
    var: item.property_name
    op: equals
    value: expected_value
"""
    return template

# Generate template for storage
op = azure_deps['storage']['independent'][0]
print(generate_rule_template('storage', op))
```

### Use Case 3: Validate Parameters

```python
def validate_params(service_name, operation_name, provided_params):
    """Validate provided parameters against operation requirements"""
    service = azure_deps[service_name]
    all_ops = service['independent'] + service['dependent']
    
    operation = next((op for op in all_ops if op['operation'] == operation_name), None)
    if not operation:
        return False, "Operation not found"
    
    # Check required params
    missing = set(operation['required_params']) - set(provided_params.keys())
    if missing:
        return False, f"Missing required parameters: {missing}"
    
    return True, "Parameters valid"

# Validate
valid, msg = validate_params('compute', 'list', {})
print(f"Valid: {valid}, Message: {msg}")
```

## 🎯 Tips

1. **Performance:** Load the JSON once and cache it
2. **Memory:** File is 2.9 MB, loads quickly
3. **Updates:** Regenerate when Azure SDK updates
4. **Categories:** Use `operations_by_category` for organized access
5. **Type Hints:** Operation structure is consistent across all services

## ❓ FAQ

**Q: How often should I regenerate?**  
A: When you update Azure SDK packages or add new services.

**Q: Are all Azure services included?**  
A: Currently 23 core services. More can be added easily.

**Q: What about output fields?**  
A: Currently placeholders, populated at runtime in the engine.

**Q: Can I modify the structure?**  
A: Yes, edit `generate_azure_dependencies_final.py` and regenerate.

## 🔗 Related Files

- `azure_sdk_dependencies_with_python_names.json` - The main file
- `generate_azure_dependencies_final.py` - Generation script
- `README.md` - Full documentation
- `AWS_AZURE_COMPARISON.md` - AWS comparison
- `IMPLEMENTATION_SUMMARY.md` - Technical details

---

**Quick Start Version:** 1.0  
**Created:** December 12, 2024  
**Maintainer:** Compliance Engine Team

