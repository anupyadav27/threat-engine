# Filter AWS-Managed Resources Implementation Plan

## Summary

Filter out AWS-managed/default resources to:
1. Reduce inventory bloat (~4,000-5,000 items)
2. Improve scan performance (30-50% faster)
3. Focus on actual customer resources

## Filters to Implement

### High Priority (Immediate)

**1. KMS Aliases (YAML filter)**
```yaml
# Filter in emit section - only keep non-AWS aliases
emit:
  items_for: '{{ response.Aliases }}'
  as: item
  # Filter out AWS-managed aliases
  where:
    - var: item.AliasName
      op: not_contains
      value: 'alias/aws/'
```

Impact: 12 per region × 85 = 1,020 items

**2. SecurityHub Products (Skip in inventory)**
- These are AWS marketplace products, not actual resources
- Should not be in inventory at all
- Modify `is_cspm_inventory_resource()` to skip describe_products

Impact: ~60 per region × 85 = 5,100 items

**3. Keyspaces System Tables (YAML filter)**
```yaml
# Filter in emit section
emit:
  items_for: '{{ response.keyspaces }}'
  as: item
  # Filter out system keyspaces
  where:
    - var: item.keyspaceName
      op: not_contains
      value: 'system_'
```

Impact: 3 per region × 85 = 255 items

**4. SSM Nodes (Already filtered - Owner: Self)**
- SSM documents already filtered ✅
- SSM patch baselines already filtered ✅
- SSM nodes (list_nodes) - unclear if filterable

### Add is_aws_managed Flag

In `engine/service_scanner.py` `extract_resource_identifier()`:

```python
def is_aws_managed_resource(resource_id: str, name: str, service: str) -> bool:
    """Determine if resource is AWS-managed."""
    
    # KMS AWS-managed aliases
    if 'alias/aws/' in resource_id or 'alias/aws/' in name:
        return True
    
    # SSM AWS-managed documents/nodes
    if name.startswith('AWS-') or resource_id.startswith('AWS-'):
        return True
    
    # Keyspaces system tables
    if name.startswith('system_'):
        return True
    
    # Default resources
    if name in ['primary', 'default']:
        return True
    
    # SecurityHub products (marketplace)
    if 'product/' in resource_id:
        return True
    
    # SageMaker Public Hub
    if 'SageMaker Public Hub' in name:
        return True
    
    return False

# In extract_resource_identifier, add:
is_aws_managed = is_aws_managed_resource(resource_id, name, service)

# Return in resource_info
return {
    "resource_id": resource_id,
    "resource_type": resource_type,
    "resource_arn": resource_arn,
    "resource_uid": resource_uid,
    "is_aws_managed": is_aws_managed  # NEW
}
```

Then in inventory asset creation, include the flag:
```python
asset["is_aws_managed"] = resource_info.get("is_aws_managed", False)
```

## Implementation Steps

1. ✅ Add `is_aws_managed` flag to inventory
2. Filter KMS list_aliases
3. Skip SecurityHub products in inventory
4. Filter Keyspaces system tables
5. Document in inventory schema

## Expected Impact

- Inventory reduction: ~6,000-7,000 items
- Performance gain: ~30-40% faster
- Cleaner inventory for UI/reporting

