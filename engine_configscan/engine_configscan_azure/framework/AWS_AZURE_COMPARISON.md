# AWS vs Azure SDK Dependencies Comparison

This document compares the AWS (boto3) and Azure Python SDK dependency mappings created for the threat-engine compliance framework.

## Overview Statistics

| Metric | AWS (boto3) | Azure SDK | Ratio |
|--------|-------------|-----------|-------|
| **Total Services** | ~150 | 23 | 6.5:1 |
| **Total Operations** | ~40,000 | 3,377 | 11.8:1 |
| **Independent Operations** | ~4,000 | 742 | 5.4:1 |
| **Dependent Operations** | ~36,000 | 2,635 | 13.7:1 |
| **Operations with output_fields** | ~40,000 (100%) | 2,489 (73.7%) | 16.1:1 |
| **Operations with item_fields** | ~40,000 (100%) | 1,590 (47.1%) | 25.2:1 |
| **File Size** | ~395 MB | ~4.8 MB | 82.3:1 |
| **Line Count** | ~414,238 | ~127,000 | 3.3:1 |

## Architectural Differences

### AWS (boto3)

**Structure:**
```json
{
  "service_name": {
    "service": "service_name",
    "total_operations": N,
    "independent": [...],
    "dependent": [...]
  }
}
```

**Characteristics:**
- Flat service structure
- Single client per service
- Operation naming: PascalCase (AWS API) → snake_case (Python)
- Rich field metadata (output_fields, item_fields)
- Extensive documentation in responses

### Azure SDK

**Structure:**
```json
{
  "service_name": {
    "service": "service_name",
    "module": "azure.mgmt.service_name",
    "total_operations": N,
    "operations_by_category": {
      "category": {
        "class_name": "OperationsClass",
        "independent": [...],
        "dependent": [...]
      }
    },
    "independent": [...],
    "dependent": [...]
  }
}
```

**Characteristics:**
- Hierarchical operations by category
- Multiple operations classes per service
- Operation naming: consistent snake_case
- Category organization (e.g., VirtualMachinesOperations, DisksOperations)
- Versioned API packages

## Service Coverage

### AWS Top Services
1. EC2 - ~1,000+ operations
2. S3 - ~200+ operations
3. IAM - ~150+ operations
4. RDS - ~200+ operations
5. CloudWatch - ~100+ operations

### Azure Top Services
1. Web (App Service) - 699 operations
2. Network - 590 operations
3. API Management - 516 operations
4. SQL - 334 operations
5. Compute - 262 operations

## Independent Operations Analysis

### AWS
- **Percentage:** ~10% of total operations
- **Common Patterns:**
  - `list_*` operations
  - `describe_*` operations
  - Service-level operations
- **Example:** `list_buckets`, `describe_instances`

### Azure
- **Percentage:** ~22% of total operations
- **Common Patterns:**
  - `list` operations
  - `list_by_*` operations
  - `enumerate_*` operations
- **Example:** `list`, `list_by_subscription`, `list_by_resource_group`

## Parameter Handling

### AWS
- **Resource Identifiers:** Explicit in each operation
- **Region:** Handled per client instance
- **Account:** Implicit from credentials
- **Common Params:**
  - Bucket, Key (S3)
  - InstanceId (EC2)
  - FunctionName (Lambda)

### Azure
- **Resource Identifiers:** Hierarchical
- **Subscription:** Filtered at engine level
- **Resource Group:** Filtered at engine level
- **Common Params:**
  - resource_name
  - parameters (for create/update)
  - expand, filter (for list operations)

## SDK Design Philosophy

### AWS (boto3)
- **Approach:** Service-oriented
- **Organization:** By AWS service
- **Versioning:** API version in client initialization
- **Naming:** Follows AWS API exactly (PascalCase)
- **Discovery:** Service metadata in botocore

### Azure SDK
- **Approach:** Resource-oriented
- **Organization:** By resource type (operations classes)
- **Versioning:** Package-level versioning
- **Naming:** Pythonic (snake_case)
- **Discovery:** Class-based structure

## Practical Implications for Compliance Engine

### AWS Engine

**Advantages:**
- More comprehensive coverage
- Richer metadata available
- Consistent parameter patterns
- Better documented output fields

**Challenges:**
- Massive file size requires optimization
- More complex to navigate
- Higher memory footprint

### Azure Engine

**Advantages:**
- More organized structure (categories)
- Smaller file, faster loading
- Clear operation classification
- Hierarchical resource organization

**Challenges:**
- Less comprehensive service coverage
- Versioned packages require maintenance
- Output field metadata requires runtime detection
- Some modules have complex import paths

## Common Patterns

### Both Platforms

✅ **Similarities:**
1. Separate independent/dependent operations
2. Parameter classification (required/optional)
3. Python method name mapping
4. JSON-based storage
5. Service-level organization

❌ **Differences:**
1. **AWS:** Massive scale, comprehensive coverage
2. **Azure:** Organized categories, cleaner structure
3. **AWS:** Flat operation lists
4. **Azure:** Hierarchical operations by category
5. **AWS:** Rich field metadata
6. **Azure:** Minimal metadata (runtime population)

## File Usage in Engines

### AWS Engine Usage
```python
# Load dependencies
with open('boto3_dependencies_with_python_names.json') as f:
    aws_deps = json.load(f)

# Get S3 operations
s3_ops = aws_deps['s3']['independent']

# Find list operations
list_ops = [op for op in s3_ops if op['operation'].startswith('list')]
```

### Azure Engine Usage
```python
# Load dependencies
with open('azure_sdk_dependencies_with_python_names.json') as f:
    azure_deps = json.load(f)

# Get storage operations
storage_ops = azure_deps['storage']['independent']

# Get operations by category
vm_ops = azure_deps['compute']['operations_by_category']['virtualmachines']
```

## Future Enhancements

### AWS
- [ ] Update to latest boto3 version
- [ ] Add cost/pricing information
- [ ] Include throttling limits
- [ ] Add CloudFormation resource mappings

### Azure
- [ ] Expand service coverage (50+ more services)
- [ ] Add runtime output field detection
- [ ] Include ARM template resource mappings
- [ ] Add Azure Policy integration
- [ ] Include RBAC permission requirements

## Recommendations

### For AWS Compliance Checks
1. Use the comprehensive service list
2. Leverage rich output field metadata
3. Focus on `describe_*` and `list_*` operations
4. Use pagination metadata

### For Azure Compliance Checks
1. Leverage category organization
2. Use subscription/resource_group filtering
3. Focus on `list*` operations
4. Consider versioned API compatibility

## Conclusion

Both dependency mappings serve their purpose well:

- **AWS:** Comprehensive, metadata-rich, suitable for extensive compliance coverage
- **Azure:** Well-organized, efficient, suitable for targeted compliance checks

The choice of structure reflects the underlying SDK design philosophy and serves the compliance engine's needs effectively.

---

**Last Updated:** December 12, 2024
**AWS Boto3 Version:** Latest stable
**Azure SDK Version:** Latest stable releases

