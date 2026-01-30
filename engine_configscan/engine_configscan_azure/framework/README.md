# Azure SDK Dependencies Framework

This directory contains the comprehensive Azure SDK Python dependencies mapping, similar to the AWS boto3 dependencies.

## Files

### `azure_sdk_dependencies_with_python_names.json`

Complete mapping of all Azure Python SDK operations with their parameters and metadata.

**Statistics:**
- **Total Services:** 23
- **Total Operations:** 3,377
- **Independent Operations (List):** 742
- **Dependent Operations (Requires params):** 2,635
- **Operations with output_fields:** 2,489 (73.7%)
- **Operations with item_fields:** 1,590 (47.1%)
- **File Size:** ~4.8 MB (127,000+ lines)

## Structure

The JSON file follows this structure:

```json
{
  "service_name": {
    "service": "service_name",
    "module": "azure.mgmt.service_name",
    "total_operations": 100,
    "operations_by_category": {
      "category_name": {
        "class_name": "OperationsClassName",
        "independent": [...],
        "dependent": [...]
      }
    },
    "independent": [...],
    "dependent": [...]
  }
}
```

### Operation Object Schema

Each operation contains:

```json
{
  "operation": "list",
  "python_method": "list",
  "yaml_action": "list",
  "required_params": [],
  "optional_params": ["filter", "expand"],
  "total_optional": 2,
  "output_fields": ["value", "next_link"],
  "main_output_field": "value",
  "item_fields": [
    "id", "name", "type", "location", "tags", 
    "properties", "sku", "identity", "..."
  ]
}
```

**Field Descriptions:**
- `operation`: Original method name in Azure SDK
- `python_method`: Python method name (usually same as operation)
- `yaml_action`: Snake_case version for YAML rules
- `required_params`: Parameters that must be provided
- `optional_params`: Parameters with default values
- `output_fields`: Top-level fields in the response (73.7% coverage)
- `main_output_field`: Primary field containing the list/data (usually 'value')
- `item_fields`: Fields within each item in the list (47.1% coverage)

## Services Covered

### Top 10 Services by Operations

1. **Web** (Azure App Service) - 699 operations
2. **Network** - 590 operations
3. **API Management** - 516 operations
4. **SQL** - 334 operations
5. **Compute** (VMs, Disks, etc.) - 262 operations
6. **Cosmos DB** - 194 operations
7. **Automation** - 116 operations
8. **Storage** - 91 operations
9. **Monitor** - 67 operations
10. **Container Service (AKS)** - 57 operations

### Complete Service List

- apimanagement (516 ops)
- authorization (21 ops)
- automation (116 ops)
- batch (41 ops)
- compute (262 ops)
- containerinstance (17 ops)
- containerservice (57 ops)
- cosmosdb (194 ops)
- eventhub (56 ops)
- keyvault (41 ops)
- managementgroups (18 ops)
- monitor (67 ops)
- network (590 ops)
- rdbms_mariadb (37 ops)
- rdbms_mysql (46 ops)
- rdbms_postgresql (37 ops)
- recoveryservices (18 ops)
- recoveryservicesbackup (46 ops)
- servicebus (57 ops)
- sql (334 ops)
- storage (91 ops)
- subscription (16 ops)
- web (699 ops)

## Independent vs Dependent Operations

### Independent Operations (742 total)
Operations that can run without resource-specific parameters:
- List operations (e.g., `list_virtual_machines`, `list_storage_accounts`)
- Enumerate operations
- Get all operations
- Typically require 0-1 parameters (usually subscription_id or resource_group_name)

### Dependent Operations (2,635 total)
Operations that require specific resource identifiers:
- Create/Update operations
- Delete operations
- Get specific resource operations
- Configure/Modify operations
- Require 2+ parameters

## Usage in Compliance Engine

This file is used by the Azure compliance engine to:

1. **Dynamic Service Discovery**: Automatically discover available Azure operations
2. **Rule Generation**: Generate compliance rules based on available operations
3. **Action Mapping**: Map YAML action names to Python SDK methods
4. **Parameter Validation**: Validate required and optional parameters
5. **Documentation**: Auto-generate documentation for supported checks

## Comparison with AWS

### Similarities
- JSON structure with service-level organization
- Separation of independent and dependent operations
- Python method name mappings
- Parameter classification (required/optional)

### Differences
- **Azure**: 23 services, 3,377 operations
- **AWS**: More services (100+), 40,000+ operations
- **Azure**: Category-based organization (operations classes)
- **AWS**: Flat operation list per service
- **Azure**: More list operations relative to total (22% independent)
- **AWS**: Lower percentage of list operations (~5-10% independent)

## Generation

This file was generated using `generate_azure_dependencies_final.py` which:

1. Imports Azure SDK management libraries
2. Inspects operations classes using Python reflection
3. Extracts method signatures and parameters
4. Classifies operations as independent or dependent
5. Exports structured JSON with all metadata

### Regeneration

To regenerate this file:

```bash
cd /Users/apple/Desktop/threat-engine/azure_compliance_python_engine
source venv/bin/activate
python3 framework/generate_azure_dependencies_final.py
```

**Prerequisites:**
- Python 3.8+
- Azure SDK packages installed (see requirements.txt)
- Virtual environment activated

## Notes

- `resource_group_name` and `subscription_id` parameters are excluded as they're handled at the engine level
- Output fields are currently placeholders (populated at runtime)
- Some Azure modules have versioned packages (e.g., `v2022_04_01`)
- Client-based modules (like `resource`) require special handling

## Future Enhancements

- [ ] Add runtime output field detection
- [ ] Include API versions for each operation
- [ ] Add response type mappings
- [ ] Include deprecation warnings
- [ ] Add operation cost/quota information
- [ ] Link to Azure documentation URLs
- [ ] Add example usage for each operation

## Version

**Generated:** December 12, 2024
**Azure SDK Version:** Latest stable releases
**Python Version:** 3.13

---

For questions or issues, refer to the main compliance engine documentation.

