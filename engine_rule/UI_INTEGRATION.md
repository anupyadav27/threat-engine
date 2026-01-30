# UI Integration Guide

## Overview

The YAML Rule Builder provides a programmatic API interface designed for UI integration. The UI can collect user input and pass it to the engine to generate YAML and metadata files.

## API Interface

### Initialize API

```python
from api import RuleBuilderAPI

api = RuleBuilderAPI()
```

## UI Input Format

The UI should collect and send the following data:

```json
{
    "service": "accessanalyzer",
    "title": "Access Analyzer Enabled",
    "description": "Check if access analyzer is enabled and active",
    "remediation": "Enable the access analyzer in AWS console:\n1. Go to IAM > Access Analyzer\n2. Click Create analyzer\n3. Select account or organization\n4. Enable the analyzer",
    "rule_id": "aws.accessanalyzer.resource.analyzer_enabled",
    "conditions": [
        {
            "field_name": "status",
            "operator": "equals",
            "value": "ACTIVE"
        }
    ],
    "logical_operator": "single"
}
```

### Multiple Conditions Example

```json
{
    "service": "accessanalyzer",
    "title": "Access Analyzer Enabled Without Findings",
    "description": "Check if analyzer is active and has no status reason",
    "remediation": "Enable analyzer and ensure no findings exist",
    "rule_id": "aws.accessanalyzer.resource.analyzer_enabled_no_findings",
    "conditions": [
        {
            "field_name": "status",
            "operator": "equals",
            "value": "ACTIVE"
        },
        {
            "field_name": "statusReason",
            "operator": "exists",
            "value": null
        }
    ],
    "logical_operator": "all"
}
```

## API Methods

### 1. Get Available Services

```python
services = api.get_available_services()
# Returns: ["accessanalyzer", "account", "acm", ...]
```

### 2. Get Service Fields

```python
fields = api.get_service_fields("accessanalyzer")
# Returns: {
#     "status": {
#         "operators": ["equals", "not_equals", "in"],
#         "type": "string",
#         "enum": true,
#         "possible_values": ["ACTIVE", "CREATING", "DISABLED", "FAILED"],
#         "operations": ["ListAnalyzers", "GetAnalyzer"]
#     },
#     ...
# }
```

### 3. Create Rule from UI Input

```python
rule = api.create_rule_from_ui_input(ui_input)
```

### 4. Validate Rule

```python
validation = api.validate_rule(rule)
# Returns: {
#     "valid": true,
#     "errors": [],
#     "warnings": [],
#     "existing_rules": [
#         {
#             "rule_id": "aws.accessanalyzer.resource.access_analyzer_enabled",
#             "source_file": ".../accessanalyzer.yaml",
#             "for_each": "aws.accessanalyzer.list_findings_v2"
#         }
#     ]
# }
```

### 5. Generate Rule

```python
result = api.generate_rule(rule)
# Returns: {
#     "success": true,
#     "yaml_path": "/path/to/accessanalyzer.yaml",
#     "metadata_path": "/path/to/metadata/rule_id.yaml",
#     "existing_rules_found": [],
#     "errors": []
# }
```

## Complete Workflow

```python
from api import RuleBuilderAPI

# 1. Initialize
api = RuleBuilderAPI()

# 2. Get available services (for dropdown)
services = api.get_available_services()

# 3. User selects service, get fields
fields = api.get_service_fields(selected_service)

# 4. User builds rule in UI
ui_input = {
    "service": "accessanalyzer",
    "title": "User-entered title",
    "description": "User-entered description",
    "remediation": "User-entered remediation",
    "rule_id": "aws.accessanalyzer.resource.custom_rule",
    "conditions": [
        {"field_name": "status", "operator": "equals", "value": "ACTIVE"},
        {"field_name": "statusReason", "operator": "exists", "value": None}
    ],
    "logical_operator": "all"
}

# 5. Create rule object
rule = api.create_rule_from_ui_input(ui_input)

# 6. Validate
validation = api.validate_rule(rule)
if not validation["valid"]:
    # Show errors to user
    print(validation["errors"])
    return

# 7. Check for existing rules
if validation["existing_rules"]:
    # Show warning: "Similar rule exists: {rule_id}"
    # Ask user: "Use existing rule or create new?"
    pass

# 8. Generate
result = api.generate_rule(rule)
if result["success"]:
    # Show success: "Rule created at {yaml_path}"
    print(f"YAML: {result['yaml_path']}")
    print(f"Metadata: {result['metadata_path']}")
else:
    # Show errors
    print(result["errors"])
```

## Logical Operators

- **"single"**: One condition (default when only one condition)
- **"all"**: All conditions must be true (AND logic)
- **"any"**: Any condition must be true (OR logic)

## Field Selection

Each condition requires:
- `field_name`: Field to check (from `get_service_fields()`)
- `operator`: Operator to use (from field's `operators` list)
- `value`: Expected value (null for `exists` operator)

## Error Handling

The API returns structured error information:

```python
{
    "valid": false,
    "errors": [
        "Field 'invalid_field' not found in service 'accessanalyzer'",
        "Operator 'invalid_op' not valid for field 'status'"
    ],
    "warnings": [
        "Value 'INVALID' may not be valid for field 'status'"
    ]
}
```

## Output Files

- **YAML File**: `aws_compliance_python_engine/services/{service}/rules/{service}.yaml`
- **Metadata File**: `aws_compliance_python_engine/services/{service}/metadata/{rule_id}.yaml`

Metadata files include:
- `custom: true` - Marks as user-created
- `source: user_created` - Source identifier
- `created_at` - Timestamp
- `created_by: yaml_rule_builder` - Tool identifier

