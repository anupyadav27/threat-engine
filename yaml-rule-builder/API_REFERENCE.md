# API Reference for UI Integration

## Overview

The `RuleBuilderAPI` class provides a clean interface for UI integration. The UI collects user input and passes it to the API, which handles validation, rule comparison, and file generation.

## Quick Start

```python
from api import RuleBuilderAPI

api = RuleBuilderAPI()

# Get services for dropdown
services = api.get_available_services()

# Get fields for selected service
fields = api.get_service_fields("accessanalyzer")

# Create and generate rule
rule = api.create_rule_from_ui_input(ui_input)
result = api.generate_rule(rule)
```

## UI Input Format

The UI should collect and send this JSON structure:

```json
{
    "service": "accessanalyzer",
    "title": "User-defined title",
    "description": "User-defined description",
    "remediation": "User-defined remediation steps",
    "rule_id": "aws.accessanalyzer.resource.custom_rule",
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

### Multiple Conditions

```json
{
    "service": "accessanalyzer",
    "title": "Multiple Conditions Rule",
    "description": "Check multiple conditions",
    "remediation": "Fix all issues",
    "rule_id": "aws.accessanalyzer.resource.multi_condition",
    "conditions": [
        {
            "field_name": "status",
            "operator": "equals",
            "value": "ACTIVE"
        },
        {
            "field_name": "statusReason",
            "operator": "not_equals",
            "value": null
        }
    ],
    "logical_operator": "all"
}
```

## API Methods

### `get_available_services() -> List[str]`

Returns list of all available AWS services.

**Use case**: Populate service dropdown in UI

**Example**:
```python
services = api.get_available_services()
# Returns: ["accessanalyzer", "account", "acm", ...]
```

### `get_service_fields(service_name: str) -> Dict[str, Dict]`

Returns all available fields for a service with metadata.

**Use case**: Populate field dropdown, show operators, show possible values

**Example**:
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

### `create_rule_from_ui_input(ui_input: Dict) -> Rule`

Creates a Rule object from UI input.

**Use case**: Convert UI form data to Rule object

**Example**:
```python
rule = api.create_rule_from_ui_input({
    "service": "accessanalyzer",
    "title": "My Rule",
    "description": "Description",
    "remediation": "Steps",
    "rule_id": "aws.accessanalyzer.resource.my_rule",
    "conditions": [...],
    "logical_operator": "all"
})
```

### `validate_rule(rule: Rule) -> Dict`

Validates a rule and checks for existing rules.

**Use case**: Validate before generation, show warnings about existing rules

**Returns**:
```python
{
    "valid": True,
    "errors": [],
    "warnings": [],
    "existing_rules": [
        {
            "rule_id": "aws.accessanalyzer.resource.existing_rule",
            "source_file": "/path/to/file.yaml",
            "for_each": "aws.accessanalyzer.list_analyzers"
        }
    ]
}
```

### `generate_rule(rule: Rule, output_path: Optional[Path] = None, create_metadata: bool = True) -> Dict`

Generates YAML and metadata files.

**Use case**: Final step - generate files after validation

**Returns**:
```python
{
    "success": True,
    "yaml_path": "/path/to/accessanalyzer.yaml",
    "metadata_path": "/path/to/metadata/rule_id.yaml",
    "existing_rules_found": [],
    "errors": []
}
```

## Logical Operators

- **"single"**: One condition (default)
- **"all"**: All conditions must be true (AND logic)
- **"any"**: Any condition must be true (OR logic)

## Complete UI Workflow

```python
# 1. Initialize
api = RuleBuilderAPI()

# 2. Load services (on page load)
services = api.get_available_services()
# Populate service dropdown

# 3. Load fields (when service selected)
fields = api.get_service_fields(selected_service)
# Populate field dropdown, show operators

# 4. User builds rule in UI
# - Selects service
# - Selects field(s)
# - Selects operator(s)
# - Enters value(s)
# - Enters title, description, remediation
# - Selects logical operator (if multiple conditions)

# 5. Create rule object
rule = api.create_rule_from_ui_input(ui_form_data)

# 6. Validate
validation = api.validate_rule(rule)
if not validation["valid"]:
    # Show errors to user
    return

# 7. Check for existing rules
if validation["existing_rules"]:
    # Show warning: "Similar rule exists: {rule_id}"
    # Ask: "Use existing or create new?"

# 8. Generate
result = api.generate_rule(rule)
if result["success"]:
    # Show success: "Rule created!"
    # Show paths: YAML and metadata
else:
    # Show errors
```

## Error Handling

All methods return structured error information:

```python
{
    "valid": False,
    "errors": [
        "Field 'invalid' not found",
        "Operator 'invalid' not valid"
    ],
    "warnings": [
        "Value may not be valid"
    ]
}
```

## Output Files

- **YAML**: `aws_compliance_python_engine/services/{service}/rules/{service}.yaml`
- **Metadata**: `aws_compliance_python_engine/services/{service}/metadata/{rule_id}.yaml`

Metadata includes:
- `custom: true` - User-created marker
- `source: user_created` - Source identifier
- `created_at` - Timestamp
- `created_by: yaml_rule_builder` - Tool identifier

