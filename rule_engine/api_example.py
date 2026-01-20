"""
Example usage of RuleBuilderAPI for UI integration
"""

from api import RuleBuilderAPI
from models.rule import Rule
from models.field_selection import FieldSelection

# Initialize API
api = RuleBuilderAPI()

# Example 1: Get available services
services = api.get_available_services()
print(f"Available services: {len(services)}")

# Example 2: Get fields for a service
fields = api.get_service_fields("accessanalyzer")
print(f"Available fields for accessanalyzer: {len(fields)}")

# Example 3: Create rule from UI input
ui_input = {
    "service": "accessanalyzer",
    "title": "Access Analyzer Enabled",
    "description": "Check if access analyzer is enabled and active",
    "remediation": "Enable the access analyzer in AWS console",
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

rule = api.create_rule_from_ui_input(ui_input)

# Example 4: Validate rule
validation = api.validate_rule(rule)
print(f"Rule valid: {validation['valid']}")
if validation["existing_rules"]:
    print(f"Found existing rules: {validation['existing_rules']}")

# Example 5: Generate rule with multiple conditions
multi_condition_rule = Rule(
    rule_id="aws.accessanalyzer.resource.analyzer_enabled_no_findings",
    service="accessanalyzer",
    title="Access Analyzer Enabled Without Findings",
    description="Check if analyzer is active and has no findings",
    remediation="Enable analyzer and resolve any findings",
    conditions=[
        FieldSelection(
            field_name="status",
            operator="equals",
            value="ACTIVE",
            rule_id="aws.accessanalyzer.resource.analyzer_enabled_no_findings"
        ),
        FieldSelection(
            field_name="statusReason",
            operator="exists",
            value=None,
            rule_id="aws.accessanalyzer.resource.analyzer_enabled_no_findings"
        )
    ],
    logical_operator="all"  # All conditions must be true
)

# Validate
validation = api.validate_rule(multi_condition_rule)
print(f"Multi-condition rule valid: {validation['valid']}")

# Generate
result = api.generate_rule(multi_condition_rule)
print(f"Generation success: {result['success']}")
print(f"YAML path: {result['yaml_path']}")
print(f"Metadata path: {result['metadata_path']}")

