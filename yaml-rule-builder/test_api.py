#!/usr/bin/env python3
"""
Test the API interface
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from api import RuleBuilderAPI
from models.rule import Rule
from models.field_selection import FieldSelection

def test_single_condition():
    """Test single condition rule"""
    print("=" * 60)
    print("Test 1: Single Condition Rule")
    print("=" * 60)
    
    api = RuleBuilderAPI()
    
    rule = Rule(
        rule_id="aws.accessanalyzer.resource.test_single",
        service="accessanalyzer",
        title="Test Single Condition",
        description="Test rule with single condition",
        remediation="Fix the issue",
        conditions=[
            FieldSelection(
                field_name="status",
                operator="equals",
                value="ACTIVE",
                rule_id="aws.accessanalyzer.resource.test_single"
            )
        ],
        logical_operator="single"
    )
    
    validation = api.validate_rule(rule)
    print(f"Valid: {validation['valid']}")
    print(f"Errors: {validation['errors']}")
    print(f"Existing rules: {validation['existing_rules']}")
    
    if validation['valid']:
        result = api.generate_rule(rule, output_path=Path("/tmp/test_single.yaml"))
        print(f"Success: {result['success']}")
        print(f"YAML: {result['yaml_path']}")
        print(f"Metadata: {result['metadata_path']}")

def test_multiple_conditions():
    """Test multiple conditions with 'all' operator"""
    print("\n" + "=" * 60)
    print("Test 2: Multiple Conditions (ALL)")
    print("=" * 60)
    
    api = RuleBuilderAPI()
    
    rule = Rule(
        rule_id="aws.accessanalyzer.resource.test_multiple_all",
        service="accessanalyzer",
        title="Test Multiple Conditions ALL",
        description="Test rule with multiple conditions (all must be true)",
        remediation="Fix all issues",
        conditions=[
            FieldSelection(
                field_name="status",
                operator="equals",
                value="ACTIVE",
                rule_id="aws.accessanalyzer.resource.test_multiple_all"
            ),
            FieldSelection(
                field_name="statusReason",
                operator="not_equals",
                value=None,
                rule_id="aws.accessanalyzer.resource.test_multiple_all"
            )
        ],
        logical_operator="all"
    )
    
    validation = api.validate_rule(rule)
    print(f"Valid: {validation['valid']}")
    print(f"Errors: {validation['errors']}")
    
    if validation['valid']:
        result = api.generate_rule(rule, output_path=Path("/tmp/test_multiple_all.yaml"))
        print(f"Success: {result['success']}")
        print(f"YAML: {result['yaml_path']}")
        if result['success']:
            # Read and show the conditions part
            import yaml
            with open(result['yaml_path'], 'r') as f:
                data = yaml.safe_load(f)
                checks = data.get('checks', [])
                if checks:
                    print(f"Conditions structure: {checks[0].get('conditions')}")

def test_ui_input():
    """Test creating rule from UI input format"""
    print("\n" + "=" * 60)
    print("Test 3: UI Input Format")
    print("=" * 60)
    
    api = RuleBuilderAPI()
    
    ui_input = {
        "service": "accessanalyzer",
        "title": "UI Test Rule",
        "description": "Test rule created from UI input",
        "remediation": "Fix the issue in UI",
        "rule_id": "aws.accessanalyzer.resource.ui_test",
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
    print(f"Rule created: {rule.rule_id}")
    print(f"Conditions: {len(rule.conditions)}")
    print(f"Logical operator: {rule.logical_operator}")
    
    validation = api.validate_rule(rule)
    print(f"Valid: {validation['valid']}")

if __name__ == "__main__":
    test_single_condition()
    test_multiple_conditions()
    test_ui_input()
    print("\n" + "=" * 60)
    print("All tests completed!")
    print("=" * 60)

