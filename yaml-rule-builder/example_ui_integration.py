#!/usr/bin/env python3
"""
Example: How UI would integrate with RuleBuilderAPI

This demonstrates the complete workflow from UI input to generated files.
"""

import json
from pathlib import Path
import sys

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from api import RuleBuilderAPI

def main():
    """Simulate UI workflow"""
    
    # Initialize API
    api = RuleBuilderAPI()
    
    print("=" * 60)
    print("UI Integration Example")
    print("=" * 60)
    
    # Step 1: UI loads available services
    print("\n1. Loading available services...")
    services = api.get_available_services()
    print(f"   Found {len(services)} services")
    
    # Step 2: User selects service, UI loads fields
    selected_service = "accessanalyzer"
    print(f"\n2. Loading fields for '{selected_service}'...")
    fields = api.get_service_fields(selected_service)
    print(f"   Found {len(fields)} fields")
    print(f"   Example fields: {list(fields.keys())[:5]}")
    
    # Step 3: User builds rule in UI (collected via form)
    print("\n3. User builds rule in UI...")
    ui_input = {
        "service": selected_service,
        "title": "Access Analyzer Enabled",
        "description": "Check if access analyzer is enabled and active",
        "remediation": "Enable the access analyzer:\n1. Go to IAM > Access Analyzer\n2. Click Create analyzer\n3. Select account or organization scope\n4. Enable the analyzer",
        "rule_id": "aws.accessanalyzer.resource.ui_analyzer_enabled",
        "conditions": [
            {
                "field_name": "status",
                "operator": "equals",
                "value": "ACTIVE"
            }
        ],
        "logical_operator": "single"
    }
    
    # Step 4: Create rule object
    print("4. Creating rule object...")
    rule = api.create_rule_from_ui_input(ui_input)
    print(f"   Rule ID: {rule.rule_id}")
    print(f"   Conditions: {len(rule.conditions)}")
    
    # Step 5: Validate rule
    print("\n5. Validating rule...")
    validation = api.validate_rule(rule)
    print(f"   Valid: {validation['valid']}")
    if validation['errors']:
        print(f"   Errors: {validation['errors']}")
    if validation['warnings']:
        print(f"   Warnings: {validation['warnings']}")
    if validation['existing_rules']:
        print(f"   ⚠️  Existing rules found:")
        for existing in validation['existing_rules']:
            print(f"      - {existing['rule_id']}")
    
    if not validation['valid']:
        print("\n❌ Validation failed. Cannot generate rule.")
        return
    
    # Step 6: Generate rule
    print("\n6. Generating rule...")
    result = api.generate_rule(rule)
    
    if result['success']:
        print(f"   ✅ Success!")
        print(f"   YAML: {result['yaml_path']}")
        print(f"   Metadata: {result['metadata_path']}")
    else:
        print(f"   ❌ Failed: {result['errors']}")
    
    # Example 2: Multiple conditions
    print("\n" + "=" * 60)
    print("Example 2: Multiple Conditions (ALL)")
    print("=" * 60)
    
    ui_input_multi = {
        "service": selected_service,
        "title": "Access Analyzer Enabled Without Findings",
        "description": "Check if analyzer is active and has no status reason",
        "remediation": "Enable analyzer and ensure no findings exist",
        "rule_id": "aws.accessanalyzer.resource.ui_analyzer_no_findings",
        "conditions": [
            {
                "field_name": "status",
                "operator": "equals",
                "value": "ACTIVE"
            },
            {
                "field_name": "statusReason",
                "operator": "not_equals",
                "value": None
            }
        ],
        "logical_operator": "all"
    }
    
    rule_multi = api.create_rule_from_ui_input(ui_input_multi)
    validation_multi = api.validate_rule(rule_multi)
    
    print(f"Valid: {validation_multi['valid']}")
    if validation_multi['valid']:
        result_multi = api.generate_rule(rule_multi, output_path=Path("/tmp/ui_multi.yaml"))
        print(f"Success: {result_multi['success']}")
        if result_multi['success']:
            # Show the conditions structure
            import yaml
            with open(result_multi['yaml_path'], 'r') as f:
                data = yaml.safe_load(f)
                checks = data.get('checks', [])
                if checks:
                    print(f"Conditions: {checks[0].get('conditions')}")

if __name__ == "__main__":
    main()

