"""
Main CLI entry point - Updated with rule comparison and metadata generation
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Dict

# Handle both package and direct execution
try:
    from .config import Config
    from .core.data_loader import DataLoader
    from .core.yaml_generator import YAMLGenerator
    from .core.rule_comparator import RuleComparator
    from .core.metadata_generator import MetadataGenerator
    from .models.field_selection import FieldSelection
    from .commands.list_services import list_services
    from .commands.list_fields import list_fields
    from .utils.validators import Validator
except ImportError:
    # Direct execution
    from config import Config
    from core.data_loader import DataLoader
    from core.yaml_generator import YAMLGenerator
    from core.rule_comparator import RuleComparator
    from core.metadata_generator import MetadataGenerator
    from models.field_selection import FieldSelection
    from commands.list_services import list_services
    from commands.list_fields import list_fields
    from utils.validators import Validator

def cmd_list_services(args, config: Config):
    """List available services"""
    services = list_services(config)
    print(f"\nAvailable services ({len(services)}):")
    for service in services:
        print(f"  - {service}")
    print()

def cmd_list_fields(args, config: Config):
    """List fields for a service"""
    if not config.validate_service(args.service):
        print(f"Error: Service '{args.service}' not found or invalid", file=sys.stderr)
        sys.exit(1)
    
    fields = list_fields(args.service, config)
    
    print(f"\nAvailable fields for '{args.service}' ({len(fields)}):\n")
    for field_name, field_info in fields.items():
        print(f"  {field_name}")
        print(f"    Type: {field_info['type']}")
        print(f"    Operators: {', '.join(field_info['operators'])}")
        if field_info.get('enum'):
            print(f"    Possible values: {', '.join(map(str, field_info['possible_values']))}")
        print()

def cmd_generate(args, config: Config):
    """Generate YAML from JSON input or interactive mode"""
    if not config.validate_service(args.service):
        print(f"Error: Service '{args.service}' not found or invalid", file=sys.stderr)
        sys.exit(1)
    
    # Load service data
    loader = DataLoader(config)
    service_data = loader.load_service_data(args.service)
    
    # Load field selections
    if args.input:
        with open(args.input, 'r') as f:
            selections_data = json.load(f)
        if isinstance(selections_data, list):
            selections = [FieldSelection.from_dict(s) for s in selections_data]
        else:
            selections = [FieldSelection.from_dict(selections_data)]
    else:
        # Interactive mode
        selections = interactive_mode(args.service, service_data, config)
    
    if not selections:
        print("Error: No field selections provided", file=sys.stderr)
        sys.exit(1)
    
    # Validate selections
    try:
        from .core.field_mapper import FieldMapper
    except ImportError:
        from core.field_mapper import FieldMapper
    mapper = FieldMapper(service_data)
    validator = Validator()
    
    for selection in selections:
        field_info = mapper.get_field_info(selection.field_name)
        if not field_info:
            print(f"Warning: Field '{selection.field_name}' not found", file=sys.stderr)
            continue
        
        if not validator.validate_operator(field_info, selection.operator):
            print(f"Error: Operator '{selection.operator}' not valid for field '{selection.field_name}'", file=sys.stderr)
            sys.exit(1)
        
        if not validator.validate_value(field_info, selection.operator, selection.value):
            print(f"Warning: Value '{selection.value}' may not be valid for field '{selection.field_name}'", file=sys.stderr)
    
    # Generate YAML
    generator = YAMLGenerator(args.service, service_data)
    
    # Check for existing rules
    comparator = RuleComparator(args.service, config)
    metadata_gen = MetadataGenerator(args.service, config)
    
    # Resolve dependencies to get for_each values
    discovery_chains = generator._resolve_all_dependencies(selections)
    
    # Process each selection
    new_rules = []
    existing_rules_found = []
    
    for selection in selections:
        for_each = generator._find_discovery_for_field(selection.field_name, discovery_chains)
        
        # Check if rule already exists
        existing_rule = comparator.find_matching_rule(selection, for_each)
        
        if existing_rule:
            existing_rules_found.append({
                "selection": selection,
                "existing_rule": existing_rule
            })
            print(f"\n⚠️  Existing rule found for: {selection.field_name} {selection.operator} {selection.value}")
            print(f"   Existing rule_id: {existing_rule['rule_id']}")
            print(f"   Source: {existing_rule['source_file']}")
        else:
            new_rules.append(selection)
    
    # Show summary
    if existing_rules_found:
        print(f"\n{'='*60}")
        print(f"Found {len(existing_rules_found)} existing rule(s)")
        print(f"{'='*60}")
        for item in existing_rules_found:
            print(f"\n  Field: {item['selection'].field_name}")
            print(f"  Operator: {item['selection'].operator}")
            print(f"  Value: {item['selection'].value}")
            print(f"  → Matches existing rule: {item['existing_rule']['rule_id']}")
    
    if new_rules:
        print(f"\n{'='*60}")
        print(f"Creating {len(new_rules)} new rule(s)")
        print(f"{'='*60}")
        
        # Generate metadata for new rules
        for selection in new_rules:
            # Get metadata from selection if available
            title = getattr(selection, 'title', None)
            description = getattr(selection, 'description', None)
            remediation = getattr(selection, 'remediation', None)
            
            if not title or not description or not remediation:
                print(f"\nEntering metadata for rule: {selection.rule_id}")
                if not title:
                    title = input(f"Title: ").strip() or f"{selection.field_name} {selection.operator} {selection.value}"
                if not description:
                    description = input(f"Description: ").strip() or f"Check if {selection.field_name} {selection.operator} {selection.value}"
                if not remediation:
                    remediation = input(f"Remediation steps: ").strip() or f"Configure {selection.field_name} to {selection.operator} {selection.value}"
            
            # Generate metadata
            metadata_file = metadata_gen.generate_metadata(
                rule_id=selection.rule_id,
                title=title,
                description=description,
                remediation=remediation,
                field_name=selection.field_name,
                operator=selection.operator,
                value=selection.value
            )
            
            print(f"✓ Created metadata: {metadata_file}")
    
    # Generate YAML with all selections (both new and existing)
    output_path = None
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = config.get_output_path(args.service) / f"{args.service}.yaml"
    
    yaml_str = generator.generate(selections, output_path)
    
    print(f"\n✓ YAML generated successfully!")
    print(f"  Output: {output_path}")
    print(f"\n=== Generated YAML ===")
    print(yaml_str)

def interactive_mode(service_name: str, service_data: Dict, config: Config) -> List[FieldSelection]:
    """
    Interactive mode: Select Field + Operator + Expected Value together
    Now includes rule comparison and metadata collection
    """
    try:
        from .core.field_mapper import FieldMapper
        from .core.rule_comparator import RuleComparator
        from .core.yaml_generator import YAMLGenerator
    except ImportError:
        from core.field_mapper import FieldMapper
        from core.rule_comparator import RuleComparator
        from core.yaml_generator import YAMLGenerator
    
    mapper = FieldMapper(service_data)
    fields = mapper.get_available_fields()
    selections = []
    
    # Initialize comparator and generator for rule checking
    comparator = RuleComparator(service_name, config)
    generator = YAMLGenerator(service_name, service_data)
    
    print(f"\n{'='*60}")
    print(f"Interactive Rule Builder for: {service_name}")
    print(f"{'='*60}\n")
    print("For each rule, you will select:")
    print("  1. Field name")
    print("  2. Operator (equals, not_equals, exists, etc.)")
    print("  3. Expected value")
    print("  4. Rule metadata (title, description, remediation)\n")
    
    rule_num = 1
    while True:
        print(f"{'─'*60}")
        print(f"Rule #{rule_num}")
        print(f"{'─'*60}\n")
        
        # STEP 1: Select Field
        print("STEP 1: Select Field")
        print("Available fields:")
        for i, field_name in enumerate(fields, 1):
            field_info = mapper.get_field_info(field_name)
            field_type = field_info.get("type", "string")
            print(f"  {i:3d}. {field_name:30s} (type: {field_type})")
        
        field_choice = input("\nSelect field number (or 'done' to finish): ").strip()
        if field_choice.lower() == 'done':
            break
        
        try:
            field_idx = int(field_choice) - 1
            if field_idx < 0 or field_idx >= len(fields):
                print("Invalid field number. Try again.\n")
                continue
            
            field_name = fields[field_idx]
            field_info = mapper.get_field_info(field_name)
            
            # STEP 2: Select Operator
            print(f"\nSTEP 2: Select Operator for field '{field_name}'")
            operators = field_info.get("operators", [])
            if not operators:
                print(f"Warning: No operators available for field '{field_name}'\n")
                continue
            
            print("Available operators:")
            for i, op in enumerate(operators, 1):
                print(f"  {i}. {op}")
            
            op_choice = input("\nSelect operator (number): ").strip()
            try:
                op_idx = int(op_choice) - 1
                if op_idx < 0 or op_idx >= len(operators):
                    print("Invalid operator number. Try again.\n")
                    continue
                operator = operators[op_idx]
            except ValueError:
                print("Invalid input. Please enter a number.\n")
                continue
            
            # STEP 3: Select/Enter Expected Value
            print(f"\nSTEP 3: Enter Expected Value")
            print(f"Field: {field_name}")
            print(f"Operator: {operator}")
            
            if operator == "exists":
                value = None
                print("Value: None (exists operator doesn't require a value)")
            elif field_info.get("enum"):
                possible_values = field_info.get("possible_values", [])
                print(f"\nPossible values for '{field_name}':")
                for i, val in enumerate(possible_values, 1):
                    print(f"  {i}. {val}")
                
                val_choice = input("\nSelect value (number): ").strip()
                try:
                    val_idx = int(val_choice) - 1
                    if val_idx < 0 or val_idx >= len(possible_values):
                        print("Invalid value number. Try again.\n")
                        continue
                    value = possible_values[val_idx]
                except ValueError:
                    print("Invalid input. Please enter a number.\n")
                    continue
            else:
                field_type = field_info.get("type", "string")
                type_hint = ""
                if field_type == "integer":
                    type_hint = " (integer)"
                elif field_type == "boolean":
                    type_hint = " (true/false)"
                elif field_type == "date-time":
                    type_hint = " (ISO 8601 format)"
                
                value_input = input(f"Enter expected value{type_hint}: ").strip()
                
                if field_type == "integer":
                    try:
                        value = int(value_input)
                    except ValueError:
                        print(f"Warning: '{value_input}' is not a valid integer. Using as string.")
                        value = value_input
                elif field_type == "boolean":
                    value = value_input.lower() in ["true", "1", "yes", "y"]
                else:
                    value = value_input
            
            # STEP 4: Check for existing rule
            print(f"\nSTEP 4: Checking for existing rules...")
            temp_selection = FieldSelection(
                field_name=field_name,
                operator=operator,
                value=value,
                rule_id="temp"
            )
            discovery_chains = generator._resolve_all_dependencies([temp_selection])
            for_each = generator._find_discovery_for_field(field_name, discovery_chains)
            
            existing_rule = comparator.find_matching_rule(temp_selection, for_each)
            
            if existing_rule:
                print(f"\n⚠️  EXISTING RULE FOUND!")
                print(f"   Rule ID: {existing_rule['rule_id']}")
                print(f"   Source: {existing_rule['source_file']}")
                use_existing = input("\nUse existing rule? (y/n): ").strip().lower()
                if use_existing in ['y', 'yes']:
                    selection = FieldSelection(
                        field_name=field_name,
                        operator=operator,
                        value=value,
                        rule_id=existing_rule['rule_id'],
                        rule_description=f"Using existing rule: {existing_rule['rule_id']}"
                    )
                    selections.append(selection)
                    print(f"✓ Using existing rule: {existing_rule['rule_id']}\n")
                    rule_num += 1
                    continue
            
            # STEP 5: Rule ID and Description
            print(f"\nSTEP 5: Rule Details")
            default_rule_id = f"aws.{service_name}.resource.{field_name}_{operator.replace('_', '_')}"
            rule_id = input(f"Rule ID [{default_rule_id}]: ").strip() or default_rule_id
            
            # STEP 6: Metadata (only for new rules)
            print(f"\nSTEP 6: Rule Metadata (for new custom rule)")
            title = input("Title: ").strip() or f"{field_name} {operator} {value}"
            description = input("Description: ").strip() or f"Check if {field_name} {operator} {value}"
            remediation = input("Remediation steps: ").strip() or f"Configure {field_name} to {operator} {value}"
            
            # Create selection with metadata
            selection = FieldSelection(
                field_name=field_name,
                operator=operator,
                value=value,
                rule_id=rule_id,
                rule_description=description
            )
            
            # Add metadata attributes
            selection.title = title
            selection.description = description
            selection.remediation = remediation
            
            selections.append(selection)
            
            # Summary
            print(f"\n{'─'*60}")
            print("✓ Rule Added Successfully!")
            print(f"{'─'*60}")
            print(f"  Field:     {field_name}")
            print(f"  Operator:  {operator}")
            print(f"  Value:     {value}")
            print(f"  Rule ID:   {rule_id}")
            print(f"  Title:     {title}")
            print(f"  Description: {description}")
            print(f"{'─'*60}\n")
            
            add_more = input("Add another rule? (y/n): ").strip().lower()
            if add_more not in ['y', 'yes']:
                break
            
            rule_num += 1
            
        except (ValueError, IndexError) as e:
            print(f"Error: {e}\n")
            continue
    
    return selections

def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="YAML Rule Builder - Generate AWS compliance rules with rule comparison",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List available services
  python -m yaml_rule_builder list-services

  # List fields for a service
  python -m yaml_rule_builder list-fields --service accessanalyzer

  # Generate YAML interactively (with rule comparison)
  python -m yaml_rule_builder generate --service accessanalyzer

  # Generate YAML from JSON file
  python -m yaml_rule_builder generate --service accessanalyzer --input rules.json --output accessanalyzer.yaml

Features:
  - Automatically detects existing rules with same field + operator + value
  - Creates metadata files for new custom rules
  - Marks custom rules with 'custom: true' field
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    list_services_parser = subparsers.add_parser('list-services', help='List available services')
    
    list_fields_parser = subparsers.add_parser('list-fields', help='List fields for a service')
    list_fields_parser.add_argument('--service', required=True, help='Service name')
    
    generate_parser = subparsers.add_parser('generate', help='Generate YAML file')
    generate_parser.add_argument('--service', required=True, help='Service name')
    generate_parser.add_argument('--input', help='JSON file with field selections')
    generate_parser.add_argument('--output', help='Output YAML file path')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        config = Config()
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    
    if args.command == 'list-services':
        cmd_list_services(args, config)
    elif args.command == 'list-fields':
        cmd_list_fields(args, config)
    elif args.command == 'generate':
        cmd_generate(args, config)
    else:
        parser.print_help()
        sys.exit(1)

if __name__ == '__main__':
    main()

