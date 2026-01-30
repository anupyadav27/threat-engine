#!/usr/bin/env python3
"""
Generate operation_registry.json and adjacency.json from service spec.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Set

def compact_json_dumps(obj, indent=2):
    """Custom JSON formatter for more compact, human-readable output."""
    def is_simple_value(val):
        """Check if value is simple (string, number, bool, null)."""
        return isinstance(val, (str, int, float, bool)) or val is None
    
    def format_value(val, level=0, in_array=False, force_single_line=False):
        if isinstance(val, dict):
            if not val:
                return "{}"
            items = []
            for k, v in val.items():
                # Force single line for consumes/produces arrays
                force_single = (k in ['consumes', 'produces'] and isinstance(v, list))
                formatted_val = format_value(v, level + 1, False, force_single)
                items.append(f'"{k}": {formatted_val}')
            
            # Single line for small objects (especially in arrays)
            content = ", ".join(items)
            if in_array or (len(content) < 100 and level > 0):
                return "{" + content + "}"
            else:
                # Multi-line for larger objects
                sep = f",\n{' ' * indent * (level + 1)}"
                return "{\n" + (' ' * indent * (level + 1)) + sep.join(items) + "\n" + (' ' * indent * level) + "}"
        
        elif isinstance(val, list):
            if not val:
                return "[]"
            
            # Check if all items are strings (common case for entity lists)
            all_strings = all(isinstance(item, str) for item in val)
            
            # For string arrays (like entity lists), always single line
            if all_strings:
                items_str = ", ".join(json.dumps(item) for item in val)
                return "[" + items_str + "]"
            
            # Format items - try to keep on single line for produces/consumes arrays
            formatted_items = [format_value(item, level + 1, True, force_single_line) for item in val]
            content = ", ".join(formatted_items)
            
            # For arrays of objects (like produces/consumes), prefer single line
            # This makes the JSON more compact and readable
            # Use single line if content is reasonable length or if forced
            if force_single_line or len(content) < 250:
                return "[" + content + "]"
            
            # Multi-line only for very long arrays
            sep = f",\n{' ' * indent * (level + 1)}"
            return "[\n" + (' ' * indent * (level + 1)) + sep.join(formatted_items) + "\n" + (' ' * indent * level) + "]"
        
        elif isinstance(val, str):
            return json.dumps(val)
        elif isinstance(val, bool):
            return "true" if val else "false"
        elif val is None:
            return "null"
        else:
            return str(val)
    
    return format_value(obj, 0, False)

def to_snake_case(name: str) -> str:
    """Convert camelCase/PascalCase to snake_case."""
    # Insert underscore before uppercase letters (except first)
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def singularize(word: str) -> str:
    """Simple singularization - remove trailing 's' if present."""
    if word.endswith('ies'):
        return word[:-3] + 'y'
    elif word.endswith('es') and len(word) > 3:
        return word[:-2]
    elif word.endswith('s') and len(word) > 1:
        return word[:-1]
    return word

def assign_kind(operation: str) -> str:
    """Auto-assign kind based on operation name."""
    op = operation
    
    # Rule 1: Delete operations
    if any(op.startswith(prefix) for prefix in ['Delete', 'Remove', 'Terminate', 'Destroy', 'Purge', 'Detach', 'Disassociate', 'Untag']):
        return 'write_delete'
    
    # Rule 2: Update operations
    if any(op.startswith(prefix) for prefix in ['Update', 'Modify', 'Put', 'Set', 'Replace', 'Patch', 'Change', 'Reset']):
        return 'write_update'
    
    # Rule 3: Create operations
    if any(op.startswith(prefix) for prefix in ['Create', 'Start', 'Run', 'Launch', 'Provision', 'Register', 'Enable', 'Generate', 'Import']):
        return 'write_create'
    
    # Rule 4: Apply operations
    if any(op.startswith(prefix) for prefix in ['Apply', 'Attach', 'Associate', 'Add', 'Grant', 'Revoke', 'Tag', 'Authorize', 'Unauthorize']):
        return 'write_apply'
    
    # Rule 5: List operations
    if op.startswith('List'):
        return 'read_list'
    
    # Rule 6: Get operations
    if op.startswith('Get'):
        return 'read_get'
    
    # Rule 7: Describe/Search/Scan/Query operations
    if any(op.startswith(prefix) for prefix in ['Describe', 'Search', 'Scan', 'Query']):
        # Check plural heuristic
        plural_indicators = ['Summaries', 'Statistics', 'Results', 'Items', 'Resources', 'Findings', 'Policies', 'Rules', 'Jobs', 'Previews']
        if op.endswith('s') or any(indicator in op for indicator in plural_indicators):
            return 'read_list'
        else:
            return 'read_get'
    
    # Rule 8: Default
    return 'other'

def has_side_effect(kind: str) -> bool:
    """Determine if operation has side effects."""
    return not kind.startswith('read_')

def map_entity(service: str, param_or_field: str, context: Dict[str, Any] = None) -> str:
    """
    Map a parameter or field name to a canonical entity with disambiguation rules.
    context can contain: main_output_field, path, operation_name, is_param
    """
    op_name = context.get('operation_name', '') if context else ''
    is_param = context.get('is_param', False) if context else False
    
    # DISAMBIGUATION RULES (applied first)
    # Rule 1: If param is "id" and operation name contains "Finding" => entity = "<service>.finding_id"
    if param_or_field.lower() == 'id' and 'Finding' in op_name:
        return f"{service}.finding_id"
    
    # Rule 2: If param is "id" and operation name contains "AccessPreview" => entity = "<service>.access_preview_id"
    if param_or_field.lower() == 'id' and 'AccessPreview' in op_name:
        return f"{service}.access_preview_id"
    
    # Rule 3: If param is "status" and operation name contains "Finding" => entity = "<service>.finding_status"
    if param_or_field.lower() == 'status' and 'Finding' in op_name:
        return f"{service}.finding_status"
    
    # Rule 4: If output field is "arn" in CreateAnalyzer => entity = "<service>.analyzer_arn"
    if param_or_field.lower() == 'arn' and op_name == 'CreateAnalyzer' and not is_param:
        return f"{service}.analyzer_arn"
    
    # Default mapping
    entity_name = to_snake_case(param_or_field)
    
    # Special handling for item_fields with generic names
    if context and 'path' in context:
        path = context['path']
        main_field = context.get('main_output_field')
        
        # Check if this is a list path ([]) or object path (.)
        is_list_path = '[]' in path if path else False
        
        if main_field:
            if is_list_path and path.startswith(f"{main_field}[]."):
                field = path.split('.')[-1]
                # Handle generic fields with singularized main field
                if field in ['arn', 'id', 'name', 'status']:
                    main_singular = singularize(to_snake_case(main_field))
                    entity_name = f"{main_singular}_{field}"
                else:
                    entity_name = to_snake_case(field)
            elif not is_list_path and path.startswith(f"{main_field}."):
                # Object path - use field name directly
                field = path.split('.')[-1]
                entity_name = to_snake_case(field)
    
    # Special handling for CreateX operations that output generic "id" or "arn"
    if op_name.startswith('Create') and param_or_field in ['id', 'arn'] and not is_param:
        # Extract the resource name from CreateX -> x
        resource_name = op_name.replace('Create', '')
        if resource_name:
            entity_name = f"{to_snake_case(resource_name)}_{param_or_field}"
    
    return f"{service}.{entity_name}"

def build_consumes(service: str, required_params: List[str], operation_name: str) -> List[Dict[str, Any]]:
    """Build consumes list from required_params with disambiguation."""
    consumes = []
    for param in required_params:
        context = {"operation_name": operation_name, "is_param": True}
        entity = map_entity(service, param, context)
        # Initially set to "either", will be finalized later after all producers are known
        consumes.append({
            "entity": entity,
            "param": param,
            "required": True,
            "source": "either"
        })
    return consumes

def build_produces(service: str, output_fields: Dict[str, Any], main_output_field: str, item_fields: Dict[str, Any], operation_name: str = None) -> List[Dict[str, Any]]:
    """Build produces list from output_fields and item_fields with correct path handling."""
    produces = []
    is_list_op = operation_name and operation_name.startswith('List') if operation_name else False
    
    # Add output_fields
    for field_name in output_fields.keys():
        context = {"operation_name": operation_name, "is_param": False} if operation_name else None
        entity = map_entity(service, field_name, context)
        produces.append({
            "entity": entity,
            "source": "output",
            "path": field_name
        })
    
    # Add item_fields if main_output_field exists
    if main_output_field and item_fields:
        for field_name in item_fields.keys():
            # OUTPUT PATH RULE:
            # - For List* outputs, item paths use "main_output_field[].field"
            # - For Get* outputs where main_output_field is an OBJECT, item paths use "main_output_field.field" (NOT [])
            if is_list_op:
                path = f"{main_output_field}[].{field_name}"
            else:
                # Get* operations - check if main_output_field is an object (not a list)
                # If output_fields has main_output_field as an object, use dot notation
                path = f"{main_output_field}.{field_name}"
            
            context = {
                "main_output_field": main_output_field,
                "path": path,
                "operation_name": operation_name,
                "is_param": False
            }
            entity = map_entity(service, field_name, context)
            produces.append({
                "entity": entity,
                "source": "item",
                "path": path
            })
    
    return produces

def detect_entity_aliases(operations: Dict[str, Any], service: str) -> Dict[str, List[str]]:
    """
    Detect entity aliases - returns canonical entity -> list of aliases.
    Format: { "<canonical_entity>": ["alias1", "alias2", ...] }
    """
    # Map: canonical entity -> set of aliases
    alias_map = {}
    
    # Collect all entity usages
    entity_usages = {}  # entity -> set of (op, param_or_field, type)
    
    for op_name, op_data in operations.items():
        # Collect from consumes
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            param = consume['param']
            if entity not in entity_usages:
                entity_usages[entity] = set()
            entity_usages[entity].add((op_name, param, 'param'))
        
        # Collect from produces
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            path = produce['path']
            if entity not in entity_usages:
                entity_usages[entity] = set()
            entity_usages[entity].add((op_name, path, 'field'))
    
    # Group entities that likely refer to the same thing
    # For now, we'll identify entities that are variations of the same concept
    # This is a simplified version - can be enhanced with more heuristics
    
    return alias_map  # Return empty for now, can be enhanced

def process_service_spec(spec_file: Path) -> tuple:
    """Process service spec and generate operation registry and adjacency."""
    
    with open(spec_file, 'r') as f:
        data = json.load(f)
    
    service_name = list(data.keys())[0]
    service_data = data[service_name]
    
    # Collect all operations
    all_operations = []
    all_operations.extend(service_data.get('independent', []))
    all_operations.extend(service_data.get('dependent', []))
    
    # Build operation registry
    operations = {}
    entity_producers = {}  # entity -> list of operations
    
    for op_spec in all_operations:
        op_name = op_spec['operation']
        kind = assign_kind(op_name)
        side_effect = has_side_effect(kind)
        
        # Build consumes
        required_params = op_spec.get('required_params', [])
        consumes = build_consumes(service_name, required_params, op_name)
        
        # Build produces
        output_fields = op_spec.get('output_fields', {})
        main_output_field = op_spec.get('main_output_field')
        item_fields = op_spec.get('item_fields', {})
        produces = build_produces(service_name, output_fields, main_output_field, item_fields, op_name)
        
        # Track entity producers (for later finalization)
        for produce in produces:
            entity = produce['entity']
            if entity not in entity_producers:
                entity_producers[entity] = []
            entity_producers[entity].append(op_name)
        
        operations[op_name] = {
            "kind": kind,
            "side_effect": side_effect,
            "sdk": {
                "client": service_name,
                "method": op_spec['python_method']
            },
            "consumes": consumes,
            "produces": produces,
            "notes": ""
        }
    
    # Finalize consumes.source now that we have all producers
    for op_name, op_data in operations.items():
        for consume in op_data['consumes']:
            entity = consume['entity']
            if entity in entity_producers:
                consume['source'] = 'internal'
            else:
                consume['source'] = 'external'
    
    # Detect entity aliases (canonical -> list of aliases)
    entity_aliases = detect_entity_aliases(operations, service_name)
    
    # Build kind_rules (documentation of rules used)
    kind_rules = {
        "write_delete": ["Delete", "Remove", "Terminate", "Destroy", "Purge", "Detach", "Disassociate", "Untag"],
        "write_update": ["Update", "Modify", "Put", "Set", "Replace", "Patch", "Change", "Reset"],
        "write_create": ["Create", "Start", "Run", "Launch", "Provision", "Register", "Enable", "Generate", "Import"],
        "write_apply": ["Apply", "Attach", "Associate", "Add", "Grant", "Revoke", "Tag", "Authorize", "Unauthorize"],
        "read_list": ["List", "Describe* (plural)", "Search* (plural)", "Scan* (plural)", "Query* (plural)"],
        "read_get": ["Get", "Describe* (singular)", "Search* (singular)", "Scan* (singular)", "Query* (singular)"],
        "other": ["default"]
    }
    
    # Build operation_registry.json
    operation_registry = {
        "service": service_name,
        "version": "1.0",
        "kind_rules": kind_rules,
        "entity_aliases": entity_aliases,
        "overrides": {},  # Empty for now, can be populated if needed
        "operations": operations
    }
    
    # Build adjacency.json
    op_consumes = {}
    op_produces = {}
    entity_consumers = {}  # entity -> list of operations
    
    for op_name, op_data in operations.items():
        # Collect consumed entities
        consumed_entities = [c['entity'] for c in op_data['consumes']]
        op_consumes[op_name] = list(set(consumed_entities))
        
        # Collect produced entities
        produced_entities = [p['entity'] for p in op_data['produces']]
        op_produces[op_name] = list(set(produced_entities))
        
        # Track entity consumers
        for entity in consumed_entities:
            if entity not in entity_consumers:
                entity_consumers[entity] = []
            entity_consumers[entity].append(op_name)
    
    # Collect external entities
    external_entities = set()
    for op_name, op_data in operations.items():
        for consume in op_data['consumes']:
            if consume['source'] == 'external':
                external_entities.add(consume['entity'])
    
    adjacency = {
        "service": service_name,
        "op_consumes": op_consumes,
        "op_produces": op_produces,
        "entity_producers": {k: list(set(v)) for k, v in entity_producers.items()},
        "entity_consumers": {k: list(set(v)) for k, v in entity_consumers.items()},
        "external_entities": sorted(list(external_entities))
    }
    
    return operation_registry, adjacency

def generate_validation_report(operation_registry: Dict[str, Any], adjacency: Dict[str, Any]) -> Dict[str, Any]:
    """Generate validation report with statistics and checks."""
    operations = operation_registry.get('operations', {})
    service = operation_registry.get('service', '')
    
    # Collect all entities
    all_entities = set()
    ambiguous_tokens = {}  # token -> list of resolutions
    overrides_applied = operation_registry.get('overrides', {})
    
    # Track ambiguous token resolutions
    for op_name, op_data in operations.items():
        # Check consumes
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            param = consume['param']
            all_entities.add(entity)
            
            # Track ambiguous tokens (id, status, arn)
            if param.lower() in ['id', 'status', 'arn']:
                token = param.lower()
                if token not in ambiguous_tokens:
                    ambiguous_tokens[token] = []
                resolution = f"{op_name}.{param} -> {entity}"
                if resolution not in ambiguous_tokens[token]:
                    ambiguous_tokens[token].append(resolution)
        
        # Check produces
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            path = produce['path']
            all_entities.add(entity)
            
            # Track ambiguous tokens in output paths
            field = path.split('.')[-1].split('[]')[-1]
            if field.lower() in ['id', 'status', 'arn']:
                token = field.lower()
                if token not in ambiguous_tokens:
                    ambiguous_tokens[token] = []
                resolution = f"{op_name}.{path} -> {entity}"
                if resolution not in ambiguous_tokens[token]:
                    ambiguous_tokens[token].append(resolution)
    
    # Check for self-cycles (op produces entity it also requires)
    self_cycles = []
    for op_name, op_data in operations.items():
        consumed_entities = {c['entity'] for c in op_data.get('consumes', [])}
        produced_entities = {p['entity'] for p in op_data.get('produces', [])}
        
        # Check for self-cycle (excluding when it's the same identifier echoed back)
        overlap = consumed_entities & produced_entities
        for entity in overlap:
            # Check if it's a legitimate echo (same identifier echoed back in output)
            is_echo = False
            for consume in op_data.get('consumes', []):
                if consume['entity'] == entity:
                    param = consume['param']
                    param_lower = param.lower()
                    
                    # Check if any produce has a matching field
                    for produce in op_data.get('produces', []):
                        if produce['entity'] == entity:
                            path = produce['path']
                            field = path.split('.')[-1].split('[]')[-1]
                            field_lower = field.lower()
                            
                            # Echo detection: param and field refer to same identifier
                            # Cases: accessPreviewId -> accessPreview.id, findingId -> finding.id, etc.
                            # Check if param contains field or field is part of param
                            if (param_lower == field_lower or 
                                param_lower.endswith(field_lower) or 
                                field_lower in param_lower or
                                # Check if removing common suffixes makes them match
                                param_lower.replace('id', '') == field_lower.replace('id', '') or
                                param_lower.replace('arn', '') == field_lower.replace('arn', '')):
                                is_echo = True
                                break
                    if is_echo:
                        break
            
            if not is_echo:
                self_cycles.append({
                    "operation": op_name,
                    "entity": entity,
                    "description": f"Operation {op_name} both consumes and produces {entity} (potential self-cycle)"
                })
    
    report = {
        "service": service,
        "summary": {
            "total_operations": len(operations),
            "total_entities": len(all_entities),
            "external_entities": len(adjacency.get('external_entities', [])),
            "entity_producers_count": len(adjacency.get('entity_producers', {})),
            "entity_consumers_count": len(adjacency.get('entity_consumers', {}))
        },
        "ambiguous_tokens": ambiguous_tokens,
        "overrides_applied": overrides_applied,
        "self_cycles": self_cycles,
        "validation_status": "PASS" if len(self_cycles) == 0 else "WARNING"
    }
    
    return report

def main():
    script_dir = Path(__file__).parent
    spec_file = script_dir / "boto3_dependencies_with_python_names_fully_enriched.json"
    
    if not spec_file.exists():
        print(f"Error: Service spec not found: {spec_file}")
        return
    
    print(f"Processing {spec_file}...")
    operation_registry, adjacency = process_service_spec(spec_file)
    
    # Write operation_registry.json with compact formatting
    registry_file = script_dir / "operation_registry.json"
    with open(registry_file, 'w') as f:
        formatted = compact_json_dumps(operation_registry, indent=2)
        f.write(formatted)
    print(f"Created: {registry_file}")
    
    # Write adjacency.json with compact formatting
    adjacency_file = script_dir / "adjacency.json"
    with open(adjacency_file, 'w') as f:
        formatted = compact_json_dumps(adjacency, indent=2)
        f.write(formatted)
    print(f"Created: {adjacency_file}")
    
    # Generate validation report
    validation_report = generate_validation_report(operation_registry, adjacency)
    
    # Print validation report
    print(f"\n{'='*60}")
    print("VALIDATION REPORT")
    print(f"{'='*60}")
    print(f"\nService: {validation_report['service']}")
    print(f"\nSummary:")
    summary = validation_report['summary']
    print(f"  Total operations: {summary['total_operations']}")
    print(f"  Total entities: {summary['total_entities']}")
    print(f"  External entities: {summary['external_entities']}")
    print(f"  Entity producers: {summary['entity_producers_count']}")
    print(f"  Entity consumers: {summary['entity_consumers_count']}")
    
    print(f"\nAmbiguous Tokens Resolved:")
    for token, resolutions in validation_report['ambiguous_tokens'].items():
        print(f"  {token.upper()}: {len(resolutions)} resolutions")
        for resolution in resolutions[:5]:  # Show first 5
            print(f"    - {resolution}")
        if len(resolutions) > 5:
            print(f"    ... and {len(resolutions) - 5} more")
    
    if validation_report['overrides_applied']:
        print(f"\nOverrides Applied: {len(validation_report['overrides_applied'])}")
        for override, value in list(validation_report['overrides_applied'].items())[:5]:
            print(f"  - {override}: {value}")
    else:
        print(f"\nOverrides Applied: None")
    
    if validation_report['self_cycles']:
        print(f"\n⚠️  SELF-CYCLES DETECTED: {len(validation_report['self_cycles'])}")
        for cycle in validation_report['self_cycles']:
            print(f"  - {cycle['description']}")
    else:
        print(f"\n✓ No self-cycles detected")
    
    print(f"\nValidation Status: {validation_report['validation_status']}")
    print(f"{'='*60}\n")
    
    # Save validation report
    report_file = script_dir / "validation_report.json"
    with open(report_file, 'w') as f:
        json.dump(validation_report, f, indent=2)
    print(f"Validation report saved to: {report_file}")

if __name__ == "__main__":
    main()

