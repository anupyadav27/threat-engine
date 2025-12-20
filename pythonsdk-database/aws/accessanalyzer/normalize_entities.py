#!/usr/bin/env python3
"""
Normalize entities in operation_registry.json to eliminate generic entities.
Applies context-based entity naming rules.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple

def to_snake_case(name: str) -> str:
    """Convert camelCase/PascalCase to snake_case."""
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

def extract_object_from_path(path: str) -> Tuple[str, str]:
    """
    Extract object name and field from a path.
    Returns: (object_name, field_name, is_list)
    Examples:
        "analyzer.arn" -> ("analyzer", "arn", False)
        "analyzers[].arn" -> ("analyzers", "arn", True)
        "id" -> ("", "id", False)
    """
    if '[]' in path:
        # List path: "analyzers[].arn"
        parts = path.split('[]')
        obj = parts[0]
        field = parts[1].lstrip('.')
        return (obj, field, True)
    elif '.' in path:
        # Object path: "analyzer.arn"
        parts = path.split('.', 1)
        obj = parts[0]
        field = parts[1]
        return (obj, field, False)
    else:
        # Direct field: "id"
        return ("", path, False)

def normalize_produces_entity(service: str, path: str, operation_name: str) -> str:
    """
    Normalize entity for produces based on path context.
    Rule B: Extract object from path and create context-specific entity.
    """
    obj, field, is_list = extract_object_from_path(path)
    
    # Rule B: Context-based entity naming
    if obj and field in ['arn', 'status', 'id', 'name']:
        obj_singular = singularize(to_snake_case(obj))
        return f"{service}.{obj_singular}_{field}"
    
    # If no object context, try operation name context
    if not obj and field in ['arn', 'status', 'id', 'name']:
        # Special cases based on operation name
        if field == 'id':
            if 'Finding' in operation_name:
                return f"{service}.finding_id"
            elif 'AccessPreview' in operation_name:
                return f"{service}.access_preview_id"
            elif 'PolicyGeneration' in operation_name or 'Job' in operation_name:
                return f"{service}.job_id"
        
        if field == 'status':
            if 'Finding' in operation_name or operation_name == 'UpdateFindings':
                return f"{service}.finding_status"
            elif 'AccessPreview' in operation_name:
                return f"{service}.access_preview_status"
            elif 'PolicyGeneration' in operation_name:
                return f"{service}.policy_generation_status"
        
        if field == 'arn':
            # Try to extract from operation name
            if 'Analyzer' in operation_name:
                return f"{service}.analyzer_arn"
            # Default to generic only as last resort
            return f"{service}.{field}"
    
    # Default: use snake_case of field
    if obj:
        obj_singular = singularize(to_snake_case(obj))
        return f"{service}.{obj_singular}_{to_snake_case(field)}"
    else:
        return f"{service}.{to_snake_case(field)}"

def normalize_consumes_entity(service: str, param: str, operation_name: str) -> str:
    """
    Normalize entity for consumes based on param and operation context.
    Rule C: Use operation name context to disambiguate.
    """
    param_lower = param.lower()
    
    # Rule C: Special-case mapping based on operation name
    if param_lower == 'id':
        if 'Finding' in operation_name:
            return f"{service}.finding_id"
        elif 'AccessPreview' in operation_name:
            return f"{service}.access_preview_id"
        elif 'PolicyGeneration' in operation_name or 'jobid' in param_lower:
            return f"{service}.job_id"
        else:
            # Try to extract context from param name (e.g., accessPreviewId -> access_preview_id)
            # Remove common suffixes
            base = param_lower.replace('id', '').replace('arn', '').replace('name', '')
            if base:
                return f"{service}.{to_snake_case(base)}_id"
            # Last resort: use param name
            return f"{service}.{to_snake_case(param)}"
    
    elif param_lower == 'status':
        if 'Finding' in operation_name or operation_name == 'UpdateFindings':
            return f"{service}.finding_status"
        else:
            # Try to extract from param name
            base = param_lower.replace('status', '')
            if base:
                return f"{service}.{to_snake_case(base)}_status"
            return f"{service}.status"  # Last resort
    
    elif param_lower == 'arn' or param_lower.endswith('arn'):
        # Rule C: Never use generic "<service>.arn"
        # Extract context from param name (e.g., analyzerArn -> analyzer_arn)
        if param_lower != 'arn':
            base = param_lower.replace('arn', '')
            if base:
                return f"{service}.{to_snake_case(base)}_arn"
        # If just "arn", try operation context
        if 'Analyzer' in operation_name:
            return f"{service}.analyzer_arn"
        # Last resort: use param name
        return f"{service}.{to_snake_case(param)}"
    
    elif param_lower == 'name' or param_lower.endswith('name'):
        # Extract context from param name
        if param_lower != 'name':
            base = param_lower.replace('name', '')
            if base:
                return f"{service}.{to_snake_case(base)}_name"
        return f"{service}.{to_snake_case(param)}"
    
    # Default: snake_case of param
    return f"{service}.{to_snake_case(param)}"

def fix_get_operation_paths(operation_name: str, produces: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Rule D: Fix Get* output object paths - remove [] from object paths.
    Only list operations should use [].
    """
    is_get_op = operation_name.startswith('Get')
    
    if not is_get_op:
        return produces
    
    fixed_produces = []
    for produce in produces:
        path = produce['path']
        
        # Rule D: Remove [] from Get* operation paths
        if '[]' in path and produce['source'] == 'item':
            # Check if this is an object path (not a list)
            # If main_output_field is an object, remove []
            new_path = path.replace('[]', '')
            fixed_produce = produce.copy()
            fixed_produce['path'] = new_path
            fixed_produces.append(fixed_produce)
        else:
            fixed_produces.append(produce)
    
    return fixed_produces

def normalize_operation_registry(registry_file: Path, service: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Normalize entities in operation registry."""
    
    with open(registry_file, 'r') as f:
        registry = json.load(f)
    
    operations = registry.get('operations', {})
    overrides = registry.get('overrides', {})
    entity_aliases = registry.get('entity_aliases', {})
    
    # Track entity mappings for consistency
    entity_mappings = {}  # old_entity -> new_entity
    normalization_log = []
    
    # First pass: normalize all entities
    for op_name, op_data in operations.items():
        # Normalize consumes
        for consume in op_data.get('consumes', []):
            old_entity = consume['entity']
            param = consume['param']
            new_entity = normalize_consumes_entity(service, param, op_name)
            
            if old_entity != new_entity:
                entity_mappings[old_entity] = new_entity
                consume['entity'] = new_entity
                normalization_log.append(f"{op_name}.consumes.{param}: {old_entity} -> {new_entity}")
        
        # Normalize produces
        produces = op_data.get('produces', [])
        
        # Rule D: Fix Get* operation paths
        produces = fix_get_operation_paths(op_name, produces)
        
        for produce in produces:
            old_entity = produce['entity']
            path = produce['path']
            new_entity = normalize_produces_entity(service, path, op_name)
            
            if old_entity != new_entity:
                entity_mappings[old_entity] = new_entity
                produce['entity'] = new_entity
                normalization_log.append(f"{op_name}.produces.{path}: {old_entity} -> {new_entity}")
        
        op_data['produces'] = produces
    
    # Update overrides with normalization changes
    if entity_mappings:
        overrides['entity_normalizations'] = entity_mappings
        overrides['normalization_count'] = len(entity_mappings)
    
    registry['overrides'] = overrides
    
    return registry, normalization_log

def rebuild_adjacency(registry: Dict[str, Any]) -> Dict[str, Any]:
    """Rebuild adjacency.json from normalized registry."""
    service = registry['service']
    operations = registry.get('operations', {})
    
    op_consumes = {}
    op_produces = {}
    entity_producers = {}
    entity_consumers = {}
    
    for op_name, op_data in operations.items():
        # Collect consumed entities
        consumed_entities = [c['entity'] for c in op_data.get('consumes', [])]
        op_consumes[op_name] = list(set(consumed_entities))
        
        # Collect produced entities
        produced_entities = [p['entity'] for p in op_data.get('produces', [])]
        op_produces[op_name] = list(set(produced_entities))
        
        # Track entity producers
        for entity in produced_entities:
            if entity not in entity_producers:
                entity_producers[entity] = []
            entity_producers[entity].append(op_name)
        
        # Track entity consumers
        for entity in consumed_entities:
            if entity not in entity_consumers:
                entity_consumers[entity] = []
            entity_consumers[entity].append(op_name)
    
    # Compute external entities (consumed but never produced)
    all_produced = set(entity_producers.keys())
    external_entities = []
    for entity in set(entity_consumers.keys()):
        if entity not in all_produced:
            external_entities.append(entity)
    
    adjacency = {
        "service": service,
        "op_consumes": op_consumes,
        "op_produces": op_produces,
        "entity_producers": {k: list(set(v)) for k, v in entity_producers.items()},
        "entity_consumers": {k: list(set(v)) for k, v in entity_consumers.items()},
        "external_entities": sorted(external_entities)
    }
    
    return adjacency

def generate_validation_report(registry: Dict[str, Any], adjacency: Dict[str, Any]) -> Dict[str, Any]:
    """Generate updated validation report."""
    operations = registry.get('operations', {})
    service = registry.get('service', '')
    
    # Collect all entities
    all_entities = set()
    ambiguous_tokens = {}
    generic_entities = {'arn': 0, 'status': 0, 'id': 0, 'name': 0}
    
    for op_name, op_data in operations.items():
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            all_entities.add(entity)
            param = consume['param']
            
            # Check for generic entities
            if entity.endswith('.arn'):
                generic_entities['arn'] += 1
            elif entity.endswith('.status'):
                generic_entities['status'] += 1
            elif entity.endswith('.id'):
                generic_entities['id'] += 1
            elif entity.endswith('.name'):
                generic_entities['name'] += 1
            
            # Track ambiguous tokens
            if param.lower() in ['id', 'status', 'arn', 'name']:
                token = param.lower()
                if token not in ambiguous_tokens:
                    ambiguous_tokens[token] = []
                resolution = f"{op_name}.{param} -> {entity}"
                if resolution not in ambiguous_tokens[token]:
                    ambiguous_tokens[token].append(resolution)
        
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            all_entities.add(entity)
            path = produce['path']
            
            # Check for generic entities
            if entity.endswith('.arn'):
                generic_entities['arn'] += 1
            elif entity.endswith('.status'):
                generic_entities['status'] += 1
            elif entity.endswith('.id'):
                generic_entities['id'] += 1
            elif entity.endswith('.name'):
                generic_entities['name'] += 1
            
            # Track ambiguous tokens
            field = path.split('.')[-1].split('[]')[-1]
            if field.lower() in ['id', 'status', 'arn', 'name']:
                token = field.lower()
                if token not in ambiguous_tokens:
                    ambiguous_tokens[token] = []
                resolution = f"{op_name}.{path} -> {entity}"
                if resolution not in ambiguous_tokens[token]:
                    ambiguous_tokens[token].append(resolution)
    
    # Check for self-cycles
    self_cycles = []
    for op_name, op_data in operations.items():
        consumed_entities = {c['entity'] for c in op_data.get('consumes', [])}
        produced_entities = {p['entity'] for p in op_data.get('produces', [])}
        
        overlap = consumed_entities & produced_entities
        for entity in overlap:
            # Check if it's a legitimate echo
            is_echo = False
            for consume in op_data.get('consumes', []):
                if consume['entity'] == entity:
                    param = consume['param']
                    param_lower = param.lower()
                    
                    for produce in op_data.get('produces', []):
                        if produce['entity'] == entity:
                            path = produce['path']
                            field = path.split('.')[-1].split('[]')[-1]
                            field_lower = field.lower()
                            
                            if (param_lower == field_lower or 
                                param_lower.endswith(field_lower) or 
                                field_lower in param_lower or
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
                    "description": f"Operation {op_name} both consumes and produces {entity}"
                })
    
    overrides_applied = registry.get('overrides', {})
    
    report = {
        "service": service,
        "summary": {
            "total_operations": len(operations),
            "total_entities": len(all_entities),
            "external_entities": len(adjacency.get('external_entities', [])),
            "entity_producers_count": len(adjacency.get('entity_producers', {})),
            "entity_consumers_count": len(adjacency.get('entity_consumers', {}))
        },
        "generic_entities": generic_entities,
        "ambiguous_tokens": ambiguous_tokens,
        "overrides_applied": overrides_applied,
        "self_cycles": self_cycles,
        "validation_status": "PASS" if len(self_cycles) == 0 and sum(generic_entities.values()) == 0 else "WARNING"
    }
    
    return report

def main():
    script_dir = Path(__file__).parent
    registry_file = script_dir / "operation_registry.json"
    
    if not registry_file.exists():
        print(f"Error: operation_registry.json not found: {registry_file}")
        return
    
    print("Reading operation_registry.json...")
    with open(registry_file, 'r') as f:
        registry = json.load(f)
    
    service = registry.get('service', 'accessanalyzer')
    print(f"Service: {service}")
    
    print("\nNormalizing entities...")
    normalized_registry, normalization_log = normalize_operation_registry(registry_file, service)
    
    print(f"Applied {len(normalization_log)} entity normalizations")
    if normalization_log:
        print("\nSample normalizations:")
        for log_entry in normalization_log[:10]:
            print(f"  {log_entry}")
        if len(normalization_log) > 10:
            print(f"  ... and {len(normalization_log) - 10} more")
    
    # Save normalized registry
    print(f"\nSaving normalized operation_registry.json...")
    with open(registry_file, 'w') as f:
        formatted = compact_json_dumps(normalized_registry, indent=2)
        f.write(formatted)
    
    # Rebuild adjacency
    print("Rebuilding adjacency.json...")
    adjacency = rebuild_adjacency(normalized_registry)
    
    adjacency_file = script_dir / "adjacency.json"
    with open(adjacency_file, 'w') as f:
        formatted = compact_json_dumps(adjacency, indent=2)
        f.write(formatted)
    print(f"Saved: {adjacency_file}")
    
    # Generate validation report
    print("Generating validation report...")
    validation_report = generate_validation_report(normalized_registry, adjacency)
    
    report_file = script_dir / "validation_report.json"
    with open(report_file, 'w') as f:
        json.dump(validation_report, f, indent=2)
    print(f"Saved: {report_file}")
    
    # Print summary
    print(f"\n{'='*60}")
    print("NORMALIZATION SUMMARY")
    print(f"{'='*60}")
    print(f"Service: {service}")
    print(f"Total operations: {validation_report['summary']['total_operations']}")
    print(f"Total entities: {validation_report['summary']['total_entities']}")
    print(f"\nGeneric entities remaining:")
    for token, count in validation_report['generic_entities'].items():
        print(f"  {token}: {count}")
    
    print(f"\nAmbiguous tokens: {len(validation_report['ambiguous_tokens'])}")
    for token, resolutions in validation_report['ambiguous_tokens'].items():
        print(f"  {token.upper()}: {len(resolutions)} resolutions")
    
    print(f"\nOverrides applied: {len(validation_report.get('overrides_applied', {}))}")
    if validation_report.get('overrides_applied'):
        for key, value in list(validation_report['overrides_applied'].items())[:5]:
            if isinstance(value, dict):
                print(f"  {key}: {len(value)} items")
            else:
                print(f"  {key}: {value}")
    
    if validation_report['self_cycles']:
        print(f"\n⚠️  Self-cycles: {len(validation_report['self_cycles'])}")
    else:
        print(f"\n✓ No self-cycles")
    
    print(f"\nValidation Status: {validation_report['validation_status']}")
    print(f"{'='*60}\n")

# Import compact_json_dumps from generate_dependency_graph
def compact_json_dumps(obj, indent=2):
    """Custom JSON formatter for more compact, human-readable output."""
    def is_simple_value(val):
        return isinstance(val, (str, int, float, bool)) or val is None
    
    def format_value(val, level=0, in_array=False, force_single_line=False):
        if isinstance(val, dict):
            if not val:
                return "{}"
            items = []
            for k, v in val.items():
                force_single = (k in ['consumes', 'produces'] and isinstance(v, list))
                formatted_val = format_value(v, level + 1, False, force_single)
                items.append(f'"{k}": {formatted_val}')
            
            content = ", ".join(items)
            if in_array or (len(content) < 100 and level > 0):
                return "{" + content + "}"
            else:
                sep = f",\n{' ' * indent * (level + 1)}"
                return "{\n" + (' ' * indent * (level + 1)) + sep.join(items) + "\n" + (' ' * indent * level) + "}"
        
        elif isinstance(val, list):
            if not val:
                return "[]"
            
            all_strings = all(isinstance(item, str) for item in val)
            if all_strings:
                items_str = ", ".join(json.dumps(item) for item in val)
                return "[" + items_str + "]"
            
            formatted_items = [format_value(item, level + 1, True, force_single_line) for item in val]
            content = ", ".join(formatted_items)
            
            if force_single_line or len(content) < 250:
                return "[" + content + "]"
            
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

if __name__ == "__main__":
    main()

