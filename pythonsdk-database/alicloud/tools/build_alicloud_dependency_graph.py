#!/usr/bin/env python3
"""
Build dependency graph artifacts for ALL AliCloud services.
Generates operation_registry.json, adjacency.json, validation_report.json per service.

Adapted from AWS/Azure build scripts but simplified for AliCloud's structure.
AliCloud enriched JSON only has operations[] with item_fields (no required_params, output_fields, etc.)
"""

import json
import re
import sys
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple, Optional
from collections import defaultdict

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

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

def to_snake_case(name: str) -> str:
    """Convert camelCase/PascalCase to snake_case."""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def singularize(word: str) -> str:
    """Singularize word - best effort."""
    if word.endswith('ies'):
        return word[:-3] + 'y'
    elif word.endswith('ses') and len(word) > 3:
        return word[:-2]
    elif word.endswith('es') and len(word) > 3:
        return word[:-2]
    elif word.endswith('s') and not word.endswith('ss') and len(word) > 1:
        return word[:-1]
    return word

def extract_noun_from_operation(operation_name: str) -> str:
    """Extract noun from operation name by removing verb prefixes."""
    op = operation_name
    
    # Verbs to strip (first match wins)
    verbs = [
        'Put', 'Create', 'Update', 'Delete', 'Remove', 'Get', 'List', 'Describe',
        'Start', 'Stop', 'Accept', 'Enable', 'Disable', 'Associate', 'Disassociate',
        'Attach', 'Detach', 'Tag', 'Untag', 'Apply', 'Cancel', 'Renew', 'Request',
        'Resend', 'Modify', 'Set', 'Replace', 'Patch', 'Change', 'Reset', 'Add',
        'Cancel', 'Revoke', 'Grant', 'Authorize', 'Unauthorize'
    ]
    
    for verb in verbs:
        if op.startswith(verb):
            noun = op[len(verb):]
            if noun:
                return singularize(to_snake_case(noun))
    
    # Fallback: use full operation name
    return singularize(to_snake_case(op))

# ============================================================================
# KIND ASSIGNMENT
# ============================================================================

def assign_kind(operation: str) -> str:
    """Auto-assign kind based on operation name prefix."""
    op = operation
    
    if op.startswith('List') or op.startswith('Describe') and 'List' in op:
        return 'read_list'
    
    if op.startswith('Get') or op.startswith('Describe'):
        return 'read_get'
    
    if any(op.startswith(prefix) for prefix in ['Create', 'Start', 'Generate', 'Import', 'Enable', 'Register']):
        return 'write_create'
    
    if any(op.startswith(prefix) for prefix in ['Update', 'Modify', 'Put', 'Set', 'Change', 'Reset', 'Patch']):
        return 'write_update'
    
    if any(op.startswith(prefix) for prefix in ['Delete', 'Remove', 'Terminate', 'Destroy', 'Disable', 'Detach', 'Disassociate', 'Untag', 'Revoke']):
        return 'write_delete'
    
    if any(op.startswith(prefix) for prefix in ['Apply', 'Attach', 'Associate', 'Add', 'Tag', 'Authorize', 'Unauthorize', 'Grant']):
        return 'write_apply'
    
    return 'other'

def has_side_effect(kind: str) -> bool:
    """Determine if operation has side effects."""
    return not kind.startswith('read_')

# ============================================================================
# ENTITY NAMING
# ============================================================================

def normalize_produces_entity(service: str, field_name: str, operation_name: str) -> str:
    """
    Normalize entity for produces based on field name and operation context.
    For AliCloud, item_fields are direct field names without path context.
    """
    field_lower = field_name.lower()
    
    # Skip RequestId (it's always present but not useful for dependency tracking)
    if field_lower in ['requestid', 'request_id']:
        return f"{service}.request_id"
    
    # For generic tokens, use operation noun as context
    if field_lower in ['id', 'status', 'name', 'arn']:
        noun = extract_noun_from_operation(operation_name)
        return f"{service}.{noun}_{field_lower}"
    
    # For compound fields like InstanceId, extract base
    if field_lower.endswith('id') and len(field_lower) > 2:
        base = field_lower[:-2]  # Remove 'id'
        return f"{service}.{to_snake_case(base)}_id"
    elif field_lower.endswith('arn') and len(field_lower) > 3:
        base = field_lower[:-3]  # Remove 'arn'
        return f"{service}.{to_snake_case(base)}_arn"
    elif field_lower.endswith('name') and len(field_lower) > 4:
        base = field_lower[:-4]  # Remove 'name'
        return f"{service}.{to_snake_case(base)}_name"
    elif field_lower.endswith('status') and len(field_lower) > 6:
        base = field_lower[:-6]  # Remove 'status'
        return f"{service}.{to_snake_case(base)}_status"
    
    # Default: snake_case of field name
    return f"{service}.{to_snake_case(field_name)}"

# ============================================================================
# BUILD OPERATION REGISTRY
# ============================================================================

def build_produces_for_alicloud(service: str, item_fields: Dict[str, Any], operation_name: str) -> List[Dict[str, Any]]:
    """Build produces list from item_fields (AliCloud structure)."""
    produces = []
    
    # Treat all item_fields as produced entities
    for field_name in item_fields.keys():
        # Skip RequestId for dependency tracking (always present, not useful)
        if field_name.lower() in ['requestid', 'request_id']:
            continue
            
        entity = normalize_produces_entity(service, field_name, operation_name)
        produces.append({
            "entity": entity,
            "source": "item",
            "path": field_name
        })
    
    return produces

def build_consumes_for_alicloud(service: str, operation_name: str, item_fields: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Build consumes list by inferring from operation name patterns.
    Since AliCloud doesn't have required_params, we infer common patterns.
    
    For now, we'll be conservative and only add consumes for operations that
    clearly need an ID input based on naming patterns.
    """
    consumes = []
    kind = assign_kind(operation_name)
    
    # Skip List operations - they typically don't need inputs
    if kind == 'read_list':
        return consumes
    
    # For Get/Describe/Update/Delete operations, infer they need an ID
    # Pattern: Get<Resource>, Describe<Resource>, Update<Resource>, Delete<Resource>
    # -> needs <resource>_id
    if kind in ['read_get', 'write_update', 'write_delete']:
        noun = extract_noun_from_operation(operation_name)
        if noun:
            # Common pattern: operation needs the resource ID
            id_entity = f"{service}.{noun}_id"
            consumes.append({
                "entity": id_entity,
                "param": f"{noun}_id",  # Inferred param name
                "required": True,
                "source": "internal"  # Will be finalized later
            })
    
    # For create operations, they might not need IDs (create from scratch)
    # But some create operations might need parent resource IDs
    # For now, we'll leave create operations without consumes (can be refined later)
    
    return consumes

def process_alicloud_service_spec(spec_file: Path) -> Dict[str, Any]:
    """Process AliCloud service spec and generate operation registry."""
    
    with open(spec_file, 'r') as f:
        data = json.load(f)
    
    service_name = list(data.keys())[0]
    service_data = data[service_name]
    
    # Get all operations
    all_operations = service_data.get('operations', [])
    
    # Build operation registry
    operations = {}
    entity_producers = {}  # entity -> list of operations
    
    for op_spec in all_operations:
        op_name = op_spec['operation']
        kind = assign_kind(op_name)
        side_effect = has_side_effect(kind)
        
        # Get item_fields (AliCloud structure)
        item_fields = op_spec.get('item_fields', {})
        
        # Build consumes (inferred from operation patterns)
        consumes = build_consumes_for_alicloud(service_name, op_name, item_fields)
        
        # Build produces (from item_fields)
        produces = build_produces_for_alicloud(service_name, item_fields, op_name)
        
        # Track entity producers
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
    
    # Finalize consumes.source (mark as internal if entity is produced, external otherwise)
    for op_name, op_data in operations.items():
        for consume in op_data['consumes']:
            entity = consume['entity']
            if entity in entity_producers:
                consume['source'] = 'internal'
            else:
                consume['source'] = 'external'
    
    # Build entity aliases (simplified - can be enhanced later)
    entity_aliases = {}
    
    # Build kind_rules
    kind_rules = {
        "read_list": ["List"],
        "read_get": ["Get", "Describe"],
        "write_create": ["Create", "Start", "Generate", "Import", "Enable", "Register"],
        "write_update": ["Update", "Modify", "Put", "Set", "Change", "Reset", "Patch"],
        "write_delete": ["Delete", "Remove", "Terminate", "Destroy", "Disable", "Detach", "Disassociate", "Untag", "Revoke"],
        "write_apply": ["Apply", "Attach", "Associate", "Add", "Tag", "Authorize", "Unauthorize", "Grant"],
        "other": ["default"]
    }
    
    operation_registry = {
        "service": service_name,
        "version": "1.0",
        "kind_rules": kind_rules,
        "entity_aliases": entity_aliases,
        "overrides": {},
        "operations": operations
    }
    
    return operation_registry

# ============================================================================
# BUILD ADJACENCY
# ============================================================================

def build_adjacency(registry: Dict[str, Any]) -> Dict[str, Any]:
    """Build adjacency.json from operation registry."""
    service = registry['service']
    operations = registry.get('operations', {})
    entity_aliases = registry.get('entity_aliases', {})
    
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
    
    # Compute external entities
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

# ============================================================================
# VALIDATION
# ============================================================================

def validate_service(registry: Dict[str, Any], adjacency: Dict[str, Any]) -> Dict[str, Any]:
    """Generate validation report for a service."""
    operations = registry.get('operations', {})
    service = registry.get('service', '')
    
    all_entities = set()
    
    for op_name, op_data in operations.items():
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            all_entities.add(entity)
        
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            all_entities.add(entity)
    
    # Check for unresolved consumes
    unresolved_consumes = []
    all_produced = set()
    for op_data in operations.values():
        for produce in op_data.get('produces', []):
            all_produced.add(produce['entity'])
    
    for op_name, op_data in operations.items():
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            if entity not in all_produced and entity not in adjacency.get('external_entities', []):
                unresolved_consumes.append({
                    "operation": op_name,
                    "entity": entity,
                    "param": consume.get('param', '')
                })
    
    # Determine status
    if len(unresolved_consumes) > 0:
        status = "WARN"
    else:
        status = "PASS"
    
    report = {
        "service": service,
        "summary": {
            "total_operations": len(operations),
            "total_entities": len(all_entities),
            "external_entities": len(adjacency.get('external_entities', [])),
            "entity_producers_count": len(adjacency.get('entity_producers', {})),
            "entity_consumers_count": len(adjacency.get('entity_consumers', {}))
        },
        "unresolved_consumes": unresolved_consumes,
        "external_entities_count": len(adjacency.get('external_entities', [])),
        "validation_status": status
    }
    
    return report

# ============================================================================
# MANUAL REVIEW GENERATION
# ============================================================================

def generate_manual_review(registry: Dict[str, Any], validation_report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Generate manual_review.json if service needs human attention."""
    if validation_report['validation_status'] == 'PASS':
        return None
    
    # For AliCloud, we can populate manual review if needed in the future
    return None

# ============================================================================
# MAIN PROCESSING
# ============================================================================

def process_alicloud_service_folder(service_folder: Path, alicloud_root: Path) -> Dict[str, Any]:
    """Process a single AliCloud service folder."""
    service_name = service_folder.name
    
    # Find service spec JSON
    spec_file = service_folder / "alicloud_dependencies_with_python_names_fully_enriched.json"
    
    if not spec_file.exists():
        return {
            "service": service_name,
            "status": "SKIP",
            "reason": "No service spec JSON found"
        }
    
    try:
        print(f"  Processing {service_name}...")
        
        # Generate operation_registry.json
        registry = process_alicloud_service_spec(spec_file)
        
        # Generate adjacency.json
        adjacency = build_adjacency(registry)
        
        # Run validation
        validation_report = validate_service(registry, adjacency)
        
        # Generate manual_review.json if needed
        manual_review = generate_manual_review(registry, validation_report)
        
        # Write files
        registry_file = service_folder / "operation_registry.json"
        with open(registry_file, 'w') as f:
            formatted = compact_json_dumps(registry, indent=2)
            f.write(formatted)
        
        adjacency_file = service_folder / "adjacency.json"
        with open(adjacency_file, 'w') as f:
            formatted = compact_json_dumps(adjacency, indent=2)
            f.write(formatted)
        
        validation_file = service_folder / "validation_report.json"
        with open(validation_file, 'w') as f:
            json.dump(validation_report, f, indent=2)
        
        if manual_review:
            review_file = service_folder / "manual_review.json"
            with open(review_file, 'w') as f:
                json.dump(manual_review, f, indent=2)
        
        return {
            "service": service_name,
            "status": validation_report['validation_status'],
            "operations": validation_report['summary']['total_operations'],
            "entities": validation_report['summary']['total_entities'],
            "has_manual_review": manual_review is not None
        }
    
    except Exception as e:
        return {
            "service": service_name,
            "status": "ERROR",
            "error": str(e)
        }

def main():
    """Process all AliCloud services."""
    if len(sys.argv) < 2:
        print("Usage: python build_alicloud_dependency_graph.py <alicloud_root_path>")
        sys.exit(1)
    
    alicloud_root = Path(sys.argv[1])
    if not alicloud_root.exists():
        print(f"Error: Path not found: {alicloud_root}")
        sys.exit(1)
    
    # Find all service directories
    service_dirs = []
    for item in alicloud_root.iterdir():
        if item.is_dir():
            spec_file = item / "alicloud_dependencies_with_python_names_fully_enriched.json"
            if spec_file.exists():
                service_dirs.append(item)
    
    service_dirs.sort()
    
    print(f"\n{'='*70}")
    print(f"BUILDING DEPENDENCY GRAPHS FOR ALICLOUD")
    print(f"{'='*70}")
    print(f"Found {len(service_dirs)} services\n")
    
    results = []
    for service_folder in service_dirs:
        result = process_alicloud_service_folder(service_folder, alicloud_root)
        results.append(result)
        
        status = result.get('status', 'UNKNOWN')
        if status == 'PASS':
            print(f"  ✓ {result['service']}: {result['operations']} operations, {result['entities']} entities")
        elif status == 'WARN':
            print(f"  ⚠ {result['service']}: {result['operations']} operations (WARN)")
        elif status == 'SKIP':
            print(f"  ⊘ {result['service']}: {result.get('reason', 'Skipped')}")
        else:
            print(f"  ✗ {result['service']}: {result.get('error', 'Error')}")
    
    # Summary
    passed = sum(1 for r in results if r.get('status') == 'PASS')
    warned = sum(1 for r in results if r.get('status') == 'WARN')
    failed = sum(1 for r in results if r.get('status') == 'ERROR')
    skipped = sum(1 for r in results if r.get('status') == 'SKIP')
    
    print(f"\n{'='*70}")
    print(f"SUMMARY")
    print(f"{'='*70}")
    print(f"Total: {len(results)}")
    print(f"  ✓ PASS: {passed}")
    print(f"  ⚠ WARN: {warned}")
    print(f"  ✗ ERROR: {failed}")
    print(f"  ⊘ SKIP: {skipped}")
    print(f"{'='*70}\n")
    
    # Save results
    results_file = alicloud_root / "dependency_graph_build_results.json"
    with open(results_file, 'w') as f:
        json.dump({
            "total": len(results),
            "passed": passed,
            "warned": warned,
            "failed": failed,
            "skipped": skipped,
            "services": results
        }, f, indent=2)
    
    print(f"Results saved to: {results_file}\n")

if __name__ == '__main__':
    main()

