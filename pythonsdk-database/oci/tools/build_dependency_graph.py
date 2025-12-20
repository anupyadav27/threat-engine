#!/usr/bin/env python3
"""
Build dependency graph artifacts for ALL OCI services.
Generates operation_registry.json, adjacency.json, validation_report.json per service,
with two-pass auto-fix pipeline as specified in final_promt_oci.
"""

import json
import re
import sys
import shutil
from pathlib import Path
from typing import Dict, List, Any, Set, Tuple, Optional
from collections import defaultdict

# ============================================================================
# OCI-SPECIFIC GLOBAL IDENTITY EXCEPTIONS
# ============================================================================

OCI_GLOBAL_IDENTITIES = {
    'compartmentId': 'oci.compartment_id',
    'compartment_id': 'oci.compartment_id',
    'tenancyId': 'oci.tenancy_id',
    'tenancy_id': 'oci.tenancy_id',
    'region': 'oci.region',
    'availabilityDomain': 'oci.availability_domain',
    'availability_domain': 'oci.availability_domain',
    'page': 'oci.pagination_token',
    'limit': 'oci.pagination_token',
    'opc-next-page': 'oci.pagination_token',
    'nextPage': 'oci.pagination_token',
}

def is_oci_global_identity(param: str) -> Optional[str]:
    """Check if param is an OCI global identity and return canonical entity."""
    param_lower = param.lower()
    for key, canonical in OCI_GLOBAL_IDENTITIES.items():
        if param_lower == key.lower():
            return canonical
    return None

def is_ocid_field(field_name: str, field_type: str = None) -> bool:
    """Check if field represents an OCID (Oracle Cloud ID)."""
    field_lower = field_name.lower()
    # OCIDs typically start with "ocid1." and are strings
    if field_lower in ['id', 'ocid'] and (field_type == 'string' or field_type is None):
        return True
    return False

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def compact_json_dumps(obj, indent=2):
    """Custom JSON formatter for more compact, human-readable output."""
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

def extract_meaningful_parent(path: str) -> Optional[str]:
    """Extract the nearest meaningful parent segment from a path."""
    generic_containers = {'resource', 'item', 'data', 'details', 'detail', 'info', 'information', 
                          'result', 'response', 'output', 'response_metadata'}
    
    if '[]' in path:
        list_part, rest = path.split('[]', 1)
        segments = [list_part]
        if rest:
            segments.extend(rest.lstrip('.').split('.'))
    else:
        segments = path.split('.')
    
    if len(segments) < 2:
        return None
    
    for i in range(len(segments) - 2, -1, -1):
        segment = segments[i]
        segment_lower = segment.lower()
        
        if segment_lower not in generic_containers:
            return segment
    
    return segments[-2] if len(segments) >= 2 else None

# ============================================================================
# OCI KIND ASSIGNMENT (from prompt)
# ============================================================================

def assign_kind(operation: str, python_method: Optional[str] = None) -> str:
    """
    Auto-assign kind based on operation name or python_method.
    OCI-aware: Prefer python_method if present.
    """
    # Use python_method if available, else operation name
    name = (python_method or operation).lower()
    
    # Priority order (first match wins):
    # 1. Delete operations
    if any(name.startswith(prefix) for prefix in ['delete', 'remove', 'terminate', 'destroy', 'purge', 'detach', 'disassociate', 'revoke', 'cancel', 'disable']):
        return 'write_delete'
    
    # 2. Update operations
    if any(name.startswith(prefix) for prefix in ['update', 'modify', 'set', 'change', 'patch', 'replace', 'add', 'attach', 'associate', 'enable', 'move']):
        return 'write_update'
    
    # 3. Create operations
    if any(name.startswith(prefix) for prefix in ['create', 'launch', 'start', 'run', 'provision', 'register', 'generate', 'import', 'enable']):
        return 'write_create'
    
    # 4. List operations
    if any(name.startswith(prefix) for prefix in ['list', 'search', 'query', 'enumerate']):
        return 'read_list'
    
    # 5. Get operations
    if any(name.startswith(prefix) for prefix in ['get', 'describe', 'read', 'fetch']):
        return 'read_get'
    
    # Default
    return 'other'

def has_side_effect(kind: str) -> bool:
    """Determine if operation has side effects."""
    return not kind.startswith('read_')

# ============================================================================
# OCI ENTITY NAMING (from prompt)
# ============================================================================

def normalize_oci_field_name(field_name: str) -> str:
    """OCI-specific field normalization."""
    # displayName => name
    if field_name.lower() == 'displayname' or field_name.lower() == 'display_name':
        return 'name'
    # lifecycleState => status
    if field_name.lower() == 'lifecyclestate' or field_name.lower() == 'lifecycle_state':
        return 'status'
    return field_name

def extract_noun_from_operation(operation_name: str, main_output_field: Optional[str] = None) -> str:
    """Extract noun from operation name by removing verb prefixes."""
    if main_output_field and main_output_field.lower() not in ['id', 'name', 'status', 'result', 'response']:
        noun = main_output_field.replace('[]', '')
        return singularize(to_snake_case(noun))
    
    op = operation_name.lower()
    verbs = ['list', 'get', 'describe', 'create', 'update', 'delete', 'change', 'set', 'patch', 'add', 'remove',
             'launch', 'start', 'run', 'provision', 'register', 'generate', 'import', 'enable', 'disable',
             'terminate', 'destroy', 'purge', 'detach', 'disassociate', 'revoke', 'cancel']
    
    for verb in verbs:
        if op.startswith(verb):
            noun = operation_name[len(verb):] if len(operation_name) > len(verb) else 'resource'
            return singularize(to_snake_case(noun))
    
    return singularize(to_snake_case(operation_name))

def normalize_entity_name_for_alias(entity: str, service: str) -> str:
    """Normalize entity name by stripping wrappers for aliasing."""
    if entity.startswith(f"oci.{service}."):
        base = entity[len(f"oci.{service}."):]
    else:
        base = entity
    
    parts = base.split('.')
    if len(parts) > 1:
        # Remove wrapper words from resource part
        resource_parts = parts[0].split('_')
        wrapper_words = {'summary', 'list', 'detail', 'details', 'info', 'information', 'data'}
        filtered = [p for p in resource_parts if p not in wrapper_words]
        normalized_resource = '_'.join(filtered) if filtered else parts[0]
        return f"oci.{service}.{normalized_resource}.{'.'.join(parts[1:])}"
    
    return entity

def extract_resource_from_operation(operation_name: str, main_output_field: Optional[str] = None, item_fields: Optional[Dict] = None) -> str:
    """
    Derive resource name from operation context.
    Follows prompt rules 3.1 a-d.
    """
    # Rule 3.1a: If main_output_field exists and item_fields exist
    if main_output_field and item_fields:
        # Infer resource from main_output_field container name (singularize)
        container = main_output_field.replace('[]', '').split('.')[0]
        return singularize(to_snake_case(container))
    
    # Rule 3.1b: If operation starts with List and output has "items"
    if operation_name.lower().startswith('list'):
        # Strip "list" prefix and singularize
        resource = operation_name[4:] if len(operation_name) > 4 else 'resource'
        return singularize(to_snake_case(resource))
    
    # Rule 3.1c: Derive from operation name by stripping verbs
    verbs = ['list', 'get', 'describe', 'create', 'update', 'delete', 'change', 'set', 'patch', 'add', 'remove']
    op_lower = operation_name.lower()
    for verb in verbs:
        if op_lower.startswith(verb):
            resource = operation_name[len(verb):] if len(operation_name) > len(verb) else 'resource'
            return singularize(to_snake_case(resource))
    
    # Rule 3.1d: Fallback
    return 'resource'

def normalize_consumes_entity(service: str, param: str, operation_name: str, main_output_field: Optional[str] = None) -> str:
    """
    Normalize entity for consumes based on param and operation context.
    Follows prompt rules 2 (global exceptions) and 3.2 (consumes mapping).
    """
    param_lower = param.lower()
    
    # Rule 2: Check global identity exceptions FIRST
    global_entity = is_oci_global_identity(param)
    if global_entity:
        return global_entity
    
    # Rule 3.2: Handle generic tokens
    if param_lower == 'id' or param_lower.endswith('id'):
        # Check if it's an OCID
        if is_ocid_field(param):
            return 'oci.ocid'
        # Map to resource-specific id
        resource = extract_resource_from_operation(operation_name, main_output_field)
        if param_lower == 'id':
            return f"oci.{service}.{resource}.{resource}_id"
        else:
            # Compound param like "instanceId" -> extract base
            base = param_lower.replace('id', '')
            if base:
                return f"oci.{service}.{to_snake_case(base)}_id"
        return f"oci.{service}.{resource}.{resource}_id"
    
    elif param_lower == 'name' or param_lower.endswith('name') or param_lower == 'displayname':
        resource = extract_resource_from_operation(operation_name, main_output_field)
        if param_lower == 'name' or param_lower == 'displayname':
            return f"oci.{service}.{resource}.name"
        else:
            base = param_lower.replace('name', '')
            if base:
                return f"oci.{service}.{to_snake_case(base)}_name"
        return f"oci.{service}.{resource}.name"
    
    elif param_lower == 'status' or param_lower.endswith('status') or param_lower == 'lifecyclestate':
        resource = extract_resource_from_operation(operation_name, main_output_field)
        if param_lower == 'status' or param_lower == 'lifecyclestate':
            return f"oci.{service}.{resource}.status"
        else:
            base = param_lower.replace('status', '')
            if base:
                return f"oci.{service}.{to_snake_case(base)}_status"
        return f"oci.{service}.{resource}.status"
    
    # Default: snake_case of param
    return f"oci.{service}.{to_snake_case(param)}"

def normalize_produces_entity(service: str, path: str, operation_name: str, main_output_field: Optional[str] = None) -> str:
    """
    Normalize entity for produces based on path context.
    Follows prompt rules 2 (global exceptions) and 3.3 (produces mapping).
    """
    field_name = path.split('.')[-1].split('[]')[-1]
    field_normalized = normalize_oci_field_name(field_name)
    field_lower = field_normalized.lower()
    
    # Rule 2: Check global identity exceptions
    global_entity = is_oci_global_identity(field_normalized)
    if global_entity:
        return global_entity
    
    # Check if it's an OCID
    if is_ocid_field(field_normalized):
        return 'oci.ocid'
    
    # Extract resource from operation (better than trying to parse path)
    resource = extract_resource_from_operation(operation_name, main_output_field)
    
    # Rule 3.3: Handle generic tokens (id/name/status)
    if field_lower in ['id', 'name', 'status']:
        # Try to find meaningful parent from path first
        parent = extract_meaningful_parent(path)
        if parent and parent.lower() not in ['item', 'items', 'data', 'resource', 'result', 'response']:
            parent_snake = singularize(to_snake_case(parent))
            parent_snake = parent_snake.strip('_')
            while parent_snake.startswith('_'):
                parent_snake = parent_snake[1:]
            if parent_snake and parent_snake != 'resource':
                return f"oci.{service}.{parent_snake}.{field_lower}"
        
        # Fallback to resource from operation
        if resource and resource != 'resource':
            return f"oci.{service}.{resource}.{resource}_{field_lower}"
        else:
            # Last resort: use field name directly
            return f"oci.{service}.{field_lower}"
    
    # For non-generic fields, try parent first, then resource
    parent = extract_meaningful_parent(path)
    if parent and parent.lower() not in ['item', 'items', 'data', 'resource', 'result', 'response']:
        parent_snake = singularize(to_snake_case(parent))
        parent_snake = parent_snake.strip('_')
        while parent_snake.startswith('_'):
            parent_snake = parent_snake[1:]
        if parent_snake and parent_snake != 'resource':
            field_snake = to_snake_case(field_normalized)
            # Avoid duplication
            if field_snake.startswith(parent_snake + '_'):
                return f"oci.{service}.{field_snake}"
            return f"oci.{service}.{parent_snake}.{field_snake}"
    
    # Use resource from operation if available
    if resource and resource != 'resource':
        field_snake = to_snake_case(field_normalized)
        return f"oci.{service}.{resource}.{field_snake}"
    
    # Last resort: use field name directly
    return f"oci.{service}.{to_snake_case(field_normalized)}"

# ============================================================================
# BUILD OPERATION REGISTRY
# ============================================================================

def build_consumes(service: str, required_params: List[str], operation_name: str, 
                   main_output_field: Optional[str] = None, overrides: Optional[Dict] = None) -> List[Dict[str, Any]]:
    """Build consumes list from required_params."""
    consumes = []
    for param in required_params:
        # Check for override first
        override_key = f"{operation_name}:param:{param}"
        if overrides and 'param_aliases' in overrides and override_key in overrides['param_aliases']:
            entity = overrides['param_aliases'][override_key]
        elif overrides and 'consumes_overrides' in overrides and f"{operation_name}.{param}" in overrides['consumes_overrides']:
            entity = overrides['consumes_overrides'][f"{operation_name}.{param}"]
        else:
            entity = normalize_consumes_entity(service, param, operation_name, main_output_field)
        
        consumes.append({
            "entity": entity,
            "param": param,
            "required": True,
            "source": "either"  # Will be finalized later
        })
    return consumes

def build_produces(service: str, output_fields: Dict[str, Any], main_output_field: Optional[str], 
                  item_fields: Dict[str, Any], operation_name: str, overrides: Optional[Dict] = None) -> List[Dict[str, Any]]:
    """Build produces list from output_fields and item_fields."""
    produces = []
    is_list_op = assign_kind(operation_name) == 'read_list'
    
    # Add output_fields
    for field_name in output_fields.keys():
        override_key = f"{operation_name}:out:{field_name}"
        if overrides and 'produces_overrides' in overrides and f"{operation_name}.{field_name}" in overrides['produces_overrides']:
            entity = overrides['produces_overrides'][f"{operation_name}.{field_name}"]
        else:
            entity = normalize_produces_entity(service, field_name, operation_name, main_output_field)
        
        produces.append({
            "entity": entity,
            "source": "output",
            "path": field_name
        })
    
    # Add item_fields if main_output_field exists
    if main_output_field and item_fields:
        for field_name in item_fields.keys():
            # Rule: Use [] for list ops, dot notation for get ops
            if is_list_op:
                path = f"{main_output_field}[].{field_name}"
            else:
                path = f"{main_output_field}.{field_name}"
            
            override_key = f"{operation_name}:out:{path}"
            if overrides and 'produces_overrides' in overrides and f"{operation_name}.{path}" in overrides['produces_overrides']:
                entity = overrides['produces_overrides'][f"{operation_name}.{path}"]
            else:
                entity = normalize_produces_entity(service, path, operation_name, main_output_field)
            
            produces.append({
                "entity": entity,
                "source": "item",
                "path": path
            })
    elif item_fields and not main_output_field:
        # If item_fields exist but no main_output_field, assume "items" container
        for field_name in item_fields.keys():
            path = f"items[].{field_name}" if is_list_op else f"items.{field_name}"
            override_key = f"{operation_name}:out:{path}"
            if overrides and 'produces_overrides' in overrides and f"{operation_name}.{path}" in overrides['produces_overrides']:
                entity = overrides['produces_overrides'][f"{operation_name}.{path}"]
            else:
                entity = normalize_produces_entity(service, path, operation_name, main_output_field)
            
            produces.append({
                "entity": entity,
                "source": "item",
                "path": path
            })
    
    return produces

def resolve_entity_alias(entity: str, entity_aliases: Dict[str, str], visited: Optional[Set[str]] = None) -> str:
    """Resolve entity alias to canonical (multi-hop safe)."""
    if visited is None:
        visited = set()
    
    if entity in visited:
        return entity  # Cycle detected
    
    if entity in entity_aliases:
        visited.add(entity)
        return resolve_entity_alias(entity_aliases[entity], entity_aliases, visited)
    
    return entity

def infer_required_params_from_operation(op_name: str, python_method: Optional[str], kind: str, item_fields: Dict) -> List[str]:
    """Infer required parameters from operation name and context."""
    name = (python_method or op_name).lower()
    params = []
    
    # Get operations typically need an id parameter
    if kind == 'read_get':
        # Check if item_fields has 'id' - suggests the operation needs an id param
        if 'id' in item_fields:
            # Infer param name from operation - extract resource and convert to camelCase
            resource = extract_resource_from_operation(op_name)
            if resource and resource != 'resource':
                # Convert snake_case to camelCase for param name
                parts = resource.split('_')
                if len(parts) > 1:
                    param_name = parts[0] + ''.join(p.capitalize() for p in parts[1:]) + 'Id'
                else:
                    param_name = resource + 'Id'
                params.append(param_name)
            else:
                params.append('id')
    
    # List operations typically need compartment_id
    if kind == 'read_list':
        params.append('compartmentId')
    
    # Create/Update/Delete operations typically need the resource id
    if kind in ['write_create', 'write_update', 'write_delete']:
        resource = extract_resource_from_operation(op_name)
        if resource and resource != 'resource':
            # Convert to camelCase
            parts = resource.split('_')
            if len(parts) > 1:
                param_name = parts[0] + ''.join(p.capitalize() for p in parts[1:]) + 'Id'
            else:
                param_name = resource + 'Id'
            params.append(param_name)
        else:
            params.append('id')
    
    return params

def process_service_spec(spec_file: Path, overrides: Optional[Dict] = None) -> Dict[str, Any]:
    """Process service spec and generate operation registry."""
    
    with open(spec_file, 'r') as f:
        data = json.load(f)
    
    service_name = list(data.keys())[0]
    service_data = data[service_name]
    
    # OCI structure: operations array
    all_operations = service_data.get('operations', [])
    
    # Build operation registry
    operations = {}
    entity_producers = {}
    
    for op_spec in all_operations:
        op_name = op_spec['operation']
        python_method = op_spec.get('python_method')
        kind = assign_kind(op_name, python_method)
        side_effect = has_side_effect(kind)
        
        # Build consumes - infer params if missing
        required_params = op_spec.get('required_params', [])
        if not required_params:
            # Infer from operation context
            item_fields = op_spec.get('item_fields', {})
            required_params = infer_required_params_from_operation(op_name, python_method, kind, item_fields)
        
        main_output_field = op_spec.get('main_output_field')
        consumes = build_consumes(service_name, required_params, op_name, main_output_field, overrides)
        
        # Build produces
        output_fields = op_spec.get('output_fields', {})
        item_fields = op_spec.get('item_fields', {})
        
        # If no main_output_field but we have item_fields, infer it
        if not main_output_field and item_fields:
            # For list operations, use "items" or infer from operation name
            if kind == 'read_list':
                # Try to infer from operation name
                resource = extract_resource_from_operation(op_name, None, item_fields)
                main_output_field = f"{to_snake_case(resource)}s" if resource != 'resource' else "items"
            else:
                # For get operations, use singular resource name
                resource = extract_resource_from_operation(op_name, None, item_fields)
                main_output_field = to_snake_case(resource) if resource != 'resource' else "data"
        
        produces = build_produces(service_name, output_fields, main_output_field, item_fields, op_name, overrides)
        
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
                "method": python_method or op_name
            },
            "consumes": consumes,
            "produces": produces,
            "notes": ""
        }
    
    # Apply entity aliases if present
    entity_aliases = {}
    if overrides and 'entity_aliases' in overrides:
        entity_aliases = overrides['entity_aliases']
    
    # Resolve aliases in operations
    for op_name, op_data in operations.items():
        for consume in op_data.get('consumes', []):
            consume['entity'] = resolve_entity_alias(consume['entity'], entity_aliases)
        for produce in op_data.get('produces', []):
            produce['entity'] = resolve_entity_alias(produce['entity'], entity_aliases)
    
    # Rebuild entity_producers after alias resolution
    entity_producers = {}
    for op_name, op_data in operations.items():
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            if entity not in entity_producers:
                entity_producers[entity] = []
            entity_producers[entity].append(op_name)
    
    # Finalize consumes.source
    for op_name, op_data in operations.items():
        for consume in op_data['consumes']:
            entity = consume['entity']
            if entity in entity_producers:
                consume['source'] = 'internal'
            else:
                consume['source'] = 'external'
    
    operation_registry = {
        "service": service_name,
        "version": "1.0",
        "entity_aliases": entity_aliases,
        "overrides": overrides or {},
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
    
    def resolve_entity(entity: str) -> str:
        return resolve_entity_alias(entity, entity_aliases)
    
    op_consumes = {}
    op_produces = {}
    entity_producers = {}
    entity_consumers = {}
    
    for op_name, op_data in operations.items():
        consumed_entities = [resolve_entity(c['entity']) for c in op_data.get('consumes', [])]
        op_consumes[op_name] = list(set(consumed_entities))
        
        produced_entities = [resolve_entity(p['entity']) for p in op_data.get('produces', [])]
        op_produces[op_name] = list(set(produced_entities))
        
        for entity in produced_entities:
            if entity not in entity_producers:
                entity_producers[entity] = []
            entity_producers[entity].append(op_name)
        
        for entity in consumed_entities:
            if entity not in entity_consumers:
                entity_consumers[entity] = []
            entity_consumers[entity].append(op_name)
    
    all_produced = set(entity_producers.keys())
    external_entities = []
    for entity in set(entity_consumers.keys()):
        if entity not in all_produced:
            external_entities.append(entity)
    
    # Find independent ops and root seeds
    independent_ops = []
    root_seeds = []
    for op_name, op_data in operations.items():
        if op_data['kind'] in ['read_list', 'read_get']:
            # Check if it has no internal dependencies
            has_internal_deps = any(c['source'] == 'internal' for c in op_data.get('consumes', []))
            if not has_internal_deps:
                independent_ops.append(op_name)
                if op_data['kind'] == 'read_list':
                    root_seeds.append(op_name)
    
    adjacency = {
        "service": service,
        "op_consumes": op_consumes,
        "op_produces": op_produces,
        "entity_producers": {k: list(set(v)) for k, v in entity_producers.items()},
        "entity_consumers": {k: list(set(v)) for k, v in entity_consumers.items()},
        "external_entities": sorted(external_entities),
        "independent_ops": sorted(independent_ops),
        "root_seeds": sorted(root_seeds)
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
    generic_token_hits = defaultdict(int)
    ambiguous_evidence_keys = defaultdict(list)
    unresolved_consumers = []
    
    for op_name, op_data in operations.items():
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            all_entities.add(entity)
            param = consume['param']
            
            # Check for generic tokens (oci.<service>.id, oci.<service>.name, etc.)
            if entity.startswith(f"oci.{service}."):
                parts = entity.split('.')
                if len(parts) == 3 and parts[2] in ['id', 'name', 'status']:
                    generic_token_hits[parts[2]] += 1
                    ambiguous_evidence_keys[f"{op_name}:param:{param}"].append(entity)
            
            # Check if unresolved
            if consume['source'] == 'external' and entity not in adjacency.get('external_entities', []):
                unresolved_consumers.append({
                    "operation": op_name,
                    "entity": entity,
                    "param": param
                })
        
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            all_entities.add(entity)
            path = produce['path']
            
            # Check for generic tokens
            if entity.startswith(f"oci.{service}."):
                parts = entity.split('.')
                if len(parts) == 3 and parts[2] in ['id', 'name', 'status']:
                    generic_token_hits[parts[2]] += 1
                    ambiguous_evidence_keys[f"{op_name}:out:{path}"].append(entity)
    
    # Count satisfiable operations
    all_produced = set()
    for op_data in operations.values():
        for produce in op_data.get('produces', []):
            all_produced.add(produce['entity'])
    
    satisfiable_ops = 0
    for op_name, op_data in operations.items():
        all_satisfied = True
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            if entity not in all_produced and entity not in adjacency.get('external_entities', []):
                all_satisfied = False
                break
        if all_satisfied:
            satisfiable_ops += 1
    
    satisfiable_percent = (satisfiable_ops / len(operations) * 100) if operations else 0
    
    # Check for cycles (simplified - just self-cycles for now)
    cycles = []
    for op_name, op_data in operations.items():
        consumed = {c['entity'] for c in op_data.get('consumes', [])}
        produced = {p['entity'] for p in op_data.get('produces', [])}
        overlap = consumed & produced
        if overlap:
            cycles.append({
                "operation": op_name,
                "entities": list(overlap)
            })
    
    report = {
        "service": service,
        "summary": {
            "total_operations": len(operations),
            "total_entities": len(all_entities),
            "external_entities": len(adjacency.get('external_entities', [])),
            "satisfiable_ops": satisfiable_ops,
            "satisfiable_ops_percent": round(satisfiable_percent, 2)
        },
        "generic_token_hits": dict(generic_token_hits),
        "ambiguous_evidence_keys": {k: list(set(v)) for k, v in ambiguous_evidence_keys.items() if len(set(v)) > 1},
        "unresolved_consumers": unresolved_consumers,
        "cycles": cycles,
        "overrides_applied_count": len(registry.get('overrides', {}).get('param_aliases', {})) + \
                                   len(registry.get('overrides', {}).get('consumes_overrides', {})) + \
                                   len(registry.get('overrides', {}).get('produces_overrides', {})),
        "aliases_applied_count": len(registry.get('entity_aliases', {}))
    }
    
    return report

# ============================================================================
# MANUAL REVIEW GENERATION
# ============================================================================

def generate_manual_review(registry: Dict[str, Any], validation_report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Generate manual_review.json with suggested_overrides."""
    if not validation_report.get('generic_token_hits') and \
       not validation_report.get('unresolved_consumers') and \
       not validation_report.get('ambiguous_evidence_keys'):
        return None
    
    service = registry['service']
    operations = registry.get('operations', {})
    
    suggested_overrides = []
    
    # Generate suggestions from validation issues
    for op_name, op_data in operations.items():
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            param = consume['param']
            
            # Check if it's a generic token hit
            if entity.startswith(f"oci.{service}."):
                parts = entity.split('.')
                if len(parts) == 3 and parts[2] in ['id', 'name', 'status']:
                    # Suggest resource-specific entity
                    resource = extract_resource_from_operation(op_name)
                    suggested_entity = f"oci.{service}.{resource}.{resource}_{parts[2]}"
                    suggested_overrides.append({
                        "operation": op_name,
                        "type": "consumes",
                        "key": param,
                        "suggested_entity": suggested_entity,
                        "confidence": "HIGH",
                        "reason": f"Generic token '{parts[2]}' should be resource-specific"
                    })
        
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            path = produce['path']
            
            # Check if it's a generic token hit
            if entity.startswith(f"oci.{service}."):
                parts = entity.split('.')
                if len(parts) == 3 and parts[2] in ['id', 'name', 'status']:
                    resource = extract_resource_from_operation(op_name)
                    suggested_entity = f"oci.{service}.{resource}.{resource}_{parts[2]}"
                    suggested_overrides.append({
                        "operation": op_name,
                        "type": "produces",
                        "key": path,
                        "suggested_entity": suggested_entity,
                        "confidence": "HIGH",
                        "reason": f"Generic token '{parts[2]}' should be resource-specific"
                    })
    
    review = {
        "service": service,
        "unresolved_consumers": validation_report.get('unresolved_consumers', []),
        "ambiguous_evidence_keys": validation_report.get('ambiguous_evidence_keys', {}),
        "generic_token_hits": validation_report.get('generic_token_hits', {}),
        "suggested_overrides": suggested_overrides[:50]  # Limit to 50
    }
    
    return review

# ============================================================================
# TWO-PASS AUTO-FIX PIPELINE
# ============================================================================

def auto_apply_suggestions(manual_review: Dict[str, Any], validation_report: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Auto-apply suggestions based on confidence.
    Returns: (overrides_dict, fixes_applied_dict)
    """
    overrides = {
        "param_aliases": {},
        "entity_aliases": {},
        "consumes_overrides": {},
        "produces_overrides": {}
    }
    fixes_applied = []
    
    if not manual_review:
        return overrides, fixes_applied
    
    suggested = manual_review.get('suggested_overrides', [])
    baseline_metrics = {
        'generic_token_hits': sum(validation_report.get('generic_token_hits', {}).values()),
        'ambiguous_count': len(validation_report.get('ambiguous_evidence_keys', {})),
        'unresolved_consumers_count': len(validation_report.get('unresolved_consumers', []))
    }
    
    for suggestion in suggested:
        confidence = suggestion.get('confidence', 'LOW')
        op_name = suggestion['operation']
        sugg_type = suggestion['type']
        key = suggestion['key']
        suggested_entity = suggestion['suggested_entity']
        
        # Auto-apply HIGH confidence
        if confidence == 'HIGH':
            if sugg_type == 'consumes':
                evidence_key = f"{op_name}:param:{key}"
                overrides['param_aliases'][evidence_key] = suggested_entity
                overrides['consumes_overrides'][f"{op_name}.{key}"] = suggested_entity
            else:  # produces
                overrides['produces_overrides'][f"{op_name}.{key}"] = suggested_entity
            
            fixes_applied.append({
                "suggestion": suggestion,
                "decision": "accepted",
                "reason": "HIGH confidence auto-apply"
            })
        
        # MEDIUM confidence: only if it reduces issues
        elif confidence == 'MEDIUM':
            # For now, accept MEDIUM if it addresses generic tokens
            if 'generic' in suggestion.get('reason', '').lower():
                if sugg_type == 'consumes':
                    evidence_key = f"{op_name}:param:{key}"
                    overrides['param_aliases'][evidence_key] = suggested_entity
                    overrides['consumes_overrides'][f"{op_name}.{key}"] = suggested_entity
                else:
                    overrides['produces_overrides'][f"{op_name}.{key}"] = suggested_entity
                
                fixes_applied.append({
                    "suggestion": suggestion,
                    "decision": "accepted",
                    "reason": "MEDIUM confidence - reduces generic tokens"
                })
    
    return overrides, fixes_applied

# ============================================================================
# MAIN PROCESSING
# ============================================================================

def process_service_folder(service_folder: Path, oci_root: Path) -> Dict[str, Any]:
    """Process a single service folder with two-pass pipeline."""
    service_name = service_folder.name
    
    # Find service spec JSON
    spec_file = service_folder / "oci_dependencies_with_python_names_fully_enriched.json"
    if not spec_file.exists():
        return {
            "service": service_name,
            "status": "SKIP",
            "reason": "No service spec JSON found"
        }
    
    try:
        print(f"  Processing {service_name}...")
        
        # Load existing overrides if present
        overrides_file = service_folder / "overrides.json"
        existing_overrides = {}
        if overrides_file.exists():
            with open(overrides_file, 'r') as f:
                existing_overrides = json.load(f)
        
        # PASS 1: Generate without overrides (or with existing)
        registry = process_service_spec(spec_file, existing_overrides)
        adjacency = build_adjacency(registry)
        validation_report = validate_service(registry, adjacency)
        manual_review = generate_manual_review(registry, validation_report)
        
        # Auto-apply suggestions
        new_overrides, fixes_applied = auto_apply_suggestions(manual_review, validation_report)
        
        # Merge with existing overrides
        merged_overrides = existing_overrides.copy()
        for key, value in new_overrides.items():
            if key not in merged_overrides:
                merged_overrides[key] = {}
            merged_overrides[key].update(value)
        
        # PASS 2: Regenerate with merged overrides
        if fixes_applied:
            print(f"    Applying {len(fixes_applied)} auto-fixes...")
            registry = process_service_spec(spec_file, merged_overrides)
            adjacency = build_adjacency(registry)
            validation_report = validate_service(registry, adjacency)
            # Regenerate manual_review (should be smaller now)
            manual_review = generate_manual_review(registry, validation_report)
        
        # Write files with backups
        files_to_write = {
            "operation_registry.json": registry,
            "adjacency.json": adjacency,
            "validation_report.json": validation_report,
            "overrides.json": merged_overrides
        }
        
        if manual_review:
            files_to_write["manual_review.json"] = manual_review
        
        if fixes_applied:
            files_to_write["fixes_applied.json"] = fixes_applied
        
        for filename, data in files_to_write.items():
            filepath = service_folder / filename
            # Backup if exists
            if filepath.exists():
                backup_path = filepath.with_suffix(filepath.suffix + '.bak')
                shutil.copy2(filepath, backup_path)
            
            with open(filepath, 'w') as f:
                if filename in ['operation_registry.json', 'adjacency.json']:
                    formatted = compact_json_dumps(data, indent=2)
                    f.write(formatted)
                else:
                    json.dump(data, f, indent=2, sort_keys=True)
        
        return {
            "service": service_name,
            "status": "PASS" if validation_report.get('generic_token_hits') == {} and \
                              not validation_report.get('unresolved_consumers') else "WARN",
            "operations": validation_report['summary']['total_operations'],
            "entities": validation_report['summary']['total_entities'],
            "generic_token_hits": sum(validation_report.get('generic_token_hits', {}).values()),
            "unresolved_consumers": len(validation_report.get('unresolved_consumers', [])),
            "fixes_applied": len(fixes_applied),
            "has_manual_review": manual_review is not None
        }
    
    except Exception as e:
        import traceback
        return {
            "service": service_name,
            "status": "ERROR",
            "error": str(e),
            "traceback": traceback.format_exc()
        }

def process_service_from_consolidated(service_name: str, service_data: Dict[str, Any], oci_root: Path) -> Dict[str, Any]:
    """Process a service from consolidated file - create folder and process."""
    service_folder = oci_root / service_name
    service_folder.mkdir(parents=True, exist_ok=True)
    
    # Write service-specific JSON file
    spec_file = service_folder / "oci_dependencies_with_python_names_fully_enriched.json"
    with open(spec_file, 'w') as f:
        json.dump({service_name: service_data}, f, indent=2)
    
    # Now process it
    return process_service_folder(service_folder, oci_root)

def main():
    """Main entry point."""
    script_dir = Path(__file__).parent
    oci_root = script_dir.parent
    
    print(f"OCI Root: {oci_root}")
    
    # Load consolidated file
    consolidated_file = oci_root / "oci_dependencies_with_python_names_fully_enriched.json"
    if not consolidated_file.exists():
        print(f"❌ Consolidated file not found: {consolidated_file}")
        return
    
    print(f"Loading consolidated file: {consolidated_file.name}")
    with open(consolidated_file, 'r') as f:
        consolidated_data = json.load(f)
    
    print(f"Found {len(consolidated_data)} services in consolidated file\n")
    
    # Process each service
    results = []
    services = sorted(consolidated_data.keys())
    
    for service_name in services:
        service_data = consolidated_data[service_name]
        
        # Check if service folder already exists with spec file
        service_folder = oci_root / service_name
        spec_file = service_folder / "oci_dependencies_with_python_names_fully_enriched.json"
        
        if spec_file.exists():
            # Use existing folder
            result = process_service_folder(service_folder, oci_root)
        else:
            # Create folder and process from consolidated
            result = process_service_from_consolidated(service_name, service_data, oci_root)
        
        results.append(result)
        status_icon = "✓" if result['status'] == 'PASS' else "⚠" if result['status'] == 'WARN' else "✗" if result['status'] == 'FAIL' else "?"
        print(f"  {status_icon} {result['service']}: {result['status']}")
        if result.get('fixes_applied', 0) > 0:
            print(f"      Applied {result['fixes_applied']} auto-fixes")
    
    # Generate global summary
    print("\nGenerating global summary...")
    
    passed = [r['service'] for r in results if r['status'] == 'PASS']
    warn = [r['service'] for r in results if r['status'] == 'WARN']
    errors = [r['service'] for r in results if r['status'] == 'ERROR']
    skipped = [r['service'] for r in results if r['status'] == 'SKIP']
    
    global_summary = {
        "total_services": len(results),
        "passed": passed,
        "warn": warn,
        "errors": errors,
        "skipped": skipped,
        "summary_stats": {
            "total_operations": sum(r.get('operations', 0) for r in results),
            "total_entities": sum(r.get('entities', 0) for r in results),
            "total_fixes_applied": sum(r.get('fixes_applied', 0) for r in results),
            "services_with_manual_review": len([r for r in results if r.get('has_manual_review', False)])
        }
    }
    
    summary_file = oci_root / "global_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(global_summary, f, indent=2)
    
    print(f"\n{'='*60}")
    print("GLOBAL SUMMARY")
    print(f"{'='*60}")
    print(f"Total services: {len(results)}")
    print(f"  ✓ PASSED: {len(passed)}")
    print(f"  ⚠ WARN: {len(warn)}")
    print(f"  ? ERRORS: {len(errors)}")
    print(f"  - SKIPPED: {len(skipped)}")
    print(f"\nTotal fixes applied: {global_summary['summary_stats']['total_fixes_applied']}")
    print(f"Services with manual review: {global_summary['summary_stats']['services_with_manual_review']}")
    print(f"\nGlobal summary saved to: {summary_file}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    main()

