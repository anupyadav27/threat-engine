#!/usr/bin/env python3
"""
Build dependency graph artifacts for ALL IBM Cloud services.
Generates operation_registry.json, adjacency.json, validation_report.json per service,
following the IBM-specific rules from final_promt_ibm.
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
    """Singularize word - improved to handle more cases."""
    if not word:
        return word
    
    word_lower = word.lower()
    
    # Handle special cases first
    special_cases = {
        'policies': 'policy',
        'profiles': 'profile',
        'servers': 'server',
        'networks': 'network',
        'groups': 'group',
        'hosts': 'host',
        'instances': 'instance',
        'volumes': 'volume',
        'snapshots': 'snapshot',
        'keys': 'key',
        'images': 'image',
        'vpcs': 'vpc',
        'subnets': 'subnet',
        'routes': 'route',
        'rules': 'rule',
        'gateways': 'gateway',
        'interfaces': 'interface',
        'attachments': 'attachment',
        'bindings': 'binding',
        'templates': 'template',
        'managers': 'manager',
        'actions': 'action',
        'ranges': 'range',
        'reservations': 'reservation',
        'shares': 'share',
        'targets': 'target',
        'clones': 'clone',
        'prefixes': 'prefix',
        'tables': 'table',
    }
    
    if word_lower in special_cases:
        # Preserve original case pattern
        if word.isupper():
            return special_cases[word_lower].upper()
        elif word[0].isupper():
            return special_cases[word_lower].capitalize()
        return special_cases[word_lower]
    
    # Standard pluralization rules
    if word_lower.endswith('ies') and len(word) > 3:
        return word[:-3] + 'y'
    elif word_lower.endswith('ses') and len(word) > 3:
        return word[:-2]
    elif word_lower.endswith('ches') or word_lower.endswith('shes') or word_lower.endswith('xes'):
        return word[:-2]
    elif word_lower.endswith('es') and len(word) > 3:
        # Check if it's a valid plural (e.g., boxes -> box, but not "bases" -> "base")
        return word[:-2]
    elif word_lower.endswith('s') and not word_lower.endswith('ss') and len(word) > 1:
        return word[:-1]
    
    return word

def extract_noun_from_operation(op_name: str, main_output_field: Optional[str] = None) -> str:
    """
    Extract noun/resource from operation name by stripping verbs.
    Improved to handle plural resources and extract meaningful resource names.
    """
    # Priority 1: Use main_output_field if meaningful (not generic)
    generic_tokens = ['items', 'item', 'resources', 'resource', 'data', 'result', 
                     'response', 'output', 'value', 'values', 'list', 'array']
    if main_output_field and main_output_field.lower() not in generic_tokens:
        noun = main_output_field.replace('[]', '').replace('_', ' ')
        noun = singularize(to_snake_case(noun))
        return noun
    
    op_lower = op_name.lower()
    
    # Remove common verb prefixes (in priority order)
    verbs = [
        'list', 'get', 'describe', 'create', 'update', 'delete', 'modify', 
        'set', 'patch', 'attach', 'detach', 'enable', 'disable', 'remove',
        'terminate', 'destroy', 'purge', 'disassociate', 'unbind', 'revoke',
        'untag', 'start', 'run', 'launch', 'provision', 'register', 'generate',
        'import', 'install', 'authorize', 'grant', 'search', 'query', 'find',
        'enumerate', 'read', 'fetch', 'add', 'check', 'configure', 'activate'
    ]
    
    for verb in verbs:
        if op_lower.startswith(verb + '_'):
            remaining = op_lower[len(verb) + 1:]
            # Handle plural resources (e.g., list_backup_policies -> backup_policy)
            # Take all remaining parts, singularize the last one
            parts = remaining.split('_')
            if parts:
                # If last part looks plural (ends with s, es, ies), singularize it
                if len(parts) > 1:
                    # Join all parts, singularize
                    resource = '_'.join(parts)
                    resource = singularize(resource)
                    return resource
                else:
                    return singularize(parts[0])
    
    # If no verb prefix, take first token and singularize
    parts = op_lower.split('_')
    if parts:
        return singularize(parts[0])
    
    return 'resource'

# ============================================================================
# KIND ASSIGNMENT (IBM-specific rules from prompt)
# ============================================================================

def assign_kind(operation: str, python_method: Optional[str] = None) -> str:
    """
    Auto-assign kind based on operation name.
    Prefer python_method if present; else use operation.
    Case-insensitive matching.
    """
    name = (python_method or operation).lower()
    
    # Priority order (first match wins):
    
    # 1. write_delete
    if any(name.startswith(prefix) for prefix in [
        'delete', 'remove', 'terminate', 'destroy', 'purge', 'detach', 
        'disassociate', 'unbind', 'revoke', 'disable', 'untag'
    ]):
        return 'write_delete'
    
    # 2. write_update
    if any(name.startswith(prefix) for prefix in [
        'update', 'modify', 'put', 'set', 'replace', 'patch', 'change', 
        'reset', 'attach', 'bind', 'associate', 'add', 'tag', 'enable'
    ]):
        return 'write_update'
    
    # 3. write_create
    if any(name.startswith(prefix) for prefix in [
        'create', 'start', 'run', 'launch', 'provision', 'register', 
        'generate', 'import', 'install', 'authorize', 'grant'
    ]):
        return 'write_create'
    
    # 4. read_list
    if any(name.startswith(prefix) for prefix in [
        'list', 'search', 'query', 'find', 'enumerate'
    ]):
        return 'read_list'
    
    # Also read_list if starts with 'get' and output is list-like
    # (We'll check this later when we have output info)
    
    # 5. read_get
    if any(name.startswith(prefix) for prefix in [
        'get', 'describe', 'read', 'fetch'
    ]):
        return 'read_get'
    
    # Default
    return 'other'

def has_side_effect(kind: str) -> bool:
    """Determine if operation has side effects."""
    return not kind.startswith('read_')

# ============================================================================
# GLOBAL IDENTITY EXCEPTIONS (IBM Cloud specific)
# ============================================================================

IBM_GLOBAL_ENTITIES = {
    'account_id': 'ibm.account_id',
    'accountid': 'ibm.account_id',
    'region': 'ibm.region',
    'region_id': 'ibm.region',
    'regionid': 'ibm.region',
    'crn': 'ibm.crn',
    'CRN': 'ibm.crn',
    'resource_group_id': 'ibm.resource_group_id',
    'resourcegroupid': 'ibm.resource_group_id',
    'instance_id': 'ibm.resource_instance_id',
    'instanceid': 'ibm.resource_instance_id',
    'resource_instance_id': 'ibm.resource_instance_id',
    'resourceinstanceid': 'ibm.resource_instance_id',
    'iam_id': 'ibm.iam_id',
    'iamid': 'ibm.iam_id',
    'iamId': 'ibm.iam_id',
    # Pagination tokens (NOT security identity)
    'start': 'ibm.pagination_token',
    'offset': 'ibm.pagination_token',
    'page': 'ibm.pagination_token',
    'pagetoken': 'ibm.pagination_token',
    'next': 'ibm.pagination_token',
    'limit': 'ibm.pagination_token',
}

def is_global_entity(param_name: str) -> Optional[str]:
    """Check if parameter matches global IBM entity."""
    param_lower = param_name.lower()
    return IBM_GLOBAL_ENTITIES.get(param_lower) or IBM_GLOBAL_ENTITIES.get(param_name)

# ============================================================================
# CANONICAL ENTITY NAMING (ibm.<service>.<resource>.<field>)
# ============================================================================

def build_consumes(service: str, required_params: List[str], operation: str, 
                   main_output_field: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Build consumes list from required_params.
    Maps to canonical entities: ibm.<service>.<resource>.<field>
    """
    consumes = []
    
    for param in required_params:
        # Skip kwargs and common internal params
        if param in ['kwargs', 'self', 'cls']:
            continue
        
        # Check global exceptions first
        global_entity = is_global_entity(param)
        if global_entity:
            consumes.append({
                'entity': global_entity,
                'param': param,
                'required': True,
                'source': 'external'
            })
            continue
        
        # Extract resource from operation name
        resource = extract_noun_from_operation(operation)
        
        # Extract resource from operation for better entity naming
        resource = extract_noun_from_operation(operation, main_output_field)
        
        # Handle generic tokens (id, name, status)
        param_lower = param.lower()
        if param_lower in ['id', 'name', 'status']:
            entity = f"ibm.{service}.{resource}.{resource}_{param_lower}"
        elif param_lower.endswith('id') or param_lower.endswith('Id'):
            # Extract base noun (e.g., instanceId -> instance)
            base = param_lower[:-2] if param_lower.endswith('id') else param_lower[:-2]
            # If base is too short or generic, use resource from operation
            if len(base) < 3 or base in ['id', 'name', 'status']:
                entity = f"ibm.{service}.{resource}.{resource}_id"
            else:
                entity = f"ibm.{service}.{base}.{base}_id"
        elif param_lower.endswith('name') or param_lower.endswith('Name'):
            base = param_lower[:-4] if param_lower.endswith('name') else param_lower[:-4]
            if len(base) < 3 or base in ['id', 'name', 'status']:
                entity = f"ibm.{service}.{resource}.{resource}_name"
            else:
                entity = f"ibm.{service}.{base}.{base}_name"
        else:
            # Use param as field name with resource context
            entity = f"ibm.{service}.{resource}.{to_snake_case(param)}"
        
        consumes.append({
            'entity': entity,
            'param': param,
            'required': True,
            'source': 'either'
        })
    
    return consumes

def build_produces(service: str, output_fields: Dict[str, Any], 
                   main_output_field: Optional[str], 
                   item_fields: Dict[str, Any],
                   operation: str) -> List[Dict[str, Any]]:
    """
    Build produces list from output_fields and item_fields.
    Maps to canonical entities: ibm.<service>.<resource>.<field>
    IMPROVED: Extracts specific resource names from operation names instead of using generic "item"
    Also handles create/update operations to produce the entities they create
    CRITICAL FIX: Handles get operations (main_output_field="item" singular) correctly
    """
    produces = []
    
    # Detect get operation (single object, not list)
    is_get_operation = main_output_field == 'item'  # Singular "item", not "items"
    
    # Extract resource from operation name (IMPROVED - no more generic "item")
    resource = extract_noun_from_operation(operation, main_output_field)
    
    # If we still got a generic resource, try harder to extract from operation
    if resource in ['resource', 'item', 'items']:
        # Try to extract from operation name more aggressively
        op_lower = operation.lower()
        # Look for patterns like list_X, get_X, create_X
        for verb in ['list_', 'get_', 'describe_', 'create_', 'update_', 'delete_']:
            if op_lower.startswith(verb):
                remaining = op_lower[len(verb):]
                parts = remaining.split('_')
                if parts:
                    # Take meaningful parts (skip common suffixes)
                    meaningful_parts = [p for p in parts if p not in ['by', 'for', 'with', 'from', 'to']]
                    if meaningful_parts:
                        resource = singularize('_'.join(meaningful_parts))
                        break
    
    # CRITICAL: For get operations, ensure we have a proper resource name
    if is_get_operation and resource in ['resource', 'item', 'items']:
        # Extract from get_X pattern
        op_lower = operation.lower()
        if op_lower.startswith('get_'):
            remaining = op_lower[4:]  # Remove "get_"
            parts = remaining.split('_')
            if parts:
                meaningful_parts = [p for p in parts if p not in ['by', 'for', 'with', 'from', 'to', 'the', 'a', 'an']]
                if meaningful_parts:
                    resource = singularize('_'.join(meaningful_parts))
                else:
                    resource = singularize(parts[0]) if parts else 'resource'
    
    # For create/update operations, if no output_fields but we have a resource, produce the entity
    op_lower = operation.lower()
    is_create_or_update = op_lower.startswith('create_') or op_lower.startswith('update_')
    
    if is_create_or_update and not output_fields and resource not in ['resource', 'item', 'items']:
        # Create operations should produce the entity they create
        # Produce common fields: id, name, crn, status
        produces.append({
            'entity': f"ibm.{service}.{resource}.{resource}_id",
            'source': 'output',
            'path': 'id'
        })
        produces.append({
            'entity': f"ibm.{service}.{resource}.{resource}_name",
            'source': 'output',
            'path': 'name'
        })
        produces.append({
            'entity': 'ibm.crn',
            'source': 'output',
            'path': 'crn'
        })
        return produces
    
    # Process output_fields (top-level)
    for field_name, field_data in output_fields.items():
        if isinstance(field_data, dict):
            # Skip "item" field for get operations - we'll process it via item_fields
            if is_get_operation and field_name.lower() == 'item':
                continue
            
            # Check if it's a global entity
            global_entity = is_global_entity(field_name)
            if global_entity:
                produces.append({
                    'entity': global_entity,
                    'source': 'output',
                    'path': field_name
                })
                continue
            
            # For generic tokens, use resource context
            field_lower = field_name.lower()
            if field_lower in ['id', 'name', 'status']:
                # CRITICAL: Use resource name, not "item"
                entity = f"ibm.{service}.{resource}.{resource}_{field_lower}"
            else:
                entity = f"ibm.{service}.{resource}.{to_snake_case(field_name)}"
            
            produces.append({
                'entity': entity,
                'source': 'output',
                'path': field_name
            })
    
    # Process item_fields (per-item fields)
    for field_name, field_data in item_fields.items():
        if isinstance(field_data, dict):
            # Check global entities
            global_entity = is_global_entity(field_name)
            if global_entity:
                # For get operations, path is "item.field" not "item[].field"
                if is_get_operation:
                    path = f"{main_output_field}.{field_name}" if main_output_field else f"item.{field_name}"
                else:
                    path = f"{main_output_field}[].{field_name}" if main_output_field else f"items[].{field_name}"
                produces.append({
                    'entity': global_entity,
                    'source': 'item',
                    'path': path
                })
                continue
            
            # For generic tokens, use resource context
            field_lower = field_name.lower()
            if field_lower in ['id', 'name', 'status', 'crn']:
                if field_lower == 'crn':
                    entity = 'ibm.crn'
                else:
                    # CRITICAL: Use resource name, not "item"
                    entity = f"ibm.{service}.{resource}.{resource}_{field_lower}"
            else:
                entity = f"ibm.{service}.{resource}.{to_snake_case(field_name)}"
            
            # For get operations, path is "item.field" not "item[].field"
            if is_get_operation:
                path = f"{main_output_field}.{field_name}" if main_output_field else f"item.{field_name}"
            else:
                path = f"{main_output_field}[].{field_name}" if main_output_field else f"items[].{field_name}"
            
            produces.append({
                'entity': entity,
                'source': 'item',
                'path': path
            })
    
    return produces

# ============================================================================
# PROCESS SERVICE SPEC
# ============================================================================

def process_service_spec(spec_file: Path, overrides: Dict[str, Any] = None) -> Dict[str, Any]:
    """Process service spec and generate operation registry."""
    
    with open(spec_file, 'r') as f:
        data = json.load(f)
    
    service_name = list(data.keys())[0]
    service_data = data[service_name]
    
    # Collect all operations
    all_operations = []
    if 'independent' in service_data:
        all_operations.extend(service_data['independent'])
    if 'dependent' in service_data:
        all_operations.extend(service_data['dependent'])
    if 'operations' in service_data:
        all_operations.extend(service_data['operations'])
    
    # Build operation registry
    operations = {}
    entity_producers = {}  # entity -> list of operations
    
    for op_spec in all_operations:
        op_name = op_spec['operation']
        python_method = op_spec.get('python_method', op_name)
        
        # Assign kind
        kind = assign_kind(op_name, python_method)
        side_effect = has_side_effect(kind)
        
        # Build consumes
        required_params = op_spec.get('required_params', [])
        main_output_field = op_spec.get('main_output_field')
        # Extract resource for better entity naming in consumes
        resource = extract_noun_from_operation(op_name, main_output_field)
        consumes = build_consumes(service_name, required_params, op_name, main_output_field)
        
        # Build produces
        output_fields = op_spec.get('output_fields', {})
        item_fields = op_spec.get('item_fields', {})
        produces = build_produces(service_name, output_fields, main_output_field, item_fields, op_name)
        
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
                "method": python_method
            },
            "consumes": consumes,
            "produces": produces,
            "notes": ""
        }
    
    operation_registry = {
        "service": service_name,
        "version": "1.0",
        "entity_aliases": {},
        "overrides": overrides or {"param_aliases": {}, "consumes": {}, "produces": {}},
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
    
    # Resolve entity aliases (multi-hop safe)
    def resolve_entity(entity: str) -> str:
        resolved = entity
        visited = set()
        while resolved in entity_aliases and resolved not in visited:
            visited.add(resolved)
            resolved = entity_aliases[resolved]
        return resolved
    
    op_consumes = {}
    op_produces = {}
    entity_producers = {}
    entity_consumers = {}
    edges = []
    
    for op_name, op_data in operations.items():
        # Collect consumed entities
        consumed_entities = [resolve_entity(c['entity']) for c in op_data.get('consumes', [])]
        op_consumes[op_name] = list(set(consumed_entities))
        
        # Collect produced entities
        produced_entities = [resolve_entity(p['entity']) for p in op_data.get('produces', [])]
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
    
    # Build edges (producer -> consumer)
    for consumer_op, consumed_entities in op_consumes.items():
        for entity in consumed_entities:
            if entity in entity_producers:
                for producer_op in entity_producers[entity]:
                    if producer_op != consumer_op:  # No self-loops
                        # Find the specific consume and produce entries
                        consume_entry = next((c for c in operations[consumer_op].get('consumes', []) 
                                            if resolve_entity(c['entity']) == entity), None)
                        produce_entry = next((p for p in operations[producer_op].get('produces', []) 
                                             if resolve_entity(p['entity']) == entity), None)
                        
                        edges.append({
                            'from_operation_id': producer_op,
                            'to_operation_id': consumer_op,
                            'entity': entity,
                            'from_key': produce_entry['path'] if produce_entry else '',
                            'to_param': consume_entry['param'] if consume_entry else '',
                            'confidence': 'high',
                            'reason': 'entity_match'
                        })
    
    # Find independent operations
    independent_ops = [op for op, data in operations.items() 
                      if not data.get('consumes') or all(c.get('source') == 'external' for c in data.get('consumes', []))]
    
    # Find root seeds (best starting list/get operations)
    root_seeds = [op for op, data in operations.items() 
                  if data.get('kind') in ['read_list', 'read_get'] and op in independent_ops]
    
    # External entities
    all_produced = set(entity_producers.keys())
    external_entities = [e for e in set(entity_consumers.keys()) if e not in all_produced]
    
    adjacency = {
        "service": service,
        "op_consumes": op_consumes,
        "op_produces": op_produces,
        "entity_producers": {k: list(set(v)) for k, v in entity_producers.items()},
        "entity_consumers": {k: list(set(v)) for k, v in entity_consumers.items()},
        "edges": edges,
        "independent_ops": independent_ops,
        "root_seeds": root_seeds,
        "external_entities": sorted(external_entities)
    }
    
    return adjacency

# ============================================================================
# VALIDATION
# ============================================================================

def validate_service(registry: Dict[str, Any], adjacency: Dict[str, Any]) -> Dict[str, Any]:
    """Generate validation report."""
    operations = registry.get('operations', {})
    op_consumes = adjacency.get('op_consumes', {})
    entity_producers = adjacency.get('entity_producers', {})
    external_entities = set(adjacency.get('external_entities', []))
    
    total_ops = len(operations)
    satisfiable_ops = 0
    unsatisfiable_ops = []
    unresolved_consumers = []
    generic_token_hits = []
    
    for op_name, op_data in operations.items():
        consumed = op_consumes.get(op_name, [])
        all_satisfiable = True
        
        for entity in consumed:
            if entity in external_entities:
                unresolved_consumers.append({
                    'operation': op_name,
                    'entity': entity,
                    'param': next((c['param'] for c in op_data.get('consumes', []) if c['entity'] == entity), '')
                })
                all_satisfiable = False
        
        if all_satisfiable and consumed:
            satisfiable_ops += 1
        elif not all_satisfiable:
            unsatisfiable_ops.append(op_name)
    
    # Check for generic tokens
    for op_name, op_data in operations.items():
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            if '.id' in entity or '.name' in entity or '.status' in entity:
                generic_token_hits.append({
                    'operation': op_name,
                    'entity': entity,
                    'param': consume['param']
                })
    
    satisfiable_percent = (satisfiable_ops / total_ops * 100) if total_ops > 0 else 0
    
    return {
        'validation_status': 'pass' if len(unsatisfiable_ops) == 0 else 'warnings',
        'summary': {
            'total_operations': total_ops,
            'total_edges': len(adjacency.get('edges', [])),
            'total_entities': len(set(list(entity_producers.keys()) + list(adjacency.get('entity_consumers', {}).keys())))
        },
        'satisfiable_ops_percent': round(satisfiable_percent, 2),
        'unsatisfiable_ops_count': len(unsatisfiable_ops),
        'unsatisfiable_ops': unsatisfiable_ops,
        'unresolved_consumers': unresolved_consumers,
        'generic_token_hits_count': len(generic_token_hits),
        'generic_token_hits': generic_token_hits[:10],  # Sample
        'ambiguous_evidence_keys': [],
        'overrides_applied_count': 0,
        'aliases_applied_count': len(registry.get('entity_aliases', {})),
        'cycles': []
    }

# ============================================================================
# MANUAL REVIEW
# ============================================================================

def generate_manual_review(registry: Dict[str, Any], validation_report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Generate manual_review.json for unresolved items."""
    unresolved = validation_report.get('unresolved_consumers', [])
    generic_hits = validation_report.get('generic_token_hits', [])
    
    if not unresolved and not generic_hits:
        return None
    
    return {
        'unresolved_required_params': unresolved,
        'generic_token_hits': generic_hits,
        'suggested_overrides': []  # Will be populated in two-pass
    }

# ============================================================================
# MAIN PROCESSING
# ============================================================================

def process_service_folder(service_folder: Path, ibm_root: Path) -> Dict[str, Any]:
    """Process a single service folder."""
    service_name = service_folder.name
    
    # Find service spec file
    spec_file = service_folder / "ibm_dependencies_with_python_names_fully_enriched.json"
    if not spec_file.exists():
        return {
            "service": service_name,
            "status": "skipped",
            "reason": "No service spec JSON found"
        }
    
    try:
        print(f"  Processing {service_name}...")
        
        # Step 1: Load service spec and generate operation_registry.json
        registry = process_service_spec(spec_file)
        
        # Step 2: Generate adjacency.json
        adjacency = build_adjacency(registry)
        
        # Step 3: Run validation
        validation_report = validate_service(registry, adjacency)
        
        # Step 4: Generate manual_review.json if needed
        manual_review = generate_manual_review(registry, validation_report)
        
        # Write files
        registry_file = service_folder / "operation_registry.json"
        if registry_file.exists():
            registry_file.rename(registry_file.with_suffix('.json.bak'))
        with open(registry_file, 'w') as f:
            formatted = compact_json_dumps(registry, indent=2)
            f.write(formatted)
        
        adjacency_file = service_folder / "adjacency.json"
        if adjacency_file.exists():
            adjacency_file.rename(adjacency_file.with_suffix('.json.bak'))
        with open(adjacency_file, 'w') as f:
            formatted = compact_json_dumps(adjacency, indent=2)
            f.write(formatted)
        
        validation_file = service_folder / "validation_report.json"
        if validation_file.exists():
            validation_file.rename(validation_file.with_suffix('.json.bak'))
        with open(validation_file, 'w') as f:
            json.dump(validation_report, f, indent=2)
        
        if manual_review:
            review_file = service_folder / "manual_review.json"
            if review_file.exists():
                review_file.rename(review_file.with_suffix('.json.bak'))
            with open(review_file, 'w') as f:
                json.dump(manual_review, f, indent=2)
        
        # Create empty overrides.json if it doesn't exist
        overrides_file = service_folder / "overrides.json"
        if not overrides_file.exists():
            with open(overrides_file, 'w') as f:
                json.dump({
                    "param_aliases": {},
                    "entity_aliases": {},
                    "consumes_overrides": {},
                    "produces_overrides": {}
                }, f, indent=2)
        
        return {
            "service": service_name,
            "status": validation_report['validation_status'],
            "operations": validation_report['summary']['total_operations'],
            "entities": validation_report['summary']['total_entities'],
            "generic_entities": validation_report['generic_token_hits_count'],
            "unsatisfiable_ops": validation_report['unsatisfiable_ops_count'],
            "has_manual_review": manual_review is not None
        }
    
    except Exception as e:
        return {
            "service": service_name,
            "status": "error",
            "error": str(e)
        }

def main():
    """Main execution - process all IBM services."""
    ibm_root = Path("/Users/apple/Desktop/threat-engine/pythonsdk-database/ibm")
    
    print("=" * 80)
    print("IBM Cloud Dependency Graph Builder")
    print("=" * 80)
    print()
    
    # Find all service folders
    service_folders = [d for d in ibm_root.iterdir() if d.is_dir() and (d / "ibm_dependencies_with_python_names_fully_enriched.json").exists()]
    
    print(f"Found {len(service_folders)} service folders")
    print()
    
    results = []
    for service_folder in sorted(service_folders):
        result = process_service_folder(service_folder, ibm_root)
        results.append(result)
        status_icon = "✅" if result.get('status') == 'pass' else "⚠️" if result.get('status') == 'warnings' else "❌"
        print(f"{status_icon} {result['service']}: {result.get('operations', 0)} ops, {result.get('entities', 0)} entities")
    
    # Summary
    print()
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Total Services: {len(results)}")
    print(f"Total Operations: {sum(r.get('operations', 0) for r in results)}")
    print(f"Total Entities: {sum(r.get('entities', 0) for r in results)}")
    print(f"Services with Warnings: {sum(1 for r in results if r.get('status') == 'warnings')}")
    print(f"Services with Errors: {sum(1 for r in results if r.get('status') == 'error')}")

if __name__ == '__main__':
    main()

