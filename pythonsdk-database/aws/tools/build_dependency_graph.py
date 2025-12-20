#!/usr/bin/env python3
"""
Build dependency graph artifacts for ALL AWS services.
Generates operation_registry.json, adjacency.json, validation_report.json per service,
and a global_summary.json at the end.
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

def extract_object_from_path(path: str) -> Tuple[str, str, bool]:
    """Extract object name and field from a path. Returns (object_name, field_name, is_list)."""
    if '[]' in path:
        parts = path.split('[]')
        obj = parts[0]
        field = parts[1].lstrip('.')
        return (obj, field, True)
    elif '.' in path:
        parts = path.split('.', 1)
        obj = parts[0]
        field = parts[1]
        return (obj, field, False)
    else:
        return ("", path, False)

def extract_meaningful_parent(path: str) -> Optional[str]:
    """
    Extract the nearest meaningful parent segment from a path.
    Skips generic containers like "resource", "item", "data", "details", "info".
    Returns the parent segment to use for entity naming.
    
    Examples:
    - "analyzer.arn" -> "analyzer"
    - "accessPreview.id" -> "accessPreview"
    - "CertificateSummaryList[].Status" -> "CertificateSummaryList" (but will be normalized)
    - "Certificate.Status" -> "Certificate"
    - "resource.analyzer.arn" -> "analyzer" (skip generic "resource")
    """
    generic_containers = {'resource', 'item', 'data', 'details', 'detail', 'info', 'information', 
                          'result', 'response', 'output', 'response_metadata'}
    
    # Split path into segments
    if '[]' in path:
        # Handle list paths: "CertificateSummaryList[].Status"
        list_part, rest = path.split('[]', 1)
        segments = [list_part]
        if rest:
            segments.extend(rest.lstrip('.').split('.'))
    else:
        segments = path.split('.')
    
    # Find the last meaningful segment before the leaf
    if len(segments) < 2:
        return None
    
    # Leaf is the last segment
    # Parent candidates are segments before the leaf
    for i in range(len(segments) - 2, -1, -1):
        segment = segments[i]
        segment_lower = segment.lower()
        
        # Skip generic containers
        if segment_lower not in generic_containers:
            return segment
    
    # If all parents are generic, return the immediate parent anyway
    return segments[-2] if len(segments) >= 2 else None

def strip_wrapper_from_path(path: str) -> str:
    """
    Strip wrapper prefixes from paths to normalize list vs describe patterns.
    Examples:
    - "CertificateSummaryList[].CertificateArn" -> "Certificate[].CertificateArn"
    - "Regions[].RegionName" -> "Region[].RegionName"
    - "CertificateSummary.CertificateArn" -> "Certificate.CertificateArn"
    
    Wrapper patterns to strip:
    - *SummaryList -> (singular)
    - *Summary -> (singular)
    - *List -> (singular)
    - *Details -> (singular)
    - *Info -> (singular)
    """
    # Common wrapper suffixes to remove
    wrapper_patterns = [
        'SummaryList', 'Summary', 'List', 'Details', 'Detail', 'Info', 'Information'
    ]
    
    # Split path into object and field parts
    if '[]' in path:
        obj_part, field_part = path.split('[]', 1)
        field_part = field_part.lstrip('.')
    elif '.' in path:
        parts = path.split('.', 1)
        obj_part = parts[0]
        field_part = parts[1] if len(parts) > 1 else ""
    else:
        return path  # No wrapper to strip
    
    # Strip wrapper from object part
    obj_clean = obj_part
    for pattern in wrapper_patterns:
        # Match at end of object name
        if obj_clean.endswith(pattern):
            obj_clean = obj_clean[:-len(pattern)]
            break
    
    # Reconstruct path
    if '[]' in path:
        return f"{obj_clean}[].{field_part}" if field_part else f"{obj_clean}[]"
    else:
        return f"{obj_clean}.{field_part}" if field_part else obj_clean

def normalize_entity_name_for_alias(entity: str, service: str) -> str:
    """
    Normalize entity name by stripping wrappers to create canonical form for aliasing.
    This helps unify entities that differ only by wrapper prefixes.
    Example: "certificate_summary_list_certificate_arn" -> "certificate_certificate_arn"
    """
    # Remove service prefix
    if entity.startswith(f"{service}."):
        base = entity[len(service) + 1:]
    else:
        base = entity
    
    # Split into parts
    parts = base.split('_')
    
    # Remove wrapper words
    wrapper_words = {'summary', 'list', 'detail', 'details', 'info', 'information', 'data'}
    filtered_parts = [p for p in parts if p not in wrapper_words]
    
    # Reconstruct
    normalized = '_'.join(filtered_parts) if filtered_parts else base
    return f"{service}.{normalized}" if entity.startswith(f"{service}.") else normalized

# ============================================================================
# KIND ASSIGNMENT
# ============================================================================

def assign_kind(operation: str) -> str:
    """
    Auto-assign kind based on operation name prefix.
    Single clean rule with priority order.
    """
    op = operation
    
    # Priority order (first match wins):
    # 1. List operations
    if op.startswith('List'):
        return 'read_list'
    
    # 2. Get/Describe operations
    if op.startswith('Get') or op.startswith('Describe'):
        return 'read_get'
    
    # 3. Create operations
    if any(op.startswith(prefix) for prefix in ['Create', 'Start', 'Generate', 'Import', 'Enable', 'Register']):
        return 'write_create'
    
    # 4. Update operations
    if any(op.startswith(prefix) for prefix in ['Update', 'Modify', 'Put', 'Set', 'Change', 'Reset', 'Patch']):
        return 'write_update'
    
    # 5. Delete operations
    if any(op.startswith(prefix) for prefix in ['Delete', 'Remove', 'Terminate', 'Destroy', 'Disable', 'Detach', 'Disassociate', 'Untag', 'Revoke']):
        return 'write_delete'
    
    # 6. Apply operations
    if any(op.startswith(prefix) for prefix in ['Apply', 'Attach', 'Associate', 'Add', 'Tag', 'Authorize', 'Unauthorize', 'Grant']):
        return 'write_apply'
    
    # Default
    return 'other'

def has_side_effect(kind: str) -> bool:
    """Determine if operation has side effects."""
    return not kind.startswith('read_')

# ============================================================================
# ENTITY NAMING (CRITICAL - NO GENERIC ENTITIES)
# ============================================================================

def normalize_produces_entity(service: str, path: str, operation_name: str) -> str:
    """
    Normalize entity for produces based on path context.
    Uses nearest meaningful parent segment for generic tokens (arn, id, name, status).
    Never creates generic entities like <service>.arn, <service>.id, etc.
    """
    field_lower = path.split('.')[-1].split('[]')[-1].lower()
    
    # For generic leaf tokens, find nearest meaningful parent
    if field_lower in ['arn', 'status', 'id', 'name']:
        parent = extract_meaningful_parent(path)
        
        if parent:
            # Convert parent to snake_case (handles camelCase like "accessPreview" -> "access_preview")
            parent_snake = to_snake_case(parent)
            # Singularize if needed
            parent_snake = singularize(parent_snake)
            
            # Remove wrapper suffixes if present (SummaryList, Summary, List, etc.)
            wrapper_suffixes = ['_summary_list', '_summary', '_list', '_details', '_detail', '_info', '_information']
            for suffix in wrapper_suffixes:
                if parent_snake.endswith(suffix):
                    parent_snake = parent_snake[:-len(suffix)]
                    break
            
            # Remove stopwords
            stopwords = {'details', 'detail', 'info', 'information', 'data'}
            parts = parent_snake.split('_')
            parts = [p for p in parts if p not in stopwords]
            parent_clean = '_'.join(parts) if parts else parent_snake
            
            return f"{service}.{parent_clean}_{field_lower}"
        
        # Fallback: use operation name context
        noun = extract_noun_from_operation(operation_name)
        return f"{service}.{noun}_{field_lower}"
    
    # For non-generic fields, use parent context if available
    parent = extract_meaningful_parent(path)
    field_name = path.split('.')[-1].split('[]')[-1]
    
    if parent:
        # Use parent.field pattern
        parent_snake = to_snake_case(parent)
        parent_snake = singularize(parent_snake)
        
        # Remove wrapper suffixes
        wrapper_suffixes = ['_summary_list', '_summary', '_list', '_details', '_detail', '_info', '_information']
        for suffix in wrapper_suffixes:
            if parent_snake.endswith(suffix):
                parent_snake = parent_snake[:-len(suffix)]
                break
        
        field_snake = to_snake_case(field_name)
        
        # Avoid duplication (e.g., "analyzer_analyzer_arn" -> "analyzer_arn")
        if parent_snake and field_snake.startswith(parent_snake + '_'):
            return f"{service}.{field_snake}"
        
        return f"{service}.{parent_snake}_{field_snake}"
    else:
        # No parent context, use field name directly
        return f"{service}.{to_snake_case(field_name)}"

def extract_noun_from_operation(operation_name: str, main_output_field: Optional[str] = None) -> str:
    """
    Extract noun from operation name by removing verb prefixes.
    Returns snake_case singularized noun.
    """
    # Priority 1: Use main_output_field if meaningful
    # Exclude generic tokens and non-meaningful fields
    generic_tokens = ['arn', 'id', 'name', 'status', 'result', 'response', 'details', 'output', 'token', 'nextToken']
    if main_output_field and main_output_field.lower() not in generic_tokens and main_output_field not in ['', 'result', 'response', 'details', 'output']:
        noun = main_output_field
        # Remove [] if present
        noun = noun.replace('[]', '')
        # Remove plural
        noun = singularize(to_snake_case(noun))
        return noun
    
    # Priority 2: Extract from operation name
    op = operation_name
    
    # Verbs to strip (first match wins)
    verbs = [
        'Put', 'Create', 'Update', 'Delete', 'Remove', 'Get', 'List', 'Describe',
        'Start', 'Stop', 'Accept', 'Enable', 'Disable', 'Associate', 'Disassociate',
        'Attach', 'Detach', 'Tag', 'Untag', 'Apply', 'Cancel', 'Renew', 'Request',
        'Resend', 'Modify', 'Set', 'Replace', 'Patch', 'Change', 'Reset'
    ]
    
    for verb in verbs:
        if op.startswith(verb):
            noun = op[len(verb):]
            if noun:
                return singularize(to_snake_case(noun))
    
    # Fallback: use full operation name
    return singularize(to_snake_case(op))

def normalize_consumes_entity(service: str, param: str, operation_name: str, main_output_field: Optional[str] = None) -> str:
    """
    Normalize entity for consumes based on param and operation context.
    CRITICAL: Never create generic <service>.name/id/arn/status entities.
    """
    param_lower = param.lower()
    
    # GENERIC PARAM CONTEXT RULE: If param is exactly a generic token, infer noun from operation
    if param_lower in ['name', 'id', 'arn', 'status']:
        # Extract noun from operation
        noun = extract_noun_from_operation(operation_name, main_output_field)
        return f"{service}.{noun}_{param_lower}"
    
    # Special-case mapping for compound params (e.g., analyzerArn, jobId)
    if param_lower == 'id' or param_lower.endswith('id'):
        if 'Finding' in operation_name:
            return f"{service}.finding_id"
        elif 'AccessPreview' in operation_name or 'accesspreview' in param_lower:
            return f"{service}.access_preview_id"
        elif 'PolicyGeneration' in operation_name or 'job' in param_lower:
            return f"{service}.job_id"
        elif param_lower != 'id':
            # Compound param like "jobId" -> extract base
            base = param_lower.replace('id', '')
            if base:
                return f"{service}.{to_snake_case(base)}_id"
        # Fallback: use operation noun
        noun = extract_noun_from_operation(operation_name, main_output_field)
        return f"{service}.{noun}_id"
    
    elif param_lower == 'status' or param_lower.endswith('status'):
        if 'Finding' in operation_name or operation_name == 'UpdateFindings':
            return f"{service}.finding_status"
        elif param_lower != 'status':
            base = param_lower.replace('status', '')
            if base:
                return f"{service}.{to_snake_case(base)}_status"
        # Fallback: use operation noun
        noun = extract_noun_from_operation(operation_name, main_output_field)
        return f"{service}.{noun}_status"
    
    elif param_lower == 'arn' or param_lower.endswith('arn'):
        # Never use generic "<service>.arn"
        if param_lower != 'arn':
            base = param_lower.replace('arn', '')
            if base:
                return f"{service}.{to_snake_case(base)}_arn"
        # Try operation context
        if 'analyzer' in param_lower or 'Analyzer' in operation_name:
            return f"{service}.analyzer_arn"
        elif 'resource' in param_lower or 'Resource' in operation_name:
            return f"{service}.resource_arn"
        else:
            # Fallback: use operation noun
            noun = extract_noun_from_operation(operation_name, main_output_field)
            return f"{service}.{noun}_arn"
    
    elif param_lower == 'name' or param_lower.endswith('name'):
        if param_lower != 'name':
            base = param_lower.replace('name', '')
            if base:
                return f"{service}.{to_snake_case(base)}_name"
        # Fallback: use operation noun (NEVER generic <service>.name)
        noun = extract_noun_from_operation(operation_name, main_output_field)
        return f"{service}.{noun}_name"
    
    # Default: snake_case of param
    return f"{service}.{to_snake_case(param)}"

# ============================================================================
# BUILD OPERATION REGISTRY
# ============================================================================

def build_consumes(service: str, required_params: List[str], operation_name: str, main_output_field: Optional[str] = None) -> List[Dict[str, Any]]:
    """Build consumes list from required_params."""
    consumes = []
    for param in required_params:
        entity = normalize_consumes_entity(service, param, operation_name, main_output_field)
        consumes.append({
            "entity": entity,
            "param": param,
            "required": True,
            "source": "either"  # Will be finalized later
        })
    return consumes

def build_produces(service: str, output_fields: Dict[str, Any], main_output_field: Optional[str], 
                  item_fields: Dict[str, Any], operation_name: str) -> List[Dict[str, Any]]:
    """Build produces list from output_fields and item_fields."""
    produces = []
    is_list_op = operation_name.startswith('List') or assign_kind(operation_name) == 'read_list'
    
    # Add output_fields
    for field_name in output_fields.keys():
        entity = normalize_produces_entity(service, field_name, operation_name)
        produces.append({
            "entity": entity,
            "source": "output",
            "path": field_name
        })
    
    # Add item_fields if main_output_field exists
    if main_output_field and item_fields:
        for field_name in item_fields.keys():
            # Rule D: Fix Get* output object paths - remove [] for read_get operations
            if is_list_op:
                path = f"{main_output_field}[].{field_name}"
            else:
                # Get* operations - use dot notation without []
                path = f"{main_output_field}.{field_name}"
            
            entity = normalize_produces_entity(service, path, operation_name)
            produces.append({
                "entity": entity,
                "source": "item",
                "path": path
            })
    
    return produces

def generate_safe_aliases(operations: Dict[str, Any], service: str) -> Dict[str, str]:
    """
    Generate safe alias candidates using heuristics.
    Returns alias_map: {alias_entity: canonical_entity}
    
    Heuristics:
    1. Same field name appears as input and output (redundant prefix removal)
    2. Stray generic entity exists alongside dominant specific entity
    3. DO NOT auto-alias statuses across different parent objects
    """
    alias_map = {}
    entity_usage = defaultdict(lambda: {'consumes': [], 'produces': [], 'params': set(), 'paths': set()})
    
    # Collect usage patterns
    for op_name, op_data in operations.items():
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            param = consume['param']
            entity_usage[entity]['consumes'].append(op_name)
            entity_usage[entity]['params'].add(param)
        
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            path = produce['path']
            entity_usage[entity]['produces'].append(op_name)
            entity_usage[entity]['paths'].add(path)
    
    # Heuristic 1: Same field name appears as input and output
    # If an operation has consumes param X and produces path with same field name X,
    # and entities differ only by redundant prefix, alias output -> input
    for op_name, op_data in operations.items():
        consumes_by_param = {c['param']: c['entity'] for c in op_data.get('consumes', [])}
        produces_by_path = {p['path']: p['entity'] for p in op_data.get('produces', [])}
        
        for param, consume_entity in consumes_by_param.items():
            param_lower = param.lower()
            
            # Find matching produce paths
            for path, produce_entity in produces_by_path.items():
                field = path.split('.')[-1].split('[]')[-1]
                field_lower = field.lower()
                
                # Check if param and field match (case-insensitive)
                if param_lower == field_lower or param_lower.endswith(field_lower) or field_lower.endswith(param_lower):
                    # Check if entities differ only by redundant prefix
                    # e.g., "account.alternate_contact_alternate_contact_type" vs "account.alternate_contact_type"
                    consume_base = consume_entity.replace(f'{service}.', '')
                    produce_base = produce_entity.replace(f'{service}.', '')
                    
                    # If produce has redundant prefix, alias it to consume
                    if produce_base.startswith(consume_base + '_') or consume_base in produce_base:
                        # Prefer the shorter one as canonical
                        if len(consume_entity) <= len(produce_entity):
                            alias_map[produce_entity] = consume_entity
                        else:
                            alias_map[consume_entity] = produce_entity
    
    # Heuristic 2: Stray generic entity exists alongside dominant specific entity
    # If one entity is "<service>.arn" but another is "<service>.<object>_arn" and both
    # originate from same conceptual object, alias generic -> specific
    all_entities = set(entity_usage.keys())
    generic_tokens = ['arn', 'id', 'name']
    
    for token in generic_tokens:
        generic_entity = f"{service}.{token}"
        if generic_entity not in all_entities:
            continue
        
        # Find specific entities with same token
        specific_entities = [e for e in all_entities 
                             if e.endswith(f'_{token}') and e != generic_entity]
        
        if not specific_entities:
            continue
        
        # Check if generic and specific entities share the same conceptual object
        # by checking if they appear in similar operations or share params
        generic_usage = entity_usage[generic_entity]
        
        for specific_entity in specific_entities:
            specific_usage = entity_usage[specific_entity]
            
            # Check if they share operations or params (same conceptual object)
            shared_ops = set(generic_usage['consumes'] + generic_usage['produces']) & \
                        set(specific_usage['consumes'] + specific_usage['produces'])
            shared_params = generic_usage['params'] & specific_usage['params']
            
            if shared_ops or shared_params:
                # Alias generic -> specific (specific is more canonical)
                alias_map[generic_entity] = specific_entity
                break
    
    # Heuristic 3: DO NOT auto-alias statuses across different parent objects
    # This is enforced by not creating aliases for status entities with different parents
    
    return alias_map

def build_entity_aliases(operations: Dict[str, Any], service: str, entity_producers: Dict[str, List[str]]) -> Dict[str, str]:
    """
    Build entity_aliases mapping: alias_entity -> canonical_entity
    
    Combines:
    1. Safe alias heuristics (same field input/output, stray generic entities)
    2. Wrapper-based aliasing (list vs describe patterns)
    3. Param-based aliasing (same param name -> same entity)
    """
    # Start with safe aliases from heuristics
    alias_map = generate_safe_aliases(operations, service)
    
    # Collect entity usage patterns
    entity_usage = defaultdict(lambda: {'consumes': [], 'produces': [], 'params': set(), 'paths': set()})
    
    for op_name, op_data in operations.items():
        # Track consumes
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            param = consume['param']
            entity_usage[entity]['consumes'].append(op_name)
            entity_usage[entity]['params'].add(param)
        
        # Track produces
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            path = produce['path']
            entity_usage[entity]['produces'].append(op_name)
            entity_usage[entity]['paths'].add(path)
    
    # Build param-based entity groups
    # Group entities by the param names they're associated with
    param_to_entities = defaultdict(set)
    
    for entity, usage in entity_usage.items():
        for param in usage['params']:
            param_lower = param.lower()
            # Only consider arn/id/name params
            if 'arn' in param_lower or 'id' in param_lower or 'name' in param_lower:
                param_to_entities[param_lower].add(entity)
    
    alias_map = {}  # alias -> canonical
    processed = set()
    
    # For each param, find the canonical entity
    for param, entities in param_to_entities.items():
        if len(entities) < 2:
            continue  # Need at least 2 entities to alias
        
        # Extract expected canonical from param name
        # e.g., "analyzerArn" -> "analyzer_arn", "jobId" -> "job_id"
        param_base = param.replace('arn', '').replace('id', '').replace('name', '')
        if not param_base:
            continue
        
        expected_canonical = f"{service}.{to_snake_case(param_base)}"
        if 'arn' in param:
            expected_canonical += "_arn"
        elif 'id' in param:
            expected_canonical += "_id"
        elif 'name' in param:
            expected_canonical += "_name"
        
        # Find best canonical from entities
        candidates = list(entities)
        best_canonical = None
        best_score = -1
        
        for candidate in candidates:
            if candidate in processed:
                continue
            
            usage = entity_usage[candidate]
            # Score: prefers consumes, frequency, and matches expected canonical
            score = len(usage['consumes']) * 10 + len(usage['consumes']) + len(usage['produces'])
            
            # Bonus if matches expected canonical
            if candidate == expected_canonical:
                score += 100
            # Penalty for length
            score -= len(candidate) / 10
            
            if score > best_score:
                best_score = score
                best_canonical = candidate
        
        if best_canonical:
            # Alias other entities to canonical
            for entity in candidates:
                if entity != best_canonical and entity not in processed:
                    # Safety: only alias if they share the same base concept
                    canonical_base = best_canonical.replace(f'{service}.', '').replace('_arn', '').replace('_id', '').replace('_name', '')
                    entity_base = entity.replace(f'{service}.', '').replace('_arn', '').replace('_id', '').replace('_name', '')
                    
                    # Check if canonical_base appears in entity_base (e.g., "analyzer" in "access_preview_analyzer")
                    if canonical_base in entity_base or entity_base in canonical_base:
                        alias_map[entity] = best_canonical
                        processed.add(entity)
            
            processed.add(best_canonical)
    
    # Also handle cases where entities share a common substring pattern
    # e.g., "job_id", "job_detail_job_id", "policy_generation_job_id"
    all_entities = set(entity_usage.keys())
    
    for entity in all_entities:
        if entity in processed or not (entity.endswith('_arn') or entity.endswith('_id') or entity.endswith('_name')):
            continue
        
        # Extract base (e.g., "job" from "job_id", "analyzer" from "analyzer_arn")
        suffix = '_arn' if entity.endswith('_arn') else '_id' if entity.endswith('_id') else '_name'
        base = entity.replace(f'{service}.', '').replace(suffix, '')
        
        # Find shorter entities that might be canonical
        # e.g., if entity is "job_detail_job_id", look for "job_id"
        if '_' in base:
            parts = base.split('_')
            # Try shorter variants
            for i in range(1, len(parts)):
                shorter_base = '_'.join(parts[-i:])
                shorter_entity = f"{service}.{shorter_base}{suffix}"
                
                if shorter_entity in all_entities and shorter_entity not in processed:
                    # Check if shorter is used in consumes (preferred canonical)
                    shorter_usage = entity_usage[shorter_entity]
                    entity_usage_count = entity_usage[entity]
                    
                    if len(shorter_usage['consumes']) > 0 or len(shorter_usage['consumes']) + len(shorter_usage['produces']) > len(entity_usage_count['consumes']) + len(entity_usage_count['produces']):
                        alias_map[entity] = shorter_entity
                        processed.add(entity)
                        break
    
    # WRAPPER-BASED ALIAS DETECTION: Unify entities that differ only by wrappers
    # e.g., "certificate_summary_list_certificate_arn" vs "certificate_certificate_arn"
    all_entities_list = list(all_entities)
    for i, entity1 in enumerate(all_entities_list):
        if entity1 in processed:
            continue
        
        # Normalize entity1 to remove wrappers
        normalized1 = normalize_entity_name_for_alias(entity1, service)
        
        # Compare with other entities
        for entity2 in all_entities_list[i+1:]:
            if entity2 in processed or entity1 == entity2:
                continue
            
            # Normalize entity2
            normalized2 = normalize_entity_name_for_alias(entity2, service)
            
            # If normalized forms match, they differ only by wrappers
            if normalized1 == normalized2:
                # Choose canonical: prefer shorter, or one with consumes, or alphabetical
                usage1 = entity_usage[entity1]
                usage2 = entity_usage[entity2]
                
                # Prefer entity with consumes (inputs are more canonical)
                if len(usage1['consumes']) > len(usage2['consumes']):
                    canonical = entity1
                    alias = entity2
                elif len(usage2['consumes']) > len(usage1['consumes']):
                    canonical = entity2
                    alias = entity1
                # Prefer shorter name
                elif len(entity1) < len(entity2):
                    canonical = entity1
                    alias = entity2
                elif len(entity2) < len(entity1):
                    canonical = entity2
                    alias = entity1
                # Alphabetical tie-breaker
                else:
                    canonical = min(entity1, entity2)
                    alias = max(entity1, entity2)
                
                # Only alias if canonical is not already an alias
                if canonical not in alias_map.values() and alias not in processed:
                    alias_map[alias] = canonical
                    processed.add(alias)
    
    return alias_map

def resolve_entity_alias(entity: str, entity_aliases: Dict[str, str]) -> str:
    """
    Resolve entity through alias chain (multi-hop safe).
    Example: if A -> B and B -> C, then A resolves to C.
    """
    visited = set()
    current = entity
    
    while current in entity_aliases and current not in visited:
        visited.add(current)
        current = entity_aliases[current]
    
    return current

def apply_overrides_to_operations(operations: Dict[str, Any], overrides: Dict[str, Any]):
    """
    Apply overrides to operations.
    Overrides format: {
        "<operation_name>": {
            "consumes": {"<param_name>": "<service>.<entity>"},
            "produces": {"<path>": "<service>.<entity>"}
        }
    }
    """
    for op_name, op_data in operations.items():
        if op_name not in overrides:
            continue
        
        op_overrides = overrides[op_name]
        
        # Apply consumes overrides
        if 'consumes' in op_overrides:
            for consume in op_data.get('consumes', []):
                param = consume['param']
                if param in op_overrides['consumes']:
                    consume['entity'] = op_overrides['consumes'][param]
        
        # Apply produces overrides
        if 'produces' in op_overrides:
            for produce in op_data.get('produces', []):
                path = produce['path']
                if path in op_overrides['produces']:
                    produce['entity'] = op_overrides['produces'][path]

def apply_aliases_to_operations(operations: Dict[str, Any], entity_aliases: Dict[str, str]):
    """Apply aliases to operations - resolve aliases to canonicals (multi-hop safe)."""
    for op_name, op_data in operations.items():
        # Resolve consumes
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            resolved = resolve_entity_alias(entity, entity_aliases)
            if resolved != entity:
                consume['entity'] = resolved
        
        # Resolve produces
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            resolved = resolve_entity_alias(entity, entity_aliases)
            if resolved != entity:
                produce['entity'] = resolved

def process_service_spec(spec_file: Path) -> Dict[str, Any]:
    """Process service spec and generate operation registry."""
    
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
        main_output_field = op_spec.get('main_output_field')
        consumes = build_consumes(service_name, required_params, op_name, main_output_field)
        
        # Build produces
        output_fields = op_spec.get('output_fields', {})
        main_output_field = op_spec.get('main_output_field')
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
                "method": op_spec['python_method']
            },
            "consumes": consumes,
            "produces": produces,
            "notes": ""
        }
    
    # Initialize overrides (empty by default, can be populated from external config or manual review)
    overrides = {}
    
    # Apply overrides FIRST (most specific, before aliases)
    apply_overrides_to_operations(operations, overrides)
    
    # Rebuild entity_producers after overrides
    entity_producers = {}
    for op_name, op_data in operations.items():
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            if entity not in entity_producers:
                entity_producers[entity] = []
            entity_producers[entity].append(op_name)
    
    # Finalize consumes.source (before aliases)
    for op_name, op_data in operations.items():
        for consume in op_data['consumes']:
            entity = consume['entity']
            if entity in entity_producers:
                consume['source'] = 'internal'
            else:
                consume['source'] = 'external'
    
    # Build entity aliases (includes safe heuristics + wrapper-based + param-based)
    entity_aliases = build_entity_aliases(operations, service_name, entity_producers)
    
    # Apply aliases to operations (resolve aliases to canonicals, multi-hop safe)
    apply_aliases_to_operations(operations, entity_aliases)
    
    # Rebuild entity_producers after alias resolution
    entity_producers = {}
    for op_name, op_data in operations.items():
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            if entity not in entity_producers:
                entity_producers[entity] = []
            entity_producers[entity].append(op_name)
    
    # Re-finalize consumes.source after alias resolution
    for op_name, op_data in operations.items():
        for consume in op_data['consumes']:
            entity = consume['entity']
            if entity in entity_producers:
                consume['source'] = 'internal'
            else:
                consume['source'] = 'external'
    
    # Build kind_rules (matching simplified assign_kind function)
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
        "entity_aliases": entity_aliases,  # Now populated
        "overrides": overrides,
        "operations": operations
    }
    
    return operation_registry

# ============================================================================
# BUILD ADJACENCY
# ============================================================================

def build_adjacency(registry: Dict[str, Any]) -> Dict[str, Any]:
    """Build adjacency.json from operation registry. Resolves aliases (multi-hop safe)."""
    service = registry['service']
    operations = registry.get('operations', {})
    entity_aliases = registry.get('entity_aliases', {})
    
    # Resolve function - maps entity to canonical (if aliased, multi-hop safe)
    def resolve_entity(entity: str) -> str:
        return resolve_entity_alias(entity, entity_aliases)
    
    op_consumes = {}
    op_produces = {}
    entity_producers = {}
    entity_consumers = {}
    
    for op_name, op_data in operations.items():
        # Collect consumed entities (already resolved by apply_aliases_to_operations)
        consumed_entities = [resolve_entity(c['entity']) for c in op_data.get('consumes', [])]
        op_consumes[op_name] = list(set(consumed_entities))
        
        # Collect produced entities (already resolved)
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
    generic_entities = {'arn': 0, 'status': 0, 'id': 0, 'name': 0}
    ambiguous_tokens = defaultdict(list)
    
    for op_name, op_data in operations.items():
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            all_entities.add(entity)
            param = consume['param']
            
            # Check for generic entities
            if entity.endswith('.arn') and entity.count('_') == 0:
                generic_entities['arn'] += 1
            elif entity.endswith('.status') and entity.count('_') == 0:
                generic_entities['status'] += 1
            elif entity.endswith('.id') and entity.count('_') == 0:
                generic_entities['id'] += 1
            elif entity.endswith('.name') and entity.count('_') == 0:
                generic_entities['name'] += 1
            
            # Track ambiguous tokens
            if param.lower() in ['id', 'status', 'arn', 'name']:
                token = param.lower()
                ambiguous_tokens[token].append(f"{op_name}.{param} -> {entity}")
        
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            all_entities.add(entity)
            path = produce['path']
            
            # Check for generic entities
            if entity.endswith('.arn') and entity.count('_') == 0:
                generic_entities['arn'] += 1
            elif entity.endswith('.status') and entity.count('_') == 0:
                generic_entities['status'] += 1
            elif entity.endswith('.id') and entity.count('_') == 0:
                generic_entities['id'] += 1
            elif entity.endswith('.name') and entity.count('_') == 0:
                generic_entities['name'] += 1
            
            # Track ambiguous tokens
            field = path.split('.')[-1].split('[]')[-1]
            if field.lower() in ['id', 'status', 'arn', 'name']:
                token = field.lower()
                ambiguous_tokens[token].append(f"{op_name}.{path} -> {entity}")
    
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
    
    # Determine status (UPDATED: More lenient - WARN if only ambiguous tokens)
    has_generic = sum(generic_entities.values()) > 0
    has_cycles = len(self_cycles) > 0
    has_ambiguous = len(ambiguous_tokens) > 0
    
    # Check for unresolved consumes (entities consumed but never produced, not in external_entities)
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
                    "param": consume['param']
                })
    
    # FAIL only if generic entities or cycles exist
    # WARN if ambiguous tokens but no generic/cycles
    # PASS otherwise
    if has_generic or has_cycles:
        status = "FAIL"
    elif has_ambiguous or len(unresolved_consumes) > 0:
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
        "generic_entities_found": generic_entities,
        "ambiguous_tokens_found": dict(ambiguous_tokens),
        "cycles_detected": len(self_cycles) > 0,
        "self_cycles": self_cycles,
        "unresolved_consumes": unresolved_consumes,
        "external_entities_count": len(adjacency.get('external_entities', [])),
        "overrides_applied_count": sum(len(op_overrides.get('consumes', {})) + len(op_overrides.get('produces', {})) 
                                      for op_overrides in registry.get('overrides', {}).values() 
                                      if isinstance(op_overrides, dict)),
        "aliases_applied_count": len(registry.get('entity_aliases', {})),
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
    
    service = registry['service']
    operations = registry.get('operations', {})
    entity_aliases = registry.get('entity_aliases', {})
    
    issues = {
        "generic_entities": [],
        "ambiguous_tokens": [],
        "unresolved_consumes": [],
        "suspicious_paths": []
    }
    
    # Collect generic entities (counts)
    generic = validation_report.get('generic_entities_found', {})
    issues["generic_entities"] = {token: count for token, count in generic.items() if count > 0}
    
    # Collect unresolved consumes
    unresolved = validation_report.get('unresolved_consumes', [])
    for item in unresolved:
        issues["unresolved_consumes"].append({
            "operation": item.get("operation", ""),
            "entity": item.get("entity", ""),
            "param": item.get("param", ""),
            "description": f"Operation {item.get('operation', '')} consumes {item.get('entity', '')} (param: {item.get('param', '')}) but it's never produced and not marked as external"
        })
    
    # Collect ambiguous tokens: leaf token -> list of mappings
    ambiguous = validation_report.get('ambiguous_tokens_found', {})
    ambiguous_tokens_dict = {}
    for token, resolutions in ambiguous.items():
        # Group by entity to see if token maps to multiple entities
        entity_map = defaultdict(list)
        for resolution in resolutions:
            if ' -> ' in resolution:
                entity = resolution.split(' -> ')[1]
                entity_map[entity].append(resolution)
        
        # Only report if token maps to multiple different entities
        if len(entity_map) > 1:
            ambiguous_tokens_dict[token] = [
                {
                    "mapping": resolution,
                    "evidence": resolution.split(' -> ')[0] if ' -> ' in resolution else resolution,
                    "entity": resolution.split(' -> ')[1] if ' -> ' in resolution else ""
                }
                for resolution in resolutions[:20]  # Limit to 20 per token
            ]
    
    issues["ambiguous_tokens"] = ambiguous_tokens_dict
    
    # Check for suspicious paths (Get* with [], inconsistent casing, output path == param name mismatches)
    for op_name, op_data in operations.items():
        if op_data['kind'] == 'read_get':
            for produce in op_data.get('produces', []):
                if '[]' in produce['path']:
                    issues["suspicious_paths"].append({
                        "operation": op_name,
                        "path": produce['path'],
                        "issue": "Get* operation should not use [] in paths"
                    })
        
        # Check for output path == param name mismatches
        for consume in op_data.get('consumes', []):
            param = consume['param']
            param_lower = param.lower()
            
            for produce in op_data.get('produces', []):
                path = produce['path']
                field = path.split('.')[-1].split('[]')[-1]
                field_lower = field.lower()
                
                # If param and field are similar but entity names differ significantly, flag it
                if (param_lower == field_lower or 
                    param_lower.replace('id', '') == field_lower.replace('id', '') or
                    param_lower.replace('arn', '') == field_lower.replace('arn', '')):
                    if consume['entity'] != produce['entity']:
                        issues["suspicious_paths"].append({
                            "operation": op_name,
                            "path": path,
                            "param": param,
                            "consume_entity": consume['entity'],
                            "produce_entity": produce['entity'],
                            "issue": f"Param '{param}' and output field '{field}' are similar but map to different entities"
                        })
    
    # Generate alias candidates that were NOT auto-applied
    alias_candidates = []
    
    # Collect all entities and their usage
    entity_usage = defaultdict(lambda: {'consumes': [], 'produces': [], 'params': set()})
    
    for op_name, op_data in operations.items():
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            param = consume['param']
            entity_usage[entity]['consumes'].append(op_name)
            entity_usage[entity]['params'].add(param)
        
        for produce in op_data.get('produces', []):
            entity = produce['entity']
            entity_usage[entity]['produces'].append(op_name)
    
    # Find potential aliases that weren't applied
    all_entities = set(entity_usage.keys())
    aliased_entities = set(entity_aliases.keys()) | set(entity_aliases.values())  # Both aliases and canonicals
    
    # Track which entities we've already suggested aliases for
    suggested_pairs = set()
    
    for entity in all_entities:
        if entity in aliased_entities:  # Already aliased or is canonical
            continue
        
        if not (entity.endswith('_arn') or entity.endswith('_id') or entity.endswith('_name')):
            continue
        
        # Normalize entity to check for wrapper-based matches
        normalized_entity = normalize_entity_name_for_alias(entity, service)
        
        # Look for similar entities (both exact matches and wrapper-normalized matches)
        suffix = '_arn' if entity.endswith('_arn') else '_id' if entity.endswith('_id') else '_name'
        base = entity.replace(f'{service}.', '').replace(suffix, '')
        
        for other_entity in all_entities:
            if other_entity == entity or other_entity in aliased_entities:
                continue
            
            if not other_entity.endswith(suffix):
                continue
            
            # Check if normalized forms match (wrapper-based alias candidate)
            normalized_other = normalize_entity_name_for_alias(other_entity, service)
            is_wrapper_match = normalized_entity == normalized_other
            
            # Check if base is similar (substring match)
            other_base = other_entity.replace(f'{service}.', '').replace(suffix, '')
            is_base_match = base in other_base or other_base in base
            
            if is_wrapper_match or is_base_match:
                # Check if they share params or paths
                entity_params = entity_usage[entity]['params']
                other_params = entity_usage[other_entity]['params']
                shared_params = entity_params & other_params
                
                # Only suggest if there's evidence they're related
                if shared_params or is_wrapper_match:
                    # Create pair key to avoid duplicates
                    pair_key = tuple(sorted([entity, other_entity]))
                    if pair_key in suggested_pairs:
                        continue
                    suggested_pairs.add(pair_key)
                    
                    # Suggest alias
                    # Prefer shorter or one with consumes
                    if len(entity) < len(other_entity) or len(entity_usage[entity]['consumes']) > len(entity_usage[other_entity]['consumes']):
                        canonical = entity
                        alias = other_entity
                    else:
                        canonical = other_entity
                        alias = entity
                    
                    confidence = "HIGH" if is_wrapper_match else "MEDIUM" if shared_params else "LOW"
                    reason = "Wrapper-normalized forms match" if is_wrapper_match else \
                            f"Both entities share param names and have similar base" if shared_params else \
                            f"Entities have similar base '{base}'"
                    
                    alias_candidates.append({
                        "alias_entity": alias,
                        "canonical_entity": canonical,
                        "confidence": confidence,
                        "reason": reason,
                        "evidence": {
                            "shared_params": list(shared_params),
                            "normalized_match": is_wrapper_match,
                            "alias_usage": {"consumes": len(entity_usage[alias]['consumes']), "produces": len(entity_usage[alias]['produces'])},
                            "canonical_usage": {"consumes": len(entity_usage[canonical]['consumes']), "produces": len(entity_usage[canonical]['produces'])}
                        }
                    })
                    break
    
    # Generate suggested overrides for remaining issues
    suggested_overrides = []
    
    # Look for cases where generic entities still exist
    for op_name, op_data in operations.items():
        for consume in op_data.get('consumes', []):
            entity = consume['entity']
            param = consume['param']
            
            # Generic entity detection
            if entity.endswith('.arn') and entity.count('_') == 0:
                # Suggest context-specific entity based on param or operation
                noun = extract_noun_from_operation(op_name)
                suggested_overrides.append({
                    "operation": op_name,
                    "type": "consumes",
                    "key": param,
                    "suggested_entity": f"{service}.{noun}_arn",
                    "confidence": "HIGH",
                    "reason": f"Generic arn entity should be context-specific based on operation '{op_name}'"
                })
            elif entity.endswith('.id') and entity.count('_') == 0:
                noun = extract_noun_from_operation(op_name)
                suggested_overrides.append({
                    "operation": op_name,
                    "type": "consumes",
                    "key": param,
                    "suggested_entity": f"{service}.{noun}_id",
                    "confidence": "HIGH",
                    "reason": f"Generic id entity should be context-specific based on operation '{op_name}'"
                })
            elif entity.endswith('.name') and entity.count('_') == 0:
                noun = extract_noun_from_operation(op_name)
                suggested_overrides.append({
                    "operation": op_name,
                    "type": "consumes",
                    "key": param,
                    "suggested_entity": f"{service}.{noun}_name",
                    "confidence": "HIGH",
                    "reason": f"Generic name entity should be context-specific based on operation '{op_name}'"
                })
            elif entity.endswith('.status') and entity.count('_') == 0:
                noun = extract_noun_from_operation(op_name)
                suggested_overrides.append({
                    "operation": op_name,
                    "type": "consumes",
                    "key": param,
                    "suggested_entity": f"{service}.{noun}_status",
                    "confidence": "HIGH",
                    "reason": f"Generic status entity should be context-specific based on operation '{op_name}'"
                })
        
        # Suggest overrides for suspicious paths (param and output field match but entities differ)
        for consume in op_data.get('consumes', []):
            param = consume['param']
            param_lower = param.lower()
            consume_entity = consume['entity']
            
            for produce in op_data.get('produces', []):
                path = produce['path']
                field = path.split('.')[-1].split('[]')[-1]
                field_lower = field.lower()
                produce_entity = produce['entity']
                
                # If param and field match but entities differ, suggest override
                if (param_lower == field_lower or 
                    (param_lower.endswith('id') and field_lower.endswith('id')) or
                    (param_lower.endswith('arn') and field_lower.endswith('arn'))) and \
                   consume_entity != produce_entity:
                    # Prefer the consume entity (input is usually more canonical)
                    suggested_overrides.append({
                        "operation": op_name,
                        "type": "produces",
                        "key": path,
                        "suggested_entity": consume_entity,
                        "confidence": "MEDIUM",
                        "reason": f"Param '{param}' and output field '{field}' match but map to different entities. Suggest unifying to consume entity."
                    })
    
    review = {
        "service": service,
        "issues": issues,
        "alias_candidates_not_applied": alias_candidates[:20],
        "suggested_overrides": suggested_overrides[:20]
    }
    
    return review

# ============================================================================
# MAIN PROCESSING
# ============================================================================

def process_service_folder(service_folder: Path, aws_root: Path) -> Dict[str, Any]:
    """Process a single service folder."""
    service_name = service_folder.name
    
    # Find service spec JSON
    spec_file = None
    for pattern in ['boto3_dependencies_with_python_names_fully_enriched.json', 
                    f'{service_name}_spec.json', 
                    'service_spec.json']:
        candidate = service_folder / pattern
        if candidate.exists():
            spec_file = candidate
            break
    
    if not spec_file:
        return {
            "service": service_name,
            "status": "SKIP",
            "reason": "No service spec JSON found"
        }
    
    try:
        # Step A: Load service spec
        print(f"  Processing {service_name}...")
        
        # Step B: Generate operation_registry.json
        registry = process_service_spec(spec_file)
        
        # Step C: Normalization is already done in entity naming functions
        
        # Step D: Generate adjacency.json
        adjacency = build_adjacency(registry)
        
        # Step E: Run validation
        validation_report = validate_service(registry, adjacency)
        
        # Step F: Generate manual_review.json if needed
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
            "generic_entities": sum(validation_report['generic_entities_found'].values()),
            "ambiguous_tokens": len(validation_report['ambiguous_tokens_found']),
            "cycles": validation_report['cycles_detected'],
            "has_manual_review": manual_review is not None
        }
    
    except Exception as e:
        return {
            "service": service_name,
            "status": "ERROR",
            "error": str(e)
        }

def main():
    """Main entry point."""
    script_dir = Path(__file__).parent
    aws_root = script_dir.parent
    
    print(f"AWS Root: {aws_root}")
    print("Scanning service folders...")
    
    # Find all service folders
    service_folders = []
    for item in aws_root.iterdir():
        if item.is_dir() and not item.name.startswith('.') and item.name != 'tools':
            # Check if it looks like a service folder (has JSON files)
            if any(item.glob('*.json')):
                service_folders.append(item)
    
    service_folders.sort()
    print(f"Found {len(service_folders)} service folders\n")
    
    # Process each service
    results = []
    for service_folder in service_folders:
        result = process_service_folder(service_folder, aws_root)
        results.append(result)
        status_icon = "✓" if result['status'] == 'PASS' else "⚠" if result['status'] == 'WARN' else "✗" if result['status'] == 'FAIL' else "?"
        print(f"  {status_icon} {result['service']}: {result['status']}")
    
    # Generate global summary
    print("\nGenerating global summary...")
    
    passed = [r['service'] for r in results if r['status'] == 'PASS']
    warn = [r['service'] for r in results if r['status'] == 'WARN']
    failed = [r['service'] for r in results if r['status'] == 'FAIL']
    errors = [r['service'] for r in results if r['status'] == 'ERROR']
    skipped = [r['service'] for r in results if r['status'] == 'SKIP']
    
    # Aggregate issues
    generic_entities_services = [r['service'] for r in results if r.get('generic_entities', 0) > 0]
    ambiguous_tokens_services = [r['service'] for r in results if r.get('ambiguous_tokens', 0) > 0]
    
    global_summary = {
        "total_services": len(service_folders),
        "passed": passed,
        "warn": warn,
        "failed": failed,
        "errors": errors,
        "skipped": skipped,
        "top_issues": {
            "generic_entities": {
                "count": len(generic_entities_services),
                "services": generic_entities_services[:20]  # Limit to 20
            },
            "ambiguous_tokens": {
                "count": len(ambiguous_tokens_services),
                "services": ambiguous_tokens_services[:20]  # Limit to 20
            }
        },
        "summary_stats": {
            "total_operations": sum(r.get('operations', 0) for r in results),
            "total_entities": sum(r.get('entities', 0) for r in results),
            "services_with_manual_review": len([r for r in results if r.get('has_manual_review', False)])
        }
    }
    
    summary_file = aws_root / "global_summary.json"
    with open(summary_file, 'w') as f:
        json.dump(global_summary, f, indent=2)
    
    print(f"\n{'='*60}")
    print("GLOBAL SUMMARY")
    print(f"{'='*60}")
    print(f"Total services: {len(service_folders)}")
    print(f"  ✓ PASSED: {len(passed)}")
    print(f"  ⚠ WARN: {len(warn)}")
    print(f"  ✗ FAILED: {len(failed)}")
    print(f"  ? ERRORS: {len(errors)}")
    print(f"  - SKIPPED: {len(skipped)}")
    print(f"\nIssues:")
    print(f"  Generic entities: {len(generic_entities_services)} services")
    print(f"  Ambiguous tokens: {len(ambiguous_tokens_services)} services")
    print(f"\nGlobal summary saved to: {summary_file}")
    print(f"{'='*60}\n")

if __name__ == "__main__":
    main()

