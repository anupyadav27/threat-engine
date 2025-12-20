#!/usr/bin/env python3
"""
Offline Dependency Index Builder

Builds a precomputed dependency index for services to avoid runtime computation
of dependency chains during rule/yaml generation.

Reads:
  - <service>/operation_registry.json
  - <service>/adjacency.json
  - <service>/manual_review.json (optional)

Writes:
  - <service>/dependency_index.json
  - <service>/overrides_applied.json (if auto-applied overrides exist)
"""

import json
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from collections import deque, defaultdict
import copy


def compact_json_arrays(json_str):
    """
    Post-process JSON string to compact short arrays onto single lines.
    """
    import re
    
    # Match arrays with 1-3 simple string items, each on its own line
    # Example: [\n          "amplify.app_id"\n        ]
    def compact_array(match):
        prefix = match.group(1)  # Indentation before the array
        items_text = match.group(2)  # Content between brackets
        
        # Extract individual items
        items = []
        for line in items_text.split('\n'):
            line = line.strip().rstrip(',')
            if line and not line.startswith('//'):
                items.append(line)
        
        # Only compact if 1-3 items and all are simple (strings, numbers, booleans, null)
        if 1 <= len(items) <= 3:
            all_simple = True
            for item in items:
                item_clean = item.strip().rstrip(',')
                # Check if simple: quoted string, number, boolean, null, or empty array
                if not (item_clean.startswith('"') and item_clean.endswith('"') or
                       item_clean.replace('-', '').replace('.', '').isdigit() or
                       item_clean in ['true', 'false', 'null', '[]']):
                    all_simple = False
                    break
            
            if all_simple:
                # Compact to single line
                items_clean = [item.strip().rstrip(',') for item in items]
                return prefix + '[' + ', '.join(items_clean) + ']'
        
        return match.group(0)
    
    # Pattern: match arrays with newlines, capturing indentation
    # Matches: "key": [\n          "item1",\n          "item2"\n        ]
    pattern = r'(\n\s+)\[\s*\n((?:\s+"[^"]+"(?:\s*,\s*)?\s*\n)*)\s+\]'
    
    # More specific: match after colon and newline
    pattern = r':\s*\[\s*\n((?:\s+"[^"]+"(?:\s*,\s*)?\s*\n)+)\s+\]'
    
    def compact_after_colon(match):
        items_text = match.group(1)
        items = []
        for line in items_text.split('\n'):
            line = line.strip().rstrip(',')
            if line and line.startswith('"'):
                items.append(line)
        
        if 1 <= len(items) <= 3:
            return ': [' + ', '.join(items) + ']'
        return match.group(0)
    
    json_str = re.sub(pattern, compact_after_colon, json_str)
    
    return json_str


def canonical_entity(
    entity: str,
    entity_aliases: Dict[str, str],
    entity_normalizations: Dict[str, str],
    applied_overrides: Dict[str, Dict[str, str]]
) -> str:
    """
    Canonicalize an entity name.
    
    Applies:
    1. entity_aliases mapping
    2. entity_normalizations from overrides
    3. applied_overrides (from manual_review auto-acceptance)
    """
    # Apply entity aliases first
    canonical = entity_aliases.get(entity, entity)
    
    # Apply entity normalizations from overrides
    canonical = entity_normalizations.get(canonical, canonical)
    
    # Apply auto-accepted overrides
    # Format: applied_overrides[operation][key] = suggested_entity
    # We need to check if this entity should be normalized based on any override
    # This is a bit tricky - we'd need to know the operation context
    # For now, we'll handle this at the operation level when building chains
    
    return canonical


def auto_apply_safe_overrides(
    manual_review: Optional[Dict[str, Any]],
    operation_registry: Dict[str, Any]
) -> Tuple[Dict[str, Dict[str, str]], List[Dict[str, Any]]]:
    """
    Auto-apply safe overrides from manual_review.json.
    
    Returns:
        (applied_overrides, accepted_list)
        applied_overrides: {operation: {key: suggested_entity}}
        accepted_list: List of accepted override records
    """
    applied_overrides = {}
    accepted = []
    
    if not manual_review:
        return applied_overrides, accepted
    
    suggested_overrides = manual_review.get('suggested_overrides', [])
    operations = operation_registry.get('operations', {})
    
    for override in suggested_overrides:
        op_name = override.get('operation')
        confidence = override.get('confidence', '')
        suggested_entity = override.get('suggested_entity', '')
        key = override.get('key', '')
        override_type = override.get('type', '')
        
        # Auto-accept HIGH confidence
        if confidence == 'HIGH':
            if op_name not in applied_overrides:
                applied_overrides[op_name] = {}
            applied_overrides[op_name][key] = suggested_entity
            accepted.append(override)
            continue
        
        # For MEDIUM: only if operation consumes entity X and produces key with same param name
        # AND suggested_entity equals the consume_entity (strict rule)
        if confidence == 'MEDIUM' and override_type == 'produces':
            op_data = operations.get(op_name, {})
            consumes = op_data.get('consumes', [])
            
            # Check if any consume entity matches suggested_entity
            for consume_entry in consumes:
                consume_entity = consume_entry.get('entity', '') if isinstance(consume_entry, dict) else consume_entry
                if consume_entity == suggested_entity:
                    # Check if key param name matches consume param name
                    consume_param = consume_entry.get('param', '') if isinstance(consume_entry, dict) else ''
                    # Extract param name from key (e.g., "branch.activeJobId" -> "activeJobId")
                    key_param = key.split('.')[-1] if '.' in key else key
                    key_param_base = key_param.replace('Id', '').replace('id', '').lower()
                    consume_param_base = consume_param.replace('Id', '').replace('id', '').lower()
                    
                    # Strict check: suggested_entity must equal consume_entity
                    if suggested_entity == consume_entity:
                        if op_name not in applied_overrides:
                            applied_overrides[op_name] = {}
                        applied_overrides[op_name][key] = suggested_entity
                        accepted.append(override)
                        break
    
    return applied_overrides, accepted


def find_roots(
    operations: Dict[str, Any],
    adjacency: Dict[str, Any],
    entity_aliases: Dict[str, str],
    entity_normalizations: Dict[str, str],
    applied_overrides: Dict[str, Dict[str, str]],
    read_only: bool = True
) -> List[Dict[str, Any]]:
    """
    Find root operations (operations with no dependencies after canonicalization).
    
    Returns list of root operations with their produced entities.
    """
    roots = []
    op_consumes = adjacency.get('op_consumes', {})
    op_produces = adjacency.get('op_produces', {})
    external_entities = set(adjacency.get('external_entities', []))
    
    # For OCI services, add global entities as external (they're consumed as filter parameters)
    # Check if this is OCI by looking at entity names (they start with "oci.")
    if op_consumes or op_produces:
        sample_entities = list(op_consumes.values())[0] if op_consumes else list(op_produces.values())[0] if op_produces else []
        if sample_entities and any(e.startswith('oci.') for e in sample_entities):
            # Add OCI global entities that should be treated as external when consumed
            oci_global_entities = {
                'oci.compartment_id',
                'oci.tenancy_id',
                'oci.region',
                'oci.availability_domain',
                'oci.ocid'  # Generic OCID - often used as input parameter
            }
            external_entities.update(oci_global_entities)
    
    allowed_kinds = ['read_list', 'read_get'] if read_only else None
    
    for op_name, op_data in operations.items():
        # Filter by kind if read_only
        if allowed_kinds and op_data.get('kind') not in allowed_kinds:
            continue
        
        # Get consumes for this operation
        consumes_raw = op_consumes.get(op_name, [])
        
        # Canonicalize all consumed entities
        consumes_canonical = set()
        for entity in consumes_raw:
            canonical = canonical_entity(
                entity,
                entity_aliases,
                entity_normalizations,
                applied_overrides
            )
            consumes_canonical.add(canonical)
        
        # Subtract external entities - only internal dependencies matter for roots
        consumes_internal = consumes_canonical - external_entities
        
        # If no internal dependencies after canonicalization, it's a root
        if not consumes_internal:
            produces = op_produces.get(op_name, [])
            # Canonicalize produced entities too
            produces_canonical = [
                canonical_entity(
                    e,
                    entity_aliases,
                    entity_normalizations,
                    applied_overrides
                )
                for e in produces
            ]
            # For Azure, shorten operation_id for readability while maintaining uniqueness
            # Remove "azure.{service}." prefix since we're already in service context
            display_op = op_name
            if isinstance(op_data, dict):
                # Check if this looks like an Azure operation_id (starts with azure.)
                if op_name.startswith('azure.'):
                    # Remove "azure.{service}." prefix for cleaner display
                    # e.g., "azure.advisor.configurations.list" -> "configurations.list"
                    parts = op_name.split('.')
                    if len(parts) >= 4:  # azure.{service}.{category}.{operation}
                        display_op = '.'.join(parts[2:])  # Keep category.operation
                    elif len(parts) == 3:  # azure.{service}.{operation}
                        display_op = parts[2]
                # For AWS or other formats, op_name is already the operation name
            roots.append({
                'op': display_op,
                'produces': list(set(produces_canonical))  # dedupe
            })
    
    return roots


def find_shortest_paths(
    target_entity: str,
    roots: List[Dict[str, Any]],
    operations: Dict[str, Any],
    adjacency: Dict[str, Any],
    entity_aliases: Dict[str, str],
    entity_normalizations: Dict[str, str],
    applied_overrides: Dict[str, Dict[str, str]],
    max_paths: int = 3
) -> List[Dict[str, Any]]:
    """
    Find top 1-3 shortest operation chains from any root that produces target_entity.
    
    Returns list of path objects, each with:
    {
        "operations": [op1, op2, ...],
        "produces": {op1: [entities], op2: [entities]},
        "consumes": {op1: [entities], op2: [entities]},
        "external_inputs": [entities]  # Entities that must be provided externally
    }
    """
    op_consumes = adjacency.get('op_consumes', {})
    op_produces = adjacency.get('op_produces', {})
    entity_producers = adjacency.get('entity_producers', {})
    external_entities = set(adjacency.get('external_entities', []))
    
    # For OCI services, add global entities as external (they're consumed as filter parameters)
    if op_consumes or op_produces:
        sample_entities = list(op_consumes.values())[0] if op_consumes else list(op_produces.values())[0] if op_produces else []
        if sample_entities and any(e.startswith('oci.') for e in sample_entities):
            # Add OCI global entities that should be treated as external when consumed
            oci_global_entities = {
                'oci.compartment_id',
                'oci.tenancy_id',
                'oci.region',
                'oci.availability_domain',
                'oci.ocid'  # Generic OCID - often used as input parameter
            }
            external_entities.update(oci_global_entities)
    
    # Canonicalize target entity
    target_canonical = canonical_entity(
        target_entity,
        entity_aliases,
        entity_normalizations,
        applied_overrides
    )
    
    # Find all operations that produce this entity (canonicalized)
    candidate_ops = set()
    for entity, producers in entity_producers.items():
        canonical_entity_name = canonical_entity(
            entity,
            entity_aliases,
            entity_normalizations,
            applied_overrides
        )
        if canonical_entity_name == target_canonical:
            candidate_ops.update(producers)
    
    if not candidate_ops:
        return []
    
    # First, check if any root directly produces this entity
    # If so, prioritize single-op paths (they're always shortest and most efficient)
    # Note: root['op'] is already a display name, we need to find the operation_id
    direct_root_paths = []
    
    # Create mapping from display name to operation_id
    display_to_op_id = {}
    for op_id in operations.keys():
        if op_id.startswith('azure.'):
            parts = op_id.split('.')
            if len(parts) >= 4:
                display = '.'.join(parts[2:])
            elif len(parts) == 3:
                display = parts[2]
            else:
                display = op_id
        else:
            display = op_id
        display_to_op_id[display] = op_id
    
    for root in roots:
        root_display = root['op']
        # Find operation_id from display name
        root_op_id = display_to_op_id.get(root_display)
        if not root_op_id:
            continue
        
        root_produces = op_produces.get(root_op_id, [])
        root_produces_canonical = {
            canonical_entity(
                e,
                entity_aliases,
                entity_normalizations,
                applied_overrides
            )
            for e in root_produces
        }
        if target_canonical in root_produces_canonical:
            # This root directly produces the target - create single-op path
            path_obj = build_path_object(
                [root_op_id],  # Use operation_id for lookup
                operations,
                adjacency,
                entity_aliases,
                entity_normalizations,
                applied_overrides,
                external_entities,
                target_entity=target_entity,
                display_path=[root_display]  # Use display name for output
            )
            if path_obj:
                direct_root_paths.append(path_obj)
    
    # If we found direct root paths, return them (prioritize single-op paths)
    if direct_root_paths:
        # Sort by preference (read_list before read_get)
        def path_preference(p):
            ops = p.get('operations', [])
            if not ops:
                return (999, 0)
            op_data = operations.get(ops[0] if isinstance(ops[0], str) else ops[0]['op'], {})
            kind = op_data.get('kind', '')
            if kind == 'read_list':
                return (0, 0)
            elif kind == 'read_get':
                return (1, 0)
            return (2, 0)
        
        direct_root_paths.sort(key=path_preference)
        return direct_root_paths[:max_paths]
    
    # If no direct root produces the entity, use BFS to find dependency chains
    # BFS from roots to find shortest paths
    # State: (path_so_far, available_entities, depth)
    # Note: path contains operation_id, not display names
    paths = []
    
    # Start from each root
    for root_idx, root in enumerate(roots):
        root_display = root['op']
        root_op_id = display_to_op_id.get(root_display)
        if not root_op_id:
            continue
        
        root_produces = set(root['produces'])
        
        # BFS queue: (path_operation_ids, available_entities, depth)
        # Use operation_id in path for lookups
        queue = deque([([root_op_id], root_produces.copy(), 0)])
        visited = set()  # frozenset(path) to avoid revisiting same path
        
        iterations = 0
        max_iterations = 2000  # Further reduced for faster processing
        max_queue_size = 1000  # Reduced queue size
        
        while queue and len(paths) < max_paths and iterations < max_iterations:
            iterations += 1
            
            # Limit queue size
            if len(queue) > max_queue_size:
                # Keep only shortest paths
                queue = deque(sorted(queue, key=lambda x: (len(x[0]), x[2]))[:max_queue_size])
            
            path, available, depth = queue.popleft()
            
            if depth > 4:  # Reduced from 5 to 4 for faster termination
                continue
            
            path_key = frozenset(path)
            if path_key in visited:
                continue
            visited.add(path_key)
            
            current_op_id = path[-1]  # This is operation_id
            
            # Check if current op produces target entity
            op_produces_list = op_produces.get(current_op_id, [])
            op_produces_canonical = {
                canonical_entity(
                    e,
                    entity_aliases,
                    entity_normalizations,
                    applied_overrides
                )
                for e in op_produces_list
            }
            
            if target_canonical in op_produces_canonical:
                # Found a path candidate! But first validate it's a real dependency chain
                # For multi-operation paths, verify each op actually depends on previous ops
                is_valid_chain = True
                if len(path) > 1:
                    available_entities = set()
                    for i, op_id in enumerate(path):
                        op_cons = op_consumes.get(op_id, [])
                        op_cons_canonical = {
                            canonical_entity(e, entity_aliases, entity_normalizations, applied_overrides)
                            for e in op_cons
                        } - external_entities
                        
                        if i == 0:
                            # First op should be root (no internal dependencies)
                            if op_cons_canonical:
                                is_valid_chain = False
                                break
                        else:
                            # Subsequent ops must consume at least one entity from previous ops
                            if op_cons_canonical and not (op_cons_canonical & available_entities):
                                # This op needs entities not provided by previous - invalid chain
                                is_valid_chain = False
                                break
                        
                        # Track what this op produces for next ops
                        op_prod = op_produces.get(op_id, [])
                        op_prod_canonical = {
                            canonical_entity(e, entity_aliases, entity_normalizations, applied_overrides)
                            for e in op_prod
                        }
                        available_entities.update(op_prod_canonical)
                
                if not is_valid_chain:
                    # Skip invalid paths - continue exploring
                    continue
                
                # Convert path from operation_id to shorter format for Azure readability
                # Remove "azure.{service}." prefix while maintaining uniqueness
                display_path = []
                for op_id in path:
                    if op_id.startswith('azure.'):
                        # Remove "azure.{service}." prefix
                        # e.g., "azure.advisor.configurations.list" -> "configurations.list"
                        parts = op_id.split('.')
                        if len(parts) >= 4:  # azure.{service}.{category}.{operation}
                            display_op = '.'.join(parts[2:])  # Keep category.operation
                        elif len(parts) == 3:  # azure.{service}.{operation}
                            display_op = parts[2]
                        else:
                            display_op = op_id
                        display_path.append(display_op)
                    else:
                        display_path.append(op_id)
                
                path_obj = build_path_object(
                    path,  # Still pass original path for internal lookups
                    operations,
                    adjacency,
                    entity_aliases,
                    entity_normalizations,
                    applied_overrides,
                    external_entities,
                    target_entity=target_entity,
                    display_path=display_path  # Pass display version
                )
                if path_obj:
                    paths.append(path_obj)
                    if len(paths) >= max_paths * 5:  # Enough candidates
                        break
                # Continue exploring - might find shorter paths
            
            # Explore next operations that can be executed
            # Limit exploration to prevent exponential growth
            reachable_ops = []
            for next_op, next_consumes_list in op_consumes.items():
                if next_op in path:  # Avoid cycles
                    continue
                
                # Filter by read-only operations only
                next_op_kind = operations.get(next_op, {}).get('kind', '')
                if next_op_kind not in ['read_list', 'read_get']:
                    continue
                
                next_consumes_canonical = {
                    canonical_entity(
                        e,
                        entity_aliases,
                        entity_normalizations,
                        applied_overrides
                    )
                    for e in next_consumes_list
                }
                next_consumes_internal = next_consumes_canonical - external_entities
                
                # Check if all internal consumes are satisfied
                if next_consumes_internal.issubset(available):
                    reachable_ops.append(next_op)
            
            # Limit to top 8 reachable ops (prioritize candidate ops)
            if len(reachable_ops) > 8:
                reachable_ops.sort(key=lambda op: (
                    0 if op in candidate_ops else 1,  # Candidate ops first
                    len(op_consumes.get(op, []))  # Then by dependency count
                ))
                reachable_ops = reachable_ops[:8]
            
            # Add limited set to queue
            for next_op in reachable_ops:
                next_produces_list = op_produces.get(next_op, [])
                next_produces_canonical = {
                    canonical_entity(
                        e,
                        entity_aliases,
                        entity_normalizations,
                        applied_overrides
                    )
                    for e in next_produces_list
                }
                new_available = available | next_produces_canonical
                new_path = path + [next_op]
                queue.append((new_path, new_available, depth + 1))
    
    # Sort paths by length, then by preference (read_list before read_get)
    def path_score(path_obj):
        ops = path_obj['operations']
        length = len(ops)
        # Tie-breaker: prefer read_list before read_get
        kind_score = 0
        for op in ops:
            op_kind = operations.get(op, {}).get('kind', '')
            if op_kind == 'read_list':
                kind_score += 1
            elif op_kind == 'read_get':
                kind_score += 0.5
        return (length, -kind_score)  # Negative because we want higher kind_score first
    
    paths.sort(key=path_score)
    
    # Filter: Only include paths where operations form a valid dependency chain
    # Rule: Each operation (except the first/root) must consume at least one entity 
    # that was produced by a previous operation in the chain
    optimized_paths = []
    for path_obj in paths:
        ops = path_obj['operations']
        if not ops:
            continue
        
        # Rebuild path_obj to ensure proper dependency flow is shown
        # Check if this is a valid dependency chain
        is_valid_chain = True
        available_from_prev = set()
        
        for idx, op in enumerate(ops):
            if idx == 0:
                # First op is root - should have no internal dependencies
                op_consumes_list = op_consumes.get(op, [])
                op_consumes_internal = {
                    canonical_entity(e, entity_aliases, entity_normalizations, applied_overrides)
                    for e in op_consumes_list
                } - external_entities
                # Root should not have internal dependencies (or it's not a valid root)
                if op_consumes_internal:
                    is_valid_chain = False
                    break
            else:
                # Subsequent ops must consume at least one entity from previous ops
                op_consumes_list = op_consumes.get(op, [])
                op_consumes_internal = {
                    canonical_entity(e, entity_aliases, entity_normalizations, applied_overrides)
                    for e in op_consumes_list
                } - external_entities
                
                # Check if this op actually consumes something from previous ops
                if op_consumes_internal and not (op_consumes_internal & available_from_prev):
                    # This op needs entities that weren't produced by previous ops - invalid chain
                    is_valid_chain = False
                    break
            
            # Add what this op produces to available entities for next ops
            op_produces_list = op_produces.get(op, [])
            op_produces_internal = {
                canonical_entity(e, entity_aliases, entity_normalizations, applied_overrides)
                for e in op_produces_list
            }
            available_from_prev.update(op_produces_internal)
        
        # Also verify last op produces the target entity
        if is_valid_chain:
            last_op = ops[-1]
            last_op_produces = op_produces.get(last_op, [])
            last_op_produces_canonical = {
                canonical_entity(e, entity_aliases, entity_normalizations, applied_overrides)
                for e in last_op_produces
            }
            # Last op should produce target (or if single-op path, it's ok)
            if target_canonical in last_op_produces_canonical or len(ops) == 1:
                optimized_paths.append(path_obj)
    
    # If we have optimized paths, use them; otherwise fall back to original
    if optimized_paths:
        paths = optimized_paths
        paths.sort(key=path_score)
    
    # Return top max_paths unique paths, preferring shortest
    seen = set()
    unique_paths = []
    for path_obj in paths:
        path_key = tuple(path_obj['operations'])
        if path_key not in seen:
            seen.add(path_key)
            unique_paths.append(path_obj)
            if len(unique_paths) >= max_paths:
                break
    
    return unique_paths


def build_path_object(
    ops: List[str],
    operations: Dict[str, Any],
    adjacency: Dict[str, Any],
    entity_aliases: Dict[str, str],
    entity_normalizations: Dict[str, str],
    applied_overrides: Dict[str, Dict[str, str]],
    external_entities: Set[str],
    target_entity: Optional[str] = None,
    display_path: Optional[List[str]] = None
) -> Optional[Dict[str, Any]]:
    """
    Build a path object from a list of operations.
    
    Only includes entities that are actually needed:
    - For intermediate operations: only entities consumed by next operation
    - For final operation: only the target entity (or all if target not specified)
    
    Validates that the chain is executable and returns the path structure.
    """
    op_consumes = adjacency.get('op_consumes', {})
    op_produces = adjacency.get('op_produces', {})
    
    available = set()
    path_produces = {}
    path_consumes = {}  # Track what each op consumes from previous ops
    requires_initial = set()
    
    # Canonicalize target entity if provided
    target_canonical = None
    if target_entity:
        target_canonical = canonical_entity(
            target_entity,
            entity_aliases,
            entity_normalizations,
            applied_overrides
        )
    
    for i, op in enumerate(ops):
        # Get consumes (canonicalized)
        consumes_raw = op_consumes.get(op, [])
        consumes_canonical = {
            canonical_entity(
                e,
                entity_aliases,
                entity_normalizations,
                applied_overrides
            )
            for e in consumes_raw
        }
        
        # Determine what this op consumes from previous operations
        consumes_from_prev = set()
        consumes_internal = consumes_canonical - external_entities
        for entity in consumes_internal:
            if entity in available:
                # This entity comes from a previous operation
                consumes_from_prev.add(entity)
            else:
                # This entity is not available - must be provided initially
                requires_initial.add(entity)
        
        # Store what this operation consumes (only internal entities from previous ops)
        path_consumes[op] = sorted(list(consumes_from_prev))
        
        # Get produces (canonicalized)
        produces_raw = op_produces.get(op, [])
        produces_canonical = {
            canonical_entity(
                e,
                entity_aliases,
                entity_normalizations,
                applied_overrides
            )
            for e in produces_raw
        }
        
        # Determine which entities to include for this operation
        # For dependency_index, we want to show the dependency flow clearly:
        # - Show what each operation produces that's relevant to the chain
        # - For intermediate ops: show what they produce that the next op consumes
        # - For final op: show the target entity
        needed_entities = set()
        
        if i == len(ops) - 1:
            # Last operation: include the target entity (if specified)
            if target_canonical and target_canonical in produces_canonical:
                needed_entities.add(target_canonical)
            elif not target_canonical:
                # If no target specified, include all (fallback)
                needed_entities = produces_canonical
        else:
            # Intermediate operation: include entities consumed by next operation
            next_op = ops[i + 1]
            next_consumes_raw = op_consumes.get(next_op, [])
            next_consumes_canonical = {
                canonical_entity(
                    e,
                    entity_aliases,
                    entity_normalizations,
                    applied_overrides
                )
                for e in next_consumes_raw
            }
            next_consumes_internal = next_consumes_canonical - external_entities
            
            # Only include entities that:
            # 1. This op produces
            # 2. Next op consumes (and they're internal dependencies)
            needed_entities = next_consumes_internal & produces_canonical
            
            # If no internal dependencies, this means next op doesn't depend on this op
            # In this case, don't create a chain - they should be separate paths
            # But for now, we'll still show what this op produces (even if empty)
        
        path_produces[op] = sorted(list(needed_entities))
        available.update(produces_canonical)  # Track all available for dependency checking
    
    # Convert operation keys in produces/consumes to display format
    display_produces = {}
    display_consumes = {}
    
    # Use display_path if provided, otherwise use ops
    display_ops = display_path if display_path else ops
    
    # Build mapping from operation_id to display name
    op_id_to_display = {}
    for op_id, display_op in zip(ops, display_ops):
        op_id_to_display[op_id] = display_op
    
    # Convert produces and consumes to use display names
    for op_id, entities in path_produces.items():
        display_op = op_id_to_display.get(op_id, op_id)
        display_produces[display_op] = entities
    
    for op_id, entities in path_consumes.items():
        display_op = op_id_to_display.get(op_id, op_id)
        display_consumes[display_op] = entities
    
    return {
        'operations': display_ops,  # List of operations in dependency order (using display names)
        'produces': display_produces,  # What each operation produces (using display names as keys)
        'consumes': display_consumes,  # What each operation consumes (using display names as keys)
        'external_inputs': sorted(list(requires_initial))  # Entities that must be provided externally (not produced by chain)
    }


def build_dependency_index(
    service_path: Path,
    read_only: bool = True,
    include_all_kinds: bool = False
) -> Dict[str, Any]:
    """
    Build dependency index for a service.
    
    Args:
        service_path: Path to service directory
        read_only: If True, only include read_list and read_get operations
        include_all_kinds: If True, override read_only and include all operations
    
    Returns:
        Dependency index dictionary
    """
    # Load data sources
    op_registry_path = service_path / 'operation_registry.json'
    adjacency_path = service_path / 'adjacency.json'
    manual_review_path = service_path / 'manual_review.json'
    
    if not op_registry_path.exists():
        raise FileNotFoundError(f"Missing: {op_registry_path}")
    if not adjacency_path.exists():
        raise FileNotFoundError(f"Missing: {adjacency_path}")
    
    with open(op_registry_path) as f:
        operation_registry = json.load(f)
    
    with open(adjacency_path) as f:
        adjacency = json.load(f)
    
    manual_review = None
    if manual_review_path.exists():
        with open(manual_review_path) as f:
            manual_review = json.load(f)
    
    service_name = operation_registry.get('service', service_path.name)
    
    # Get canonicalization mappings
    entity_aliases = operation_registry.get('entity_aliases', {})
    overrides = operation_registry.get('overrides', {})
    entity_normalizations = overrides.get('entity_normalizations', {})
    
    # Auto-apply safe overrides
    applied_overrides, accepted_overrides = auto_apply_safe_overrides(
        manual_review,
        operation_registry
    )
    
    # Save applied overrides if any
    if accepted_overrides:
        overrides_applied_path = service_path / 'overrides_applied.json'
        with open(overrides_applied_path, 'w') as f:
            json.dump({
                'service': service_name,
                'applied': accepted_overrides,
                'applied_overrides': applied_overrides
            }, f, indent=2)
    
    # Determine read_only mode
    actual_read_only = read_only and not include_all_kinds
    
    # Filter operations by kind if read_only
    operations = operation_registry.get('operations', {})
    if actual_read_only:
        operations = {
            op: data
            for op, data in operations.items()
            if data.get('kind') in ['read_list', 'read_get']
        }
    
    # Find roots
    print(f"  Finding roots...", flush=True)
    roots = find_roots(
        operations,
        adjacency,
        entity_aliases,
        entity_normalizations,
        applied_overrides,
        read_only=actual_read_only
    )
    print(f"  Found {len(roots)} root operations", flush=True)
    
    # Build entity paths
    entity_producers = adjacency.get('entity_producers', {})
    entity_paths = {}
    
    # Get all entities (canonicalized)
    all_entities = set()
    for entity in entity_producers.keys():
        canonical = canonical_entity(
            entity,
            entity_aliases,
            entity_normalizations,
            applied_overrides
        )
        all_entities.add(canonical)
    
    # Find paths for each entity
    total_entities = len(all_entities)
    print(f"  Finding paths for {total_entities} entities...", flush=True)
    
    for entity_idx, entity in enumerate(sorted(all_entities), 1):
        if entity_idx % 50 == 0 or entity_idx == total_entities:
            print(f"    Progress: {entity_idx}/{total_entities} entities ({len(entity_paths)} with paths)", flush=True)
        paths = find_shortest_paths(
            entity,
            roots,
            operations,
            adjacency,
            entity_aliases,
            entity_normalizations,
            applied_overrides,
            max_paths=3
        )
        if paths:
            # Filter out invalid paths: multi-op paths where operations don't form a dependency chain
            # A valid chain means each operation (after first) consumes at least one entity from previous ops
            valid_paths = []
            op_consumes = adjacency.get('op_consumes', {})
            op_produces = adjacency.get('op_produces', {})
            
            for path_obj in paths:
                ops_in_path = path_obj.get('operations', [])
                
                if len(ops_in_path) == 1:
                    # Single operation path - always valid (it's a root)
                    valid_paths.append(path_obj)
                else:
                    # Multi-op path: verify dependency chain
                    is_valid = True
                    # Check produces/consumes from path_obj to see if ops actually depend on each other
                    produces_dict = path_obj.get('produces', {})
                    consumes_dict = path_obj.get('consumes', {})
                    
                    for i in range(1, len(ops_in_path)):
                        prev_op_display = ops_in_path[i-1]
                        curr_op_display = ops_in_path[i]
                        
                        # Get entities produced by previous op and consumed by current op
                        prev_produces = set(produces_dict.get(prev_op_display, []))
                        curr_consumes = set(consumes_dict.get(curr_op_display, []))
                        
                        # Current op must consume at least one entity from previous op
                        if not (prev_produces & curr_consumes):
                            is_valid = False
                            break
                    
                    if is_valid:
                        valid_paths.append(path_obj)
            
            # Prefer single-op paths (roots) over multi-op paths when entity is directly produced
            single_op_paths = [p for p in valid_paths if len(p.get('operations', [])) == 1]
            multi_op_paths = [p for p in valid_paths if len(p.get('operations', [])) > 1]
            
            # Use single-op path if available, otherwise multi-op
            # Never fallback to invalid paths - if no valid paths, entity has no path
            if single_op_paths:
                entity_paths[entity] = [single_op_paths[0]]
            elif multi_op_paths:
                entity_paths[entity] = [multi_op_paths[0]]
            # If no valid paths, don't add anything (entity will be in "missing" list)
    
    # Build index
    index = {
        'service': service_name,
        'read_only': actual_read_only,
        'roots': roots,
        'entity_paths': entity_paths
    }
    
    return index


def validate_index(index: Dict[str, Any], operation_registry: Dict[str, Any], adjacency: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate the dependency index.
    
    Returns validation summary.
    """
    operations = operation_registry.get('operations', {})
    op_consumes = adjacency.get('op_consumes', {})
    op_produces = adjacency.get('op_produces', {})
    external_entities = set(adjacency.get('external_entities', []))
    
    entity_aliases = operation_registry.get('entity_aliases', {})
    overrides = operation_registry.get('overrides', {})
    entity_normalizations = overrides.get('entity_normalizations', {})
    applied_overrides = {}  # Would need to load from overrides_applied.json
    
    num_roots = len(index.get('roots', []))
    entity_paths = index.get('entity_paths', {})
    num_entities_covered = len(entity_paths)
    
    # Count total entities
    entity_producers = adjacency.get('entity_producers', {})
    all_entities = set()
    for entity in entity_producers.keys():
        canonical = canonical_entity(
            entity,
            entity_aliases,
            entity_normalizations,
            applied_overrides
        )
        all_entities.add(canonical)
    
    num_entities_total = len(all_entities)
    num_entities_missing = num_entities_total - num_entities_covered
    
    # Validate each path
    invalid_paths = []
    for entity, paths in entity_paths.items():
        for path_obj in paths:
            ops = path_obj['operations']
            # Use produces/consumes from path_obj (already in display name format)
            # instead of looking up in adjacency (which uses operation_id)
            path_produces = path_obj.get('produces', {})
            path_consumes = path_obj.get('consumes', {})
            
            available = set()
            
            for op in ops:
                consumes = set(path_consumes.get(op, []))
                consumes_internal = consumes - external_entities
                
                # Check if consumes are satisfied
                missing = consumes_internal - available
                if missing:
                    invalid_paths.append({
                        'entity': entity,
                        'ops': ops,
                        'missing_at': op,
                        'missing_entities': list(missing)
                    })
                
                # Add produces to available
                produces = set(path_produces.get(op, []))
                available.update(produces)
            
            # Check if final path produces target entity
            final_op = ops[-1]
            final_produces = set(path_produces.get(final_op, []))
            
            # Check canonicalized
            canonical_entity_name = canonical_entity(
                entity,
                entity_aliases,
                entity_normalizations,
                applied_overrides
            )
            final_produces_canonical = {
                canonical_entity(
                    e,
                    entity_aliases,
                    entity_normalizations,
                    applied_overrides
                )
                for e in final_produces
            }
            if canonical_entity_name not in final_produces_canonical:
                invalid_paths.append({
                    'entity': entity,
                    'ops': ops,
                    'issue': 'final_op_does_not_produce_target'
                })
    
    return {
        'num_roots': num_roots,
        'num_entities_covered': num_entities_covered,
        'num_entities_total': num_entities_total,
        'num_entities_missing': num_entities_missing,
        'num_invalid_paths': len(invalid_paths),
        'invalid_paths': invalid_paths[:10]  # Limit to first 10
    }


def main():
    parser = argparse.ArgumentParser(description='Build dependency index for a service')
    parser.add_argument('service_path', type=Path, help='Path to service directory')
    parser.add_argument('--all-kinds', action='store_true', help='Include all operation kinds (not just read-only)')
    parser.add_argument('--validate', action='store_true', help='Run validation after building')
    
    args = parser.parse_args()
    
    service_path = args.service_path
    if not service_path.is_dir():
        print(f"Error: {service_path} is not a directory", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Build index
        print(f"Building dependency index for {service_path.name}...")
        index = build_dependency_index(
            service_path,
            read_only=True,
            include_all_kinds=args.all_kinds
        )
        
        # Write index with compact formatting
        index_path = service_path / 'dependency_index.json'
        # First write with standard formatting
        json_str = json.dumps(index, indent=2)
        # Then compact short arrays
        json_str = compact_json_arrays(json_str)
        with open(index_path, 'w') as f:
            f.write(json_str)
        
        print(f"✓ Created: {index_path}")
        print(f"  Roots: {len(index['roots'])}")
        print(f"  Entities with paths: {len(index['entity_paths'])}")
        
        # Validate if requested
        if args.validate:
            print("\nValidating index...")
            with open(service_path / 'operation_registry.json') as f:
                operation_registry = json.load(f)
            with open(service_path / 'adjacency.json') as f:
                adjacency = json.load(f)
            
            validation = validate_index(index, operation_registry, adjacency)
            print(f"  Roots: {validation['num_roots']}")
            print(f"  Entities covered: {validation['num_entities_covered']}/{validation['num_entities_total']}")
            print(f"  Entities missing: {validation['num_entities_missing']}")
            print(f"  Invalid paths: {validation['num_invalid_paths']}")
            
            if validation['invalid_paths']:
                print("\n  Invalid paths (first 10):")
                for invalid in validation['invalid_paths']:
                    print(f"    - {invalid}")
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

