#!/usr/bin/env python3
"""
Build dependency index for a single service.

Finds root operations (operations that don't consume entities) and shortest
dependency paths for each entity using BFS.
"""

import json
import sys
from collections import deque
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple


def get_display_name(operation_id: str, operation_registry: Dict) -> str:
    """Convert operation_id to shorter display name."""
    if operation_id not in operation_registry:
        # Fallback: extract from operation_id
        parts = operation_id.split('.')
        if len(parts) >= 4:
            return f"{parts[2]}.{parts[3]}"
        return operation_id
    
    op = operation_registry[operation_id]
    category = op.get('category', '')
    operation = op.get('operation', '')
    
    if category and category != 'root':
        return f"{category}.{operation}"
    return operation or operation_id.split('.')[-1]


def find_roots(adjacency: Dict, operation_registry: Dict, read_only: bool = False) -> List[Dict]:
    """Find root operations (operations that don't consume any entities)."""
    roots = []
    op_consumes = adjacency.get('op_consumes', {})
    
    for op_id, consumes in op_consumes.items():
        if not consumes:  # No dependencies
            # If read_only, filter to read operations only
            if read_only:
                op = operation_registry.get(op_id, {})
                kind = op.get('kind', '')
                if not kind.startswith('read_'):
                    continue
            
            display_name = get_display_name(op_id, operation_registry)
            produces = adjacency.get('op_produces', {}).get(op_id, [])
            roots.append({
                'op': display_name,
                'produces': produces
            })
    
    return roots


def find_shortest_paths(
    adjacency: Dict,
    operation_registry: Dict,
    read_only: bool = False,
    include_all_kinds: bool = False
) -> Dict[str, List[Dict]]:
    """Find shortest dependency paths for each entity using BFS."""
    op_consumes = adjacency.get('op_consumes', {})
    op_produces = adjacency.get('op_produces', {})
    entity_producers = adjacency.get('entity_producers', {})
    
    # Get all entities
    all_entities = set()
    for produces in op_produces.values():
        all_entities.update(produces)
    
    entity_paths = {}
    total_entities = len(all_entities)
    
    print(f"  Finding paths for {total_entities} entities...")
    
    for idx, entity in enumerate(sorted(all_entities)):
        if (idx + 1) % 100 == 0:
            print(f"    Progress: {idx + 1}/{total_entities} entities")
        
        paths = []
        
        # Find operations that produce this entity
        producers = entity_producers.get(entity, [])
        
        # Filter by read_only if needed
        if read_only and not include_all_kinds:
            producers = [
                op_id for op_id in producers
                if operation_registry.get(op_id, {}).get('kind', '').startswith('read_')
            ]
        
        # Check if any producer is a root (single-operation path)
        root_producers = []
        for op_id in producers:
            if not op_consumes.get(op_id, []):
                display_name = get_display_name(op_id, operation_registry)
                root_producers.append((op_id, display_name))
        
        # If we have root producers, prioritize single-operation paths
        if root_producers:
            for op_id, display_name in root_producers:
                path_obj = build_path_object(
                    [op_id],
                    [display_name],
                    adjacency,
                    operation_registry
                )
                if path_obj:
                    paths.append(path_obj)
        
        # If no root producers or we want all paths, use BFS
        if not root_producers or include_all_kinds:
            # BFS to find shortest paths
            queue = deque()
            visited = set()
            
            # Initialize queue with operations that produce the entity
            for op_id in producers:
                if read_only and not include_all_kinds:
                    if not operation_registry.get(op_id, {}).get('kind', '').startswith('read_'):
                        continue
                
                queue.append(([op_id], {entity}))  # (path, entities_produced_so_far)
                visited.add(op_id)
            
            found_paths = []
            max_depth = 5  # Limit depth to avoid infinite loops
            
            while queue and len(found_paths) < 10:  # Limit number of paths
                path, produced_entities = queue.popleft()
                
                if len(path) > max_depth:
                    continue
                
                # Check if current path ends at a root
                last_op = path[-1]
                if not op_consumes.get(last_op, []):
                    # This is a valid path ending at a root
                    path_obj = build_path_object(
                        path,
                        [get_display_name(op_id, operation_registry) for op_id in path],
                        adjacency,
                        operation_registry
                    )
                    if path_obj:
                        found_paths.append(path_obj)
                    continue
                
                # Find next operations that consume entities we've produced
                last_op_consumes = set(op_consumes.get(last_op, []))
                last_op_produces = set(op_produces.get(last_op, []))
                
                # Check if this path is valid (each op consumes something from previous)
                if len(path) > 1:
                    prev_op_produces = set(op_produces.get(path[-2], []))
                    if not last_op_consumes.intersection(prev_op_produces):
                        # Invalid chain - skip
                        continue
                
                # Find operations that consume entities we've produced
                next_ops = []
                for next_op_id, next_consumes in op_consumes.items():
                    if next_op_id in visited or next_op_id in path:
                        continue
                    
                    if read_only and not include_all_kinds:
                        if not operation_registry.get(next_op_id, {}).get('kind', '').startswith('read_'):
                            continue
                    
                    # Check if this operation consumes something we've produced
                    next_consumes_set = set(next_consumes)
                    if next_consumes_set.intersection(produced_entities):
                        next_ops.append(next_op_id)
                
                # Add valid next operations to queue
                for next_op_id in next_ops:
                    next_produces = set(op_produces.get(next_op_id, []))
                    new_produced = produced_entities | next_produces
                    queue.append((path + [next_op_id], new_produced))
                    visited.add(next_op_id)
            
            # Add found paths (avoid duplicates)
            for path_obj in found_paths:
                if path_obj not in paths:
                    paths.append(path_obj)
        
        if paths:
            entity_paths[entity] = paths
    
    return entity_paths


def build_path_object(
    op_ids: List[str],
    display_names: List[str],
    adjacency: Dict,
    operation_registry: Dict
) -> Optional[Dict]:
    """Build a path object with produces/consumes information."""
    op_consumes = adjacency.get('op_consumes', {})
    op_produces = adjacency.get('op_produces', {})
    
    produces_dict = {}
    consumes_dict = {}
    
    for i, op_id in enumerate(op_ids):
        display_name = display_names[i] if i < len(display_names) else get_display_name(op_id, operation_registry)
        
        produces_dict[display_name] = op_produces.get(op_id, [])
        
        if i == 0:
            # First operation consumes nothing (it's a root)
            consumes_dict[display_name] = []
        else:
            # Subsequent operations consume entities produced by previous
            prev_op_id = op_ids[i - 1]
            prev_produces = set(op_produces.get(prev_op_id, []))
            this_consumes = set(op_consumes.get(op_id, []))
            consumed_from_prev = list(this_consumes.intersection(prev_produces))
            consumes_dict[display_name] = consumed_from_prev
    
    # Validate: each operation after the first must consume something from previous
    for i in range(1, len(display_names)):
        if not consumes_dict[display_names[i]]:
            # Invalid path - skip
            return None
    
    return {
        'operations': display_names,
        'produces': produces_dict,
        'consumes': consumes_dict,
        'external_inputs': list(op_consumes.get(op_ids[0], []))
    }


def validate_index(index: Dict, adjacency: Dict) -> Dict:
    """Validate the generated dependency index."""
    entity_paths = index.get('entity_paths', {})
    op_produces = adjacency.get('op_produces', {})
    op_consumes = adjacency.get('op_consumes', {})
    
    num_entities_covered = len(entity_paths)
    all_entities = set()
    for produces in op_produces.values():
        all_entities.update(produces)
    num_entities_total = len(all_entities)
    num_entities_missing = num_entities_total - num_entities_covered
    
    num_invalid_paths = 0
    
    # Validate each path
    for entity, paths in entity_paths.items():
        for path_obj in paths:
            operations = path_obj.get('operations', [])
            produces = path_obj.get('produces', {})
            consumes = path_obj.get('consumes', {})
            
            # Check that each operation after the first consumes something from previous
            for i in range(1, len(operations)):
                op_name = operations[i]
                consumed = consumes.get(op_name, [])
                if not consumed:
                    num_invalid_paths += 1
                    break
    
    return {
        'num_entities_covered': num_entities_covered,
        'num_entities_total': num_entities_total,
        'num_entities_missing': num_entities_missing,
        'num_invalid_paths': num_invalid_paths
    }


def build_service_index(
    service_dir: Path,
    read_only: bool = False,
    include_all_kinds: bool = False,
    validate: bool = True
) -> Dict:
    """Build dependency index for a service."""
    adjacency_file = service_dir / 'adjacency.json'
    registry_file = service_dir / 'operation_registry.json'
    index_file = service_dir / 'dependency_index.json'
    
    if not adjacency_file.exists():
        raise FileNotFoundError(f"adjacency.json not found in {service_dir}")
    if not registry_file.exists():
        raise FileNotFoundError(f"operation_registry.json not found in {service_dir}")
    
    with open(adjacency_file) as f:
        adjacency = json.load(f)
    
    with open(registry_file) as f:
        operation_registry_data = json.load(f)
        operation_registry = operation_registry_data.get('operations', {})
    
    service_name = adjacency.get('service', service_dir.name)
    
    print(f"\nBuilding dependency index for {service_name}...")
    print(f"  Read-only: {read_only}, All kinds: {include_all_kinds}")
    
    # Find roots
    print("  Finding root operations...")
    roots = find_roots(adjacency, operation_registry, read_only=read_only)
    print(f"  Found {len(roots)} root operations")
    
    # Find shortest paths
    entity_paths = find_shortest_paths(
        adjacency,
        operation_registry,
        read_only=read_only,
        include_all_kinds=include_all_kinds
    )
    print(f"  Found paths for {len(entity_paths)} entities")
    
    # Build index
    index = {
        'service': service_name,
        'read_only': read_only and not include_all_kinds,
        'roots': roots,
        'entity_paths': entity_paths
    }
    
    # Validate
    validation = None
    if validate:
        print("  Validating index...")
        validation = validate_index(index, adjacency)
        print(f"  Validation: {validation['num_entities_covered']}/{validation['num_entities_total']} entities covered")
        if validation['num_invalid_paths'] > 0:
            print(f"  Warning: {validation['num_invalid_paths']} invalid paths found")
    
    # Save
    with open(index_file, 'w') as f:
        json.dump(index, f, indent=2)
    
    print(f"  ✓ Saved to {index_file}")
    
    return {
        'num_roots': len(roots),
        'num_entities_with_paths': len(entity_paths),
        'read_only': read_only and not include_all_kinds,
        'validation': validation
    }


def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Build dependency index for a service')
    parser.add_argument('service_dir', type=Path, help='Service directory path')
    parser.add_argument('--read-only', action='store_true', help='Only include read operations')
    parser.add_argument('--all-kinds', action='store_true', help='Include all operation kinds')
    parser.add_argument('--validate', action='store_true', default=True, help='Validate the index')
    parser.add_argument('--no-validate', dest='validate', action='store_false', help='Skip validation')
    
    args = parser.parse_args()
    
    try:
        stats = build_service_index(
            args.service_dir,
            read_only=args.read_only,
            include_all_kinds=args.all_kinds,
            validate=args.validate
        )
        print(f"\n✓ Success: {stats['num_roots']} roots, {stats['num_entities_with_paths']} entities")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

