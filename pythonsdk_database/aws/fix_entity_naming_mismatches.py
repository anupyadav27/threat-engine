#!/usr/bin/env python3
"""
Script to detect and fix entity naming mismatches between direct_vars.json 
and operation_registry.json.

This script:
1. Detects naming pattern mismatches (duplicated prefixes, different parent context, etc.)
2. Generates entity_aliases to map direct_vars entity names to operation_registry entity names
3. Adds these aliases to operation_registry.json
4. Can optionally validate and re-run the dependency_index fix script
"""

import json
import re
from pathlib import Path
from collections import defaultdict
from difflib import SequenceMatcher

def load_json_file(filepath):
    """Load and parse a JSON file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        return None

def save_json_file(filepath, data):
    """Save data to a JSON file."""
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"Error saving {filepath}: {e}")
        return False

def similarity(a, b):
    """Calculate similarity between two strings (0-1)."""
    return SequenceMatcher(None, a, b).ratio()

def find_duplicated_prefix(entity_name):
    """Detect and fix duplicated prefix pattern.
    e.g., connection_connection_id -> connection_id
    """
    parts = entity_name.split('_')
    if len(parts) >= 3:
        # Check if first two parts are the same
        if parts[0] == parts[1]:
            # Remove duplication
            fixed = '_'.join(parts[1:])
            return fixed
    return None

def extract_suffix(entity_name, service_name):
    """Extract suffix from entity name (last 2-3 parts)."""
    base = entity_name.replace(f'{service_name}.', '')
    parts = base.split('_')
    if len(parts) >= 2:
        return '_'.join(parts[-2:])  # Last 2 parts
    return None

def find_similar_entities_in_registry(missing_entity, registry_entities, service_name, threshold=0.7):
    """Find similar entities in registry using suffix matching and similarity."""
    missing_base = missing_entity.replace(f'{service_name}.', '')
    missing_suffix = extract_suffix(missing_entity, service_name)
    
    candidates = []
    
    for registry_entity in registry_entities:
        registry_base = registry_entity.replace(f'{service_name}.', '')
        
        # Check suffix match first (most reliable)
        if missing_suffix:
            registry_suffix = extract_suffix(registry_entity, service_name)
            if registry_suffix == missing_suffix:
                candidates.append((registry_entity, 1.0, 'suffix_match'))
        
        # Check similarity
        sim = similarity(missing_base, registry_base)
        if sim >= threshold and sim < 1.0:
            candidates.append((registry_entity, sim, 'similarity'))
    
    # Sort by score (highest first)
    candidates.sort(key=lambda x: x[1], reverse=True)
    
    if candidates:
        return candidates[0][0]  # Return best match
    return None

def detect_naming_mismatches(service_dir):
    """Detect naming mismatches for a service."""
    service_path = Path(service_dir)
    service_name = service_path.name
    
    direct_vars_path = service_path / 'direct_vars.json'
    op_registry_path = service_path / 'operation_registry.json'
    
    if not direct_vars_path.exists() or not op_registry_path.exists():
        return None
    
    direct_vars = load_json_file(direct_vars_path)
    op_registry = load_json_file(op_registry_path)
    
    if not direct_vars or not op_registry:
        return None
    
    # Get entities from direct_vars
    entities_from_direct_vars = set()
    field_to_entity = {}
    if 'fields' in direct_vars:
        for field_name, field_data in direct_vars['fields'].items():
            if 'dependency_index_entity' in field_data:
                entity = field_data['dependency_index_entity']
                entities_from_direct_vars.add(entity)
                field_to_entity[field_name] = entity
    
    # Get entities from operation_registry
    entities_from_registry = set()
    entity_to_operations = defaultdict(list)
    ops_dict = op_registry.get('operations', {})
    for op_name, op_data in ops_dict.items():
        if 'produces' in op_data:
            for produce_item in op_data['produces']:
                if isinstance(produce_item, dict):
                    entity = produce_item.get('entity')
                    entities_from_registry.add(entity)
                    entity_to_operations[entity].append(op_name)
    
    # Get existing aliases
    existing_aliases = op_registry.get('entity_aliases', {})
    
    # Find missing entities (not in registry and not already aliased)
    missing = entities_from_direct_vars - entities_from_registry
    missing = missing - set(existing_aliases.keys())  # Exclude already aliased
    
    if not missing:
        return {
            'service': service_name,
            'aliases_to_add': [],
            'patterns': {}
        }
    
    # Detect patterns and find matches
    aliases_to_add = {}
    patterns = {
        'duplicated_prefix': [],
        'suffix_match': [],
        'similarity_match': [],
        'no_match': []
    }
    
    for missing_entity in missing:
        if not missing_entity.startswith(f'{service_name}.'):
            continue
        
        match_found = False
        matched_entity = None
        pattern_type = None
        
        # Pattern 1: Check for duplicated prefix
        fixed_entity = find_duplicated_prefix(missing_entity.replace(f'{service_name}.', ''))
        if fixed_entity:
            candidate = f"{service_name}.{fixed_entity}"
            if candidate in entities_from_registry:
                matched_entity = candidate
                pattern_type = 'duplicated_prefix'
                match_found = True
        
        # Pattern 2: Suffix matching (check if suffix matches)
        if not match_found:
            missing_base = missing_entity.replace(f'{service_name}.', '')
            missing_parts = missing_base.split('_')
            if len(missing_parts) >= 2:
                # Try last 2 parts as suffix
                suffix = '_'.join(missing_parts[-2:])
                for registry_entity in entities_from_registry:
                    registry_base = registry_entity.replace(f'{service_name}.', '')
                    registry_parts = registry_base.split('_')
                    if len(registry_parts) >= 2:
                        registry_suffix = '_'.join(registry_parts[-2:])
                        if suffix == registry_suffix and registry_entity != missing_entity:
                            # Check if they're reasonably similar overall
                            sim = similarity(missing_base, registry_base)
                            if sim >= 0.5:  # At least 50% similar
                                matched_entity = registry_entity
                                pattern_type = 'suffix_match'
                                match_found = True
                                break
        
        # Pattern 3: High similarity match
        if not match_found:
            similar = find_similar_entities_in_registry(
                missing_entity, entities_from_registry, service_name, threshold=0.75
            )
            if similar:
                matched_entity = similar
                pattern_type = 'similarity_match'
                match_found = True
        
        if match_found and matched_entity:
            aliases_to_add[missing_entity] = matched_entity
            patterns[pattern_type].append({
                'from': missing_entity,
                'to': matched_entity,
                'operations': entity_to_operations[matched_entity]
            })
        else:
            patterns['no_match'].append(missing_entity)
    
    return {
        'service': service_name,
        'aliases_to_add': aliases_to_add,
        'patterns': patterns,
        'total_missing': len(missing),
        'total_matched': len(aliases_to_add)
    }

def add_aliases_to_registry(service_dir, aliases, dry_run=False):
    """Add entity aliases to operation_registry.json."""
    service_path = Path(service_dir)
    op_registry_path = service_path / 'operation_registry.json'
    
    op_registry = load_json_file(op_registry_path)
    if not op_registry:
        return False
    
    # Get existing aliases
    if 'entity_aliases' not in op_registry:
        op_registry['entity_aliases'] = {}
    
    # Add new aliases (don't overwrite existing)
    added_count = 0
    for alias_from, alias_to in aliases.items():
        if alias_from not in op_registry['entity_aliases']:
            op_registry['entity_aliases'][alias_from] = alias_to
            added_count += 1
        elif op_registry['entity_aliases'][alias_from] != alias_to:
            # Update if different
            op_registry['entity_aliases'][alias_from] = alias_to
            added_count += 1
    
    if dry_run:
        return added_count > 0
    
    # Save updated registry
    if save_json_file(op_registry_path, op_registry):
        return added_count
    else:
        return 0

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Detect and fix entity naming mismatches between direct_vars.json and operation_registry.json'
    )
    parser.add_argument('--service', help='Process a specific service only')
    parser.add_argument('--dry-run', action='store_true', help='Dry run (detect but don\'t modify files)')
    parser.add_argument('--limit', type=int, help='Limit number of services to process')
    parser.add_argument('--min-confidence', type=float, default=0.75, 
                       help='Minimum similarity threshold (0-1, default: 0.75)')
    args = parser.parse_args()
    
    base_dir = Path(__file__).parent
    services_dir = base_dir
    
    # Get service directories
    service_dirs = [d for d in services_dir.iterdir() 
                   if d.is_dir() and (d / 'direct_vars.json').exists() 
                   and (d / 'operation_registry.json').exists()]
    
    if args.service:
        service_dirs = [d for d in service_dirs if d.name == args.service]
        if not service_dirs:
            print(f"Service '{args.service}' not found")
            return
    
    service_dirs.sort()
    
    if args.limit:
        service_dirs = service_dirs[:args.limit]
    
    print(f"Analyzing {len(service_dirs)} services for naming mismatches...")
    print("=" * 80)
    
    total_aliases = 0
    services_modified = 0
    results = []
    
    for service_dir in service_dirs:
        result = detect_naming_mismatches(service_dir)
        if not result:
            # Service has no issues or couldn't be processed
            continue
        
        # Ensure result has all required keys
        if 'total_missing' not in result:
            result['total_missing'] = 0
        if 'total_matched' not in result:
            result['total_matched'] = 0
        if 'aliases_to_add' not in result:
            result['aliases_to_add'] = {}
        
        results.append(result)
        
        aliases_count = len(result['aliases_to_add'])
        if aliases_count > 0:
            status = "DRY RUN" if args.dry_run else "FIXED"
            print(f"\n{result['service']}: {aliases_count}/{result['total_missing']} mismatches detected")
            
            # Show pattern breakdown
            for pattern_type, matches in result['patterns'].items():
                if matches and pattern_type != 'no_match':
                    print(f"  {pattern_type}: {len(matches)}")
            
            if not args.dry_run:
                added = add_aliases_to_registry(service_dir, result['aliases_to_add'], dry_run=False)
                if added > 0:
                    total_aliases += added
                    services_modified += 1
                    print(f"  Added {added} aliases to operation_registry.json")
    
    print("\n" + "=" * 80)
    print(f"\nSummary:")
    print(f"Services analyzed: {len(results)}")
    
    total_missing = sum(r['total_missing'] for r in results)
    total_matched = sum(r['total_matched'] for r in results)
    
    print(f"Total missing entities: {total_missing}")
    print(f"Total mismatches matched: {total_matched}")
    
    if not args.dry_run:
        print(f"Total aliases added: {total_aliases}")
        print(f"Services modified: {services_modified}")
        print(f"\nNext step: Re-run fix_dependency_index.py to use these aliases")
    else:
        print(f"\nRun without --dry-run to apply fixes")
    
    # Save detailed report
    report_path = base_dir / 'entity_naming_mismatch_report.json'
    with open(report_path, 'w') as f:
        json.dump({
            'summary': {
                'total_services': len(results),
                'total_missing': total_missing,
                'total_matched': total_matched,
                'total_aliases_added': total_aliases if not args.dry_run else 0
            },
            'services': {
                r['service']: {
                    'total_missing': r['total_missing'],
                    'total_matched': r['total_matched'],
                    'aliases': r['aliases_to_add'],
                    'pattern_counts': {k: len(v) for k, v in r['patterns'].items()}
                }
                for r in results if r['aliases_to_add']
            }
        }, f, indent=2)
    
    print(f"\nDetailed report saved to: {report_path}")

if __name__ == '__main__':
    main()

