#!/usr/bin/env python3
"""
Script to validate and find missing dependency_index entries across all AWS services.
Compares direct_vars.json entities with dependency_index.json entries.
"""

import json
import os
import sys
from pathlib import Path
from collections import defaultdict

def load_json_file(filepath):
    """Load and parse a JSON file."""
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        return None

def extract_entities_from_direct_vars(direct_vars):
    """Extract all dependency_index_entity values from direct_vars.json."""
    entities = set()
    
    # Check fields section
    if 'fields' in direct_vars:
        for field_name, field_data in direct_vars['fields'].items():
            if 'dependency_index_entity' in field_data:
                entities.add(field_data['dependency_index_entity'])
    
    # Check field_mappings section
    if 'field_mappings' in direct_vars:
        for field_name, mapping_data in direct_vars['field_mappings'].items():
            if 'dependency_index_entity' in mapping_data:
                entities.add(mapping_data['dependency_index_entity'])
    
    return entities

def extract_entities_from_dependency_index(dependency_index):
    """Extract all entity keys from dependency_index.json entity_paths."""
    entities = set()
    if 'entity_paths' in dependency_index:
        entities = set(dependency_index['entity_paths'].keys())
    return entities

def find_missing_entities(service_dir):
    """Find missing entities for a service."""
    service_path = Path(service_dir)
    direct_vars_path = service_path / 'direct_vars.json'
    dependency_index_path = service_path / 'dependency_index.json'
    operation_registry_path = service_path / 'operation_registry.json'
    
    if not direct_vars_path.exists() or not dependency_index_path.exists():
        return None
    
    direct_vars = load_json_file(direct_vars_path)
    dependency_index = load_json_file(dependency_index_path)
    operation_registry = load_json_file(operation_registry_path)
    
    if not direct_vars or not dependency_index:
        return None
    
    direct_vars_entities = extract_entities_from_direct_vars(direct_vars)
    dependency_index_entities = extract_entities_from_dependency_index(dependency_index)
    
    missing = direct_vars_entities - dependency_index_entities
    
    return {
        'service': service_path.name,
        'missing_entities': sorted(missing),
        'total_direct_vars_entities': len(direct_vars_entities),
        'total_dependency_index_entities': len(dependency_index_entities),
        'operation_registry': operation_registry
    }

def main():
    base_dir = Path(__file__).parent
    services_dir = base_dir
    
    results = []
    services_with_issues = []
    
    print("Scanning services for missing dependency_index entries...")
    print("=" * 80)
    
    # Get all service directories
    service_dirs = [d for d in services_dir.iterdir() 
                   if d.is_dir() and (d / 'direct_vars.json').exists() 
                   and (d / 'dependency_index.json').exists()]
    
    service_dirs.sort()
    
    for service_dir in service_dirs:
        result = find_missing_entities(service_dir)
        if result and result['missing_entities']:
            services_with_issues.append(result)
            results.append(result)
            print(f"\n{result['service']}: {len(result['missing_entities'])} missing entities")
            if len(result['missing_entities']) <= 10:
                for entity in result['missing_entities']:
                    print(f"  - {entity}")
            else:
                for entity in result['missing_entities'][:10]:
                    print(f"  - {entity}")
                print(f"  ... and {len(result['missing_entities']) - 10} more")
    
    print("\n" + "=" * 80)
    print(f"\nSummary:")
    print(f"Total services checked: {len(service_dirs)}")
    print(f"Services with missing entries: {len(services_with_issues)}")
    
    if services_with_issues:
        total_missing = sum(len(r['missing_entities']) for r in services_with_issues)
        print(f"Total missing entities: {total_missing}")
        
        # Write detailed report
        report_path = base_dir / 'dependency_index_validation_report.json'
        with open(report_path, 'w') as f:
            json.dump({
                'summary': {
                    'total_services_checked': len(service_dirs),
                    'services_with_issues': len(services_with_issues),
                    'total_missing_entities': total_missing
                },
                'services_with_missing_entities': {
                    r['service']: {
                        'missing_count': len(r['missing_entities']),
                        'missing_entities': r['missing_entities']
                    }
                    for r in services_with_issues
                }
            }, f, indent=2)
        
        print(f"\nDetailed report written to: {report_path}")
    
    return services_with_issues

if __name__ == '__main__':
    main()

