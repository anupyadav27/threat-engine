#!/usr/bin/env python3
"""
Comprehensive two-phase validation script:
Phase 1: Validate operation_registry.json completeness
Phase 2: Validate dependency_index.json coverage

Phase 1 checks:
- operation_registry.json exists
- validation_report.json exists and status
- All operations have produces entries
- No critical issues (unresolved_consumes)

Phase 2 checks:
- All dependency_index_entity values from direct_vars.json exist in dependency_index.json
"""

import json
import os
from pathlib import Path
from collections import defaultdict

def load_json_file(filepath):
    """Load and parse a JSON file."""
    try:
        if not filepath.exists():
            return None
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        return None

def phase1_validate_operation_registry(service_dir):
    """Phase 1: Validate operation_registry.json completeness."""
    service_path = Path(service_dir)
    service_name = service_path.name
    
    op_registry_path = service_path / 'operation_registry.json'
    validation_report_path = service_path / 'validation_report.json'
    
    result = {
        'service': service_name,
        'has_operation_registry': False,
        'has_validation_report': False,
        'validation_status': None,
        'total_operations': 0,
        'operations_without_produces': [],
        'unresolved_consumes_count': 0,
        'phase1_status': 'FAIL',  # FAIL, WARN, PASS
        'phase1_issues': []
    }
    
    # Check if operation_registry.json exists
    if not op_registry_path.exists():
        result['phase1_issues'].append('Missing operation_registry.json')
        return result
    
    result['has_operation_registry'] = True
    op_registry = load_json_file(op_registry_path)
    if not op_registry:
        result['phase1_issues'].append('Cannot parse operation_registry.json')
        return result
    
    # Get operations
    operations = op_registry.get('operations', {})
    result['total_operations'] = len(operations)
    
    # Check each operation has produces
    for op_name, op_data in operations.items():
        if 'produces' not in op_data or len(op_data.get('produces', [])) == 0:
            result['operations_without_produces'].append(op_name)
    
    # Check validation_report.json
    if validation_report_path.exists():
        result['has_validation_report'] = True
        validation_report = load_json_file(validation_report_path)
        if validation_report:
            result['validation_status'] = validation_report.get('validation_status', 'UNKNOWN')
            result['unresolved_consumes_count'] = len(validation_report.get('unresolved_consumes', []))
    else:
        result['phase1_issues'].append('Missing validation_report.json')
    
    # Determine phase1_status
    if result['operations_without_produces']:
        result['phase1_status'] = 'FAIL'
        result['phase1_issues'].append(f"{len(result['operations_without_produces'])} operations without produces")
    elif not result['has_validation_report']:
        result['phase1_status'] = 'WARN'
    elif result['validation_status'] == 'FAIL':
        result['phase1_status'] = 'FAIL'
        result['phase1_issues'].append('validation_report.json shows FAIL status')
    elif result['unresolved_consumes_count'] > 0:
        result['phase1_status'] = 'WARN'
        result['phase1_issues'].append(f"{result['unresolved_consumes_count']} unresolved consumes")
    elif result['validation_status'] == 'WARN':
        result['phase1_status'] = 'WARN'
    elif result['validation_status'] == 'PASS':
        result['phase1_status'] = 'PASS'
    else:
        result['phase1_status'] = 'PASS'  # Default to PASS if no issues found
    
    return result

def phase2_validate_dependency_index(service_dir):
    """Phase 2: Validate dependency_index.json coverage."""
    service_path = Path(service_dir)
    service_name = service_path.name
    
    direct_vars_path = service_path / 'direct_vars.json'
    dependency_index_path = service_path / 'dependency_index.json'
    operation_registry_path = service_path / 'operation_registry.json'
    
    result = {
        'service': service_name,
        'has_direct_vars': False,
        'has_dependency_index': False,
        'total_direct_vars_entities': 0,
        'total_dependency_index_entities': 0,
        'missing_entities': [],
        'missing_count': 0,
        'phase2_status': 'FAIL',  # FAIL, WARN, PASS
        'phase2_issues': []
    }
    
    # Check if required files exist
    if not direct_vars_path.exists():
        result['phase2_issues'].append('Missing direct_vars.json')
        return result
    
    if not dependency_index_path.exists():
        result['phase2_issues'].append('Missing dependency_index.json')
        return result
    
    result['has_direct_vars'] = True
    result['has_dependency_index'] = True
    
    direct_vars = load_json_file(direct_vars_path)
    dependency_index = load_json_file(dependency_index_path)
    operation_registry = load_json_file(operation_registry_path)
    
    if not direct_vars:
        result['phase2_issues'].append('Cannot parse direct_vars.json')
        return result
    
    if not dependency_index:
        result['phase2_issues'].append('Cannot parse dependency_index.json')
        return result
    
    # Extract entities from direct_vars.json
    direct_vars_entities = set()
    
    # Check fields section
    if 'fields' in direct_vars:
        for field_name, field_data in direct_vars['fields'].items():
            if isinstance(field_data, dict) and 'dependency_index_entity' in field_data:
                entity = field_data['dependency_index_entity']
                if entity:  # Skip empty strings
                    direct_vars_entities.add(entity)
    
    # Check field_mappings section
    if 'field_mappings' in direct_vars:
        for field_name, mapping_data in direct_vars['field_mappings'].items():
            if isinstance(mapping_data, dict) and 'dependency_index_entity' in mapping_data:
                entity = mapping_data['dependency_index_entity']
                if entity:  # Skip empty strings
                    direct_vars_entities.add(entity)
    
    result['total_direct_vars_entities'] = len(direct_vars_entities)
    
    # Extract entities from dependency_index.json
    dependency_index_entities = set()
    if 'entity_paths' in dependency_index:
        dependency_index_entities = set(dependency_index['entity_paths'].keys())
    
    result['total_dependency_index_entities'] = len(dependency_index_entities)
    
    # Find missing entities
    missing = direct_vars_entities - dependency_index_entities
    result['missing_entities'] = sorted(missing)
    result['missing_count'] = len(missing)
    
    # Check if entities can be found in operation_registry.json (for context)
    entities_found_in_registry = set()
    if operation_registry:
        ops_dict = operation_registry.get('operations', {})
        entity_aliases = operation_registry.get('entity_aliases', {})
        
        all_registry_entities = set()
        for op_data in ops_dict.values():
            for produce in op_data.get('produces', []):
                if isinstance(produce, dict):
                    entity = produce.get('entity')
                    if entity:
                        all_registry_entities.add(entity)
        
        # Check missing entities against registry (with aliases)
        for missing_entity in missing:
            # Check direct match
            if missing_entity in all_registry_entities:
                entities_found_in_registry.add(missing_entity)
                continue
            
            # Check via alias
            canonical = entity_aliases.get(missing_entity)
            if canonical and canonical in all_registry_entities:
                entities_found_in_registry.add(missing_entity)
    
    result['missing_entities_in_registry'] = len(entities_found_in_registry)
    result['missing_entities_not_in_registry'] = result['missing_count'] - len(entities_found_in_registry)
    
    # Determine phase2_status
    if result['missing_count'] > 0:
        if result['missing_entities_not_in_registry'] > 0:
            result['phase2_status'] = 'FAIL'
            result['phase2_issues'].append(f"{result['missing_entities_not_in_registry']} missing entities not found in operation_registry.json")
        else:
            result['phase2_status'] = 'WARN'
            result['phase2_issues'].append(f"{result['missing_count']} missing entities (but found in operation_registry.json - can be fixed)")
    else:
        result['phase2_status'] = 'PASS'
    
    return result

def main():
    base_dir = Path(__file__).parent
    services_dir = base_dir
    
    print("=" * 80)
    print("COMPREHENSIVE VALIDATION: Phase 1 + Phase 2")
    print("=" * 80)
    
    # Get all service directories
    service_dirs = [d for d in services_dir.iterdir() 
                   if d.is_dir() and not d.name.startswith('.') and not d.name.startswith('_')
                   and (d / 'direct_vars.json').exists()]
    
    service_dirs.sort()
    
    print(f"\nFound {len(service_dirs)} service directories")
    print("\nRunning Phase 1: Validate operation_registry.json completeness...")
    print("-" * 80)
    
    phase1_results = []
    for service_dir in service_dirs:
        result = phase1_validate_operation_registry(service_dir)
        phase1_results.append(result)
        if result['phase1_status'] != 'PASS':
            print(f"{result['service']}: {result['phase1_status']} - {', '.join(result['phase1_issues'][:2])}")
    
    print("\n" + "=" * 80)
    print("Running Phase 2: Validate dependency_index.json coverage...")
    print("-" * 80)
    
    phase2_results = []
    for service_dir in service_dirs:
        result = phase2_validate_dependency_index(service_dir)
        phase2_results.append(result)
        if result['phase2_status'] != 'PASS':
            status_msg = f"{result['missing_count']} missing" if result['missing_count'] > 0 else "OK"
            print(f"{result['service']}: {result['phase2_status']} - {status_msg}")
    
    # Combine results
    combined_results = {}
    for p1, p2 in zip(phase1_results, phase2_results):
        service = p1['service']
        combined_results[service] = {
            'phase1': p1,
            'phase2': p2,
            'overall_status': 'PASS' if p1['phase1_status'] == 'PASS' and p2['phase2_status'] == 'PASS' else 'FAIL'
        }
    
    # Generate summary
    phase1_pass = sum(1 for r in phase1_results if r['phase1_status'] == 'PASS')
    phase1_warn = sum(1 for r in phase1_results if r['phase1_status'] == 'WARN')
    phase1_fail = sum(1 for r in phase1_results if r['phase1_status'] == 'FAIL')
    
    phase2_pass = sum(1 for r in phase2_results if r['phase2_status'] == 'PASS')
    phase2_warn = sum(1 for r in phase2_results if r['phase2_status'] == 'WARN')
    phase2_fail = sum(1 for r in phase2_results if r['phase2_status'] == 'FAIL')
    
    total_missing = sum(r['missing_count'] for r in phase2_results)
    
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"\nPhase 1 (operation_registry.json):")
    print(f"  PASS: {phase1_pass}")
    print(f"  WARN: {phase1_warn}")
    print(f"  FAIL: {phase1_fail}")
    
    print(f"\nPhase 2 (dependency_index.json):")
    print(f"  PASS: {phase2_pass}")
    print(f"  WARN: {phase2_warn}")
    print(f"  FAIL: {phase2_fail}")
    print(f"  Total missing entities: {total_missing}")
    
    # Services that need attention
    phase1_fail_services = [r['service'] for r in phase1_results if r['phase1_status'] == 'FAIL']
    phase2_fail_services = [r['service'] for r in phase2_results if r['phase2_status'] == 'FAIL']
    
    if phase1_fail_services:
        print(f"\nPhase 1 FAIL services ({len(phase1_fail_services)}):")
        for svc in sorted(phase1_fail_services)[:20]:
            print(f"  - {svc}")
        if len(phase1_fail_services) > 20:
            print(f"  ... and {len(phase1_fail_services) - 20} more")
    
    if phase2_fail_services:
        print(f"\nPhase 2 FAIL services ({len(phase2_fail_services)}):")
        for svc in sorted(phase2_fail_services)[:20]:
            result = next(r for r in phase2_results if r['service'] == svc)
            print(f"  - {svc}: {result['missing_count']} missing entities")
        if len(phase2_fail_services) > 20:
            print(f"  ... and {len(phase2_fail_services) - 20} more")
    
    # Write detailed report
    report_path = base_dir / 'comprehensive_validation_report.json'
    with open(report_path, 'w') as f:
        json.dump({
            'summary': {
                'total_services': len(service_dirs),
                'phase1': {
                    'pass': phase1_pass,
                    'warn': phase1_warn,
                    'fail': phase1_fail
                },
                'phase2': {
                    'pass': phase2_pass,
                    'warn': phase2_warn,
                    'fail': phase2_fail,
                    'total_missing_entities': total_missing
                }
            },
            'services': combined_results
        }, f, indent=2)
    
    print(f"\nDetailed report written to: {report_path}")
    
    return combined_results

if __name__ == '__main__':
    main()

