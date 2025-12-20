#!/usr/bin/env python3
"""
Quality check and validation for OCI dependency chains.
Validates structure, completeness, and correctness of generated artifacts.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Set
from collections import defaultdict

def validate_operation_registry(registry: Dict[str, Any], service_name: str) -> List[str]:
    """Validate operation_registry.json structure and content."""
    issues = []
    
    # Check required top-level keys
    required_keys = ['service', 'version', 'operations']
    for key in required_keys:
        if key not in registry:
            issues.append(f"Missing required key: {key}")
    
    if registry.get('service') != service_name:
        issues.append(f"Service name mismatch: expected {service_name}, got {registry.get('service')}")
    
    operations = registry.get('operations', {})
    if not operations:
        issues.append("No operations found")
        return issues
    
    # Validate each operation
    for op_name, op_data in operations.items():
        # Check required operation keys
        if 'kind' not in op_data:
            issues.append(f"{op_name}: Missing 'kind'")
        if 'consumes' not in op_data:
            issues.append(f"{op_name}: Missing 'consumes'")
        if 'produces' not in op_data:
            issues.append(f"{op_name}: Missing 'produces'")
        if 'sdk' not in op_data:
            issues.append(f"{op_name}: Missing 'sdk'")
        
        # Validate consumes structure
        for consume in op_data.get('consumes', []):
            if 'entity' not in consume:
                issues.append(f"{op_name}: consume missing 'entity'")
            if 'param' not in consume:
                issues.append(f"{op_name}: consume missing 'param'")
            if 'source' not in consume:
                issues.append(f"{op_name}: consume missing 'source'")
            # Check entity format
            entity = consume.get('entity', '')
            if entity and not entity.startswith('oci.'):
                issues.append(f"{op_name}: Invalid entity format '{entity}' (should start with 'oci.')")
        
        # Validate produces structure
        for produce in op_data.get('produces', []):
            if 'entity' not in produce:
                issues.append(f"{op_name}: produce missing 'entity'")
            if 'path' not in produce:
                issues.append(f"{op_name}: produce missing 'path'")
            if 'source' not in produce:
                issues.append(f"{op_name}: produce missing 'source'")
            # Check entity format
            entity = produce.get('entity', '')
            if entity and not entity.startswith('oci.'):
                issues.append(f"{op_name}: Invalid entity format '{entity}' (should start with 'oci.')")
    
    return issues

def validate_adjacency(adjacency: Dict[str, Any], registry: Dict[str, Any], service_name: str) -> List[str]:
    """Validate adjacency.json structure and consistency with registry."""
    issues = []
    
    # Check required keys
    required_keys = ['service', 'op_consumes', 'op_produces', 'entity_producers', 'entity_consumers']
    for key in required_keys:
        if key not in adjacency:
            issues.append(f"Missing required key: {key}")
    
    if adjacency.get('service') != service_name:
        issues.append(f"Service name mismatch in adjacency")
    
    # Check consistency with registry
    registry_ops = set(registry.get('operations', {}).keys())
    adj_ops_consumes = set(adjacency.get('op_consumes', {}).keys())
    adj_ops_produces = set(adjacency.get('op_produces', {}).keys())
    
    if registry_ops != adj_ops_consumes:
        missing = registry_ops - adj_ops_consumes
        extra = adj_ops_consumes - registry_ops
        if missing:
            issues.append(f"Operations in registry but not in op_consumes: {list(missing)[:5]}")
        if extra:
            issues.append(f"Operations in op_consumes but not in registry: {list(extra)[:5]}")
    
    if registry_ops != adj_ops_produces:
        missing = registry_ops - adj_ops_produces
        if missing:
            issues.append(f"Operations in registry but not in op_produces: {list(missing)[:5]}")
    
    # Validate entity_producers and entity_consumers reference valid operations
    all_ops = registry_ops
    for entity, producers in adjacency.get('entity_producers', {}).items():
        for op in producers:
            if op not in all_ops:
                issues.append(f"entity_producers['{entity}'] references unknown operation: {op}")
    
    for entity, consumers in adjacency.get('entity_consumers', {}).items():
        for op in consumers:
            if op not in all_ops:
                issues.append(f"entity_consumers['{entity}'] references unknown operation: {op}")
    
    return issues

def validate_validation_report(report: Dict[str, Any], service_name: str) -> List[str]:
    """Validate validation_report.json structure."""
    issues = []
    
    if report.get('service') != service_name:
        issues.append("Service name mismatch in validation_report")
    
    if 'summary' not in report:
        issues.append("Missing 'summary' in validation_report")
    else:
        summary = report['summary']
        if 'total_operations' not in summary:
            issues.append("Missing 'total_operations' in summary")
        if 'total_entities' not in summary:
            issues.append("Missing 'total_entities' in summary")
    
    return issues

def check_entity_naming_quality(registry: Dict[str, Any], service_name: str) -> List[str]:
    """Check for generic entities and naming quality issues."""
    issues = []
    generic_entities = []
    
    operations = registry.get('operations', {})
    for op_name, op_data in operations.items():
        # Check consumes
        for consume in op_data.get('consumes', []):
            entity = consume.get('entity', '')
            if entity.startswith(f'oci.{service_name}.'):
                parts = entity.split('.')
                if len(parts) == 3 and parts[2] in ['id', 'name', 'status']:
                    generic_entities.append(f"{op_name}.consumes.{entity}")
        
        # Check produces
        for produce in op_data.get('produces', []):
            entity = produce.get('entity', '')
            if entity.startswith(f'oci.{service_name}.'):
                parts = entity.split('.')
                if len(parts) == 3 and parts[2] in ['id', 'name', 'status']:
                    generic_entities.append(f"{op_name}.produces.{entity}")
    
    if generic_entities:
        issues.append(f"Found {len(generic_entities)} generic entities (oci.{service_name}.id/name/status)")
        issues.append(f"  Examples: {generic_entities[:5]}")
    
    return issues

def check_dependency_consistency(registry: Dict[str, Any], adjacency: Dict[str, Any]) -> List[str]:
    """Check consistency between registry and adjacency."""
    issues = []
    
    operations = registry.get('operations', {})
    
    for op_name, op_data in operations.items():
        # Get entities from registry
        registry_consumes = {c['entity'] for c in op_data.get('consumes', [])}
        registry_produces = {p['entity'] for p in op_data.get('produces', [])}
        
        # Get entities from adjacency
        adj_consumes = set(adjacency.get('op_consumes', {}).get(op_name, []))
        adj_produces = set(adjacency.get('op_produces', {}).get(op_name, []))
        
        if registry_consumes != adj_consumes:
            missing = registry_consumes - adj_consumes
            extra = adj_consumes - registry_consumes
            if missing:
                issues.append(f"{op_name}: Entities in registry.consumes but not in adjacency: {list(missing)[:3]}")
            if extra:
                issues.append(f"{op_name}: Entities in adjacency but not in registry.consumes: {list(extra)[:3]}")
        
        if registry_produces != adj_produces:
            missing = registry_produces - adj_produces
            extra = adj_produces - registry_produces
            if missing:
                issues.append(f"{op_name}: Entities in registry.produces but not in adjacency: {list(missing)[:3]}")
            if extra:
                issues.append(f"{op_name}: Entities in adjacency but not in registry.produces: {list(extra)[:3]}")
    
    return issues

def validate_service_folder(service_folder: Path) -> Dict[str, Any]:
    """Validate all files in a service folder."""
    service_name = service_folder.name
    results = {
        'service': service_name,
        'valid': True,
        'issues': [],
        'file_checks': {}
    }
    
    # Check required files
    required_files = {
        'oci_dependencies_with_python_names_fully_enriched.json': 'spec',
        'operation_registry.json': 'registry',
        'adjacency.json': 'adjacency',
        'validation_report.json': 'validation',
        'overrides.json': 'overrides'
    }
    
    for filename, file_type in required_files.items():
        filepath = service_folder / filename
        if not filepath.exists():
            results['issues'].append(f"Missing required file: {filename}")
            results['valid'] = False
            results['file_checks'][filename] = False
        else:
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                results['file_checks'][filename] = True
                
                # Validate based on file type
                if file_type == 'registry':
                    reg_issues = validate_operation_registry(data, service_name)
                    results['issues'].extend(reg_issues)
                elif file_type == 'adjacency':
                    # Need registry for adjacency validation
                    reg_file = service_folder / 'operation_registry.json'
                    if reg_file.exists():
                        with open(reg_file, 'r') as rf:
                            registry = json.load(rf)
                        adj_issues = validate_adjacency(data, registry, service_name)
                        results['issues'].extend(adj_issues)
                elif file_type == 'validation':
                    val_issues = validate_validation_report(data, service_name)
                    results['issues'].extend(val_issues)
                
            except json.JSONDecodeError as e:
                results['issues'].append(f"{filename}: Invalid JSON - {e}")
                results['valid'] = False
                results['file_checks'][filename] = False
            except Exception as e:
                results['issues'].append(f"{filename}: Error - {e}")
                results['valid'] = False
                results['file_checks'][filename] = False
    
    # Additional quality checks if registry exists
    reg_file = service_folder / 'operation_registry.json'
    adj_file = service_folder / 'adjacency.json'
    if reg_file.exists() and adj_file.exists():
        try:
            with open(reg_file, 'r') as f:
                registry = json.load(f)
            with open(adj_file, 'r') as f:
                adjacency = json.load(f)
            
            # Check entity naming quality
            naming_issues = check_entity_naming_quality(registry, service_name)
            results['issues'].extend(naming_issues)
            
            # Check dependency consistency
            consistency_issues = check_dependency_consistency(registry, adjacency)
            results['issues'].extend(consistency_issues)
            
        except Exception as e:
            results['issues'].append(f"Quality check error: {e}")
    
    if results['issues']:
        results['valid'] = False
    
    return results

def main():
    """Run quality checks on all OCI services."""
    script_dir = Path(__file__).parent
    oci_root = script_dir.parent
    
    print("=" * 80)
    print("OCI Dependency Chain Quality Check")
    print("=" * 80)
    print()
    
    # Find all service folders
    service_folders = []
    for item in oci_root.iterdir():
        if item.is_dir() and not item.name.startswith('.') and item.name != 'tools':
            if (item / 'oci_dependencies_with_python_names_fully_enriched.json').exists():
                service_folders.append(item)
    
    service_folders.sort()
    print(f"Found {len(service_folders)} service folders\n")
    
    # Validate each service
    results = []
    for service_folder in service_folders:
        result = validate_service_folder(service_folder)
        results.append(result)
        
        status = "✓" if result['valid'] else "✗"
        issue_count = len(result['issues'])
        print(f"  {status} {result['service']}: {issue_count} issue(s)")
        if result['issues']:
            for issue in result['issues'][:3]:  # Show first 3 issues
                print(f"      - {issue}")
            if len(result['issues']) > 3:
                print(f"      ... and {len(result['issues']) - 3} more")
    
    # Summary
    print("\n" + "=" * 80)
    print("QUALITY CHECK SUMMARY")
    print("=" * 80)
    
    valid_count = sum(1 for r in results if r['valid'])
    invalid_count = len(results) - valid_count
    total_issues = sum(len(r['issues']) for r in results)
    
    print(f"Total services checked: {len(results)}")
    print(f"  ✓ Valid: {valid_count}")
    print(f"  ✗ Invalid: {invalid_count}")
    print(f"  Total issues: {total_issues}")
    
    # Group issues by type
    issue_types = defaultdict(int)
    for result in results:
        for issue in result['issues']:
            if 'Missing' in issue:
                issue_types['missing_files'] += 1
            elif 'Invalid JSON' in issue:
                issue_types['invalid_json'] += 1
            elif 'generic entities' in issue.lower():
                issue_types['generic_entities'] += 1
            elif 'mismatch' in issue.lower():
                issue_types['mismatches'] += 1
            elif 'consistency' in issue.lower() or 'not in' in issue:
                issue_types['inconsistencies'] += 1
            else:
                issue_types['other'] += 1
    
    if issue_types:
        print(f"\nIssue breakdown:")
        for issue_type, count in sorted(issue_types.items(), key=lambda x: -x[1]):
            print(f"  {issue_type}: {count}")
    
    # Services with most issues
    services_with_issues = [(r['service'], len(r['issues'])) for r in results if r['issues']]
    services_with_issues.sort(key=lambda x: -x[1])
    
    if services_with_issues:
        print(f"\nServices with most issues:")
        for service, count in services_with_issues[:10]:
            print(f"  {service}: {count} issues")
    
    print("=" * 80)
    
    # Save detailed report
    report_file = oci_root / "quality_check_report.json"
    with open(report_file, 'w') as f:
        json.dump({
            'summary': {
                'total_services': len(results),
                'valid': valid_count,
                'invalid': invalid_count,
                'total_issues': total_issues
            },
            'issue_types': dict(issue_types),
            'services_with_issues': services_with_issues[:20],
            'detailed_results': results
        }, f, indent=2)
    
    print(f"\nDetailed report saved to: {report_file}")
    
    return 0 if invalid_count == 0 else 1

if __name__ == '__main__':
    sys.exit(main())

