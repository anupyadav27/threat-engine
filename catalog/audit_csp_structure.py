#!/usr/bin/env python3
"""
Audit CSP structure to identify missing files.
Checks for the three required files per service:
1. SDK Dependencies (e.g., boto3_dependencies_with_python_names_fully_enriched.json)
2. dependency_index.json
3. direct_vars.json
"""

import json
from pathlib import Path
from collections import defaultdict

# CSP configurations
CSP_CONFIG = {
    'aws': {
        'sdk_file': 'boto3_dependencies_with_python_names_fully_enriched.json',
        'name': 'AWS'
    },
    'azure': {
        'sdk_file': 'azure_dependencies_with_python_names_fully_enriched.json',
        'name': 'Azure'
    },
    'gcp': {
        'sdk_file': 'gcp_dependencies_with_python_names_fully_enriched.json',
        'name': 'GCP'
    },
    'alicloud': {
        'sdk_file': 'alicloud_dependencies_with_python_names_fully_enriched.json',
        'name': 'Alicloud'
    },
    'oci': {
        'sdk_file': 'oci_dependencies_with_python_names_fully_enriched.json',
        'name': 'OCI'
    },
    'ibm': {
        'sdk_file': 'ibm_dependencies_with_python_names_fully_enriched.json',
        'name': 'IBM'
    }
}

def audit_csp(csp_name: str, base_dir: Path) -> dict:
    """Audit a single CSP"""
    config = CSP_CONFIG[csp_name]
    csp_dir = base_dir / csp_name
    
    if not csp_dir.exists():
        return {
            'csp': config['name'],
            'status': 'MISSING_DIR',
            'services': 0,
            'sdk_files': 0,
            'dependency_index': 0,
            'direct_vars': 0,
            'complete': 0,
            'missing_dependency_index': [],
            'missing_direct_vars': [],
            'missing_sdk': []
        }
    
    # Find all service directories
    service_dirs = [d for d in csp_dir.iterdir() 
                   if d.is_dir() and not d.name.startswith('_') 
                   and not d.name.startswith('.') and d.name not in ['tools', 'backup']]
    
    services = []
    stats = {
        'csp': config['name'],
        'services': len(service_dirs),
        'sdk_files': 0,
        'dependency_index': 0,
        'direct_vars': 0,
        'complete': 0,
        'missing_dependency_index': [],
        'missing_direct_vars': [],
        'missing_sdk': []
    }
    
    for service_dir in service_dirs:
        service_name = service_dir.name
        has_sdk = (service_dir / config['sdk_file']).exists()
        has_dependency_index = (service_dir / 'dependency_index.json').exists()
        has_direct_vars = (service_dir / 'direct_vars.json').exists()
        
        if has_sdk:
            stats['sdk_files'] += 1
        else:
            stats['missing_sdk'].append(service_name)
        
        if has_dependency_index:
            stats['dependency_index'] += 1
        else:
            stats['missing_dependency_index'].append(service_name)
        
        if has_direct_vars:
            stats['direct_vars'] += 1
        else:
            stats['missing_direct_vars'].append(service_name)
        
        if has_sdk and has_dependency_index and has_direct_vars:
            stats['complete'] += 1
        
        services.append({
            'name': service_name,
            'sdk': has_sdk,
            'dependency_index': has_dependency_index,
            'direct_vars': has_direct_vars,
            'complete': has_sdk and has_dependency_index and has_direct_vars
        })
    
    # Determine overall status
    if stats['complete'] == stats['services']:
        stats['status'] = 'COMPLETE'
    elif stats['complete'] == 0:
        stats['status'] = 'INCOMPLETE'
    else:
        stats['status'] = 'PARTIAL'
    
    stats['services_detail'] = services
    return stats

def main():
    base_dir = Path(__file__).parent
    results = {}
    
    print("="*80)
    print("CSP STRUCTURE AUDIT")
    print("="*80)
    print()
    
    for csp_name in CSP_CONFIG.keys():
        stats = audit_csp(csp_name, base_dir)
        results[csp_name] = stats
        
        print(f"{stats['csp']} ({stats['status']}):")
        print(f"  Total Services: {stats['services']}")
        print(f"  SDK Dependencies: {stats['sdk_files']}/{stats['services']} ({stats['sdk_files']*100//stats['services'] if stats['services'] > 0 else 0}%)")
        print(f"  Dependency Index: {stats['dependency_index']}/{stats['services']} ({stats['dependency_index']*100//stats['services'] if stats['services'] > 0 else 0}%)")
        print(f"  Direct Vars: {stats['direct_vars']}/{stats['services']} ({stats['direct_vars']*100//stats['services'] if stats['services'] > 0 else 0}%)")
        print(f"  Complete (all 3 files): {stats['complete']}/{stats['services']} ({stats['complete']*100//stats['services'] if stats['services'] > 0 else 0}%)")
        
        if stats['missing_dependency_index']:
            print(f"  Missing dependency_index.json: {len(stats['missing_dependency_index'])} services")
            if len(stats['missing_dependency_index']) <= 10:
                print(f"    {', '.join(stats['missing_dependency_index'])}")
        
        if stats['missing_direct_vars']:
            print(f"  Missing direct_vars.json: {len(stats['missing_direct_vars'])} services")
            if len(stats['missing_direct_vars']) <= 10:
                print(f"    {', '.join(stats['missing_direct_vars'])}")
        
        print()
    
    # Save detailed results
    output_file = base_dir / 'csp_structure_audit_results.json'
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Detailed results saved to: {output_file}")
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    total_missing_di = sum(len(r['missing_dependency_index']) for r in results.values())
    total_missing_dv = sum(len(r['missing_direct_vars']) for r in results.values())
    
    print(f"Total services missing dependency_index.json: {total_missing_di}")
    print(f"Total services missing direct_vars.json: {total_missing_dv}")
    
    # Priority list
    print("\nPriority Order (by missing files):")
    priority = sorted(results.items(), 
                     key=lambda x: len(x[1]['missing_dependency_index']) + len(x[1]['missing_direct_vars']),
                     reverse=True)
    
    for csp_name, stats in priority:
        total_missing = len(stats['missing_dependency_index']) + len(stats['missing_direct_vars'])
        if total_missing > 0:
            print(f"  {stats['csp']}: {total_missing} missing files "
                  f"({len(stats['missing_dependency_index'])} DI, {len(stats['missing_direct_vars'])} DV)")

if __name__ == '__main__':
    main()

