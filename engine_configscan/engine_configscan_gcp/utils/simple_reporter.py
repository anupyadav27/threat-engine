"""
Simple reporting utility for GCP compliance scans.
Creates clean, uniform output structure matching AWS/Azure format.
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any


def save_scan_results(results: List[Dict[str, Any]], scan_folder: str) -> str:
    """
    Save scan results in clean, uniform format.
    
    Args:
        results: List of scan results from service_scanner
        scan_folder: Output folder path
    
    Creates:
        - project_{id}/
            - {region}_{service}_inventory.json
            - {region}_{service}_checks.json
        - summary.json
        - latest symlink
    
    Returns:
        Path to scan folder
    """
    
    # Organize by project
    by_project = {}
    
    for result in results:
        project = result.get('project', 'unknown')
        service = result.get('service', 'unknown')
        region = result.get('region', 'global')
        scope = result.get('scope', 'regional')
        
        if project not in by_project:
            by_project[project] = {}
        
        # Create unique key for this service/region combo
        key = f"{region}_{service}" if scope == 'regional' else f"global_{service}"
        
        by_project[project][key] = result
    
    # Save per project
    for project_id, proj_results in by_project.items():
        proj_folder = os.path.join(scan_folder, f"project_{project_id}")
        os.makedirs(proj_folder, exist_ok=True)
        
        for result_key, result in proj_results.items():
            service = result.get('service')
            region = result.get('region', 'global')
            
            # Save inventory
            if result.get('inventory'):
                inventory_file = os.path.join(proj_folder, f"{result_key}_inventory.json")
                inventory_data = {
                    'service': service,
                    'project': project_id,
                    'region': region,
                    'discovered': result['inventory'],
                    'count': sum(len(v) for v in result['inventory'].values()) if isinstance(result['inventory'], dict) else 0,
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                }
                
                with open(inventory_file, 'w') as f:
                    json.dump(inventory_data, f, indent=2, default=str)
            
            # Save checks
            if result.get('checks'):
                checks_file = os.path.join(proj_folder, f"{result_key}_checks.json")
                
                # Calculate summary
                passed = sum(1 for c in result['checks'] if c.get('result') == 'PASS')
                failed = sum(1 for c in result['checks'] if c.get('result') == 'FAIL')
                skipped = sum(1 for c in result['checks'] if c.get('result') == 'SKIP')
                errors = sum(1 for c in result['checks'] if c.get('result') == 'ERROR')
                
                checks_data = {
                    'service': service,
                    'project': project_id,
                    'region': region,
                    'checks': result['checks'],
                    'summary': {
                        'total': len(result['checks']),
                        'passed': passed,
                        'failed': failed,
                        'skipped': skipped,
                        'errors': errors
                    },
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                }
                
                with open(checks_file, 'w') as f:
                    json.dump(checks_data, f, indent=2, default=str)
    
    # Create overall summary
    total_checks = sum(len(r.get('checks', [])) for r in results)
    total_passed = sum(sum(1 for c in r.get('checks', []) if c.get('result') == 'PASS') for r in results)
    total_failed = sum(sum(1 for c in r.get('checks', []) if c.get('result') == 'FAIL') for r in results)
    total_skipped = sum(sum(1 for c in r.get('checks', []) if c.get('result') == 'SKIP') for r in results)
    total_errors = sum(sum(1 for c in r.get('checks', []) if c.get('result') == 'ERROR') for r in results)
    
    total_resources = 0
    for r in results:
        if r.get('inventory'):
            if isinstance(r['inventory'], dict):
                total_resources += sum(len(v) for v in r['inventory'].values())
            elif isinstance(r['inventory'], list):
                total_resources += len(r['inventory'])
    
    summary_data = {
        'metadata': {
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'scan_folder': scan_folder,
            'total_projects': len(by_project),
            'total_services': len(set(r.get('service') for r in results)),
            'total_regions': len(set(r.get('region') for r in results))
        },
        'summary': {
            'total_checks': total_checks,
            'passed': total_passed,
            'failed': total_failed,
            'skipped': total_skipped,
            'errors': total_errors,
            'total_resources': total_resources,
            'compliance_rate': round(100.0 * total_passed / total_checks, 2) if total_checks > 0 else 0
        },
        'projects': list(by_project.keys()),
        'services': sorted(list(set(r.get('service') for r in results))),
        'regions': sorted(list(set(r.get('region') for r in results)))
    }
    
    summary_file = os.path.join(scan_folder, 'summary.json')
    with open(summary_file, 'w') as f:
        json.dump(summary_data, f, indent=2)
    
    # Create index file listing all project folders
    index_data = {
        'metadata': {
            'generated_at': datetime.utcnow().isoformat() + 'Z',
            'scan_folder': scan_folder
        },
        'project_folders': [f"project_{pid}" for pid in by_project.keys()],
        'summary': summary_data['summary']
    }
    
    index_file = os.path.join(scan_folder, 'index.json')
    with open(index_file, 'w') as f:
        json.dump(index_data, f, indent=2)
    
    # Create latest symlink
    output_dir = os.path.dirname(scan_folder)
    latest_link = os.path.join(output_dir, 'latest')
    
    # Remove old symlink
    if os.path.islink(latest_link):
        os.unlink(latest_link)
    elif os.path.exists(latest_link):
        import shutil
        shutil.rmtree(latest_link)
    
    # Create new symlink
    os.symlink(os.path.basename(scan_folder), latest_link)
    
    print(f"\n✅ Results saved to:")
    print(f"   {scan_folder}")
    print(f"   {latest_link} -> {os.path.basename(scan_folder)}")
    print(f"\n📊 Summary:")
    print(f"   Projects: {len(by_project)}")
    print(f"   Services: {summary_data['metadata']['total_services']}")
    print(f"   Total Checks: {total_checks}")
    print(f"   Passed: {total_passed}")
    print(f"   Failed: {total_failed}")
    if total_skipped > 0:
        print(f"   Skipped: {total_skipped}")
    
    return scan_folder


if __name__ == '__main__':
    print("Simple Reporter Utility - Uniform CSP Output (GCP)")
    print()
    print("This module creates uniform output structure:")
    print("  - project_{id}/")
    print("    - {region}_{service}_inventory.json")
    print("    - {region}_{service}_checks.json")
    print("  - summary.json")
    print("  - index.json")
    print("  - latest -> scan_YYYYMMDD_HHMMSS")
