#!/usr/bin/env python3
"""
Finalize all AWS services by running finalize_service.py on each service folder.

Generates a summary report with:
- services_pass, services_warn, services_fail
- services_with_conflicts
- services_with_remaining_manual_review
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime
import subprocess

def finalize_all_services(root_path: Path) -> Dict[str, Any]:
    """
    Finalize all services in the root directory.
    
    Returns summary report dictionary.
    """
    root_path = Path(root_path)
    if not root_path.exists():
        raise ValueError(f"Root path does not exist: {root_path}")
    
    # Find finalize_service.py script
    script_path = Path(__file__).parent / "finalize_service.py"
    if not script_path.exists():
        raise FileNotFoundError(f"finalize_service.py not found at {script_path}")
    
    print("=" * 70)
    print("FINALIZING ALL AWS SERVICES")
    print("=" * 70)
    print(f"Root path: {root_path}")
    print(f"Script: {script_path}")
    print()
    
    # Find all service folders
    service_folders = []
    for item in root_path.iterdir():
        if item.is_dir() and not item.name.startswith('.'):
            # Check if it looks like a service folder (has operation_registry.json or source spec)
            if (item / "operation_registry.json").exists() or \
               any(f.name.startswith("boto3_dependencies") for f in item.glob("*.json")):
                service_folders.append(item)
    
    service_folders.sort()
    
    print(f"Found {len(service_folders)} service folders")
    print()
    
    # Process each service
    results = []
    services_pass = []
    services_warn = []
    services_fail = []
    services_with_conflicts = []
    services_with_remaining_manual_review = []
    
    for i, service_folder in enumerate(service_folders, 1):
        service_name = service_folder.name
        print(f"[{i}/{len(service_folders)}] Processing {service_name}...")
        
        try:
            # Run finalize_service.py
            result = subprocess.run(
                [sys.executable, str(script_path), str(service_folder)],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout per service
            )
            
            # Parse result
            if result.returncode == 0:
                # Try to extract result from output or load from file
                result_file = service_folder / "finalize_result.json"
                if result_file.exists():
                    with open(result_file, 'r') as f:
                        service_result = json.load(f)
                else:
                    # Parse from stdout
                    service_result = {
                        'service': service_name,
                        'status': 'success',
                        'merged_aliases': 0,
                        'merged_params': 0,
                        'conflicts': [],
                        'accepted_suggestions': 0,
                        'rejected_suggestions': 0,
                        'errors': []
                    }
                
                results.append(service_result)
                
                # Categorize
                if service_result['status'] == 'success':
                    if service_result.get('conflicts'):
                        services_warn.append(service_name)
                        services_with_conflicts.append(service_name)
                    else:
                        services_pass.append(service_name)
                    
                    # Check for remaining manual review
                    mr_file = service_folder / "manual_review.json"
                    if mr_file.exists():
                        with open(mr_file, 'r') as f:
                            mr = json.load(f)
                            issues = mr.get('issues', {})
                            has_issues = any(
                                (isinstance(v, list) and len(v) > 0) or
                                (isinstance(v, dict) and any(len(items) > 0 for items in v.values()))
                                for v in issues.values()
                            )
                            if has_issues:
                                services_with_remaining_manual_review.append(service_name)
                else:
                    services_fail.append(service_name)
            else:
                # Failed
                services_fail.append(service_name)
                results.append({
                    'service': service_name,
                    'status': 'error',
                    'errors': [f"Process failed: {result.stderr[:200]}"]
                })
                print(f"  ❌ Failed: {result.stderr[:100]}")
        
        except subprocess.TimeoutExpired:
            services_fail.append(service_name)
            results.append({
                'service': service_name,
                'status': 'error',
                'errors': ['Timeout after 5 minutes']
            })
            print(f"  ❌ Timeout")
        
        except Exception as e:
            services_fail.append(service_name)
            results.append({
                'service': service_name,
                'status': 'error',
                'errors': [str(e)]
            })
            print(f"  ❌ Error: {e}")
    
    # Generate summary report
    summary = {
        'timestamp': datetime.now().isoformat(),
        'total_services': len(service_folders),
        'services_pass': len(services_pass),
        'services_warn': len(services_warn),
        'services_fail': len(services_fail),
        'services_with_conflicts': len(services_with_conflicts),
        'services_with_remaining_manual_review': len(services_with_remaining_manual_review),
        'services_pass_list': sorted(services_pass),
        'services_warn_list': sorted(services_warn),
        'services_fail_list': sorted(services_fail),
        'services_with_conflicts_list': sorted(services_with_conflicts),
        'services_with_remaining_manual_review_list': sorted(services_with_remaining_manual_review),
        'detailed_results': results
    }
    
    # Save summary report
    summary_file = root_path / "finalization_summary_report.json"
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    # Print summary
    print()
    print("=" * 70)
    print("FINALIZATION SUMMARY")
    print("=" * 70)
    print(f"Total services: {summary['total_services']}")
    print(f"  ✅ Pass: {summary['services_pass']}")
    print(f"  ⚠️  Warn (conflicts): {summary['services_warn']}")
    print(f"  ❌ Fail: {summary['services_fail']}")
    print(f"  🔀 With conflicts: {summary['services_with_conflicts']}")
    print(f"  📋 With remaining manual review: {summary['services_with_remaining_manual_review']}")
    print()
    print(f"Summary report saved to: {summary_file}")
    print("=" * 70)
    
    return summary


def main():
    """CLI entry point."""
    if len(sys.argv) < 2:
        print("Usage: finalize_all_services.py <root_path>")
        print("Example: finalize_all_services.py pythonsdk-database/aws")
        sys.exit(1)
    
    root_path = Path(sys.argv[1])
    
    try:
        summary = finalize_all_services(root_path)
        sys.exit(0 if summary['services_fail'] == 0 else 1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()

