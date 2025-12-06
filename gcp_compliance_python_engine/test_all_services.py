#!/usr/bin/env python3
"""
Test All GCP Services Systematically

Tests each service one by one to validate:
1. No engine errors
2. Discovery works (finds resources or returns empty cleanly)
3. Checks execute without errors
4. Reports pass/fail rates

Output: Detailed report of which services work and which need fixes.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.gcp_engine import (
    load_service_catalog,
    run_service_compliance,
    list_all_projects
)
import json

# Test configuration
TEST_PROJECT = os.getenv('GCP_PROJECTS', 'test-2277')
TEST_REGION = 'us-central1'

def test_service(service_name: str, scope: str, project_id: str) -> dict:
    """Test a single service"""
    try:
        if scope == 'global':
            result = run_service_compliance(service_name, project_id, region=None)
        else:
            result = run_service_compliance(service_name, project_id, region=TEST_REGION)
        
        checks = result.get('checks', [])
        inventory = result.get('inventory', {})
        error = result.get('error')
        
        # Count inventory items
        inv_count = sum(len(v) if isinstance(v, list) else 1 for v in inventory.values() if v)
        
        # Count checks
        pass_count = sum(1 for c in checks if c.get('result') == 'PASS')
        fail_count = sum(1 for c in checks if c.get('result') == 'FAIL')
        
        return {
            'service': service_name,
            'scope': scope,
            'status': 'ERROR' if error else 'OK',
            'error': error,
            'inventory_items': inv_count,
            'total_checks': len(checks),
            'pass': pass_count,
            'fail': fail_count,
            'pass_rate': round(pass_count / len(checks) * 100, 1) if checks else 0
        }
        
    except Exception as e:
        return {
            'service': service_name,
            'scope': scope,
            'status': 'EXCEPTION',
            'error': str(e),
            'inventory_items': 0,
            'total_checks': 0,
            'pass': 0,
            'fail': 0,
            'pass_rate': 0
        }


def main():
    print('=' * 70)
    print('GCP COMPLIANCE ENGINE - COMPREHENSIVE SERVICE TEST')
    print('=' * 70)
    print()
    
    # Load catalog
    catalog = load_service_catalog()
    
    # Get test projects
    projects = [TEST_PROJECT] if TEST_PROJECT else [p['projectId'] for p in list_all_projects()]
    test_project = projects[0] if projects else None
    
    if not test_project:
        print('❌ No test project available')
        return
    
    print(f'Test Project: {test_project}')
    print(f'Test Region: {TEST_REGION} (for regional services)')
    print()
    
    results = []
    
    # Test each service
    for svc_config in catalog:
        service_name = svc_config.get('name')
        scope = svc_config.get('scope', 'global')
        enabled = svc_config.get('enabled', True)
        
        if not enabled:
            continue
        
        print(f'Testing {service_name} ({scope})...', end=' ')
        
        result = test_service(service_name, scope, test_project)
        results.append(result)
        
        # Print immediate result
        if result['status'] == 'OK':
            if result['total_checks'] > 0:
                print(f"✅ {result['total_checks']} checks ({result['pass_rate']}% pass)")
            elif result['inventory_items'] > 0:
                print(f"✅ {result['inventory_items']} items discovered, 0 checks")
            else:
                print(f"✅ No resources (API may be disabled)")
        else:
            print(f"❌ {result['status']}: {result['error'][:50]}...")
    
    # Summary
    print()
    print('=' * 70)
    print('SUMMARY')
    print('=' * 70)
    
    ok_services = [r for r in results if r['status'] == 'OK']
    error_services = [r for r in results if r['status'] != 'OK']
    services_with_checks = [r for r in ok_services if r['total_checks'] > 0]
    services_with_inventory = [r for r in ok_services if r['inventory_items'] > 0]
    
    print(f"Total services tested: {len(results)}")
    print(f"✅ Ran without errors: {len(ok_services)}")
    print(f"❌ Had errors: {len(error_services)}")
    print(f"📊 Services with checks executed: {len(services_with_checks)}")
    print(f"📦 Services with inventory: {len(services_with_inventory)}")
    print()
    
    if services_with_checks:
        total_checks = sum(r['total_checks'] for r in services_with_checks)
        total_pass = sum(r['pass'] for r in services_with_checks)
        print(f"Total checks executed: {total_checks}")
        print(f"Total PASS: {total_pass} ({round(total_pass/total_checks*100, 1)}%)")
        print()
    
    if error_services:
        print("Services with errors:")
        for r in error_services:
            print(f"  ❌ {r['service']}: {r['error'][:80]}")
    
    print()
    print(f"✅ Engine Status: {'ALL SERVICES CLEAN' if len(error_services) == 0 else f'{len(error_services)} services need fixes'}")
    
    # Save detailed results
    with open('service_test_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n📄 Detailed results saved to: service_test_results.json")


if __name__ == '__main__':
    main()

