"""
Simple reporting utility for Azure compliance scans.
Creates clean, uniform output structure matching AWS format.
"""

import json
import os
from datetime import datetime
from typing import List, Dict, Any


def save_scan_results(results: List[Dict[str, Any]], scan_folder: str) -> None:
    """
    Save scan results in clean, uniform format.
    
    Args:
        results: List of scan results from service_scanner
        scan_folder: Output folder path
    
    Creates:
        - {subscription_id}/
            - {region}_keyvault_inventory.json
            - {region}_keyvault_checks.json
        - summary.json
    """
    
    # Organize by subscription
    by_subscription = {}
    
    for result in results:
        subscription = result.get('subscription', 'unknown')
        service = result.get('service', 'unknown')
        location = result.get('location', 'global')
        scope = result.get('scope', 'regional')
        
        if subscription not in by_subscription:
            by_subscription[subscription] = {}
        
        # Create unique key for this service/location combo
        key = f"{location}_{service}" if scope == 'regional' else f"global_{service}"
        
        by_subscription[subscription][key] = result
    
    # Save per subscription
    for subscription_id, sub_results in by_subscription.items():
        sub_folder = os.path.join(scan_folder, f"subscription_{subscription_id}")
        os.makedirs(sub_folder, exist_ok=True)
        
        for result_key, result in sub_results.items():
            service = result.get('service')
            location = result.get('location', 'global')
            
            # Save inventory
            if result.get('inventory'):
                inventory_file = os.path.join(sub_folder, f"{result_key}_inventory.json")
                inventory_data = {
                    'service': service,
                    'subscription': subscription_id,
                    'location': location,
                    'discovered': result['inventory'],
                    'count': sum(len(v) for v in result['inventory'].values()) if isinstance(result['inventory'], dict) else 0,
                    'timestamp': datetime.utcnow().isoformat() + 'Z'
                }
                
                with open(inventory_file, 'w') as f:
                    json.dump(inventory_data, f, indent=2, default=str)
            
            # Save checks
            if result.get('checks'):
                checks_file = os.path.join(sub_folder, f"{result_key}_checks.json")
                
                # Calculate summary
                passed = sum(1 for c in result['checks'] if c.get('result') == 'PASS')
                failed = sum(1 for c in result['checks'] if c.get('result') == 'FAIL')
                errors = sum(1 for c in result['checks'] if c.get('result') == 'ERROR')
                
                checks_data = {
                    'service': service,
                    'subscription': subscription_id,
                    'location': location,
                    'checks': result['checks'],
                    'summary': {
                        'total': len(result['checks']),
                        'passed': passed,
                        'failed': failed,
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
            'total_subscriptions': len(by_subscription),
            'total_services': len(set(r.get('service') for r in results)),
            'total_locations': len(set(r.get('location') for r in results))
        },
        'summary': {
            'total_checks': total_checks,
            'passed': total_passed,
            'failed': total_failed,
            'errors': total_errors,
            'total_resources': total_resources
        },
        'subscriptions': list(by_subscription.keys()),
        'services': list(set(r.get('service') for r in results)),
        'locations': list(set(r.get('location') for r in results))
    }
    
    summary_file = os.path.join(scan_folder, 'summary.json')
    with open(summary_file, 'w') as f:
        json.dump(summary_data, f, indent=2)
    
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
    
    return scan_folder


if __name__ == '__main__':
    print("Simple Reporter Utility - Uniform CSP Output")
    print()
    print("This module creates uniform output structure:")
    print("  - subscription_{id}/")
    print("    - {location}_{service}_inventory.json")
    print("    - {location}_{service}_checks.json")
    print("  - summary.json")
    print("  - latest -> scan_YYYYMMDD_HHMMSS")

