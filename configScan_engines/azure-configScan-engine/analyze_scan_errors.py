#!/usr/bin/env python3
"""
Analyze Azure compliance scan errors from log files
"""
import re
import glob
import os
import json

def analyze_scan_errors():
    # Find latest scan
    scan_folders = glob.glob('output/scan_*')
    latest_scan = sorted(scan_folders)[-1] if scan_folders else None
    
    if not latest_scan:
        print("❌ No scan found")
        return
    
    log_file = f'{latest_scan}/logs/scan.log'
    
    print("=" * 80)
    print("SCAN ERROR ANALYSIS")
    print("=" * 80)
    print(f"Scan: {latest_scan.split('/')[-1]}")
    print(f"Log: {log_file}")
    print()
    
    if not os.path.exists(log_file):
        print("❌ Log file not found")
        return
    
    # Read log
    with open(log_file, 'r') as f:
        content = f.read()
    
    # Extract errors
    errors = {
        'missing_sdk': set(),
        'missing_rules': set(),
        'failed_services': set(),
        'client_errors': set()
    }
    
    # Find patterns
    for line in content.split('\n'):
        # Missing SDK
        if 'No module named' in line or 'Failed to import' in line:
            match = re.search(r'azure\.mgmt\.([\w]+)', line)
            if match:
                errors['missing_sdk'].add(f"azure-mgmt-{match.group(1)}")
        
        # Missing rules
        if 'Rules file not found' in line:
            match = re.search(r'Rules file not found for (\w+)', line)
            if match:
                errors['missing_rules'].add(match.group(1))
        
        # Failed services
        if 'Service ' in line and 'failed' in line:
            match = re.search(r'Service (\w+) failed', line)
            if match:
                errors['failed_services'].add(match.group(1))
        
        # Client errors
        if 'Could not create client' in line:
            match = re.search(r'Could not create client for (\w+)', line)
            if match:
                errors['client_errors'].add(match.group(1))
    
    # Print summary
    print("📊 ERROR SUMMARY:")
    print(f"   Missing SDK packages: {len(errors['missing_sdk'])}")
    print(f"   Missing rule files: {len(errors['missing_rules'])}")
    print(f"   Failed services: {len(errors['failed_services'])}")
    print(f"   Client creation errors: {len(errors['client_errors'])}")
    print()
    
    if errors['missing_sdk']:
        print("=" * 80)
        print("MISSING SDK PACKAGES")
        print("=" * 80)
        for pkg in sorted(errors['missing_sdk']):
            print(f"   • {pkg}")
        print()
    
    if errors['missing_rules']:
        print("=" * 80)
        print("MISSING RULE FILES")
        print("=" * 80)
        for svc in sorted(errors['missing_rules']):
            print(f"   • {svc}")
        print()
    
    if errors['failed_services']:
        print("=" * 80)
        print("FAILED SERVICES")
        print("=" * 80)
        for svc in sorted(errors['failed_services']):
            print(f"   • {svc}")
        print()
    
    if errors['client_errors']:
        print("=" * 80)
        print("CLIENT CREATION ERRORS")
        print("=" * 80)
        for svc in sorted(errors['client_errors']):
            print(f"   • {svc}")
        print()

if __name__ == '__main__':
    analyze_scan_errors()

