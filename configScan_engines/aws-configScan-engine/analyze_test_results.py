#!/usr/bin/env python3
"""
Analyze test scan results for S3 and EC2 optimization test
"""
import os
import sys
import json
import time
from pathlib import Path

def analyze_scan_results(scan_id='test_optimizations_s3_ec2_all_accounts'):
    """Analyze scan results"""
    
    base_dir = Path(__file__).parent.parent.parent / 'engines-output' / 'aws-configScan-engine' / 'output' / scan_id
    
    print('='*80)
    print('SCAN RESULTS ANALYSIS')
    print('='*80)
    print()
    
    # Check if scan completed
    summary_file = base_dir / 'summary.json'
    scan_log = base_dir / 'logs' / 'scan.log'
    
    if not summary_file.exists():
        print('⏳ Scan still running or not completed yet')
        print(f'   Check log: {scan_log}')
        return
    
    # Load summary
    with open(summary_file) as f:
        summary = json.load(f)
    
    print('📊 SCAN SUMMARY')
    print('-'*80)
    print(f"Scan ID: {scan_id}")
    print(f"Duration: {summary.get('duration_seconds', 0):.2f} seconds ({summary.get('duration_seconds', 0)/60:.2f} minutes)")
    print(f"Total checks: {summary.get('total_checks', 0):,}")
    print(f"  ✅ PASS: {summary.get('passed_checks', 0):,}")
    print(f"  ❌ FAIL: {summary.get('failed_checks', 0):,}")
    print(f"Services scanned: {summary.get('services_scanned', 0)}")
    print(f"Accounts: {len(summary.get('accounts', []))}")
    print(f"Regions: {len(summary.get('regions', []))}")
    print()
    
    # Check for optimization indicators in logs
    if scan_log.exists():
        print('🔍 OPTIMIZATION INDICATORS')
        print('-'*80)
        
        with open(scan_log, 'r') as f:
            log_content = f.read()
        
        # Count parallel processing occurrences
        parallel_discoveries = log_content.count('Processing') + log_content.count('independent discoveries in parallel')
        independent_parallel = log_content.count('independent discoveries in parallel')
        for_each_parallel = log_content.count('Starting parallel execution')
        
        print(f"✅ Parallel independent discoveries detected: {independent_parallel} occurrences")
        print(f"✅ Parallel for_each execution: {for_each_parallel} occurrences")
        print()
        
        # Extract completion times
        import re
        completion_times = re.findall(r'Completed discovery.*?(\d+\.\d+)s', log_content)
        if completion_times:
            times = [float(t) for t in completion_times]
            print(f"Discovery completion times:")
            print(f"  Min: {min(times):.2f}s")
            print(f"  Max: {max(times):.2f}s")
            print(f"  Avg: {sum(times)/len(times):.2f}s")
            print()
    
    # Performance analysis
    print('⚡ PERFORMANCE ANALYSIS')
    print('-'*80)
    total_tasks = summary.get('total_tasks', 0)
    duration = summary.get('duration_seconds', 0)
    
    if total_tasks > 0 and duration > 0:
        tasks_per_second = total_tasks / duration
        print(f"Total tasks: {total_tasks}")
        print(f"Tasks/second: {tasks_per_second:.2f}")
        print()
    
    # Services breakdown
    if 'services' in summary:
        print('📦 SERVICES BREAKDOWN')
        print('-'*80)
        for service, data in summary.get('services', {}).items():
            checks = data.get('checks', 0)
            passed = data.get('passed', 0)
            failed = data.get('failed', 0)
            print(f"{service}:")
            print(f"  Checks: {checks:,} (✅ {passed:,}, ❌ {failed:,})")
        print()
    
    print('='*80)
    print('✅ Analysis complete')
    print('='*80)

if __name__ == '__main__':
    analyze_scan_results()

