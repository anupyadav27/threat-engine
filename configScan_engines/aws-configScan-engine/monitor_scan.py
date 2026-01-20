#!/usr/bin/env python3
"""
Monitor test scan progress
"""
import time
import os
from pathlib import Path

scan_id = 'test_optimizations_s3_ec2_all_accounts'
log_file = f'/tmp/test_optimizations_all.log'
scan_dir = Path(__file__).parent.parent.parent / 'engines-output' / 'aws-configScan-engine' / 'output' / scan_id
summary_file = scan_dir / 'summary.json'

print('='*80)
print('MONITORING SCAN PROGRESS')
print('='*80)
print()

# Check if scan is running
process_running = os.system(f'ps aux | grep -v grep | grep "{scan_id}" > /dev/null') == 0

if process_running:
    print('✅ Scan is running')
    
    # Check log for progress
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            lines = f.readlines()
            
        # Count completed discoveries
        completed = sum(1 for line in lines if 'Completed discovery' in line)
        
        # Look for optimization indicators
        parallel_independent = sum(1 for line in lines if 'independent discoveries in parallel' in line)
        parallel_foreach = sum(1 for line in lines if 'Starting parallel execution' in line)
        
        print(f'  Completed discoveries: {completed}')
        print(f'  Parallel independent discoveries batches: {parallel_independent}')
        print(f'  Parallel for_each executions: {parallel_foreach}')
        print()
        
        # Show recent activity
        print('Recent activity (last 5 discoveries):')
        for line in lines[-50:]:
            if 'Completed discovery' in line or 'Processing' in line and 'discoveries in parallel' in line:
                print(f'  {line.strip()[-100:]}')
else:
    print('⏸️  Scan process not found (may have completed)')

print()
if summary_file.exists():
    print('✅ Scan completed! Summary file exists.')
    print(f'   Path: {summary_file}')
else:
    print('⏳ Scan still running or not started yet')

print()
print('='*80)
