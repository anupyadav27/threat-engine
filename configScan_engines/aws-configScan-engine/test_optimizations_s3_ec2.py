#!/usr/bin/env python3
"""
Test optimizations on S3 and EC2 services for one account
"""
import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from engine.main_scanner import scan

# Set output directory
os.environ['OUTPUT_DIR'] = os.path.join(os.path.dirname(__file__), '..', '..', 'engines-output', 'aws-configScan-engine', 'output')

print('='*80)
print('TESTING OPTIMIZATIONS: S3 + EC2')
print('='*80)
print()
print('Services: s3, ec2')
print('Configuration:')
print('  - MAX_DISCOVERY_WORKERS: 20 (parallel independent discoveries)')
print('  - FOR_EACH_MAX_WORKERS: 50 (parallel for_each items, up from 20)')
print('  - max_total_workers: 50 (service-level parallelism)')
print()

print('Testing: ALL accounts, ALL enabled regions, S3 + EC2')
print('Note: Using enabled regions only (code automatically does this)')
print()

start_time = time.time()

# Test scan: S3 and EC2 for ALL accounts, ALL enabled regions
# The code automatically uses list_enabled_regions() which returns only enabled regions
try:
    summary = scan(
        # No account specified = scans all accounts
        include_services=['s3', 'ec2'],
        max_total_workers=100,
        stream_results=True,
        save_report=True,  # Save report for analysis
        output_scan_id='test_optimizations_s3_ec2_all_accounts'
    )
    
    elapsed = time.time() - start_time
    
    print()
    print('='*80)
    print('TEST SCAN COMPLETE')
    print('='*80)
    print(f'Duration: {elapsed:.2f} seconds ({elapsed/60:.2f} minutes)')
    print(f'Total checks: {summary.get("total_checks", 0):,}')
    print(f'  PASS: {summary.get("passed_checks", 0):,}')
    print(f'  FAIL: {summary.get("failed_checks", 0):,}')
    print(f'Services scanned: {summary.get("services_scanned", 0)}')
    print(f'Report folder: {summary.get("report_folder", "N/A")}')
    print()
    print('✅ Optimizations tested successfully!')
    print('='*80)
    
except Exception as e:
    import traceback
    print(f'❌ Error during test: {e}')
    print(traceback.format_exc())
    sys.exit(1)

