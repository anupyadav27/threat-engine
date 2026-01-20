#!/usr/bin/env python3
"""Quick test script to run scanner locally with performance tracking"""
import os
import sys
import time

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.main_scanner import scan

# Set output directory
output_dir = "/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output"
os.environ["OUTPUT_DIR"] = output_dir
os.makedirs(output_dir, exist_ok=True)

print("="*80)
print("PERFORMANCE TEST: S3 Service Only")
print("="*80)
print(f"Output directory: {output_dir}")
print("Services: s3")
print("Account: Single account (588989875114)")
print("Region: us-east-1")
print("-" * 80)

# Track start time
start_time = time.time()

# Run scan with FLATTENED model (maximum parallelism)
# This creates one task per (account, region, service) combination
# All tasks run in a single ThreadPoolExecutor for maximum speed
summary = scan(
    include_accounts=["588989875114"],  # Single account for testing
    include_services=["s3"],  # S3 service only
    include_regions=["us-east-1"],  # One region for testing
    max_total_workers=20,  # FLATTENED MODEL: All service tasks run in parallel
    stream_results=True,  # Write NDJSON incrementally
    save_report=False,    # Skip heavy report bundle
    output_scan_id="test_s3_minimal"
)

# Calculate elapsed time
elapsed_time = time.time() - start_time

print("-" * 80)
print("SCAN COMPLETE - PERFORMANCE METRICS")
print("-" * 80)
print(f"⏱️  Total time: {elapsed_time:.2f} seconds ({elapsed_time/60:.2f} minutes)")
print(f"📊 Summary: {summary.get('total_checks')} checks")
print(f"   ✓ Passed: {summary.get('passed_checks')}")
print(f"   ✗ Failed: {summary.get('failed_checks')}")

if summary.get('results_files'):
    print(f"📁 Results files: {len(summary.get('results_files', []))} account+region files")
    print(f"📁 Inventory files: {len(summary.get('inventory_files', []))} account+region files")
    
    # Calculate throughput
    total_tasks = len(summary.get('results_files', []))
    if elapsed_time > 0:
        tasks_per_sec = total_tasks / elapsed_time
        print(f"⚡ Throughput: {tasks_per_sec:.2f} tasks/second")
        print(f"⚡ Avg time per task: {elapsed_time/total_tasks:.2f} seconds")
else:
    print(f"📁 Results file: {summary.get('results_file')}")

print(f"📂 Report folder: {summary.get('report_folder')}")

# Check for log file
scan_folder = summary.get('report_folder')
if scan_folder:
    log_file = os.path.join(scan_folder, "logs", "scan.log")
    if os.path.exists(log_file):
        print(f"📝 Log file: {log_file}")
        log_size = os.path.getsize(log_file)
        print(f"   Log size: {log_size / 1024:.1f} KB")
print("="*80)

