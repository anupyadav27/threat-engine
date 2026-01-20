#!/usr/bin/env python3
"""
Quick EC2 Test: Mumbai Region Only
Tests EC2 service in ap-south-1 region with all optimizations.
"""
import os
import sys
import time
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.main_scanner import scan

# Set output directory
output_dir = os.path.join(os.path.dirname(__file__), "..", "..", "engines-output", "aws-configScan-engine", "output")
os.environ["OUTPUT_DIR"] = output_dir
os.makedirs(output_dir, exist_ok=True)

import sys
sys.stdout.flush()

print("="*80)
print("QUICK EC2 TEST: Mumbai (ap-south-1)")
print("="*80)
sys.stdout.flush()
print(f"Output directory: {output_dir}")
print(f"Service: EC2")
print(f"Region: ap-south-1 (Mumbai)")
print()
print("Optimizations Active:")
print("  ✅ Default pagination: MaxResults: 1000 (automatic)")
print("  ✅ Customer-managed filters: OwnerIds/Owners")
print("  ✅ Boto3 paginators with fallbacks")
print("  ✅ Operation timeouts: 300s")
print("  ✅ AWS-managed resource filtering")
print("-" * 80)

# Track start time
start_time = time.time()
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

# Run scan
print(f"\n🚀 Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}...")
print()

try:
    summary = scan(
        include_services=["ec2"],  # EC2 only
        include_regions=["ap-south-1"],  # Mumbai only
        max_total_workers=100,
        stream_results=True,
        save_report=False,
        output_scan_id=f"test_ec2_mumbai_{timestamp}"
    )
    
    # Calculate elapsed time
    elapsed_time = time.time() - start_time
    
    print()
    print("-" * 80)
    print("SCAN COMPLETE")
    print("-" * 80)
    print(f"⏱️  Total time: {elapsed_time:.2f} seconds ({elapsed_time/60:.2f} minutes)")
    print(f"📊 Summary:")
    print(f"   Total checks: {summary.get('total_checks', 0):,}")
    print(f"   ✓ Passed: {summary.get('passed_checks', 0):,}")
    print(f"   ✗ Failed: {summary.get('failed_checks', 0):,}")
    
    # Check for results files
    scan_folder = os.path.join(output_dir, f"test_ec2_mumbai_{timestamp}")
    if os.path.exists(scan_folder):
        results_files = [f for f in os.listdir(scan_folder) if f.startswith("results_") and f.endswith(".ndjson")]
        inventory_files = [f for f in os.listdir(scan_folder) if f.startswith("inventory_") and f.endswith(".ndjson")]
        
        if results_files:
            print(f"\n📁 Results files ({len(results_files)}):")
            for file in sorted(results_files):
                filepath = os.path.join(scan_folder, file)
                size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
                lines = sum(1 for _ in open(filepath)) if os.path.exists(filepath) and size > 0 else 0
                print(f"   - {file} ({lines} lines, {size:,} bytes)")
        
        if inventory_files:
            print(f"\n📦 Inventory files ({len(inventory_files)}):")
            for file in sorted(inventory_files):
                filepath = os.path.join(scan_folder, file)
                size = os.path.getsize(filepath) if os.path.exists(filepath) else 0
                lines = sum(1 for _ in open(filepath)) if os.path.exists(filepath) and size > 0 else 0
                print(f"   - {file} ({lines} lines, {size:,} bytes)")
    
    print()
    print("="*80)
    
except Exception as e:
    elapsed_time = time.time() - start_time
    print(f"\n❌ Error during scan: {e}")
    print(f"Scan ran for {elapsed_time:.2f} seconds before error")
    import traceback
    traceback.print_exc()
    sys.exit(1)

