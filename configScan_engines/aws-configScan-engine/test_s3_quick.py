#!/usr/bin/env python3
"""Quick S3 scan test without streaming to check if scan completes"""
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
print("S3 SCAN TEST (NON-STREAMING)")
print("="*80)

# Track start time
start_time = time.time()

try:
    # Run scan WITHOUT streaming - let it collect all results in memory then write at end
    summary = scan(
        include_accounts=["588989875114"],
        include_services=["s3"],
        include_regions=["us-east-1"],
        max_total_workers=20,  # Flattened model
        stream_results=False,  # NO STREAMING - write at end
        save_report=True,      # Generate full report
        output_scan_id="test_s3_quick"
    )
    
    elapsed_time = time.time() - start_time
    
    print("-" * 80)
    print("✅ SCAN COMPLETED SUCCESSFULLY")
    print("-" * 80)
    print(f"⏱️  Total time: {elapsed_time:.2f} seconds")
    print(f"📊 Checks: {summary.get('total_checks')}")
    print(f"   ✓ Passed: {summary.get('passed_checks')}")
    print(f"   ✗ Failed: {summary.get('failed_checks')}")
    print(f"📂 Output: {summary.get('report_folder')}")
    print("="*80)
    
except Exception as e:
    elapsed_time = time.time() - start_time
    print(f"\n❌ SCAN FAILED after {elapsed_time:.2f} seconds")
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()

