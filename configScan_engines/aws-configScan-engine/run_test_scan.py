#!/usr/bin/env python3
"""Simple test scan runner with immediate output"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

print("="*80)
print("STARTING TEST SCAN")
print("="*80)
print()

# Import and run
try:
    from engine.main_scanner import scan
    from datetime import datetime
    import time
    
    print("✅ Imports successful")
    print(f"⏰ Start time: {datetime.now()}")
    print()
    
    start = time.time()
    
    summary = scan(
        include_services=["ec2", "inspector", "sagemaker"],
        max_total_workers=100,
        stream_results=True,
        save_report=False,
        output_scan_id=f"test_new_code_{int(time.time())}"
    )
    
    elapsed = time.time() - start
    
    print()
    print("="*80)
    print("SCAN COMPLETE")
    print("="*80)
    print(f"Time: {elapsed:.2f}s ({elapsed/60:.2f} min)")
    print(f"Checks: {summary.get('total_checks', 0)}")
    print(f"Passed: {summary.get('passed_checks', 0)}")
    print(f"Failed: {summary.get('failed_checks', 0)}")
    print("="*80)
    
except Exception as e:
    print(f"❌ ERROR: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

