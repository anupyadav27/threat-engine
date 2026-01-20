#!/usr/bin/env python3
"""Performance comparison test - Run test scan for common services and compare with baseline"""
import os
import sys
import time
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.main_scanner import scan

# Set output directory
output_dir = "/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output"
os.environ["OUTPUT_DIR"] = output_dir
os.makedirs(output_dir, exist_ok=True)

# Common services to test (7-10 services)
# These are representative services that were likely tested before
TEST_SERVICES = [
    's3',          # Global, fast
    'ec2',         # Regional, many resources
    'iam',         # Global, important
    'rds',         # Regional, moderate resources
    'lambda',      # Regional, moderate
    'kms',         # Regional, moderate
    'cloudtrail',  # Regional, moderate
    'sns',         # Regional, moderate
]

# Test configuration
TEST_ACCOUNT = "588989875114"  # Single test account
TEST_REGION = "us-east-1"      # Single region for faster test
WORKER_CONFIGS = [20, 50]      # Test with both 20 and 50 workers

print("="*80)
print("PERFORMANCE COMPARISON TEST")
print("="*80)
print(f"Services: {', '.join(TEST_SERVICES)} ({len(TEST_SERVICES)} services)")
print(f"Account: {TEST_ACCOUNT}")
print(f"Region: {TEST_REGION}")
print(f"Worker configs: {WORKER_CONFIGS}")
print("-"*80)

results = []

for max_workers in WORKER_CONFIGS:
    print(f"\n🧪 Testing with max_total_workers={max_workers}...")
    
    scan_id = f"perf_test_{max_workers}workers_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    start_time = time.time()
    
    try:
        summary = scan(
            include_accounts=[TEST_ACCOUNT],
            include_services=TEST_SERVICES,
            include_regions=[TEST_REGION],
            max_total_workers=max_workers,
            stream_results=True,
            save_report=False,
            output_scan_id=scan_id
        )
        
        elapsed_time = time.time() - start_time
        
        result = {
            "workers": max_workers,
            "duration_seconds": elapsed_time,
            "duration_minutes": elapsed_time / 60,
            "total_checks": summary.get('total_checks', 0),
            "passed_checks": summary.get('passed_checks', 0),
            "failed_checks": summary.get('failed_checks', 0),
            "services_scanned": len(TEST_SERVICES),
            "scan_id": scan_id
        }
        
        results.append(result)
        
        print(f"  ✓ Completed in {elapsed_time/60:.2f} minutes")
        print(f"    Checks: {result['total_checks']:,} (PASS: {result['passed_checks']:,}, FAIL: {result['failed_checks']:,})")
        
    except Exception as e:
        print(f"  ✗ Failed: {e}")
        import traceback
        traceback.print_exc()

# Comparison report
print("\n" + "="*80)
print("PERFORMANCE COMPARISON RESULTS")
print("="*80)

if len(results) >= 2:
    baseline = results[0]
    optimized = results[1]
    
    print(f"\n📊 BASELINE (max_total_workers={baseline['workers']}):")
    print(f"  Duration: {baseline['duration_minutes']:.2f} minutes")
    print(f"  Total checks: {baseline['total_checks']:,}")
    
    print(f"\n⚡ OPTIMIZED (max_total_workers={optimized['workers']}):")
    print(f"  Duration: {optimized['duration_minutes']:.2f} minutes")
    print(f"  Total checks: {optimized['total_checks']:,}")
    
    improvement = ((baseline['duration_seconds'] - optimized['duration_seconds']) / baseline['duration_seconds']) * 100
    speedup = baseline['duration_seconds'] / optimized['duration_seconds'] if optimized['duration_seconds'] > 0 else 0
    
    print(f"\n📈 IMPROVEMENT:")
    print(f"  Time saved: {baseline['duration_seconds'] - optimized['duration_seconds']:.1f}s ({baseline['duration_minutes'] - optimized['duration_minutes']:.2f} minutes)")
    print(f"  Improvement: {improvement:.1f}% faster")
    print(f"  Speedup: {speedup:.2f}x")
    
    if speedup > 1.5:
        print(f"  ✅ Significant improvement! {speedup:.1f}x faster with {optimized['workers']} workers")
    elif speedup > 1.1:
        print(f"  ✓ Good improvement: {speedup:.1f}x faster")
    else:
        print(f"  ⚠️  Limited improvement - may need further optimization")
        
elif len(results) == 1:
    result = results[0]
    print(f"\n📊 SINGLE TEST RESULT (max_total_workers={result['workers']}):")
    print(f"  Duration: {result['duration_minutes']:.2f} minutes")
    print(f"  Total checks: {result['total_checks']:,}")

# Save results
results_file = os.path.join(output_dir, f"perf_comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
with open(results_file, 'w') as f:
    json.dump({
        "test_config": {
            "services": TEST_SERVICES,
            "account": TEST_ACCOUNT,
            "region": TEST_REGION
        },
        "results": results
    }, f, indent=2)

print(f"\n💾 Results saved to: {results_file}")
print("="*80)


