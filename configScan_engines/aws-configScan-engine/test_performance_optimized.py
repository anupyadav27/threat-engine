#!/usr/bin/env python3
"""
Performance Test: EC2, Inspector, SageMaker
Tests the performance improvements from:
- Default pagination (MaxResults: 1000)
- Customer-managed filters
- Optimized worker counts
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

# Test services (high time-consuming ones)
test_services = ["ec2", "inspector", "sagemaker"]

print("="*80)
print("PERFORMANCE TEST: EC2, Inspector, SageMaker")
print("="*80)
print(f"Output directory: {output_dir}")
print(f"Services: {', '.join(test_services)}")
print("Account: Single account (default)")
print("Regions: All enabled regions")
print()
print("Optimizations Active:")
print("  ✅ Default pagination: MaxResults: 1000 (automatic)")
print("  ✅ Customer-managed filters: OwnerIds/Owners/IncludeShared")
print("  ✅ Optimized worker counts: 100")
print("  ✅ 3-Phase Architecture: Discover → Inventory → Checks (parallel)")
print("  ✅ Memory Optimization: Clear data after writing (~90% reduction)")
print("  ✅ Parallel Checks: MAX_CHECK_WORKERS=50")
print("-" * 80)

# Track start time
start_time = time.time()
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

# Run scan
print(f"\n🚀 Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}...")
print()

try:
    summary = scan(
        include_services=test_services,  # EC2, Inspector, SageMaker
        # include_regions=["us-east-1"],  # All regions for comprehensive test
        max_total_workers=100,  # Optimized parallelism
        stream_results=True,  # Write NDJSON incrementally
        save_report=False,    # Skip heavy report bundle
        output_scan_id=f"test_performance_{timestamp}"
    )
    
    # Calculate elapsed time
    elapsed_time = time.time() - start_time
    
    print()
    print("-" * 80)
    print("SCAN COMPLETE - PERFORMANCE METRICS")
    print("-" * 80)
    print(f"⏱️  Total time: {elapsed_time:.2f} seconds ({elapsed_time/60:.2f} minutes)")
    print(f"📊 Summary:")
    print(f"   Total checks: {summary.get('total_checks', 0):,}")
    print(f"   ✓ Passed: {summary.get('passed_checks', 0):,}")
    print(f"   ✗ Failed: {summary.get('failed_checks', 0):,}")
    print(f"   Services scanned: {summary.get('services_scanned', 0)}")
    
    # Check for results files (flattened model uses per-account+region files)
    scan_folder = os.path.join(output_dir, f"test_performance_{timestamp}")
    results_files = []
    inventory_files = []
    
    if os.path.exists(scan_folder):
        # Check for flattened model files (results_{account}_{region}.ndjson)
        for f in os.listdir(scan_folder):
            if f.startswith("results_") and f.endswith(".ndjson"):
                results_files.append(os.path.join(scan_folder, f))
            elif f.startswith("inventory_") and f.endswith(".ndjson"):
                inventory_files.append(os.path.join(scan_folder, f))
        
        # Also check main files (for non-flattened model)
        main_results = os.path.join(scan_folder, "results.ndjson")
        main_inventory = os.path.join(scan_folder, "inventory.ndjson")
        if os.path.exists(main_results):
            results_files.append(main_results)
        if os.path.exists(main_inventory):
            inventory_files.append(main_inventory)
    
    if results_files:
        print(f"\n📁 Results files ({len(results_files)}):")
        for file in sorted(results_files)[:5]:
            size = os.path.getsize(file) if os.path.exists(file) else 0
            lines = sum(1 for _ in open(file)) if os.path.exists(file) and size > 0 else 0
            print(f"   - {os.path.basename(file)} ({lines} lines, {size} bytes)")
        if len(results_files) > 5:
            print(f"   ... and {len(results_files) - 5} more")
    else:
        print(f"\n⚠️  No results files found in {scan_folder}")
    
    if inventory_files:
        print(f"\n📦 Inventory files ({len(inventory_files)}):")
        for file in sorted(inventory_files)[:5]:
            size = os.path.getsize(file) if os.path.exists(file) else 0
            lines = sum(1 for _ in open(file)) if os.path.exists(file) and size > 0 else 0
            print(f"   - {os.path.basename(file)} ({lines} lines, {size} bytes)")
        if len(inventory_files) > 5:
            print(f"   ... and {len(inventory_files) - 5} more")
    else:
        print(f"\n⚠️  No inventory files found in {scan_folder}")
    
    # Performance analysis
    print()
    print("📈 PERFORMANCE ANALYSIS:")
    print()
    
    # Expected improvements
    print("Expected improvements vs. before optimizations:")
    print("  EC2 describe_images:")
    print("    - Before: 78+ minutes (without OwnerIds filter)")
    print("    - After: 10-30 seconds (with OwnerIds: ['self'])")
    print("    - Improvement: ~150-500x faster")
    print()
    print("  Inspector list_assessment_templates:")
    print("    - Before: Very slow (no MaxResults)")
    print("    - After: Fast (MaxResults: 1000 + pagination)")
    print()
    print("  SageMaker list_device_fleets:")
    print("    - Before: Very slow (no MaxResults)")
    print("    - After: Fast (MaxResults: 1000 + pagination)")
    print()
    
    if elapsed_time < 300:  # Less than 5 minutes
        print("✅ EXCELLENT: Scan completed in < 5 minutes!")
    elif elapsed_time < 600:  # Less than 10 minutes
        print("✅ GOOD: Scan completed in < 10 minutes")
    else:
        print("⚠️  Scan took longer than expected")
    
    print()
    print("="*80)
    
except Exception as e:
    elapsed_time = time.time() - start_time
    print(f"\n❌ Error during scan: {e}")
    print(f"Scan ran for {elapsed_time:.2f} seconds before error")
    import traceback
    traceback.print_exc()
    sys.exit(1)

