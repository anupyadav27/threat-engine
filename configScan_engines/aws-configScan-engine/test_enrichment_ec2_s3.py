#!/usr/bin/env python3
"""
Test Inventory Enrichment: EC2 (Mumbai) + S3 (Global)
Tests the new inventory enrichment feature with dependent discoveries.
"""
import os
import sys
import time
import json
from datetime import datetime

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.main_scanner import scan

# Set output directory
output_dir = os.path.join(os.path.dirname(__file__), "..", "..", "engines-output", "aws-configScan-engine", "output")
os.environ["OUTPUT_DIR"] = output_dir
os.makedirs(output_dir, exist_ok=True)

sys.stdout.flush()

print("="*80)
print("INVENTORY ENRICHMENT TEST: EC2 (Mumbai) + S3 (Global)")
print("="*80)
sys.stdout.flush()
print(f"Output directory: {output_dir}")
print(f"Services: EC2 (ap-south-1), S3 (global)")
print()
print("Testing:")
print("  ✅ Inventory enrichment with dependent discoveries")
print("  ✅ EC2: Independent + dependent discoveries")
print("  ✅ S3: Independent (list_buckets) + dependent (get_bucket_versioning, etc.)")
print("  ✅ AWS-managed resource filtering")
print("-" * 80)

# Track start time
start_time = time.time()
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
scan_id = f"test_enrichment_ec2_s3_{timestamp}"

# Run scan
print(f"\n🚀 Starting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}...")
print()

try:
    summary = scan(
        include_services=["ec2", "s3"],  # EC2 and S3
        include_regions=["ap-south-1"],  # Mumbai for EC2 (S3 is global)
        max_total_workers=100,
        stream_results=True,
        save_report=False,
        output_scan_id=scan_id
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
    scan_folder = os.path.join(output_dir, scan_id)
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
            
            # Check for enrichment in inventory
            print(f"\n🔍 Checking for enrichment...")
            enrichment_found = False
            
            for inv_file in inventory_files:
                filepath = os.path.join(scan_folder, inv_file)
                if not os.path.exists(filepath) or os.path.getsize(filepath) == 0:
                    continue
                
                # Check first few lines for enriched fields
                with open(filepath, 'r') as f:
                    for i, line in enumerate(f):
                        if i >= 10:  # Check first 10 items
                            break
                        try:
                            item = json.loads(line.strip())
                            
                            # Check for S3 enrichment fields
                            if item.get('service') == 's3':
                                enriched_fields = []
                                if 'Status' in item:  # from get_bucket_versioning
                                    enriched_fields.append('Status')
                                if 'MFADelete' in item:
                                    enriched_fields.append('MFADelete')
                                if 'IsPublic' in item:  # from get_bucket_policy_status
                                    enriched_fields.append('IsPublic')
                                if 'BlockPublicAcls' in item:  # from get_public_access_block
                                    enriched_fields.append('BlockPublicAcls')
                                if '_enriched_from' in item:
                                    enriched_fields.append('_enriched_from')
                                
                                if enriched_fields:
                                    enrichment_found = True
                                    print(f"   ✅ S3 bucket enriched: {item.get('name', 'unknown')}")
                                    print(f"      Enriched fields: {', '.join(enriched_fields)}")
                                    if '_enriched_from' in item:
                                        print(f"      Sources: {', '.join(item['_enriched_from'])}")
                                    break
                            
                            # Check for EC2 enrichment
                            elif item.get('service') == 'ec2':
                                if '_enriched_from' in item:
                                    enrichment_found = True
                                    print(f"   ✅ EC2 resource enriched: {item.get('resource_type', 'unknown')}")
                                    print(f"      Sources: {', '.join(item['_enriched_from'])}")
                                    break
                        
                        except json.JSONDecodeError:
                            continue
            
            if not enrichment_found:
                print("   ⚠️  No enrichment detected in sample items (may need more items or dependent discoveries)")
            
            # Count total inventory items
            total_items = 0
            s3_items = 0
            ec2_items = 0
            enriched_items = 0
            
            for inv_file in inventory_files:
                filepath = os.path.join(scan_folder, inv_file)
                if not os.path.exists(filepath):
                    continue
                
                with open(filepath, 'r') as f:
                    for line in f:
                        try:
                            item = json.loads(line.strip())
                            total_items += 1
                            if item.get('service') == 's3':
                                s3_items += 1
                            elif item.get('service') == 'ec2':
                                ec2_items += 1
                            
                            if '_enriched_from' in item and item['_enriched_from']:
                                enriched_items += 1
                        except:
                            continue
            
            print(f"\n📊 Inventory Statistics:")
            print(f"   Total items: {total_items:,}")
            print(f"   S3 items: {s3_items:,}")
            print(f"   EC2 items: {ec2_items:,}")
            print(f"   Enriched items: {enriched_items:,}")
            if total_items > 0:
                enrichment_pct = (enriched_items / total_items) * 100
                print(f"   Enrichment rate: {enrichment_pct:.1f}%")
    
    print()
    print("="*80)
    print(f"✅ Test complete! Check output in: {scan_folder}")
    print("="*80)
    
except Exception as e:
    elapsed_time = time.time() - start_time
    print(f"\n❌ Error during scan: {e}")
    print(f"Scan ran for {elapsed_time:.2f} seconds before error")
    import traceback
    traceback.print_exc()
    sys.exit(1)

