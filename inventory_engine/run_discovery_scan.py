#!/usr/bin/env python3
"""Run inventory engine against latest discovery scan"""
import os
import sys
import json
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from inventory_engine.api.orchestrator import ScanOrchestrator

# Set output directory
output_dir = "/Users/apple/Desktop/threat-engine/engines-output/inventory-engine/output"
os.environ["INVENTORY_OUTPUT_DIR"] = output_dir
os.environ["USE_S3"] = "false"
os.environ["USE_DATABASE"] = "false"  # Use local file mode
os.makedirs(output_dir, exist_ok=True)

print("=" * 80)
print("Inventory Engine - Discovery Scan Runner")
print("=" * 80)
print(f"Output directory: {output_dir}")
print("")

# Use latest discovery scan
scan_id = "latest"  # Auto-detect latest
tenant_id = "multi_account_tenant_001"  # From discovery summary

print(f"Discovery Scan ID: {scan_id} (will auto-detect latest)")
print(f"Tenant ID: {tenant_id}")
print("")
print("Starting inventory scan from discovery...")
print("-" * 80)

# Create orchestrator
orchestrator = ScanOrchestrator(
    tenant_id=tenant_id,
    s3_bucket="cspm-lgtech",
    db_url=None,  # Skip DB for local test
    neo4j_uri=None  # Skip Neo4j for local test
)

# Run scan from discovery
try:
    result = orchestrator.run_scan_from_discovery(
        configscan_scan_id=scan_id,
        providers=None,  # All providers
        accounts=None,  # All accounts
        previous_scan_id=None  # No drift detection for now
    )
    
    print("-" * 80)
    print("✅ Scan complete!")
    print("")
    print(f"Scan Run ID: {result['scan_run_id']}")
    print(f"Status: {result['status']}")
    print(f"Started At: {result['started_at']}")
    print(f"Completed At: {result['completed_at']}")
    print(f"Total Assets: {result['total_assets']}")
    print(f"Total Relationships: {result['total_relationships']}")
    print(f"Total Drift Records: {result['total_drift']}")
    print("")
    print("Artifact Paths:")
    for key, path in result['artifact_paths'].items():
        print(f"  {key}: {path}")
    
    # Check if files exist and analyze
    print("")
    print("=" * 80)
    print("Output Analysis")
    print("=" * 80)
    
    for key, path in result['artifact_paths'].items():
        if os.path.exists(path):
            size = os.path.getsize(path)
            if path.endswith('.ndjson'):
                lines = sum(1 for _ in open(path, 'r'))
                print(f"\n✅ {key}: {path}")
                print(f"   Size: {size:,} bytes ({size/1024/1024:.2f} MB)")
                print(f"   Records: {lines:,} lines")
                
                # Sample first few records for analysis
                if lines > 0:
                    print(f"   Sample records:")
                    with open(path, 'r') as f:
                        for i, line in enumerate(f):
                            if i >= 3:  # Show first 3 records
                                break
                            try:
                                record = json.loads(line.strip())
                                if key == "assets":
                                    print(f"     - {record.get('resource_type', 'unknown')}: {record.get('resource_uid', 'N/A')[:80]}")
                                elif key == "relationships":
                                    print(f"     - {record.get('relation_type', 'unknown')}: {record.get('from_uid', 'N/A')[:40]} -> {record.get('to_uid', 'N/A')[:40]}")
                                elif key == "drift":
                                    print(f"     - {record.get('change_type', 'unknown')}: {record.get('resource_uid', 'N/A')[:80]}")
                            except:
                                pass
            else:
                print(f"\n✅ {key}: {path}")
                print(f"   Size: {size:,} bytes")
                # Try to read and show summary
                try:
                    with open(path, 'r') as f:
                        data = json.load(f)
                        if isinstance(data, dict):
                            print(f"   Summary keys: {list(data.keys())[:10]}")
                except:
                    pass
        else:
            print(f"\n❌ {key}: {path} (not found)")
    
    # Analyze assets by type
    assets_path = result['artifact_paths'].get('assets')
    if assets_path and os.path.exists(assets_path):
        print("")
        print("=" * 80)
        print("Asset Breakdown by Resource Type")
        print("=" * 80)
        
        asset_types = {}
        providers = {}
        regions = {}
        
        with open(assets_path, 'r') as f:
            for line in f:
                try:
                    asset = json.loads(line.strip())
                    rtype = asset.get('resource_type', 'unknown')
                    provider = asset.get('provider', 'unknown')
                    region = asset.get('region', 'unknown')
                    
                    asset_types[rtype] = asset_types.get(rtype, 0) + 1
                    providers[provider] = providers.get(provider, 0) + 1
                    regions[region] = regions.get(region, 0) + 1
                except:
                    continue
        
        print(f"\nBy Provider:")
        for provider, count in sorted(providers.items(), key=lambda x: -x[1]):
            print(f"  {provider}: {count:,}")
        
        print(f"\nBy Region (top 10):")
        for region, count in sorted(regions.items(), key=lambda x: -x[1])[:10]:
            print(f"  {region}: {count:,}")
        
        print(f"\nBy Resource Type (top 20):")
        for rtype, count in sorted(asset_types.items(), key=lambda x: -x[1])[:20]:
            print(f"  {rtype}: {count:,}")
    
    print("")
    print("=" * 80)
    print("✅ Analysis Complete!")
    print("=" * 80)
    
except Exception as e:
    print("")
    print("=" * 80)
    print("❌ Error during scan")
    print("=" * 80)
    print(f"Error: {str(e)}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
