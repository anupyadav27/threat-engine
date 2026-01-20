#!/usr/bin/env python3
"""Direct test of inventory engine without API server"""
import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from inventory_engine.api.orchestrator import ScanOrchestrator

# Set output directory
output_dir = "/Users/apple/Desktop/threat-engine/engines-output/inventory-engine/output"
os.environ["INVENTORY_OUTPUT_DIR"] = output_dir
os.environ["USE_S3"] = "false"
os.makedirs(output_dir, exist_ok=True)

print(f"Output directory: {output_dir}")
print("Starting inventory scan...")
print("-" * 80)

# Get AWS account ID
import boto3
try:
    sts = boto3.client('sts')
    account_id = sts.get_caller_identity()['Account']
    region = boto3.Session().region_name or 'us-east-1'
except:
    account_id = "588989875114"
    region = "us-east-1"

print(f"Account ID: {account_id}")
print(f"Region: {region}")
print("")

# Create orchestrator
orchestrator = ScanOrchestrator(
    tenant_id="test-tenant",
    s3_bucket="cspm-lgtech",
    db_url=None,  # Skip DB for quick test
    neo4j_uri=None  # Skip Neo4j for quick test
)

# Run scan
result = orchestrator.run_scan(
    providers=["aws"],
    accounts=[account_id],
    regions=[region],
    services=["s3", "ec2"]  # Just S3 and EC2 for quick test
)

print("-" * 80)
print("Scan complete!")
print(f"Scan Run ID: {result['scan_run_id']}")
print(f"Total Assets: {result['total_assets']}")
print(f"Total Relationships: {result['total_relationships']}")
print(f"Artifact Paths:")
for key, path in result['artifact_paths'].items():
    print(f"  {key}: {path}")

# Check if files exist
print("")
print("Verifying output files:")
for key, path in result['artifact_paths'].items():
    if os.path.exists(path):
        size = os.path.getsize(path)
        lines = sum(1 for _ in open(path)) if path.endswith('.ndjson') else 1
        print(f"  ✅ {key}: {path} ({size} bytes, {lines} lines)")
    else:
        print(f"  ❌ {key}: {path} (not found)")

