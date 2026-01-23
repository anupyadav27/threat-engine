#!/usr/bin/env python3
"""
Run rule_check against the latest discovery scan
"""
import os
import sys
import logging
from pathlib import Path
from datetime import datetime

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from engine.check_engine import CheckEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def find_latest_discovery_scan():
    """Find the latest discovery scan ID"""
    # Check new structure first
    base_output_dir = Path("/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output")
    
    # Try new structure: configscan/discoveries/
    configscan_dir = base_output_dir / "configscan" / "discoveries"
    if configscan_dir.exists():
        discovery_dirs = sorted(
            [d for d in configscan_dir.iterdir() if d.is_dir() and d.name.startswith("discovery_")],
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        if discovery_dirs:
            scan_id = discovery_dirs[0].name
            logger.info(f"Found latest discovery scan (new structure): {scan_id}")
            return scan_id
    
    # Fallback to old structure: discoveries/
    discoveries_dir = base_output_dir / "discoveries"
    if discoveries_dir.exists():
        discovery_dirs = sorted(
            [d for d in discoveries_dir.iterdir() if d.is_dir() and d.name.startswith("discovery_")],
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )
        if discovery_dirs:
            scan_id = discovery_dirs[0].name
            logger.info(f"Found latest discovery scan (old structure): {scan_id}")
            return scan_id
    
    return None

def extract_account_id_from_discovery(scan_id: str):
    """Extract account ID from discovery files"""
    base_output_dir = Path("/Users/apple/Desktop/threat-engine/engines-output/aws-configScan-engine/output")
    
    # Try new structure
    discovery_dir = base_output_dir / "configscan" / "discoveries" / scan_id / "discovery"
    if not discovery_dir.exists():
        # Try old structure
        discovery_dir = base_output_dir / "discoveries" / scan_id / "discovery"
    
    if not discovery_dir.exists():
        return None
    
    # Find first NDJSON file and extract account ID
    ndjson_files = list(discovery_dir.glob("*.ndjson"))
    if ndjson_files:
        # Pattern: {account_id}_{region}_{service}.ndjson
        filename = ndjson_files[0].name
        parts = filename.split("_")
        if len(parts) >= 1:
            return parts[0]
    
    return None

def main():
    """Run rule_check against latest discovery scan"""
    
    print("=" * 80)
    print("RULE CHECK - LATEST DISCOVERY SCAN")
    print("=" * 80)
    
    # Find latest discovery scan
    scan_id = find_latest_discovery_scan()
    if not scan_id:
        print("❌ No discovery scans found!")
        print("   Please run a discovery scan first.")
        return
    
    print(f"\n✅ Found latest discovery scan: {scan_id}")
    
    # Extract account ID from discovery files
    hierarchy_id = extract_account_id_from_discovery(scan_id)
    if not hierarchy_id:
        # Try to get from environment or use default
        hierarchy_id = os.getenv("AWS_ACCOUNT_ID", "039612851381")
        print(f"⚠️  Could not extract account ID, using: {hierarchy_id}")
    else:
        print(f"✅ Extracted account ID: {hierarchy_id}")
    
    # Configuration
    customer_id = os.getenv("CUSTOMER_ID", "test_customer")
    tenant_id = os.getenv("TENANT_ID", "test_tenant")
    provider = "aws"
    hierarchy_type = "account"
    
    print(f"\n📋 Configuration:")
    print(f"   Customer ID: {customer_id}")
    print(f"   Tenant ID: {tenant_id}")
    print(f"   Provider: {provider}")
    print(f"   Hierarchy: {hierarchy_id} ({hierarchy_type})")
    print(f"   Discovery Scan: {scan_id}")
    print("=" * 80)
    
    # Initialize check engine in NDJSON mode
    print("\n🔧 Initializing check engine (NDJSON mode)...")
    check_engine = CheckEngine(use_ndjson=True)
    
    # Get all services with checks
    services_dir = Path("services")
    services = [
        d.name for d in services_dir.iterdir()
        if d.is_dir() and not d.name.startswith('.')
        and (d / "checks" / "default").exists()
    ]
    print(f"✅ Found {len(services)} services with checks")
    
    # Run checks
    print(f"\n🚀 Starting rule_check scan...")
    print("=" * 80)
    
    try:
        results = check_engine.run_check_scan(
            scan_id=scan_id,
            customer_id=customer_id,
            tenant_id=tenant_id,
            provider=provider,
            hierarchy_id=hierarchy_id,
            hierarchy_type=hierarchy_type,
            services=services
        )
        
        # Print summary
        print("\n" + "=" * 80)
        print("✅ RULE CHECK COMPLETED")
        print("=" * 80)
        print(f"Mode: {results.get('mode')}")
        print(f"Total Checks: {results.get('total_checks'):,}")
        print(f"Passed: {results.get('passed'):,}")
        print(f"Failed: {results.get('failed'):,}")
        print(f"Errors: {results.get('errors'):,}")
        print(f"\n📁 Output Directory:")
        print(f"   {results.get('output_path')}")
        print("=" * 80)
        
        return results
        
    except Exception as e:
        print(f"\n❌ Error running rule_check: {e}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == '__main__':
    main()
