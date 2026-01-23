#!/usr/bin/env python3
"""
Run a full test discovery scan for all services.
This is a test scan to verify all fixes are working.
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from engine.database_manager import DatabaseManager
from engine.scan_controller import ScanController

def main():
    print("=" * 80)
    print("RUNNING FULL TEST DISCOVERY SCAN")
    print("=" * 80)
    print()
    
    # Initialize database manager
    db_manager = DatabaseManager()
    
    # Initialize scan controller
    scan_controller = ScanController(db_manager)
    
    # Test scan configuration
    customer_id = "test-customer"
    tenant_id = "test-tenant-aws"
    provider = "aws"
    hierarchy_id = "test-account-588989875114"
    hierarchy_type = "account"
    
    print(f"Customer ID: {customer_id}")
    print(f"Tenant ID: {tenant_id}")
    print(f"Provider: {provider}")
    print(f"Hierarchy ID: {hierarchy_id}")
    print(f"Hierarchy Type: {hierarchy_type}")
    print()
    
    # Run discovery-only scan
    print("Starting discovery scan...")
    print()
    
    try:
        result = scan_controller.run_scan(
            customer_id=customer_id,
            tenant_id=tenant_id,
            provider=provider,
            hierarchy_id=hierarchy_id,
            hierarchy_type=hierarchy_type,
            scan_mode="discovery_only",
            services=None,  # All services
            regions=None    # All regions
        )
        
        discovery_scan_id = result.get('discovery_scan_id')
        output_path = result.get('output_path')
        
        print()
        print("=" * 80)
        print("SCAN COMPLETED")
        print("=" * 80)
        print(f"Discovery Scan ID: {discovery_scan_id}")
        print(f"Output Path: {output_path}")
        print()
        print("To monitor progress:")
        print(f"  python3 monitor_scan_continuously.py --scan-id {discovery_scan_id}")
        print()
        print("To upload to database:")
        print(f"  python3 upload_scan_to_database.py --scan-id {discovery_scan_id} --hierarchy-id {hierarchy_id}")
        print()
        
    except Exception as e:
        print(f"❌ Error running scan: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()

