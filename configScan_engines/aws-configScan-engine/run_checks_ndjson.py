#!/usr/bin/env python3
"""
Run checks in NDJSON mode (local testing)
"""
import os
import sys
import logging
from pathlib import Path

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from engine.check_engine import CheckEngine

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def main():
    """Run checks in NDJSON mode"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run checks in NDJSON mode (local testing)')
    parser.add_argument('--scan-id', required=True, help='Discovery scan ID')
    parser.add_argument('--customer-id', default='test_customer', help='Customer ID')
    parser.add_argument('--tenant-id', default='test_tenant', help='Tenant ID')
    parser.add_argument('--provider', default='aws', help='Provider (aws, azure, gcp)')
    parser.add_argument('--hierarchy-id', required=True, help='Hierarchy ID (account_id, etc.)')
    parser.add_argument('--hierarchy-type', default='account', help='Hierarchy type')
    parser.add_argument('--services', nargs='+', help='Services to check (default: all)')
    
    args = parser.parse_args()
    
    print("=" * 80)
    print("RUNNING CHECKS IN NDJSON MODE")
    print("=" * 80)
    print(f"Scan ID: {args.scan_id}")
    print(f"Hierarchy: {args.hierarchy_id} ({args.hierarchy_type})")
    print(f"Services: {args.services or 'all'}")
    print("=" * 80)
    
    # Initialize check engine in NDJSON mode
    check_engine = CheckEngine(use_ndjson=True)
    
    # Get services
    if args.services:
        services = args.services
    else:
        # Get all services with checks
        services_dir = Path("services")
        services = [
            d.name for d in services_dir.iterdir()
            if d.is_dir() and not d.name.startswith('.')
            and (d / "checks" / "default").exists()
        ]
        print(f"Found {len(services)} services with checks")
    
    # Run checks
    results = check_engine.run_check_scan(
        scan_id=args.scan_id,
        customer_id=args.customer_id,
        tenant_id=args.tenant_id,
        provider=args.provider,
        hierarchy_id=args.hierarchy_id,
        hierarchy_type=args.hierarchy_type,
        services=services
    )
    
    # Print summary
    print("\n" + "=" * 80)
    print("CHECK SCAN COMPLETED")
    print("=" * 80)
    print(f"Mode: {results.get('mode')}")
    print(f"Total Checks: {results.get('total_checks')}")
    print(f"Passed: {results.get('passed')}")
    print(f"Failed: {results.get('failed')}")
    print(f"Errors: {results.get('errors')}")
    print(f"\nOutput: {results.get('output_path')}")
    print("=" * 80)
    
    return results

if __name__ == '__main__':
    main()
