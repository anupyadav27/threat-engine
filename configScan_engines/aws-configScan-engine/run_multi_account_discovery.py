#!/usr/bin/env python3
"""
Multi-Account Discovery Scan
Discovers all accounts and enabled regions, then scans all combinations.
"""

import os
import sys
import logging
import boto3
from pathlib import Path
from typing import List, Dict, Tuple

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from engine.database_manager import DatabaseManager
from engine.scan_controller import ScanController
from utils.organizations_scanner import list_organization_accounts, get_current_account_id, list_enabled_regions

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def discover_accounts_and_regions(session: boto3.session.Session) -> List[Dict[str, any]]:
    """
    Discover all accounts and their enabled regions.
    
    Returns:
        List of dicts with 'account_id', 'account_name', 'enabled_regions'
    """
    logger.info("=" * 80)
    logger.info("STEP 1: DISCOVERING ACCOUNTS")
    logger.info("=" * 80)
    
    # Discover accounts
    accounts = list_organization_accounts(session)
    
    if not accounts:
        # Fallback to current account
        current_account_id = get_current_account_id(session)
        if current_account_id:
            accounts = [{
                'Id': current_account_id,
                'Name': 'Current Account',
                'Email': 'unknown',
                'Status': 'ACTIVE'
            }]
            logger.info(f"  No organization access - using current account: {current_account_id}")
        else:
            logger.error("  Could not determine account ID")
            return []
    else:
        logger.info(f"  Found {len(accounts)} accounts in organization")
    
    logger.info("=" * 80)
    logger.info("STEP 2: DISCOVERING ENABLED REGIONS FOR EACH ACCOUNT")
    logger.info("=" * 80)
    
    account_region_combinations = []
    
    for account in accounts:
        account_id = account['Id']
        account_name = account.get('Name', f'Account-{account_id}')
        
        logger.info(f"\n  Processing account: {account_name} ({account_id})")
        
        # For each account, discover enabled regions
        # Note: We need to assume role or use the same session
        # For now, we'll use the same session (assuming cross-account access)
        try:
            enabled_regions = list_enabled_regions(session)
            logger.info(f"    Found {len(enabled_regions)} enabled regions")
            
            account_region_combinations.append({
                'account_id': account_id,
                'account_name': account_name,
                'account_email': account.get('Email', 'unknown'),
                'enabled_regions': enabled_regions,
                'total_combinations': len(enabled_regions)
            })
            
        except Exception as e:
            logger.warning(f"    Error discovering regions for {account_id}: {e}")
            # Use default regions as fallback
            enabled_regions = ['us-east-1', 'us-west-2', 'eu-west-1']
            account_region_combinations.append({
                'account_id': account_id,
                'account_name': account_name,
                'account_email': account.get('Email', 'unknown'),
                'enabled_regions': enabled_regions,
                'total_combinations': len(enabled_regions)
            })
    
    total_combinations = sum(acc['total_combinations'] for acc in account_region_combinations)
    
    logger.info("=" * 80)
    logger.info("STEP 3: SUMMARY")
    logger.info("=" * 80)
    logger.info(f"  Total Accounts: {len(account_region_combinations)}")
    logger.info(f"  Total Account-Region Combinations: {total_combinations}")
    logger.info("")
    for acc in account_region_combinations:
        logger.info(f"  {acc['account_name']} ({acc['account_id']}): {len(acc['enabled_regions'])} regions")
    
    return account_region_combinations

def run_multi_account_discovery_scan(
    customer_id: str,
    tenant_id: str,
    provider: str = "aws",
    use_organizations: bool = True,
    specific_accounts: List[str] = None,
    specific_regions: List[str] = None
):
    """
    Run discovery scan for multiple accounts and their enabled regions.
    
    Args:
        customer_id: Customer ID
        tenant_id: Tenant ID
        provider: CSP provider
        use_organizations: Whether to use AWS Organizations to discover accounts
        specific_accounts: If provided, only scan these accounts
        specific_regions: If provided, only scan these regions (overrides enabled regions)
    """
    logger.info("=" * 80)
    logger.info("MULTI-ACCOUNT DISCOVERY SCAN")
    logger.info("=" * 80)
    logger.info(f"Customer: {customer_id}")
    logger.info(f"Tenant: {tenant_id}")
    logger.info(f"Use Organizations: {use_organizations}")
    logger.info("")
    
    # Initialize session
    session = boto3.Session()
    
    # Discover accounts and regions
    if specific_accounts:
        # Use specific accounts
        accounts_info = []
        for acc_id in specific_accounts:
            enabled_regions = list_enabled_regions(session) if not specific_regions else specific_regions
            accounts_info.append({
                'account_id': acc_id,
                'account_name': f'Account-{acc_id}',
                'account_email': 'unknown',
                'enabled_regions': enabled_regions,
                'total_combinations': len(enabled_regions)
            })
    else:
        # Discover accounts and regions
        accounts_info = discover_accounts_and_regions(session)
    
    if not accounts_info:
        logger.error("No accounts to scan")
        return
    
    # Initialize database
    logger.info("\n" + "=" * 80)
    logger.info("INITIALIZING DATABASE")
    logger.info("=" * 80)
    db_manager = DatabaseManager()
    logger.info("✅ Database connection established")
    
    # Create customer and tenant
    db_manager.create_customer(customer_id, customer_name="Multi-Account Customer")
    db_manager.create_tenant(tenant_id, customer_id, provider, tenant_name="Multi-Account AWS Tenant")
    logger.info("✅ Customer and tenant created")
    
    # Initialize scan controller
    controller = ScanController(db_manager)
    
    # Scan each account-region combination
    logger.info("\n" + "=" * 80)
    logger.info("STEP 4: SCANNING ALL ACCOUNT-REGION COMBINATIONS")
    logger.info("=" * 80)
    
    scan_results = []
    
    for acc_info in accounts_info:
        account_id = acc_info['account_id']
        account_name = acc_info['account_name']
        regions = specific_regions if specific_regions else acc_info['enabled_regions']
        
        logger.info(f"\n  Scanning: {account_name} ({account_id})")
        logger.info(f"    Regions: {len(regions)} regions")
        
        # Register hierarchy for this account
        db_manager.register_hierarchy(
            tenant_id=tenant_id,
            provider=provider,
            hierarchy_type="account",
            hierarchy_id=account_id,
            hierarchy_name=f"AWS Account {account_id} ({account_name})"
        )
        
        # Run discovery scan for this account
        try:
            result = controller.run_scan(
                customer_id=customer_id,
                tenant_id=tenant_id,
                provider=provider,
                hierarchy_id=account_id,
                hierarchy_type="account",
                scan_mode="discovery_only",
                services=None,  # All services
                regions=regions
            )
            
            scan_results.append({
                'account_id': account_id,
                'account_name': account_name,
                'scan_id': result.get('discovery_scan_id'),
                'regions': regions,
                'status': 'completed'
            })
            
            logger.info(f"    ✅ Completed: {result.get('discovery_scan_id')}")
            
        except Exception as e:
            logger.error(f"    ❌ Failed: {e}")
            scan_results.append({
                'account_id': account_id,
                'account_name': account_name,
                'scan_id': None,
                'regions': regions,
                'status': 'failed',
                'error': str(e)
            })
    
    # Final summary
    logger.info("\n" + "=" * 80)
    logger.info("SCAN COMPLETED - SUMMARY")
    logger.info("=" * 80)
    logger.info(f"Total Accounts Scanned: {len(scan_results)}")
    logger.info(f"Successful: {len([r for r in scan_results if r['status'] == 'completed'])}")
    logger.info(f"Failed: {len([r for r in scan_results if r['status'] == 'failed'])}")
    logger.info("")
    logger.info("Scan Results:")
    for result in scan_results:
        status_icon = "✅" if result['status'] == 'completed' else "❌"
        logger.info(f"  {status_icon} {result['account_name']} ({result['account_id']}): {result['status']}")
        if result.get('scan_id'):
            logger.info(f"      Scan ID: {result['scan_id']}")
    
    return scan_results

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Run multi-account discovery scan')
    parser.add_argument('--customer-id', default='multi_account_cust_001', help='Customer ID')
    parser.add_argument('--tenant-id', default='multi_account_tenant_001', help='Tenant ID')
    parser.add_argument('--accounts', nargs='+', help='Specific account IDs to scan (overrides Organizations)')
    parser.add_argument('--regions', nargs='+', help='Specific regions to scan (overrides enabled regions)')
    parser.add_argument('--no-organizations', action='store_true', help='Do not use AWS Organizations')
    parser.add_argument('--confirm', action='store_true', help='Skip confirmation prompt')
    
    args = parser.parse_args()
    
    if not args.confirm:
        print("\n" + "=" * 80)
        print("⚠️  WARNING: This will scan multiple accounts and regions")
        print("   This will make many API calls and may take a long time")
        print("=" * 80)
        response = input("\nContinue? (yes/no): ")
        if response.lower() not in ['yes', 'y']:
            print("Cancelled.")
            sys.exit(0)
    
    try:
        results = run_multi_account_discovery_scan(
            customer_id=args.customer_id,
            tenant_id=args.tenant_id,
            use_organizations=not args.no_organizations,
            specific_accounts=args.accounts,
            specific_regions=args.regions
        )
        
        print("\n" + "=" * 80)
        print("MULTI-ACCOUNT DISCOVERY SCAN COMPLETED")
        print("=" * 80)
        print(f"Total Accounts: {len(results)}")
        print(f"Successful: {len([r for r in results if r['status'] == 'completed'])}")
        print("=" * 80)
        
    except KeyboardInterrupt:
        logger.info("\n\n⏸️  Scan interrupted by user")
    except Exception as e:
        logger.error(f"❌ Error during scan: {e}", exc_info=True)
        raise

