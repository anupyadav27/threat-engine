#!/usr/bin/env python3
"""
IBM Cloud Organization Scanner  
Enhances the engine to scan multiple accounts in an organization
"""
import logging
from typing import List, Dict, Any, Optional
from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
from ibm_platform_services import EnterpriseManagementV1, IamIdentityV1

logger = logging.getLogger('org-scanner')

class IBMOrganizationScanner:
    """Organization and multi-account scanning capabilities"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.authenticator = IAMAuthenticator(api_key)
    
    def discover_organization_accounts(self) -> List[Dict[str, str]]:
        """Discover all accounts in the organization"""
        try:
            # Try Enterprise Management API for organization accounts
            enterprise_service = EnterpriseManagementV1(authenticator=self.authenticator)
            
            logger.info("🔍 Discovering organization accounts...")
            
            # List enterprises user has access to
            enterprises = enterprise_service.list_enterprises().get_result()
            
            all_accounts = []
            
            for enterprise in enterprises.get('enterprises', []):
                enterprise_id = enterprise['id']
                logger.info(f"📋 Found enterprise: {enterprise['name']} ({enterprise_id})")
                
                try:
                    # Get accounts in this enterprise
                    accounts_response = enterprise_service.list_accounts(
                        enterprise_id=enterprise_id
                    ).get_result()
                    
                    for account in accounts_response.get('resources', []):
                        account_info = {
                            'account_id': account['id'],
                            'account_name': account.get('name', 'Unknown'),
                            'enterprise_id': enterprise_id,
                            'enterprise_name': enterprise['name'],
                            'state': account.get('state', 'unknown')
                        }
                        
                        # Only include active accounts
                        if account_info['state'].lower() in ['active', 'enabled']:
                            all_accounts.append(account_info)
                            logger.info(f"  ✅ Account: {account_info['account_name']} ({account_info['account_id']})")
                
                except Exception as e:
                    logger.warning(f"Could not list accounts for enterprise {enterprise_id}: {e}")
            
            if all_accounts:
                logger.info(f"🎯 Found {len(all_accounts)} accessible accounts")
                return all_accounts
            else:
                logger.info("No organization accounts found - scanning single account")
                return []
                
        except Exception as e:
            logger.info(f"Enterprise discovery not available: {e}")
            logger.info("Falling back to single account scanning")
            return []
    
    def scan_multiple_accounts(self, target_accounts: List[Dict] = None) -> Dict[str, Any]:
        """Scan compliance across multiple accounts"""
        logger.info("🏢 Starting multi-account IBM compliance scan")
        
        # Get accounts to scan
        if target_accounts is None:
            target_accounts = self.discover_organization_accounts()
        
        # If no org accounts found, scan current account
        if not target_accounts:
            # Get current account ID
            try:
                identity_service = IamIdentityV1(authenticator=self.authenticator)
                api_keys = identity_service.list_api_keys().get_result()
                
                current_account = None
                if api_keys and api_keys.get('apikeys'):
                    current_account = api_keys['apikeys'][0].get('account_id')
                
                if current_account:
                    target_accounts = [{
                        'account_id': current_account,
                        'account_name': 'Current Account',
                        'enterprise_id': 'none',
                        'enterprise_name': 'Individual Account'
                    }]
                    logger.info(f"📋 Scanning individual account: {current_account}")
                
            except Exception as e:
                logger.error(f"Could not determine current account: {e}")
                return {'error': 'No accounts to scan'}
        
        all_account_results = {}
        total_checks = 0
        total_resources = 0
        
        for account_info in target_accounts:
            account_id = account_info['account_id']
            account_name = account_info['account_name']
            
            logger.info(f"👤 Scanning account: {account_name} ({account_id})")
            
            try:
                # Import multi-region scanner
                from .multi_region_scanner import IBMMultiRegionScanner
                
                # Scan all regions for this account
                region_scanner = IBMMultiRegionScanner(self.api_key)
                account_results = region_scanner.scan_all_regions(account_id)
                
                all_account_results[account_id] = {
                    'account_info': account_info,
                    'scan_results': account_results,
                    'status': 'completed'
                }
                
                # Aggregate totals
                total_checks += account_results.get('total_checks', 0)
                total_resources += account_results.get('total_resources', 0)
                
                logger.info(f"✅ {account_name}: {account_results.get('total_checks', 0)} checks across {account_results.get('total_regions', 0)} regions")
                
            except Exception as e:
                logger.error(f"❌ Failed to scan account {account_name}: {e}")
                all_account_results[account_id] = {
                    'account_info': account_info,
                    'error': str(e),
                    'status': 'failed'
                }
        
        # Final aggregation
        aggregated = {
            'organization_scan': True,
            'accounts_scanned': list(all_account_results.keys()),
            'total_accounts': len(target_accounts),
            'total_checks': total_checks,
            'total_resources': total_resources,
            'account_details': all_account_results,
            'scan_timestamp': f"{__import__('datetime').datetime.now().isoformat()}Z"
        }
        
        logger.info(f"🏢 Organization scan complete: {len(target_accounts)} accounts, {total_checks} checks, {total_resources} resources")
        return aggregated

def main():
    """Test organization scanning"""
    import os
    
    api_key = os.getenv('IBM_CLOUD_API_KEY')
    
    if not api_key:
        print("❌ Set IBM_CLOUD_API_KEY environment variable")
        return
    
    scanner = IBMOrganizationScanner(api_key)
    
    # Test organization discovery
    accounts = scanner.discover_organization_accounts()
    if accounts:
        print(f"🏢 Found {len(accounts)} organization accounts:")
        for acc in accounts:
            print(f"  • {acc['account_name']} ({acc['account_id']})")
    else:
        print("📋 No organization accounts found - will scan individual account")

if __name__ == '__main__':
    main()