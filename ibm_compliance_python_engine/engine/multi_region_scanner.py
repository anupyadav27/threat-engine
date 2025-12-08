#!/usr/bin/env python3
"""
IBM Cloud Multi-Region Scanner
Enhances the engine to scan all IBM regions automatically
"""
import logging
from typing import List, Dict, Any
from ibm_cloud_sdk_core.authenticators import IAMAuthenticator
from ibm_platform_services import GlobalSearchV2

logger = logging.getLogger('multi-region-scanner')

class IBMMultiRegionScanner:
    """Multi-region scanning capabilities for IBM Cloud"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.authenticator = IAMAuthenticator(api_key)
        
        # IBM Cloud regions
        self.regions = [
            'us-south',    # Dallas
            'us-east',     # Washington DC  
            'eu-gb',       # London
            'eu-de',       # Frankfurt
            'jp-tok',      # Tokyo
            'au-syd',      # Sydney
            'ca-tor',      # Toronto
            'br-sao',      # São Paulo
            'jp-osa',      # Osaka
            'kr-seo'       # Seoul
        ]
    
    def get_available_regions(self, account_id: str) -> List[str]:
        """Discover which regions have resources for an account"""
        try:
            # Use Global Search to find resources across regions
            search_service = GlobalSearchV2(authenticator=self.authenticator)
            
            # Search for any resources to detect active regions
            search_result = search_service.search(
                query='*',
                limit=1000,
                search_cursor=None,
                fields=['region']
            ).get_result()
            
            # Extract unique regions from search results
            active_regions = set()
            for item in search_result.get('items', []):
                region = item.get('region')
                if region and region in self.regions:
                    active_regions.add(region)
            
            # If no regions found via search, default to standard regions
            if not active_regions:
                logger.info("No specific regions detected via search, using default set")
                return ['us-south', 'eu-gb', 'jp-tok']  # Common regions
            
            logger.info(f"Detected active regions: {sorted(active_regions)}")
            return sorted(active_regions)
            
        except Exception as e:
            logger.warning(f"Could not detect active regions: {e}")
            logger.info("Falling back to default regions")
            return ['us-south', 'eu-gb', 'jp-tok']
    
    def scan_all_regions(self, account_id: str, service_list: List[str] = None) -> Dict[str, Any]:
        """Scan compliance across all available regions"""
        logger.info("🌍 Starting multi-region IBM compliance scan")
        
        # Get regions to scan
        regions_to_scan = self.get_available_regions(account_id)
        
        all_region_results = {}
        total_checks = 0
        total_resources = 0
        
        for region in regions_to_scan:
            logger.info(f"📍 Scanning region: {region}")
            
            try:
                # Import here to avoid circular imports
                from .ibm_sdk_engine_v2 import IBMCloudAuth, process_service, load_enabled_services
                
                # Initialize auth for this region
                region_auth = IBMCloudAuth(self.api_key, region)
                
                # Get services to scan (enabled services or provided list)
                services_to_scan = service_list or [s[0] for s in load_enabled_services()]
                
                region_results = []
                region_checks = 0
                region_resources = 0
                
                # Scan each service in this region
                for service_name in services_to_scan:
                    try:
                        result = process_service(service_name, 'regional', region_auth, account_id)
                        if result:
                            region_results.append(result)
                            # Count checks and resources from result
                            region_checks += result.get('total_checks', 0)
                            region_resources += result.get('total_resources', 0)
                            
                    except Exception as e:
                        logger.warning(f"Service {service_name} failed in {region}: {e}")
                
                all_region_results[region] = {
                    'results': region_results,
                    'total_checks': region_checks,
                    'total_resources': region_resources,
                    'services_scanned': len(services_to_scan)
                }
                
                total_checks += region_checks
                total_resources += region_resources
                
                logger.info(f"✅ {region}: {region_checks} checks, {region_resources} resources")
                
            except Exception as e:
                logger.error(f"❌ Failed to scan region {region}: {e}")
                all_region_results[region] = {'error': str(e)}
        
        # Aggregate results
        aggregated = {
            'account_id': account_id,
            'regions_scanned': list(all_region_results.keys()),
            'total_regions': len(regions_to_scan),
            'total_checks': total_checks,
            'total_resources': total_resources,
            'region_details': all_region_results,
            'scan_type': 'multi_region'
        }
        
        logger.info(f"🌍 Multi-region scan complete: {len(regions_to_scan)} regions, {total_checks} checks, {total_resources} resources")
        return aggregated

def main():
    """Test multi-region scanning"""
    import os
    
    api_key = os.getenv('IBM_CLOUD_API_KEY')
    account_id = os.getenv('IBM_ACCOUNT_ID') 
    
    if not api_key or not account_id:
        print("❌ Set IBM_CLOUD_API_KEY and IBM_ACCOUNT_ID environment variables")
        return
    
    scanner = IBMMultiRegionScanner(api_key)
    
    # Test region detection
    regions = scanner.get_available_regions(account_id)
    print(f"🌍 Available regions for account: {regions}")
    
    # Note: Full multi-region scan would be run from main engine
    print("🔧 Multi-region capability added to engine!")

if __name__ == '__main__':
    main()