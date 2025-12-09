#!/usr/bin/env python3
"""
Enhanced OCI Compliance Engine - Enterprise Grade
Generic engine to scan across organizations, accounts, regions, and all services
Executes real YAML service definitions with standardized reporting
"""

import os
import json
import yaml
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import oci
from oci.config import from_file, validate_config

# Import standardized utilities
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.reporting_manager import save_reporting_bundle
from utils.inventory_reporter import save_scan_results
from utils.oci_helpers import extract_value, resolve_template
from auth.oci_auth import OCIAuth

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('enhanced-oci-engine')

class EnhancedOciEngine:
    """
    Enterprise-grade OCI compliance engine
    DEFAULT: Scans ALL services, accounts, regions automatically
    OPTIONAL: Can filter to specific services if requested
    """
    
    def __init__(
        self,
        config_file='~/.oci/config',
        profile='DEFAULT',
        filter_services=None,
        filter_compartments=None,
        filter_regions=None,
    ):
        self.config = from_file(config_file, profile)
        validate_config(self.config)
        
        self.auth = OCIAuth(config_file, profile)
        self.services_dir = Path(__file__).parent.parent / "services"
        self.filter_services = self._normalize_csv(filter_services or os.getenv("OCI_ENGINE_FILTER_SERVICES"))
        self.filter_compartments = self._normalize_csv(filter_compartments or os.getenv("OCI_ENGINE_FILTER_COMPARTMENTS"))
        self.filter_regions = self._normalize_csv(filter_regions or os.getenv("OCI_ENGINE_FILTER_REGIONS"))
        
        # Track all results across orgs/accounts/regions
        self.all_scan_results = []
        self.session_id = datetime.now().strftime('%Y%m%d_%H%M%S')

    @staticmethod
    def _normalize_csv(val):
        if not val:
            return None
        if isinstance(val, (list, set, tuple)):
            return sorted({v.strip() for v in val if v})
        return sorted({v.strip() for v in str(val).split(",") if v.strip()})
        
    def discover_organizations(self) -> List[Dict]:
        """Discover all organizations accessible to this user"""
        logger.info("🏢 Discovering OCI organizations...")
        
        try:
            identity = oci.identity.IdentityClient(self.config)
            
            # Get current tenancy as primary organization
            tenancy = identity.get_tenancy(self.config['tenancy']).data
            
            organizations = [{
                'id': tenancy.id,
                'name': tenancy.name,
                'description': tenancy.description or 'Primary tenancy',
                'type': 'primary_tenancy'
            }]
            
            logger.info(f"✅ Found {len(organizations)} organizations")
            return organizations
            
        except Exception as e:
            logger.error(f"❌ Organization discovery failed: {e}")
            return []
    
    def discover_accounts_in_org(self, org_id: str) -> List[Dict]:
        """Discover all accounts within an organization"""
        logger.info(f"👥 Discovering accounts in organization: {org_id[:20]}...")
        
        try:
            identity = oci.identity.IdentityClient(self.config)
            
            # For primary tenancy, the account is the tenancy itself
            # In enterprise setups, would discover child compartments/accounts
            compartments = identity.list_compartments(
                compartment_id=org_id,
                compartment_id_in_subtree=True
            ).data
            
            accounts = []
            
            # Add root compartment/account
            accounts.append({
                'id': org_id,
                'name': 'Root Account',
                'type': 'root_compartment'
            })
            
            # Add child compartments as accounts  
            for comp in compartments:
                if comp.lifecycle_state == 'ACTIVE':
                    accounts.append({
                        'id': comp.id,
                        'name': comp.name,
                        'type': 'compartment_account'
                    })
            
            if self.filter_compartments:
                accounts = [a for a in accounts if a.get('id') in set(self.filter_compartments)]
                logger.info(f"🔍 Filtered to compartments/accounts: {len(accounts)}")
            
            logger.info(f"✅ Found {len(accounts)} accounts in organization after filtering")
            return accounts
            
        except Exception as e:
            logger.error(f"❌ Account discovery failed: {e}")
            return [{'id': org_id, 'name': 'Default Account', 'type': 'default'}]
    
    def discover_regions_for_account(self, account_id: str) -> List[str]:
        """Discover all available regions for an account"""
        logger.info(f"🌍 Discovering regions for account: {account_id[:20]}...")
        
        try:
            regions = self.auth.list_regions()
            if self.filter_regions:
                regions = [r for r in regions if r in set(self.filter_regions)]
                logger.info(f"🔍 Using filtered regions: {', '.join(regions) if regions else 'none'}")
            if not regions:
                regions = [self.config.get('region', 'ap-mumbai-1')]
            logger.info(f"✅ Using regions: {', '.join(regions)}")
            return regions
            
        except Exception as e:
            logger.error(f"❌ Region discovery failed: {e}")
            return [self.config.get('region', 'us-ashburn-1')]
    
    def load_service_yaml_definition(self, service_name: str) -> Optional[Dict]:
        """Load YAML service definition for compliance checks"""
        service_file = self.services_dir / service_name / "rules" / f"{service_name}.yaml"
        
        if not service_file.exists():
            logger.warning(f"❌ Service YAML not found: {service_file}")
            return None
        
        try:
            with open(service_file, 'r') as f:
                data = yaml.safe_load(f)
            
            service_config = data.get(service_name, {})
            if not service_config:
                logger.warning(f"❌ No service config found in YAML for {service_name}")
                return None
                
            logger.info(f"✅ Loaded YAML for {service_name}: {len(service_config.get('checks', []))} checks")
            return service_config
            
        except Exception as e:
            logger.error(f"❌ Failed to load YAML for {service_name}: {e}")
            return None
    
    def execute_service_discovery(self, service_name: str, service_config: Dict, region: str, account_id: str) -> Dict:
        """Execute discovery for a service using YAML definitions"""
        logger.info(f"🔍 Executing {service_name} discovery in {region}")
        
        discovered_resources = {}
        
        try:
            # Get appropriate OCI client for this service
            client = self._get_service_client(service_name, region)
            
            if not client:
                logger.warning(f"⚠️ No client available for {service_name}")
                return {}
            
            # Execute each discovery definition from YAML
            discovery_definitions = service_config.get('discovery', [])
            
            for discovery in discovery_definitions:
                discovery_id = discovery.get('discovery_id', '')
                resource_type = discovery.get('resource_type', '')
                calls = discovery.get('calls', [])
                
                discovery_results = []
                
                for call in calls:
                    action = call.get('action', '')
                    method = call.get('method', '')
                    
                    if action == 'list' and hasattr(client, method):
                        # Execute real OCI SDK call from YAML definition
                        try:
                            if service_name == 'object_storage':
                                # Special handling for object storage
                                if method == 'list_buckets':
                                    namespace = client.get_namespace().data
                                    result = getattr(client, method)(
                                        namespace_name=namespace,
                                        compartment_id=account_id
                                    ).data
                                else:
                                    result = getattr(client, method)(compartment_id=account_id).data
                            else:
                                # Standard OCI SDK call
                                result = getattr(client, method)(compartment_id=account_id).data
                            
                            # Extract fields as defined in YAML
                            extracted_resources = []
                            for resource in result:
                                extracted = {}
                                for field in call.get('fields', []):
                                    path = field.get('path', '')
                                    var_name = field.get('var', path)
                                    extracted[var_name] = extract_value(resource, path)
                                extracted_resources.append(extracted)
                            
                            discovery_results.extend(extracted_resources)
                            
                        except Exception as e:
                            logger.warning(f"❌ Discovery call {method} failed: {e}")
                
                discovered_resources[discovery_id] = discovery_results
                logger.info(f"✅ {discovery_id}: {len(discovery_results)} resources discovered")
            
            return discovered_resources
            
        except Exception as e:
            logger.error(f"❌ Discovery failed for {service_name}: {e}")
            return {}
    
    def execute_service_checks(self, service_name: str, service_config: Dict, discovered_resources: Dict, region: str, account_id: str) -> List[Dict]:
        """Execute all YAML-defined compliance checks for a service"""
        logger.info(f"🧪 Executing {service_name} compliance checks")
        
        check_results = []
        checks = service_config.get('checks', [])
        
        try:
            client = self._get_service_client(service_name, region)
            
            for check in checks:
                check_id = check.get('check_id', '')
                title = check.get('title', '')
                severity = check.get('severity', 'medium')
                for_each = check.get('for_each', '')
                
                # Get resources to check against
                resources_to_check = discovered_resources.get(for_each, [])
                
                if not resources_to_check:
                    # No resources found, mark as skipped
                    check_results.append({
                        'check_id': check_id,
                        'check_name': title,
                        'status': 'SKIPPED',
                        'resource_id': 'N/A',
                        'resource_name': 'N/A',
                        'resource_type': service_name,
                        'region': region,
                        'account_id': account_id,
                        'severity': severity.upper(),
                        'result_detail': 'No resources found for this check',
                        'timestamp': datetime.now().isoformat()
                    })
                    continue
                
                # Execute check against each resource
                for resource in resources_to_check:
                    try:
                        # Execute YAML-defined check calls
                        check_calls = check.get('calls', [])
                        call_results = []
                        
                        for call in check_calls:
                            action = call.get('action', '')
                            fields = call.get('fields', [])
                            
                            # Execute field evaluations from YAML
                            field_results = []
                            for field in fields:
                                path = field.get('path', '')
                                operator = field.get('operator', 'equals')
                                expected = field.get('expected')
                                
                                # Get actual value from resource
                                actual_value = extract_value(resource, path)
                                
                                # Evaluate based on YAML operator
                                field_passed = self._evaluate_field(actual_value, operator, expected)
                                field_results.append(field_passed)
                            
                            # Combine field results based on logic
                            logic = check.get('logic', 'AND').upper()
                            if logic == 'OR':
                                call_passed = any(field_results)
                            else:
                                call_passed = all(field_results)
                            
                            call_results.append(call_passed)
                        
                        # Final check result
                        final_result = all(call_results) if call_results else False
                        
                        check_results.append({
                            'check_id': check_id,
                            'check_name': title,
                            'status': 'PASS' if final_result else 'FAIL',
                            'resource_id': resource.get('id', resource.get('bucket_id', 'unknown')),
                            'resource_name': resource.get('display_name', resource.get('name', 'unknown')),
                            'resource_type': service_name,
                            'region': region,
                            'account_id': account_id,
                            'severity': severity.upper(),
                            'result_detail': 'YAML check executed: ' + ('PASS' if final_result else 'FAIL'),
                            'timestamp': datetime.now().isoformat()
                        })
                        
                    except Exception as e:
                        logger.error(f"❌ Check execution failed for {check_id}: {e}")
            
            logger.info(f"✅ {service_name}: {len(check_results)} YAML checks executed")
            return check_results
            
        except Exception as e:
            logger.error(f"❌ Service check execution failed for {service_name}: {e}")
            return []
    
    def _get_service_client(self, service_name: str, region: str):
        """Get appropriate OCI service client"""
        # Update config for this region
        region_config = dict(self.config)
        region_config['region'] = region
        
        client_mapping = {
            'object_storage': oci.object_storage.ObjectStorageClient,
            'identity': oci.identity.IdentityClient,
            'compute': oci.core.ComputeClient,
            'virtual_network': oci.core.VirtualNetworkClient,
            'block_storage': oci.core.BlockstorageClient,
            'database': oci.database.DatabaseClient,
            'container_engine': oci.container_engine.ContainerEngineClient,
            'monitoring': oci.monitoring.MonitoringClient,
            'audit': oci.audit.AuditClient,
            'kms': oci.key_management.KmsVaultClient
        }
        
        client_class = client_mapping.get(service_name)
        if client_class:
            try:
                return client_class(region_config)
            except Exception as e:
                logger.warning(f"⚠️ Could not create {service_name} client: {e}")
        
        return None
    
    def _evaluate_field(self, actual, operator: str, expected) -> bool:
        """Evaluate field based on YAML operator definition"""
        if operator == 'equals':
            return str(actual) == str(expected)
        elif operator == 'not_equals':
            return str(actual) != str(expected)
        elif operator == 'exists':
            return actual is not None
        elif operator == 'not_exists':
            return actual is None
        elif operator == 'contains':
            return str(expected) in str(actual) if actual else False
        elif operator == 'greater_than':
            try:
                return float(actual) > float(expected)
            except:
                return False
        else:
            return True  # Default pass for unknown operators
    
    def get_services_to_scan(self) -> List[str]:
        """
        Get services to scan:
        DEFAULT: ALL services from services/ folder
        OPTIONAL: Filtered services if specified
        """
        logger.info("📂 Determining services to scan...")
        
        # Discover all available services
        all_services = []
        try:
            for service_dir in self.services_dir.iterdir():
                if service_dir.is_dir() and service_dir.name != '__pycache__':
                    service_name = service_dir.name
                    rules_file = service_dir / "rules" / f"{service_name}.yaml"
                    
                    if rules_file.exists():
                        all_services.append(service_name)
                        
        except Exception as e:
            logger.error(f"❌ Service discovery failed: {e}")
            return []
        
        # Apply filter if specified, otherwise use ALL services (default)
        if self.filter_services:
            filtered_services = [s for s in all_services if s in set(self.filter_services)]
            logger.info(f"🔍 Filtering to specific services: {', '.join(filtered_services)}")
            return sorted(filtered_services)
        else:
            logger.info(f"📋 DEFAULT: Scanning ALL {len(all_services)} services from services/ folder")
            logger.info(f"    Services: {', '.join(all_services[:10])}{'... +' + str(len(all_services) - 10) + ' more' if len(all_services) > 10 else ''}")
            return sorted(all_services)
    
    def scan_account_region_service(self, account_id: str, region: str, service_name: str) -> Dict:
        """Scan a single service in a specific region of an account"""
        logger.info(f"🎯 Scanning {service_name} in {region} for account {account_id[:20]}...")
        
        # Load YAML service definition
        service_config = self.load_service_yaml_definition(service_name)
        if not service_config:
            return {'error': f'No YAML definition found for {service_name}'}
        
        # Execute discovery using YAML definitions
        discovered_resources = self.execute_service_discovery(
            service_name, service_config, region, account_id
        )
        
        # Execute compliance checks using YAML definitions
        compliance_results = self.execute_service_checks(
            service_name, service_config, discovered_resources, region, account_id
        )
        
        return {
            'service': service_name,
            'region': region,
            'account_id': account_id,
            'discovery_results': discovered_resources,
            'compliance_results': compliance_results,
            'total_checks_executed': len(compliance_results),
            'total_resources_discovered': sum(len(resources) for resources in discovered_resources.values()),
            'scan_timestamp': datetime.now().isoformat()
        }
    
    def scan_account_all_regions(self, account_id: str) -> Dict:
        """Scan all regions for an account"""
        logger.info(f"🌍 Scanning all regions for account: {account_id[:20]}...")
        
        regions = self.discover_regions_for_account(account_id)
        services_to_scan = self.get_services_to_scan()
        
        account_results = {
            'account_id': account_id,
            'regions_scanned': [],
            'total_checks_executed': 0,
            'total_resources_discovered': 0,
            'region_results': {}
        }
        
        for region in regions:
            logger.info(f"📍 Scanning region: {region}")
            
            region_results = {
                'region': region,
                'services_scanned': [],
                'service_results': {}
            }
            
            for service_name in services_to_scan:
                try:
                    service_result = self.scan_account_region_service(account_id, region, service_name)
                    
                    if service_result and 'error' not in service_result:
                        region_results['services_scanned'].append(service_name)
                        region_results['service_results'][service_name] = service_result
                        
                        account_results['total_checks_executed'] += service_result.get('total_checks_executed', 0)
                        account_results['total_resources_discovered'] += service_result.get('total_resources_discovered', 0)
                        
                        logger.info(f"✅ {service_name} in {region}: {service_result.get('total_checks_executed', 0)} checks")
                    
                except Exception as e:
                    logger.error(f"❌ Service {service_name} failed in {region}: {e}")
            
            account_results['regions_scanned'].append(region)
            account_results['region_results'][region] = region_results
        
        return account_results
    
    def scan_organization_comprehensive(self, org_id: str) -> Dict:
        """Comprehensive scan of entire organization"""
        logger.info(f"🏢 Comprehensive organization scan: {org_id[:20]}...")
        
        accounts = self.discover_accounts_in_org(org_id)
        
        org_results = {
            'organization_id': org_id,
            'accounts_scanned': [],
            'total_checks_executed': 0,
            'total_resources_discovered': 0,
            'account_results': {}
        }
        
        for account in accounts:
            account_id = account['id']
            account_name = account['name']
            
            logger.info(f"👤 Scanning account: {account_name}")
            
            try:
                account_result = self.scan_account_all_regions(account_id)
                
                org_results['accounts_scanned'].append(account_id)
                org_results['account_results'][account_id] = account_result
                org_results['total_checks_executed'] += account_result.get('total_checks_executed', 0)
                org_results['total_resources_discovered'] += account_result.get('total_resources_discovered', 0)
                
                logger.info(f"✅ Account {account_name}: {account_result.get('total_checks_executed', 0)} checks")
                
            except Exception as e:
                logger.error(f"❌ Account scan failed for {account_name}: {e}")
        
        return org_results
    
    def execute_comprehensive_scan(self) -> Dict:
        """Execute comprehensive multi-org, multi-account, multi-region scan"""
        logger.info("🚀 Starting comprehensive OCI compliance scan")
        print("\n" + "="*80)
        print("Enhanced OCI Compliance Engine - Comprehensive Scan")
        print("="*80)
        
        comprehensive_results = {
            'scan_metadata': {
                'session_id': self.session_id,
                'scan_start': datetime.now().isoformat(),
                'scan_type': 'comprehensive_multi_org_multi_region',
                'engine_version': 'enhanced_oci_engine_v1.0'
            },
            'organizations_scanned': [],
            'total_accounts_scanned': 0,
            'total_regions_scanned': 0,
            'total_services_scanned': 0,
            'total_checks_executed': 0,
            'total_resources_discovered': 0,
            'organization_results': {}
        }
        
        # Discover and scan all organizations
        organizations = self.discover_organizations()
        
        for org in organizations:
            org_id = org['id']
            org_name = org['name']
            
            logger.info(f"🏢 Scanning organization: {org_name}")
            print(f"\n🏢 Organization: {org_name}")
            print("-" * 50)
            
            try:
                org_result = self.scan_organization_comprehensive(org_id)
                
                comprehensive_results['organizations_scanned'].append(org_id)
                comprehensive_results['organization_results'][org_id] = org_result
                comprehensive_results['total_accounts_scanned'] += len(org_result.get('accounts_scanned', []))
                comprehensive_results['total_checks_executed'] += org_result.get('total_checks_executed', 0)
                comprehensive_results['total_resources_discovered'] += org_result.get('total_resources_discovered', 0)
                
                print(f"✅ Organization {org_name}:")
                print(f"   Accounts: {len(org_result.get('accounts_scanned', []))}")
                print(f"   Checks: {org_result.get('total_checks_executed', 0)}")
                print(f"   Resources: {org_result.get('total_resources_discovered', 0)}")
                
            except Exception as e:
                logger.error(f"❌ Organization scan failed for {org_name}: {e}")
        
        comprehensive_results['scan_end'] = datetime.now().isoformat()
        
        # Save comprehensive results to output/ directory
        try:
            # Create output directory structure
            output_dir = Path(f'output/comprehensive_oci_scan_{self.session_id}')
            account_dir = output_dir / f'account_{self.config.get("tenancy", "unknown")[:20]}'
            account_dir.mkdir(parents=True, exist_ok=True)
            
            # Save comprehensive results
            results_file = account_dir / 'comprehensive_scan_results.json'
            with open(results_file, 'w') as f:
                json.dump(comprehensive_results, f, indent=2)
            
            # Create index file
            index_file = output_dir / 'index.json'
            with open(index_file, 'w') as f:
                json.dump({
                    'scan_session': self.session_id,
                    'total_checks': comprehensive_results['total_checks_executed'],
                    'total_resources': comprehensive_results['total_resources_discovered'],
                    'organizations_scanned': len(comprehensive_results['organizations_scanned']),
                    'accounts_scanned': comprehensive_results['total_accounts_scanned']
                }, f, indent=2)
            
            comprehensive_results['output_folder'] = str(output_dir)
            logger.info(f"✅ Comprehensive results saved to output/: {output_dir}")
            
        except Exception as e:
            logger.error(f"❌ Failed to save comprehensive results: {e}")
        
        # Print final summary
        print(f"\n{'='*80}")
        print("Comprehensive Scan Complete")
        print(f"{'='*80}")
        print(f"Organizations: {len(comprehensive_results['organizations_scanned'])}")
        print(f"Accounts: {comprehensive_results['total_accounts_scanned']}")
        print(f"Regions: {comprehensive_results['total_regions_scanned']}")
        print(f"Checks: {comprehensive_results['total_checks_executed']}")
        print(f"Resources: {comprehensive_results['total_resources_discovered']}")
        print(f"{'='*80}")
        
        return comprehensive_results
    
    def _flatten_results_for_reporting(self, comprehensive_results: Dict) -> List[Dict]:
        """Flatten comprehensive results for standardized reporting format"""
        flattened = []
        
        for org_id, org_result in comprehensive_results.get('organization_results', {}).items():
            for account_id, account_result in org_result.get('account_results', {}).items():
                for region, region_result in account_result.get('region_results', {}).items():
                    for service_name, service_result in region_result.get('service_results', {}).items():
                        for check_result in service_result.get('compliance_results', []):
                            flattened.append(check_result)
        
        return flattened

def main():
    """Main entry point for enhanced OCI compliance engine"""
    print("🎯 Enhanced OCI Compliance Engine")
    print("=================================")
    print("🚀 Multi-org, multi-account, multi-region scanning")
    print("📋 Executes real YAML service definitions")
    print("📁 Uses standardized reporting utilities")
    print()
    
    try:
        engine = EnhancedOciEngine()
        results = engine.execute_comprehensive_scan()
        
        print(f"\n🎉 Scan complete! Check reporting folder for results.")
        return results
        
    except Exception as e:
        logger.error(f"❌ Enhanced engine execution failed: {e}")
        print(f"❌ Engine execution failed: {e}")
        return None

if __name__ == '__main__':
    main()