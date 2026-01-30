#!/usr/bin/env python3
"""
OCI SDK Auto-Discovery and Catalog Generation

This script:
1. Discovers all OCI SDK packages installed
2. Introspects each service to find available operations
3. Generates catalogs for all discovered services
4. Enriches with field metadata
5. Updates the dependencies file in pythonsdk-database
"""

import json
import os
import sys
import importlib
import pkgutil
import inspect
from pathlib import Path
from typing import Dict, List, Any, Set, Optional
import re

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from enrich_oci_fields import OCIFieldEnricher
except ImportError:
    print("⚠️  Warning: enrich_oci_fields not found, enrichment will be minimal")
    OCIFieldEnricher = None


class OCIServiceDiscovery:
    """Discover all OCI services from installed SDK packages"""
    
    def __init__(self, service_list_file: str = None):
        self.discovered_services = {}
        self.service_list_file = service_list_file
        self.service_list_data = {}
        self.stats = {
            'packages_found': 0,
            'services_discovered': 0,
            'operations_found': 0,
            'errors': []
        }
        
        # Load service_list.json if provided
        if service_list_file and os.path.exists(service_list_file):
            with open(service_list_file, 'r') as f:
                self.service_list_data = json.load(f)
            print(f"📋 Loaded service list: {len(self.service_list_data.get('services', []))} services")
    
    def discover_oci_modules(self) -> Dict[str, Dict[str, str]]:
        """Discover all OCI modules and their client classes"""
        oci_modules = {}
        
        try:
            import oci
            oci_path = oci.__path__
            print(f"✅ OCI SDK found: version {getattr(oci, '__version__', 'unknown')}")
        except ImportError as e:
            print(f"❌ OCI SDK not installed. Install with: pip install oci")
            print(f"   Error: {e}")
            return oci_modules
        
        # Method 1: Use service_list.json as reference
        if self.service_list_data:
            for svc in self.service_list_data.get('services', []):
                service_name = svc.get('name', '')
                client_name = svc.get('client', '')
                
                if service_name and client_name:
                    # Try to find the module for this client
                    module_name = self.find_module_for_client(client_name)
                    if module_name:
                        oci_modules[service_name] = {
                            'module': module_name,
                            'client_class': client_name
                        }
        
        # Method 2: Discover from oci package structure
        try:
            for finder, name, ispkg in pkgutil.walk_packages(oci_path, oci.__name__ + "."):
                if ispkg:
                    # Try to find client classes in this module
                    try:
                        module = importlib.import_module(name)
                        for attr_name in dir(module):
                            if attr_name.endswith('Client') and not attr_name.startswith('_'):
                                # Extract service name from module or client name
                                service_name = self.extract_service_name(name, attr_name)
                                if service_name:
                                    oci_modules[service_name] = {
                                        'module': name,
                                        'client_class': attr_name
                                    }
                    except Exception as e:
                        pass
        except Exception as e:
            print(f"  ⚠️  Error discovering modules: {e}")
        
        # Method 3: Common OCI services (fallback)
        common_services = {
            'compute': {'module': 'oci.core', 'client_class': 'ComputeClient'},
            'object_storage': {'module': 'oci.object_storage', 'client_class': 'ObjectStorageClient'},
            'virtual_network': {'module': 'oci.core', 'client_class': 'VirtualNetworkClient'},
            'identity': {'module': 'oci.identity', 'client_class': 'IdentityClient'},
            'block_storage': {'module': 'oci.core', 'client_class': 'BlockstorageClient'},
            'load_balancer': {'module': 'oci.load_balancer', 'client_class': 'LoadBalancerClient'},
            'database': {'module': 'oci.database', 'client_class': 'DatabaseClient'},
            'key_management': {'module': 'oci.key_management', 'client_class': 'KmsVaultClient'},
            'container_engine': {'module': 'oci.container_engine', 'client_class': 'ContainerEngineClient'},
            'functions': {'module': 'oci.functions', 'client_class': 'FunctionsManagementClient'},
            'monitoring': {'module': 'oci.monitoring', 'client_class': 'MonitoringClient'},
            'logging': {'module': 'oci.logging', 'client_class': 'LoggingClient'},
            'dns': {'module': 'oci.dns', 'client_class': 'DnsClient'},
            'file_storage': {'module': 'oci.file_storage', 'client_class': 'FileStorageClient'},
            'streaming': {'module': 'oci.streaming', 'client_class': 'StreamingClient'},
            'data_science': {'module': 'oci.data_science', 'client_class': 'DataScienceClient'},
            'data_catalog': {'module': 'oci.data_catalog', 'client_class': 'DataCatalogClient'},
            'data_integration': {'module': 'oci.data_integration', 'client_class': 'DataIntegrationClient'},
            'cloud_guard': {'module': 'oci.cloud_guard', 'client_class': 'CloudGuardClient'},
            'apigateway': {'module': 'oci.apigateway', 'client_class': 'ApigatewayClient'},
            'events': {'module': 'oci.events', 'client_class': 'EventsClient'},
            'audit': {'module': 'oci.audit', 'client_class': 'AuditClient'},
            'waf': {'module': 'oci.waf', 'client_class': 'WafClient'},
            'edge_services': {'module': 'oci.edge_services', 'client_class': 'EdgeServicesClient'},
            'mysql': {'module': 'oci.mysql', 'client_class': 'MysqlClient'},
            'data_flow': {'module': 'oci.data_flow', 'client_class': 'DataFlowClient'},
            'nosql': {'module': 'oci.nosql', 'client_class': 'NosqlClient'},
            'devops': {'module': 'oci.devops', 'client_class': 'DevopsClient'},
            'artifacts': {'module': 'oci.artifacts', 'client_class': 'ArtifactsClient'},
            'certificates': {'module': 'oci.certificates', 'client_class': 'CertificatesClient'},
            'resource_manager': {'module': 'oci.resource_manager', 'client_class': 'ResourceManagerClient'},
            'bds': {'module': 'oci.bds', 'client_class': 'BdsClient'},
            'data_safe': {'module': 'oci.data_safe', 'client_class': 'DataSafeClient'},
            'ons': {'module': 'oci.ons', 'client_class': 'OnsClient'},
            'network_firewall': {'module': 'oci.network_firewall', 'client_class': 'NetworkFirewallClient'},
            'queue': {'module': 'oci.queue', 'client_class': 'QueueClient'},
            'redis': {'module': 'oci.redis', 'client_class': 'RedisClient'},
            'container_instances': {'module': 'oci.container_instances', 'client_class': 'ContainerInstancesClient'},
            'ai_anomaly_detection': {'module': 'oci.ai_anomaly_detection', 'client_class': 'AiAnomalyDetectionClient'},
            'ai_language': {'module': 'oci.ai_language', 'client_class': 'AiLanguageClient'},
            'vault': {'module': 'oci.vault', 'client_class': 'VaultClient'},
            'analytics': {'module': 'oci.analytics', 'client_class': 'AnalyticsClient'},
        }
        
        # Add common services if not already discovered
        for service_name, config in common_services.items():
            if service_name not in oci_modules:
                oci_modules[service_name] = config
        
        self.stats['packages_found'] = len(oci_modules)
        return oci_modules
    
    def find_module_for_client(self, client_name: str) -> Optional[str]:
        """Find the module that contains a client class"""
        try:
            import oci
            oci_path = oci.__path__
            
            for finder, name, ispkg in pkgutil.walk_packages(oci_path, oci.__name__ + "."):
                try:
                    module = importlib.import_module(name)
                    if hasattr(module, client_name):
                        return name
                except Exception:
                    pass
        except Exception:
            pass
        return None
    
    def extract_service_name(self, module_name: str, client_name: str) -> str:
        """Extract service name from module or client name"""
        # Remove 'oci.' prefix
        if module_name.startswith('oci.'):
            parts = module_name.split('.')
            if len(parts) > 1:
                service = parts[1]
                # Convert to snake_case
                service = service.replace('-', '_')
                return service
        
        # Extract from client name (e.g., ComputeClient -> compute)
        if client_name.endswith('Client'):
            service = client_name[:-6]  # Remove 'Client'
            # Convert CamelCase to snake_case
            service = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', service)
            service = re.sub('([a-z0-9])([A-Z])', r'\1_\2', service)
            return service.lower()
        
        return None
    
    def discover_service_operations(self, service_name: str, module_name: str, client_class_name: str) -> Dict[str, Any]:
        """Discover operations for a service"""
        operations = []
        
        try:
            # Import the module
            module = importlib.import_module(module_name)
            
            # Get the client class
            if not hasattr(module, client_class_name):
                self.stats['errors'].append(f"{service_name}: Client class {client_class_name} not found in {module_name}")
                return {'operations': [], 'error': f'Client class not found'}
            
            client_class = getattr(module, client_class_name)
            
            # Get all methods from the client class
            for method_name in dir(client_class):
                # Skip private/magic methods
                if method_name.startswith('_'):
                    continue
                
                try:
                    method = getattr(client_class, method_name)
                    if not callable(method):
                        continue
                    
                    # Focus on list/get operations (read operations)
                    if method_name.startswith('list_') or method_name.startswith('get_'):
                        # Get method signature
                        sig = inspect.signature(method)
                        params = list(sig.parameters.keys())
                        
                        # Skip 'self' parameter
                        if 'self' in params:
                            params.remove('self')
                        
                        operation = {
                            'operation': method_name,
                            'python_method': method_name,
                            'operation_type': 'list' if method_name.startswith('list_') else 'get',
                            'description': (method.__doc__ or '').split('\n')[0] if method.__doc__ else '',
                            'required_params': [],
                            'optional_params': params[1:] if len(params) > 1 else []  # First param is usually required
                        }
                        
                        operations.append(operation)
                        self.stats['operations_found'] += 1
                
                except Exception as e:
                    pass
        
        except ImportError as e:
            self.stats['errors'].append(f"{service_name}: Failed to import {module_name}: {e}")
            return {'operations': [], 'error': str(e)}
        except Exception as e:
            self.stats['errors'].append(f"{service_name}: Error discovering operations: {e}")
            return {'operations': [], 'error': str(e)}
        
        return {
            'service': service_name,
            'module': module_name,
            'client_class': client_class_name,
            'operations': operations,
            'total_operations': len(operations)
        }
    
    def discover_all_services(self) -> Dict[str, Any]:
        """Discover all OCI services"""
        print("=" * 80)
        print("OCI SDK Service Discovery")
        print("=" * 80)
        print()
        
        oci_modules = self.discover_oci_modules()
        print(f"📦 Found {len(oci_modules)} OCI service modules")
        
        if not oci_modules:
            print("\n⚠️  No OCI service modules found!")
            print("   Install OCI SDK with: pip install oci")
            print("   Or install specific services: pip install oci oci-core oci-identity")
            return {}
        
        print(f"   Services: {', '.join(sorted(oci_modules.keys())[:10])}{'...' if len(oci_modules) > 10 else ''}")
        print()
        
        # Discover services from modules
        for service_name, config in sorted(oci_modules.items()):
            print(f"  🔍 Discovering {service_name} from {config['module']}.{config['client_class']}...")
            service_info = self.discover_service_operations(
                service_name,
                config['module'],
                config['client_class']
            )
            
            if service_info.get('operations'):
                self.discovered_services[service_name] = service_info
                self.stats['services_discovered'] += 1
                print(f"     ✅ Found {len(service_info['operations'])} operations")
            else:
                error = service_info.get('error', 'No operations found')
                print(f"     ⚠️  {error}")
        
        return self.discovered_services
    
    def print_stats(self):
        """Print discovery statistics"""
        print("\n" + "=" * 80)
        print("Discovery Statistics")
        print("=" * 80)
        print(f"Packages found:        {self.stats['packages_found']}")
        print(f"Services discovered:  {self.stats['services_discovered']}")
        print(f"Operations found:      {self.stats['operations_found']}")
        if self.stats['errors']:
            print(f"Errors:                {len(self.stats['errors'])}")
            for error in self.stats['errors'][:5]:
                print(f"  - {error}")
        print("=" * 80)


class OCICatalogGenerator:
    """Generate enriched OCI catalog"""
    
    def __init__(self, discovery: OCIServiceDiscovery):
        self.discovery = discovery
        self.enricher = OCIFieldEnricher() if OCIFieldEnricher else None
        self.catalog = {}
    
    def generate_catalog(self) -> Dict[str, Any]:
        """Generate basic catalog from discovered services"""
        print("\n" + "=" * 80)
        print("Generating Catalog")
        print("=" * 80)
        
        for service_name, service_data in self.discovery.discovered_services.items():
            self.catalog[service_name] = service_data
        
        print(f"\n✅ Generated catalog with {len(self.catalog)} services")
        return self.catalog
    
    def enrich_catalog(self, catalog: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich catalog with field metadata"""
        print("\n" + "=" * 80)
        print("Enriching Catalog")
        print("=" * 80)
        
        if not self.enricher:
            print("⚠️  No enricher available, skipping enrichment")
            return catalog
        
        enriched = {}
        for service_name, service_data in catalog.items():
            print(f"  Enriching {service_name}...")
            enriched_service = self.enricher.enrich_service(service_name, service_data)
            enriched[service_name] = enriched_service
        
        print(f"\n✅ Enriched {len(enriched)} services")
        return enriched
    
    def save_catalog(self, catalog: Dict[str, Any], filename: str) -> Path:
        """Save catalog to file"""
        # Use absolute path to threat-engine directory
        script_path = Path(__file__).resolve()
        # Navigate: Agent-ruleid-rule-yaml -> oci_compliance_python_engine -> threat-engine
        base_dir = script_path.parent.parent.parent.parent
        output_dir = base_dir / "pythonsdk-database" / "oci"
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = output_dir / filename
        with open(output_file, 'w') as f:
            json.dump(catalog, f, indent=2)
        
        print(f"✅ Saved catalog to {output_file}")
        print(f"   Catalog contains {len(catalog)} services")
        return output_file
    
    def create_service_folders(self, catalog: Dict[str, Any]):
        """Create per-service folders and files"""
        print("\n" + "=" * 80)
        print("Creating Per-Service Files")
        print("=" * 80)
        
        # Use absolute path to threat-engine directory
        script_path = Path(__file__).resolve()
        base_dir = script_path.parent.parent.parent.parent / "pythonsdk-database" / "oci"
        
        for service_name, service_data in catalog.items():
            service_dir = base_dir / service_name
            service_dir.mkdir(parents=True, exist_ok=True)
            
            output_file = service_dir / "oci_dependencies_with_python_names_fully_enriched.json"
            with open(output_file, 'w') as f:
                json.dump({service_name: service_data}, f, indent=2)
        
        print(f"✅ Created {len(catalog)} service folders")
    
    def create_service_list(self, catalog: Dict[str, Any]) -> Dict[str, Any]:
        """Create service list file"""
        services = []
        services_detail = {}
        
        for service_name, service_data in catalog.items():
            services.append(service_name)
            operations_count = service_data.get('total_operations', len(service_data.get('operations', [])))
            services_detail[service_name] = operations_count
        
        service_list = {
            'total_services': len(services),
            'total_operations': sum(services_detail.values()),
            'services': sorted(services),
            'services_detail': services_detail
        }
        
        # Use absolute path to threat-engine directory
        script_path = Path(__file__).resolve()
        output_dir = script_path.parent.parent.parent.parent / "pythonsdk-database" / "oci"
        output_file = output_dir / "all_services.json"
        with open(output_file, 'w') as f:
            json.dump(service_list, f, indent=2)
        
        print(f"✅ Created service list: {output_file}")
        return service_list


def main():
    """Main execution"""
    print("=" * 80)
    print("OCI SDK Auto-Discovery and Catalog Generation")
    print("=" * 80)
    print()
    
    # Find service_list.json
    base_dir = Path(__file__).parent.parent.parent
    possible_paths = [
        base_dir / "config" / "service_list.json",
        Path(__file__).parent.parent.parent.parent / "oci_compliance_python_engine" / "config" / "service_list.json",
        Path(__file__).parent.parent.parent / "config" / "service_list.json",
    ]
    
    service_list_file = None
    for path in possible_paths:
        if path.exists():
            service_list_file = str(path)
            break
    
    if not service_list_file:
        print("⚠️  service_list.json not found, will use SDK introspection only")
        print(f"   Tried: {[str(p) for p in possible_paths]}")
    else:
        print(f"✅ Using service_list.json: {service_list_file}")
    
    print()
    
    # Step 1: Discover services
    discovery = OCIServiceDiscovery(service_list_file=service_list_file)
    discovered = discovery.discover_all_services()
    
    if not discovered:
        print("\n❌ No services discovered. Please install OCI SDK packages.")
        print("   Example: pip install oci")
        print("   Or install all: pip install oci oci-core oci-identity oci-database ...")
        return
    
    discovery.print_stats()
    
    # Step 2: Generate catalog
    print("\n" + "=" * 80)
    print("Generating Catalog")
    print("=" * 80)
    generator = OCICatalogGenerator(discovery)
    catalog = generator.generate_catalog()
    
    print(f"\n✅ Generated catalog with {len(catalog)} services")
    
    # Step 3: Save basic catalog
    generator.save_catalog(catalog, "oci_sdk_catalog.json")
    
    # Step 4: Enrich catalog
    print("\n" + "=" * 80)
    print("Enriching Catalog")
    print("=" * 80)
    enriched = generator.enrich_catalog(catalog)
    
    # Step 5: Save enriched catalog
    print("\n" + "=" * 80)
    print("Saving Enriched Catalog")
    print("=" * 80)
    output_file = generator.save_catalog(enriched, "oci_dependencies_with_python_names_fully_enriched.json")
    
    # Step 6: Create per-service files
    generator.create_service_folders(enriched)
    
    # Step 7: Create service list
    service_list = generator.create_service_list(enriched)
    
    # Final summary
    print("\n" + "=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    
    total_services = len(enriched)
    total_operations = sum(d.get('total_operations', 0) for d in enriched.values())
    
    print(f"\nTotal Services: {total_services}")
    print(f"Total Operations: {total_operations:,}")
    print(f"\nOutput File: {output_file}")
    print("=" * 80)


if __name__ == '__main__':
    main()

