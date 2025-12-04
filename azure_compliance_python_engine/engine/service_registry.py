"""
Service Registry - Central mapping of services to Azure SDK packages and clients

This registry:
1. Loads service → package → client mappings
2. Groups services by package for efficient client pooling
3. Provides lookup functions for the engine
"""

import csv
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Optional


class ServiceRegistry:
    """
    Central registry for Azure service metadata
    Maps services to their Python packages, clients, and groups
    """
    
    def __init__(self, csv_path: Optional[Path] = None):
        """
        Initialize service registry
        
        Args:
            csv_path: Path to AZURE_SERVICE_PACKAGE_MAPPING.csv
        """
        if csv_path is None:
            # Default to same directory as this file's parent
            csv_path = Path(__file__).parent.parent / 'AZURE_SERVICE_PACKAGE_MAPPING.csv'
        
        self.csv_path = csv_path
        self._services: Dict[str, Dict] = {}
        self._by_package: Dict[str, List[str]] = defaultdict(list)
        self._by_group: Dict[str, List[str]] = defaultdict(list)
        self._by_client: Dict[str, List[str]] = defaultdict(list)
        
        self._load_registry()
    
    def _load_registry(self):
        """Load service mappings from CSV"""
        if not self.csv_path.exists():
            raise FileNotFoundError(f"Service mapping CSV not found: {self.csv_path}")
        
        with open(self.csv_path, 'r') as f:
            reader = csv.DictReader(f)
            
            for row in reader:
                service = row['service']
                package = row['package']
                client = row['client']
                group = row['group']
                rules = int(row['rules'])
                data_plane = row.get('data_plane', 'NO') == 'YES'
                graph_based = row.get('graph_based', 'NO') == 'YES'
                
                self._services[service] = {
                    'package': package,
                    'client': client,
                    'group': group,
                    'rules': rules,
                    'data_plane': data_plane,
                    'graph_based': graph_based
                }
                
                # Build indexes
                self._by_package[package].append(service)
                self._by_group[group].append(service)
                self._by_client[client].append(service)
    
    # Lookup Methods
    
    def get_service_info(self, service_name: str) -> Dict:
        """Get complete info for a service"""
        if service_name not in self._services:
            raise ValueError(f"Service '{service_name}' not found in registry")
        return self._services[service_name].copy()
    
    def get_package(self, service_name: str) -> str:
        """Get package name for a service"""
        return self.get_service_info(service_name)['package']
    
    def get_client_class(self, service_name: str) -> str:
        """Get client class name for a service"""
        return self.get_service_info(service_name)['client']
    
    def get_group(self, service_name: str) -> str:
        """Get group name for a service"""
        return self.get_service_info(service_name)['group']
    
    def is_data_plane(self, service_name: str) -> bool:
        """Check if service uses data plane client"""
        return self.get_service_info(service_name).get('data_plane', False)
    
    def is_graph_based(self, service_name: str) -> bool:
        """Check if service uses Microsoft Graph"""
        return self.get_service_info(service_name).get('graph_based', False)
    
    # Group Queries
    
    def get_services_by_package(self, package: str) -> List[str]:
        """Get all services using a specific package"""
        return self._by_package.get(package, []).copy()
    
    def get_services_by_group(self, group: str) -> List[str]:
        """Get all services in a group"""
        return self._by_group.get(group, []).copy()
    
    def get_services_by_client(self, client_class: str) -> List[str]:
        """Get all services using the same client class"""
        return self._by_client.get(client_class, []).copy()
    
    def group_services_by_package(self, service_names: List[str]) -> Dict[str, List[str]]:
        """
        Group a list of services by their package
        Used for optimized execution with client pooling
        """
        grouped = defaultdict(list)
        for service in service_names:
            if service in self._services:
                package = self._services[service]['package']
                grouped[package].append(service)
        return dict(grouped)
    
    # Statistics
    
    def list_all_services(self) -> List[str]:
        """Get all registered services"""
        return sorted(self._services.keys())
    
    def list_all_packages(self) -> List[str]:
        """Get all unique packages"""
        return sorted(self._by_package.keys())
    
    def list_all_groups(self) -> List[str]:
        """Get all groups"""
        return sorted(self._by_group.keys())
    
    def get_statistics(self) -> Dict:
        """Get registry statistics"""
        return {
            'total_services': len(self._services),
            'total_packages': len(self._by_package),
            'total_groups': len(self._by_group),
            'total_rules': sum(s['rules'] for s in self._services.values()),
            'by_group': {
                group: {
                    'services': len(services),
                    'rules': sum(self._services[s]['rules'] for s in services)
                }
                for group, services in self._by_group.items()
            },
            'client_sharing': {
                package: len(services)
                for package, services in self._by_package.items()
                if len(services) > 1
            }
        }
    
    def print_summary(self):
        """Print registry summary"""
        stats = self.get_statistics()
        
        print("=" * 80)
        print(" SERVICE REGISTRY SUMMARY")
        print("=" * 80)
        print(f"Total Services: {stats['total_services']}")
        print(f"Total Packages: {stats['total_packages']}")
        print(f"Total Groups:   {stats['total_groups']}")
        print(f"Total Rules:    {stats['total_rules']}")
        
        print(f"\nClient Sharing (packages used by multiple services):")
        for package, service_count in sorted(stats['client_sharing'].items(), 
                                            key=lambda x: x[1], reverse=True):
            services = self._by_package[package]
            print(f"  {package:40s} → {service_count} services: {', '.join(services)}")
        
        print(f"\nBy Group:")
        for group, info in sorted(stats['by_group'].items(), 
                                 key=lambda x: x[1]['rules'], reverse=True):
            print(f"  {group:20s}: {info['services']:2d} services, {info['rules']:4d} rules")


if __name__ == "__main__":
    # Test the registry
    import sys
    
    try:
        registry = ServiceRegistry()
        registry.print_summary()
        
        print("\n" + "=" * 80)
        print(" TESTING SERVICE LOOKUPS")
        print("=" * 80)
        
        # Test lookups
        test_services = ['compute', 'webapp', 'function', 'network', 'aad']
        
        for service in test_services:
            info = registry.get_service_info(service)
            print(f"\n{service}:")
            print(f"  Package: {info['package']}")
            print(f"  Client:  {info['client']}")
            print(f"  Group:   {info['group']}")
            print(f"  Rules:   {info['rules']}")
            
            # Show if shared
            package_services = registry.get_services_by_package(info['package'])
            if len(package_services) > 1:
                print(f"  Shares client with: {', '.join([s for s in package_services if s != service])}")
        
        print("\n" + "=" * 80)
        print(" SERVICE GROUPING TEST")
        print("=" * 80)
        
        # Test grouping
        services_to_scan = ['webapp', 'function', 'site', 'compute', 'network']
        grouped = registry.group_services_by_package(services_to_scan)
        
        print(f"\nGrouping {len(services_to_scan)} services for optimized execution:")
        for package, services in grouped.items():
            print(f"  {package:40s} → {services}")
        
        print(f"\nResult: {len(services_to_scan)} services grouped into {len(grouped)} packages")
        print(f"Client instances needed: {len(grouped)} (vs {len(services_to_scan)} without pooling)")
        print(f"Efficiency gain: {100*(len(services_to_scan)-len(grouped))/len(services_to_scan):.1f}%")
        
        print("\n✅ Service Registry working correctly!")
        
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

