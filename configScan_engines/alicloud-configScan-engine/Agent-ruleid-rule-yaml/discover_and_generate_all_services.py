"""
AliCloud SDK Auto-Discovery and Catalog Generation

This script:
1. Discovers all AliCloud SDK packages installed
2. Introspects each package to find available operations
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
from typing import Dict, List, Any, Set
import re


class AliCloudServiceDiscovery:
    """Discover all AliCloud services from installed SDK packages"""
    
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
    
    def discover_sdk_packages(self) -> List[str]:
        """Discover all aliyun/alicloud SDK packages"""
        packages = []
        package_to_service = {}
        
        # Method 1: Use service_list.json as reference (most reliable)
        if self.service_list_data:
            for svc in self.service_list_data.get('services', []):
                sdk_package = svc.get('sdk', '')
                service_name = svc.get('name', '')
                
                if sdk_package:
                    # Convert pip package name to module name
                    # aliyun-python-sdk-ecs -> aliyunsdkecs
                    module_name = sdk_package.replace('aliyun-python-sdk-', 'aliyunsdk')
                    if module_name == 'aliyunsdkcs':
                        module_name = 'aliyunsdkcs'  # ACK uses 'cs'
                    elif module_name == 'aliyunsdkoss':
                        module_name = 'oss2'  # OSS uses oss2
                    
                    packages.append(module_name)
                    package_to_service[module_name] = service_name
        
        # Method 2: Check installed packages via pkgutil
        for importer, modname, ispkg in pkgutil.iter_modules():
            if 'aliyun' in modname.lower() or 'alicloud' in modname.lower():
                if modname not in packages:
                    packages.append(modname)
        
        # Method 3: Check common AliCloud SDK package patterns
        common_patterns = [
            'aliyunsdkcore',
            'aliyunsdkecs',
            'aliyunsdkoss',
            'aliyunsdkvpc',
            'aliyunsdkram',
            'aliyunsdkrds',
            'aliyunsdkslb',
            'aliyunsdkkms',
            'oss2',  # OSS uses oss2 package
        ]
        
        for pattern in common_patterns:
            if pattern not in packages:
                try:
                    importlib.import_module(pattern)
                    packages.append(pattern)
                except ImportError:
                    pass
        
        # Method 4: Try to discover from aliyunsdkcore
        try:
            import aliyunsdkcore
            # Get all submodules
            core_path = aliyunsdkcore.__path__
            for finder, name, ispkg in pkgutil.walk_packages(core_path, aliyunsdkcore.__name__ + "."):
                if 'aliyun' in name.lower() and name not in packages:
                    packages.append(name)
        except ImportError:
            pass
        
        # Remove duplicates and sort
        packages = sorted(list(set(packages)))
        self.stats['packages_found'] = len(packages)
        self.package_to_service = package_to_service
        
        return packages
    
    def extract_service_name_from_package(self, package_name: str) -> str:
        """Extract service name from package name"""
        # First check if we have a mapping from service_list.json
        if hasattr(self, 'package_to_service') and package_name in self.package_to_service:
            return self.package_to_service[package_name]
        
        # Patterns: aliyunsdkecs -> ecs, aliyunsdkvpc -> vpc
        if package_name.startswith('aliyunsdk'):
            service = package_name.replace('aliyunsdk', '').split('.')[0]
            # Special cases
            if service == 'cs':
                return 'ack'  # Container Service
            return service.lower()
        elif package_name == 'oss2':
            return 'oss'
        else:
            # Try to extract from module path
            parts = package_name.split('.')
            for part in parts:
                if part.startswith('aliyunsdk') and len(part) > 9:
                    service = part[9:].lower()
                    if service == 'cs':
                        return 'ack'
                    return service
        return package_name.lower()
    
    def discover_operations_from_module(self, module_name: str, service_name: str) -> List[str]:
        """Discover operations from a module"""
        operations = []
        
        try:
            module = importlib.import_module(module_name)
            
            # Look for request classes (AliCloud SDK pattern)
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj):
                    # Check if it's a request class
                    if 'Request' in name or 'request' in name.lower():
                        # Extract operation name
                        op_name = name.replace('Request', '').replace('request', '')
                        if op_name:
                            operations.append(op_name)
                    
                    # Also check for methods that might be operations
                    if hasattr(obj, '__name__'):
                        if any(keyword in obj.__name__.lower() 
                               for keyword in ['describe', 'list', 'get', 'create', 'update', 'delete']):
                            operations.append(obj.__name__)
            
            # Look for functions
            for name, obj in inspect.getmembers(module, inspect.isfunction):
                if any(keyword in name.lower() 
                       for keyword in ['describe', 'list', 'get', 'create', 'update', 'delete']):
                    operations.append(name)
        
        except Exception as e:
            self.stats['errors'].append(f"Error discovering {module_name}: {str(e)}")
        
        return sorted(list(set(operations)))
    
    def discover_operations_from_request_modules(self, package_name: str, service_name: str) -> List[str]:
        """Discover operations from request submodules (AliCloud SDK pattern)"""
        operations = []
        
        try:
            # Import base package
            base_mod = importlib.import_module(package_name)
            
            # Find request package first (pattern: package.request)
            request_package = None
            if hasattr(base_mod, '__path__'):
                for finder, name, ispkg in pkgutil.walk_packages(base_mod.__path__, package_name + "."):
                    if 'request' in name.lower() and ispkg:
                        request_package = name
                        break
            
            # If we found request package, walk into it to find versioned packages and request modules
            if request_package:
                try:
                    req_pkg_mod = importlib.import_module(request_package)
                    if hasattr(req_pkg_mod, '__path__'):
                        # Walk into request package to find versioned packages (e.g., v20200706)
                        versioned_packages = []
                        for finder, name, ispkg in pkgutil.walk_packages(req_pkg_mod.__path__, request_package + "."):
                            if ('v20' in name or 'v1' in name or 'v2' in name) and ispkg:
                                versioned_packages.append(name)
                        
                        # Process first versioned package found
                        if versioned_packages:
                            version_pkg = versioned_packages[0]  # Use first version
                            version_mod = importlib.import_module(version_pkg)
                            
                            if hasattr(version_mod, '__path__'):
                                # Walk into version package to find request class modules
                                for finder, name, ispkg in pkgutil.walk_packages(version_mod.__path__, version_pkg + "."):
                                    if not ispkg and 'Request' in name:
                                        # Extract operation name from module name
                                        # Pattern: package.request.v20200706.DescribeTrailsRequest
                                        parts = name.split('.')
                                        if len(parts) > 0:
                                            last_part = parts[-1]
                                            if 'Request' in last_part:
                                                op_name = last_part.replace('Request', '')
                                                if op_name and op_name not in operations:
                                                    operations.append(op_name)
                            
                            # If we found operations, we're done (already collected above)
                except Exception as e:
                    self.stats['errors'].append(f"Error accessing request package {request_package}: {str(e)}")
        
        except Exception as e:
            self.stats['errors'].append(f"Error discovering request modules for {package_name}: {str(e)}")
        
        return sorted(list(set(operations)))
    
    def discover_service_operations(self, service_name: str, package_name: str) -> Dict[str, Any]:
        """Discover all operations for a service"""
        operations = []
        module_paths = []
        
        # Method 1: Try to discover from request modules (AliCloud SDK pattern) - PRIORITY
        request_ops = self.discover_operations_from_request_modules(package_name, service_name)
        if request_ops:
            operations.extend(request_ops)
            module_paths.append(f"{package_name}.request.*")
            # If we found operations from request modules, prioritize those
            if operations:
                return {
                    'service': service_name,
                    'package': package_name,
                    'module_paths': module_paths,
                    'operations': sorted(list(set(operations))),
                    'operation_count': len(set(operations))
                }
        
        # Method 2: Try different module path patterns
        patterns = [
            f"{package_name}.request",
            f"{package_name}",
            f"aliyunsdk{service_name}.request",
            f"aliyunsdk{service_name}",
        ]
        
        # Special case for OSS
        if service_name == 'oss' or package_name == 'oss2':
            patterns = ['oss2', 'oss2.api', 'oss2.service']
        
        for pattern in patterns:
            try:
                module = importlib.import_module(pattern)
                if pattern not in module_paths:
                    module_paths.append(pattern)
                
                # Discover operations
                ops = self.discover_operations_from_module(pattern, service_name)
                operations.extend(ops)
                
            except ImportError:
                continue
            except Exception as e:
                self.stats['errors'].append(f"Error importing {pattern}: {str(e)}")
        
        # Remove duplicates
        operations = sorted(list(set(operations)))
        
        return {
            'service': service_name,
            'package': package_name,
            'module_paths': module_paths,
            'operations': operations,
            'operation_count': len(operations)
        }
    
    def discover_all_services(self) -> Dict[str, Any]:
        """Discover all AliCloud services"""
        print("=" * 80)
        print("AliCloud SDK Service Discovery")
        print("=" * 80)
        print()
        
        packages = self.discover_sdk_packages()
        print(f"📦 Found {len(packages)} SDK packages")
        
        if not packages:
            print("\n⚠️  No AliCloud SDK packages found!")
            print("   Install with: pip install aliyun-python-sdk-core")
            print("   Or install specific services: pip install aliyun-python-sdk-ecs")
            return {}
        
        print(f"   Packages: {', '.join(packages[:10])}{'...' if len(packages) > 10 else ''}")
        print()
        
        # Discover services from packages
        for package in packages:
            service_name = self.extract_service_name_from_package(package)
            
            if service_name and service_name not in ['core', 'common', 'auth']:
                print(f"  🔍 Discovering {service_name} from {package}...")
                service_info = self.discover_service_operations(service_name, package)
                
                if service_info['operations']:
                    self.discovered_services[service_name] = service_info
                    self.stats['services_discovered'] += 1
                    self.stats['operations_found'] += len(service_info['operations'])
                    print(f"     ✅ Found {len(service_info['operations'])} operations")
                else:
                    print(f"     ⚠️  No operations found")
        
        return self.discovered_services
    
    def generate_catalog(self) -> Dict[str, Any]:
        """Generate catalog from discovered services"""
        catalog = {}
        
        # Common operations to prioritize (based on compliance needs)
        priority_ops = {
            'describe', 'list', 'get', 'search', 'query',
            'show', 'view', 'info', 'detail'
        }
        
        for service_name, service_info in self.discovered_services.items():
            operations = []
            
            # Filter and prioritize operations
            ops = service_info['operations']
            
            # Prioritize read operations
            read_ops = [op for op in ops if any(prefix in op.lower() for prefix in priority_ops)]
            other_ops = [op for op in ops if op not in read_ops]
            
            # Take top 10 read ops + 5 other ops
            selected_ops = (read_ops[:10] + other_ops[:5])[:15]
            
            for op in selected_ops:
                operation_def = {
                    'operation': op,
                    'python_method': op,
                    'description': f"{op} - {service_name}",
                    'item_fields': {}  # Will be enriched later
                }
                operations.append(operation_def)
            
            catalog[service_name] = {
                'service': service_name,
                'module': service_info.get('package', f'aliyunsdk{service_name}'),
                'description': f"{service_name.upper()} Service",
                'operations': operations
            }
        
        return catalog
    
    def print_stats(self):
        """Print discovery statistics"""
        print("\n" + "=" * 80)
        print("Discovery Statistics")
        print("=" * 80)
        print(f"Packages found:         {self.stats['packages_found']}")
        print(f"Services discovered:     {self.stats['services_discovered']}")
        print(f"Operations found:        {self.stats['operations_found']}")
        if self.stats['errors']:
            print(f"Errors:                 {len(self.stats['errors'])}")
            for error in self.stats['errors'][:5]:
                print(f"  - {error}")
        print("=" * 80)


class AliCloudCatalogGenerator:
    """Generate and enrich AliCloud SDK catalog"""
    
    def __init__(self, discovery: AliCloudServiceDiscovery):
        self.discovery = discovery
        self.base_dir = Path(__file__).parent
        self.output_dir = self.base_dir
        
        # Find pythonsdk-database directory (try multiple locations)
        possible_paths = [
            Path(__file__).parent.parent.parent.parent / "pythonsdk-database" / "alicloud",
            Path(__file__).parent.parent.parent.parent.parent / "pythonsdk-database" / "alicloud",
            Path(__file__).parent.parent.parent / "pythonsdk-database" / "alicloud",
        ]
        
        self.pythonsdk_dir = None
        for path in possible_paths:
            if path.parent.exists():  # Check if pythonsdk-database exists
                self.pythonsdk_dir = path
                break
        
        if not self.pythonsdk_dir:
            # Default to relative path from current file
            self.pythonsdk_dir = Path(__file__).parent.parent.parent.parent / "pythonsdk-database" / "alicloud"
    
    def generate_catalog(self) -> Dict[str, Any]:
        """Generate catalog from discovered services"""
        return self.discovery.generate_catalog()
    
    def enrich_catalog(self, catalog: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich catalog with field metadata"""
        # Import the enricher
        try:
            from enrich_alicloud_fields import AliCloudFieldEnricher
            enricher = AliCloudFieldEnricher()
            enriched = enricher.enrich_catalog(catalog)
            return enriched
        except ImportError:
            print("⚠️  Could not import enricher, using basic catalog")
            return catalog
    
    def save_catalog(self, catalog: Dict[str, Any], filename: str = "alicloud_sdk_catalog.json"):
        """Save catalog to file"""
        output_file = self.output_dir / filename
        with open(output_file, 'w') as f:
            json.dump(catalog, f, indent=2)
        print(f"\n✅ Saved catalog to {output_file}")
        return output_file
    
    def update_dependencies_file(self, catalog: Dict[str, Any]):
        """Update the dependencies file in pythonsdk-database"""
        # Ensure directory exists
        self.pythonsdk_dir.mkdir(parents=True, exist_ok=True)
        
        deps_file = self.pythonsdk_dir / "alicloud_dependencies_with_python_names_fully_enriched.json"
        
        # Load existing if exists
        existing = {}
        if deps_file.exists():
            with open(deps_file, 'r') as f:
                existing = json.load(f)
        
        # Merge with new catalog
        for service_name, service_data in catalog.items():
            if service_name not in existing:
                existing[service_name] = service_data
                print(f"  ➕ Added {service_name}")
            else:
                # Update operations
                existing_ops = {op['operation'] for op in existing[service_name].get('operations', [])}
                new_ops = {op['operation'] for op in service_data.get('operations', [])}
                
                if new_ops - existing_ops:
                    print(f"  🔄 Updated {service_name} with {len(new_ops - existing_ops)} new operations")
                    existing[service_name] = service_data
        
        # Save updated file
        with open(deps_file, 'w') as f:
            json.dump(existing, f, indent=2)
        
        print(f"\n✅ Updated dependencies file: {deps_file}")
        
        # Also create per-service files
        self.create_service_folders(existing)
    
    def create_service_folders(self, catalog: Dict[str, Any]):
        """Create service folders and files"""
        self.pythonsdk_dir.mkdir(parents=True, exist_ok=True)
        
        for service_name, service_data in catalog.items():
            service_dir = self.pythonsdk_dir / service_name
            service_dir.mkdir(parents=True, exist_ok=True)
            
            service_file = service_dir / "alicloud_dependencies_with_python_names_fully_enriched.json"
            service_catalog = {service_name: service_data}
            
            with open(service_file, 'w') as f:
                json.dump(service_catalog, f, indent=2)
        
        print(f"✅ Created {len(catalog)} service folders")


def main():
    """Main execution"""
    print("=" * 80)
    print("AliCloud SDK Auto-Discovery and Catalog Generation")
    print("=" * 80)
    print()
    
    # Find service_list.json (try multiple locations)
    base_dir = Path(__file__).parent.parent.parent
    possible_paths = [
        base_dir / "config" / "service_list.json",
        Path(__file__).parent.parent.parent.parent / "alicloud_compliance_python_engine" / "config" / "service_list.json",
        Path(__file__).parent.parent.parent / "config" / "service_list.json",
    ]
    
    service_list_file = None
    for path in possible_paths:
        if path.exists():
            service_list_file = path
            break
    
    if not service_list_file:
        print("⚠️  service_list.json not found, will use SDK introspection only")
        print(f"   Tried: {[str(p) for p in possible_paths]}")
    else:
        print(f"✅ Using service_list.json: {service_list_file}")
    
    print()
    
    # Step 1: Discover services
    discovery = AliCloudServiceDiscovery(service_list_file=str(service_list_file) if service_list_file else None)
    discovered = discovery.discover_all_services()
    
    if not discovered:
        print("\n❌ No services discovered. Please install AliCloud SDK packages.")
        print("   Example: pip install aliyun-python-sdk-core aliyun-python-sdk-ecs")
        return
    
    discovery.print_stats()
    
    # Step 2: Generate catalog
    print("\n" + "=" * 80)
    print("Generating Catalog")
    print("=" * 80)
    generator = AliCloudCatalogGenerator(discovery)
    catalog = generator.generate_catalog()
    
    print(f"\n✅ Generated catalog with {len(catalog)} services")
    
    # Step 3: Save basic catalog
    generator.save_catalog(catalog, "alicloud_sdk_catalog.json")
    
    # Step 4: Enrich catalog
    print("\n" + "=" * 80)
    print("Enriching Catalog")
    print("=" * 80)
    enriched = generator.enrich_catalog(catalog)
    
    # Step 5: Save enriched catalog
    generator.save_catalog(enriched, "alicloud_sdk_catalog_enhanced.json")
    
    # Step 6: Update dependencies file
    print("\n" + "=" * 80)
    print("Updating Dependencies File")
    print("=" * 80)
    generator.update_dependencies_file(enriched)
    
    print("\n" + "=" * 80)
    print("✅ Complete!")
    print("=" * 80)
    print(f"   Discovered: {len(discovered)} services")
    print(f"   Generated: {len(catalog)} service catalogs")
    print(f"   Updated: pythonsdk-database/alicloud/")
    print("=" * 80)


if __name__ == '__main__':
    main()

