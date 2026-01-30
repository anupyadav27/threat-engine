#!/usr/bin/env python3
"""
GCP SDK Auto-Discovery and Catalog Generation

This script:
1. Discovers all google-cloud-* SDK packages installed
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
from typing import Dict, List, Any, Set, Optional
import re

# Try to import enrichment utilities
try:
    from enrich_gcp_api_fields import GCPAPIFieldEnricher
except ImportError:
    print("⚠️  enrich_gcp_api_fields.py not found, will use basic enrichment")
    GCPAPIFieldEnricher = None


class GCPServiceDiscovery:
    """Discover all GCP services from installed SDK packages"""
    
    def __init__(self):
        self.discovered_services = {}
        self.stats = {
            'packages_found': 0,
            'services_discovered': 0,
            'operations_found': 0,
            'errors': []
        }
    
    def discover_sdk_packages(self) -> Dict[str, str]:
        """Discover all google-cloud-* SDK packages"""
        packages = {}
        
        try:
            # Look for google.cloud packages - only get direct children, not sub-packages
            import google.cloud
            google_cloud_path = google.cloud.__path__
            
            # Get only direct children of google.cloud (not recursive)
            for importer, modname, ispkg in pkgutil.iter_modules(google_cloud_path, 'google.cloud.'):
                if ispkg:
                    # Extract service name (e.g., 'google.cloud.storage' -> 'storage')
                    parts = modname.split('.')
                    if len(parts) >= 3 and parts[0] == 'google' and parts[1] == 'cloud':
                        service_name = parts[2]
                        
                        # Skip internal/utility packages and versioned modules
                        skip_patterns = [
                            'core', 'common', 'auth', 'exceptions', 'helpers',
                            '_helpers', '_http', '_testing', 'client', 'obsolete',
                            'operation', 'environment_vars'
                        ]
                        
                        # Skip if starts with underscore or ends with version pattern
                        should_skip = (
                            service_name.startswith('_') or
                            service_name in skip_patterns or
                            any(pattern in service_name for pattern in ['_v', '_v1', '_v2', '_v3', '_v1beta', '_v2beta', '_v3beta'])
                        )
                        
                        if not should_skip:
                            packages[service_name] = modname
        except ImportError:
            self.stats['errors'].append("google.cloud not installed")
        
        self.stats['packages_found'] = len(packages)
        return packages
    
    def extract_service_name_from_package(self, package_name: str) -> str:
        """Extract service name from package name"""
        parts = package_name.split('.')
        if len(parts) >= 3 and parts[0] == 'google' and parts[1] == 'cloud':
            return parts[2]
        return None
    
    def find_client_classes(self, module) -> List[Any]:
        """Find client classes in a module"""
        clients = []
        for name, obj in inspect.getmembers(module, predicate=inspect.isclass):
            # Look for Client classes (GCP standard)
            if name == 'Client' and obj.__module__.startswith(module.__name__):
                clients.append((name, obj))
            # Also check for other client-like classes
            elif ('Client' in name or 'Service' in name) and name != 'BaseClient':
                if obj.__module__.startswith(module.__name__):
                    clients.append((name, obj))
        
        # If no clients found, try importing Client directly
        if not clients:
            try:
                if hasattr(module, 'Client'):
                    clients.append(('Client', module.Client))
            except Exception:
                pass
        
        return clients
    
    def extract_methods_from_client(self, client_class) -> List[Dict[str, Any]]:
        """Extract methods from a client class"""
        methods = []
        
        # Get both bound and unbound methods
        for name, obj in inspect.getmembers(client_class):
            # Skip private and special methods
            if name.startswith('_'):
                continue
            
            # Check if it's a method (function or bound method)
            if not (inspect.ismethod(obj) or inspect.isfunction(obj)):
                continue
            
            # For bound methods, get the underlying function
            if inspect.ismethod(obj):
                method = obj.__func__
            else:
                method = obj
            
            # Skip if method is from a different module (likely inherited)
            # Allow if it's from the same package
            if hasattr(method, '__module__') and method.__module__:
                if not method.__module__.startswith(client_class.__module__.rsplit('.', 1)[0]):
                    continue
            
            # Get method signature
            try:
                sig = inspect.signature(method)
                params = []
                optional_params = {}
                
                for param_name, param in sig.parameters.items():
                    if param_name == 'self':
                        continue
                    
                    # Check if optional (has default)
                    if param.default != inspect.Parameter.empty:
                        optional_params[param_name] = {
                            'type': str(param.annotation) if param.annotation != inspect.Parameter.empty else 'unknown'
                        }
                    else:
                        params.append(param_name)
                
                # Determine operation type
                op_type = 'independent'  # Default
                if any(keyword in name.lower() for keyword in ['list', 'get', 'describe']):
                    op_type = 'independent'
                elif any(keyword in name.lower() for keyword in ['create', 'update', 'delete', 'patch']):
                    op_type = 'dependent'
                
                methods.append({
                    'name': name,
                    'operation': name,
                    'python_method': name,
                    'yaml_action': name,
                    'required_params': params,
                    'optional_params': optional_params,
                    'total_optional': len(optional_params),
                    'operation_type': op_type,
                    'description': method.__doc__ or ''
                })
            except Exception as e:
                self.stats['errors'].append(f"Error parsing method {name}: {e}")
        
        return methods
    
    def discover_service_operations(self, service_name: str, package_name: str) -> Dict[str, Any]:
        """Discover operations for a service"""
        operations = []
        resources = {}
        
        try:
            # Import the package
            module = importlib.import_module(package_name)
            
            # Find client classes
            clients = self.find_client_classes(module)
            
            if not clients:
                # Try to find any classes that might be clients
                for name, obj in inspect.getmembers(module, predicate=inspect.isclass):
                    if 'Client' in name or 'Service' in name:
                        if obj.__module__ == module.__name__:
                            clients.append((name, obj))
            
            # Extract methods from clients
            for client_name, client_class in clients:
                methods = self.extract_methods_from_client(client_class)
                
                # Group methods by resource/operation type
                # For GCP, we'll organize by resource types if possible
                resource_name = service_name  # Default to service name
                
                if resource_name not in resources:
                    resources[resource_name] = {
                        'independent': [],
                        'dependent': []
                    }
                
                for method in methods:
                    op_type = method.get('operation_type', 'independent')
                    # Remove operation_type from method dict
                    method.pop('operation_type', None)
                    
                    if op_type == 'independent':
                        resources[resource_name]['independent'].append(method)
                    else:
                        resources[resource_name]['dependent'].append(method)
                    
                    operations.append(method)
            
            # If no clients found, try to find any public functions
            if not operations:
                for name, obj in inspect.getmembers(module, predicate=inspect.isfunction):
                    if not name.startswith('_'):
                        operations.append({
                            'name': name,
                            'operation': name,
                            'python_method': name,
                            'yaml_action': name,
                            'required_params': [],
                            'optional_params': {},
                            'total_optional': 0,
                            'description': obj.__doc__ or ''
                        })
        
        except Exception as e:
            self.stats['errors'].append(f"Error discovering {service_name}: {e}")
            return {
                'service': service_name,
                'module': package_name,
                'operations': [],
                'resources': {},
                'total_operations': 0
            }
        
        # Calculate total operations
        total_ops = sum(len(res.get('independent', []) + res.get('dependent', [])) 
                       for res in resources.values())
        
        return {
            'service': service_name,
            'module': package_name,
            'operations': operations,
            'resources': resources,
            'total_operations': total_ops
        }
    
    def discover_all_services(self) -> Dict[str, Any]:
        """Discover all GCP services"""
        print("=" * 80)
        print("GCP SDK Service Discovery")
        print("=" * 80)
        print()
        
        packages = self.discover_sdk_packages()
        print(f"📦 Found {len(packages)} SDK packages")
        
        if not packages:
            print("\n⚠️  No GCP SDK packages found!")
            print("   Install with: pip install google-cloud-storage google-cloud-compute")
            print("   Or install multiple: pip install google-cloud-*")
            return {}
        
        print(f"   Packages: {', '.join(sorted(packages.keys())[:10])}{'...' if len(packages) > 10 else ''}")
        print()
        
        # Discover services from packages
        for service_name, package_name in sorted(packages.items()):
            print(f"  🔍 Discovering {service_name} from {package_name}...")
            service_info = self.discover_service_operations(service_name, package_name)
            
            if service_info['total_operations'] > 0:
                self.discovered_services[service_name] = service_info
                self.stats['services_discovered'] += 1
                self.stats['operations_found'] += service_info['total_operations']
                print(f"     ✅ Found {service_info['total_operations']} operations")
            else:
                print(f"     ⚠️  No operations found")
        
        return self.discovered_services
    
    def print_stats(self):
        """Print discovery statistics"""
        print("\n" + "=" * 80)
        print("Discovery Statistics")
        print("=" * 80)
        print(f"Packages found: {self.stats['packages_found']}")
        print(f"Services discovered: {self.stats['services_discovered']}")
        print(f"Operations found: {self.stats['operations_found']}")
        if self.stats['errors']:
            print(f"Errors: {len(self.stats['errors'])}")
            for error in self.stats['errors'][:5]:
                print(f"  - {error}")


class GCPCatalogGenerator:
    """Generate and enrich GCP SDK catalog"""
    
    def __init__(self, discovery: GCPServiceDiscovery):
        self.discovery = discovery
        self.field_enricher = GCPAPIFieldEnricher() if GCPAPIFieldEnricher else None
        self.base_dir = Path(__file__).parent.parent.parent.parent
        self.output_dir = self.base_dir / 'pythonsdk-database' / 'gcp'
    
    def generate_catalog(self) -> Dict[str, Any]:
        """Generate catalog from discovered services"""
        catalog = {}
        
        for service_name, service_info in self.discovery.discovered_services.items():
            # Convert to GCP format (resources-based structure)
            service_data = {
                'service': service_name,
                'module': service_info.get('module', ''),
                'total_operations': service_info.get('total_operations', 0),
                'resources': {}
            }
            
            # Process resources
            resources = service_info.get('resources', {})
            for resource_name, resource_data in resources.items():
                service_data['resources'][resource_name] = {
                    'independent': resource_data.get('independent', []),
                    'dependent': resource_data.get('dependent', [])
                }
            
            # If no resources structure, create one from operations
            if not service_data['resources']:
                # Group operations by resource (use service name as default)
                resource_name = service_name
                independent = []
                dependent = []
                
                for op in service_info.get('operations', []):
                    op_dict = op.copy()
                    # Determine if independent or dependent
                    op_name = op.get('operation', '').lower()
                    if any(kw in op_name for kw in ['list', 'get', 'describe']):
                        independent.append(op_dict)
                    else:
                        dependent.append(op_dict)
                
                service_data['resources'][resource_name] = {
                    'independent': independent,
                    'dependent': dependent
                }
            
            catalog[service_name] = service_data
        
        return catalog
    
    def enrich_catalog(self, catalog: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich catalog with field metadata"""
        print("\n" + "=" * 80)
        print("Enriching Catalog with Field Metadata")
        print("=" * 80)
        
        enriched = {}
        
        for service_name, service_data in catalog.items():
            print(f"  Enriching {service_name}...")
            enriched_service = service_data.copy()
            
            # Enrich operations with item_fields
            for resource_name, resource_data in enriched_service.get('resources', {}).items():
                for op_type in ['independent', 'dependent']:
                    operations = resource_data.get(op_type, [])
                    for op in operations:
                        # Add item_fields using enricher if available
                        if self.field_enricher:
                            item_fields = self._enrich_with_enricher(
                                service_name, resource_name, op
                            )
                            op['item_fields'] = item_fields
                        else:
                            # Basic enrichment
                            op['item_fields'] = self._basic_enrich_fields(op)
            
            enriched[service_name] = enriched_service
        
        return enriched
    
    def _enrich_with_enricher(self, service_name: str, resource_name: str, operation: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich operation using GCPAPIFieldEnricher"""
        if not self.field_enricher:
            return self._basic_enrich_fields(operation)
        
        # Use enricher's enrich_operation method (signature: enrich_operation(operation, service_name, resource_name))
        if hasattr(self.field_enricher, 'enrich_operation'):
            enriched_op = self.field_enricher.enrich_operation(operation, service_name, resource_name)
            return enriched_op.get('item_fields', {})
        
        # Fallback: get common fields and service-specific fields
        fields = {}
        
        # Add common fields
        common_fields = self.field_enricher.COMMON_RESPONSE_FIELDS.copy()
        
        # Check if operation is list/get (should have item_fields)
        op_name = operation.get('operation', '').lower()
        if any(kw in op_name for kw in ['list', 'get', 'describe']):
            fields.update(common_fields)
            
            # Add service-specific fields
            if hasattr(self.field_enricher, 'get_resource_fields'):
                resource_fields = self.field_enricher.get_resource_fields(service_name, resource_name)
                fields.update(resource_fields)
        
        return fields
    
    def _basic_enrich_fields(self, operation: Dict[str, Any]) -> Dict[str, Any]:
        """Basic field enrichment when enricher is not available"""
        fields = {}
        
        # Add common GCP fields
        common_fields = {
            'name': {
                'type': 'string',
                'description': 'Resource name',
                'compliance_category': 'identity',
                'operators': ['equals', 'not_equals', 'contains', 'in']
            },
            'id': {
                'type': 'string',
                'description': 'Unique resource identifier',
                'compliance_category': 'identity',
                'operators': ['equals', 'not_equals', 'exists']
            },
            'selfLink': {
                'type': 'string',
                'description': 'Server-defined URL for the resource',
                'compliance_category': 'identity'
            },
            'creationTimestamp': {
                'type': 'string',
                'format': 'date-time',
                'description': 'Creation timestamp',
                'compliance_category': 'general'
            }
        }
        
        # Only add fields for list/get operations
        op_name = operation.get('operation', '').lower()
        if any(kw in op_name for kw in ['list', 'get', 'describe']):
            fields.update(common_fields)
        
        return fields
    
    def save_catalog(self, catalog: Dict[str, Any], filename: str) -> Path:
        """Save catalog to file"""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        output_file = self.output_dir / filename
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(catalog, f, indent=2, sort_keys=True, ensure_ascii=False)
        
        print(f"\n✅ Saved catalog to: {output_file}")
        return output_file
    
    def create_service_folders(self, catalog: Dict[str, Any]):
        """Create per-service folders and files"""
        print("\n" + "=" * 80)
        print("Creating Per-Service Files")
        print("=" * 80)
        
        for service_name, service_data in catalog.items():
            service_dir = self.output_dir / service_name
            service_dir.mkdir(parents=True, exist_ok=True)
            
            # Create per-service file
            service_file = service_dir / 'gcp_dependencies_with_python_names_fully_enriched.json'
            service_catalog = {service_name: service_data}
            
            with open(service_file, 'w', encoding='utf-8') as f:
                json.dump(service_catalog, f, indent=2, sort_keys=True, ensure_ascii=False)
            
            print(f"  ✅ Created {service_name}/")
    
    def create_service_list(self, catalog: Dict[str, Any]) -> Dict[str, Any]:
        """Create service list file"""
        service_list = {
            'total_services': len(catalog),
            'total_operations': sum(s.get('total_operations', 0) for s in catalog.values()),
            'services': sorted(catalog.keys()),
            'services_detail': {
                name: s.get('total_operations', 0)
                for name, s in catalog.items()
            }
        }
        
        list_file = self.output_dir / 'all_services.json'
        with open(list_file, 'w', encoding='utf-8') as f:
            json.dump(service_list, f, indent=2, sort_keys=True)
        
        print(f"\n✅ Created service list: {list_file}")
        return service_list


def main():
    """Main execution"""
    print("=" * 80)
    print("GCP SDK Auto-Discovery and Catalog Generation")
    print("=" * 80)
    print()
    
    # Step 1: Discover services
    discovery = GCPServiceDiscovery()
    discovered = discovery.discover_all_services()
    
    if not discovered:
        print("\n❌ No services discovered. Please install GCP SDK packages.")
        print("   Example: pip install google-cloud-storage google-cloud-compute")
        print("   Or install all: pip install google-cloud-*")
        return
    
    discovery.print_stats()
    
    # Step 2: Generate catalog
    print("\n" + "=" * 80)
    print("Generating Catalog")
    print("=" * 80)
    generator = GCPCatalogGenerator(discovery)
    catalog = generator.generate_catalog()
    
    print(f"\n✅ Generated catalog with {len(catalog)} services")
    
    # Step 3: Enrich catalog
    enriched = generator.enrich_catalog(catalog)
    
    # Step 4: Save enriched catalog
    print("\n" + "=" * 80)
    print("Saving Enriched Catalog")
    print("=" * 80)
    output_file = generator.save_catalog(enriched, "gcp_dependencies_with_python_names_fully_enriched.json")
    
    # Step 5: Create per-service files
    generator.create_service_folders(enriched)
    
    # Step 6: Create service list
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

