#!/usr/bin/env python3
"""
IBM Cloud SDK Auto-Discovery and Catalog Generation

This script:
1. Discovers all IBM Cloud SDK packages installed
2. Introspects each package to find available services and operations
3. Generates catalogs for all discovered services
4. Enriches with field metadata (params, output_fields, item_fields)
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


class IBMServiceDiscovery:
    """Discover all IBM Cloud services from installed SDK packages"""
    
    def __init__(self):
        self.discovered_services = {}
        self.stats = {
            'packages_found': 0,
            'services_discovered': 0,
            'operations_found': 0,
            'errors': []
        }
    
    def discover_sdk_packages(self) -> List[str]:
        """Discover all IBM Cloud SDK packages"""
        packages = []
        attempted_imports = set()
        
        # Method 1: Check installed packages via pkgutil (only top-level service packages)
        print("   Checking installed packages via pkgutil...")
        # Skip core SDK submodules - only get top-level service packages
        skip_patterns = ['ibm_cloud_sdk_core', 'ibm_sdk_introspector']
        for importer, modname, ispkg in pkgutil.iter_modules():
            if modname.startswith('ibm_') or 'ibmcloud' in modname.lower():
                # Skip if it's a submodule of core SDK
                if any(modname.startswith(pattern + '.') for pattern in skip_patterns):
                    continue
                # Only include top-level packages (not submodules)
                if '.' not in modname and modname not in packages:
                    packages.append(modname)
                    print(f"      Found: {modname}")
        
        # Method 2: Common IBM Cloud SDK package patterns (try to import)
        print("   Trying common IBM SDK packages...")
        common_patterns = [
            'ibm_vpc',
            'ibm_platform_services',
            'ibm_schematics',
            'ibm_cloud_sdk_core',
            'ibm_watson',
            'ibm_boto3',  # Object Storage (COS SDK)
            'ibmcloudsql',
            'ibm_cloudant',
            'ibm_cos_sdk',
            'ibm_db',
            'ibm_iam_identity',
            'ibm_resource_controller',
            'ibm_resource_manager',
            'ibm_container_registry',
            'ibm_key_protect',
            'ibm_secrets_manager',
            'ibm_cloud_databases',
            'ibm_code_engine',
            'ibm_functions',
            'ibm_appid',
            'ibm_watsonx_data',
            'ibm_watsonx_ai',
            # Additional packages
            'ibm_monitoring',
            'ibm_dns',
            'ibm_billing',
            'ibm_account',
        ]
        
        for pattern in common_patterns:
            if pattern not in packages and pattern not in attempted_imports:
                attempted_imports.add(pattern)
                try:
                    importlib.import_module(pattern)
                    packages.append(pattern)
                    print(f"      Found: {pattern}")
                except ImportError:
                    pass
        
        # Method 3: Skip ibm_cloud_sdk_core submodules (they're not services)
        # We only want actual service packages like ibm_vpc, ibm_platform_services, etc.
        
        # Remove duplicates and sort
        packages = sorted(list(set(packages)))
        self.stats['packages_found'] = len(packages)
        
        return packages
    
    def extract_service_name_from_package(self, package_name: str) -> str:
        """Extract service name from package name"""
        # Patterns: ibm_vpc -> vpc, ibm_platform_services -> platform_services
        if package_name.startswith('ibm_'):
            service = package_name.replace('ibm_', '').split('.')[0]
            return service.lower()
        return package_name.lower()
    
    def discover_service_class(self, package_name: str) -> Optional[str]:
        """Discover the main service class from a package"""
        try:
            module = importlib.import_module(package_name)
            
            # Priority 1: Look for service classes (IBM SDK pattern: VpcV1, IamIdentityV1, etc.)
            service_classes = []
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # IBM SDK classes typically end with V1, V2, etc. (e.g., VpcV1, IamIdentityV1)
                if re.match(r'^[A-Z][a-zA-Z]*V\d+$', name):
                    service_classes.append((name, obj, 1))  # Priority 1
                # Or classes that look like service clients
                elif 'Service' in name and 'Base' not in name:
                    service_classes.append((name, obj, 2))  # Priority 2
                elif 'Client' in name and 'Base' not in name:
                    service_classes.append((name, obj, 2))  # Priority 2
            
            # If we found service classes, return the highest priority one
            if service_classes:
                service_classes.sort(key=lambda x: x[2])  # Sort by priority
                return service_classes[0][0]
            
            # Priority 3: Check for classes with many API-like methods
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if name.startswith('_') or 'Base' in name:
                    continue
                # Check if it has methods that look like API operations
                methods = [m for m in dir(obj) if not m.startswith('_') and callable(getattr(obj, m))]
                # Filter out common object methods
                api_methods = [m for m in methods if m not in ['__class__', '__init__', '__new__', '__str__', '__repr__']]
                if len(api_methods) > 10:  # Likely a service class with many operations
                    return name
        
        except Exception as e:
            self.stats['errors'].append(f"Error discovering service class in {package_name}: {str(e)}")
        
        return None
    
    def discover_operations_from_service_class(self, package_name: str, service_class_name: str) -> List[Dict[str, Any]]:
        """Discover operations from a service class"""
        operations = []
        
        try:
            module = importlib.import_module(package_name)
            service_class = getattr(module, service_class_name, None)
            
            if not service_class:
                return operations
            
            # Get all methods from the service class
            for name, method in inspect.getmembers(service_class, predicate=inspect.isfunction):
                if name.startswith('_'):
                    continue
                
                # Skip special methods
                if name in ['__init__', '__new__', '__class__']:
                    continue
                
                # Get method signature
                try:
                    sig = inspect.signature(method)
                    required_params = []
                    optional_params = []
                    
                    for param_name, param in sig.parameters.items():
                        if param_name in ['self', 'cls']:
                            continue
                        
                        if param.default == inspect.Parameter.empty:
                            required_params.append(param_name)
                        else:
                            optional_params.append(param_name)
                    
                    # Determine operation type
                    op_type = 'dependent'
                    if any(x in name.lower() for x in ['list', 'get_all', 'enumerate']):
                        if len(required_params) <= 1:
                            op_type = 'independent'
                    
                    operation = {
                        'operation': name,
                        'python_method': name,
                        'yaml_action': name.replace('_', '-'),
                        'required_params': required_params,
                        'optional_params': optional_params,
                        'total_optional': len(optional_params),
                        'operation_type': op_type,
                        'description': self._extract_description_from_docstring(method.__doc__)
                    }
                    
                    operations.append(operation)
                    
                except Exception as e:
                    self.stats['errors'].append(f"Error processing method {name}: {str(e)}")
                    continue
        
        except Exception as e:
            self.stats['errors'].append(f"Error discovering operations from {service_class_name}: {str(e)}")
        
        return operations
    
    def _extract_description_from_docstring(self, docstring: Optional[str]) -> str:
        """Extract description from docstring"""
        if not docstring:
            return ""
        
        # Get first line or first sentence
        lines = docstring.strip().split('\n')
        first_line = lines[0].strip()
        
        # Remove common prefixes
        first_line = re.sub(r'^(List|Get|Create|Update|Delete|Describe)\s+', '', first_line, flags=re.IGNORECASE)
        
        return first_line
    
    def discover_services_from_platform_services(self) -> Dict[str, Any]:
        """Discover all services from ibm-platform-services (multi-service package)"""
        discovered = {}
        
        try:
            import ibm_platform_services
            import inspect
            
            # Get all service modules from ibm_platform_services
            # Method 1: Check dir() for direct modules
            service_modules = []
            for name in dir(ibm_platform_services):
                if name.startswith('_'):
                    continue
                obj = getattr(ibm_platform_services, name)
                if inspect.ismodule(obj) and (name.endswith('_v1') or name.endswith('_v2') or name.endswith('_v3') or name.endswith('_v4')):
                    service_modules.append((name, obj))
            
            # Method 2: Use pkgutil to find all modules (catches modules not in dir())
            import pkgutil
            for importer, modname, ispkg in pkgutil.walk_packages(ibm_platform_services.__path__, ibm_platform_services.__name__ + '.'):
                if '_v1' in modname or '_v2' in modname or '_v3' in modname or '_v4' in modname:
                    module_name = modname.split('.')[-1]
                    # Skip if already added
                    if not any(m[0] == module_name for m in service_modules):
                        try:
                            module_obj = importlib.import_module(modname)
                            service_modules.append((module_name, module_obj))
                        except Exception:
                            pass
            
            print(f"\n🔍 Discovering services from ibm-platform-services...")
            print(f"   Found {len(service_modules)} service modules")
            
            for module_name, module_obj in service_modules:
                try:
                    # Extract service name (e.g., case_management_v1 -> case_management)
                    service_name = module_name.rsplit('_v', 1)[0] if '_v' in module_name else module_name
                    
                    # Find service class in module
                    service_class = None
                    for name, obj in inspect.getmembers(module_obj, inspect.isclass):
                        if re.match(r'^[A-Z][a-zA-Z]*V\d+$', name):
                            service_class = name
                            break
                    
                    if not service_class:
                        continue
                    
                    print(f"   ✅ {service_name}: {service_class}")
                    
                    # Discover operations
                    operations = self.discover_operations_from_service_class(f'ibm_platform_services.{module_name}', service_class)
                    
                    if operations:
                        independent = [op for op in operations if op.get('operation_type') == 'independent']
                        dependent = [op for op in operations if op.get('operation_type') == 'dependent']
                        
                        discovered[service_name] = {
                            'service': service_name,
                            'package': f'ibm_platform_services.{module_name}',
                            'service_class': service_class,
                            'description': f"{service_name.replace('_', ' ').title()} Service",
                            'total_operations': len(operations),
                            'independent': independent,
                            'dependent': dependent,
                            'operations': operations
                        }
                        
                        self.stats['services_discovered'] += 1
                        self.stats['operations_found'] += len(operations)
                
                except Exception as e:
                    print(f"   ⚠️  Error processing {module_name}: {e}")
                    continue
        
        except ImportError:
            pass
        
        return discovered
    
    def discover_all_services(self) -> Dict[str, Any]:
        """Discover all services"""
        print("=" * 80)
        print("IBM Cloud SDK Service Discovery")
        print("=" * 80)
        print()
        
        packages = self.discover_sdk_packages()
        print(f"📦 Found {len(packages)} IBM SDK packages")
        
        if not packages:
            print("\n⚠️  No IBM SDK packages found!")
            print("   Please install IBM Cloud SDK packages:")
            print("   pip install ibm-vpc ibm-platform-services ibm-schematics")
            return {}
        
        discovered = {}
        
        # First, discover services from ibm-platform-services (multi-service package)
        platform_services = self.discover_services_from_platform_services()
        discovered.update(platform_services)
        
        # Then discover from other packages
        for package_name in packages:
            try:
                # Skip core SDK packages, platform_services (already processed), and non-service packages
                skip_packages = [
                    'ibm_cloud_sdk_core', 
                    'ibm_sdk_introspector', 
                    'ibm_platform_services',
                    'botocore',  # boto3 dependency, not an IBM service
                    's3transfer',  # boto3 dependency, not an IBM service
                    'ibm_boto3',  # Uses boto3 pattern, handled separately if needed
                ]
                if package_name in skip_packages:
                    continue
                
                service_name = self.extract_service_name_from_package(package_name)
                print(f"\n🔍 Processing: {package_name} -> {service_name}")
                
                # Discover service class
                service_class = self.discover_service_class(package_name)
                if not service_class:
                    print(f"   ⚠️  No service class found, skipping")
                    continue
                
                # Skip if it's a base class or utility class
                if 'Base' in service_class or 'Stream' in service_class or 'Adapter' in service_class or 'Manager' in service_class:
                    print(f"   ⚠️  Skipping utility class: {service_class}")
                    continue
                
                print(f"   ✅ Found service class: {service_class}")
                
                # Special handling for ibm_boto3 (Object Storage - uses boto3 pattern)
                if package_name == 'ibm_boto3':
                    # ibm_boto3 uses boto3 client pattern, not service classes
                    print(f"   ℹ️  ibm_boto3 uses boto3 client pattern (skipping class-based discovery)")
                    # Could add boto3-style discovery here if needed
                    continue
                
                # Discover operations
                operations = self.discover_operations_from_service_class(package_name, service_class)
                print(f"   ✅ Found {len(operations)} operations")
                
                if operations:
                    # Separate independent and dependent operations
                    independent = [op for op in operations if op.get('operation_type') == 'independent']
                    dependent = [op for op in operations if op.get('operation_type') == 'dependent']
                    
                    # Handle name conflicts (if service already exists from platform_services)
                    if service_name in discovered:
                        service_name = f"{service_name}_standalone"
                    
                    discovered[service_name] = {
                        'service': service_name,
                        'package': package_name,
                        'service_class': service_class,
                        'description': f"{service_name.replace('_', ' ').title()} Service",
                        'total_operations': len(operations),
                        'independent': independent,
                        'dependent': dependent,
                        'operations': operations  # Keep all for backward compatibility
                    }
                    
                    self.stats['services_discovered'] += 1
                    self.stats['operations_found'] += len(operations)
            
            except Exception as e:
                error_msg = f"Error processing {package_name}: {str(e)}"
                print(f"   ❌ {error_msg}")
                self.stats['errors'].append(error_msg)
                continue
        
        print("\n" + "=" * 80)
        print("Discovery Summary")
        print("=" * 80)
        print(f"Services Discovered: {self.stats['services_discovered']}")
        print(f"Total Operations: {self.stats['operations_found']}")
        print(f"Errors: {len(self.stats['errors'])}")
        
        return discovered


class IBMCatalogGenerator:
    """Generate and enrich IBM service catalogs"""
    
    def __init__(self, discovery: IBMServiceDiscovery):
        self.discovery = discovery
        self.base_dir = Path("/Users/apple/Desktop/threat-engine/pythonsdk-database/ibm")
        self.base_dir.mkdir(parents=True, exist_ok=True)
    
    def infer_compliance_category(self, field_name: str) -> str:
        """Infer compliance category from field name"""
        field_lower = field_name.lower()
        
        if any(x in field_lower for x in ['id', 'arn', 'name', 'user', 'role', 'principal', 'account']):
            return 'identity'
        elif any(x in field_lower for x in ['encryption', 'key', 'secret', 'password', 'token', 'credential', 'auth']):
            return 'security'
        elif any(x in field_lower for x in ['network', 'vpc', 'subnet', 'security_group', 'firewall', 'acl', 'endpoint']):
            return 'network'
        elif any(x in field_lower for x in ['region', 'zone', 'availability', 'redundancy', 'backup']):
            return 'availability'
        
        return 'general'
    
    def infer_field_type(self, field_name: str) -> str:
        """Infer field type from name"""
        field_lower = field_name.lower()
        
        if any(x in field_lower for x in ['time', 'date', 'created', 'updated', 'modified']):
            return 'string'  # date-time format
        elif any(x in field_lower for x in ['count', 'size', 'number']):
            return 'integer'
        elif any(x in field_lower for x in ['enabled', 'active', 'is_', 'has_']):
            return 'boolean'
        elif any(x in field_lower for x in ['tags', 'list', 'items', 'array']):
            return 'array'
        
        return 'string'
    
    def get_operators_for_type(self, field_type: str) -> List[str]:
        """Get appropriate operators for field type"""
        base_operators = ['equals', 'not_equals', 'contains', 'in', 'exists']
        
        if field_type in ['integer', 'number']:
            return base_operators + ['gt', 'lt', 'gte', 'lte']
        elif field_type == 'array':
            return ['contains', 'not_empty', 'exists']
        elif field_type == 'boolean':
            return ['equals', 'not_equals', 'exists']
        
        return base_operators
    
    def enrich_item_field(self, field_name: str) -> Dict[str, Any]:
        """Enrich a single item field"""
        field_type = self.infer_field_type(field_name)
        compliance_category = self.infer_compliance_category(field_name)
        operators = self.get_operators_for_type(field_type)
        
        description = field_name.replace('_', ' ').replace('-', ' ').title()
        
        # Special handling for common fields
        if 'id' in field_name.lower() and 'arn' not in field_name.lower():
            description = "Resource identifier"
        elif 'arn' in field_name.lower() or 'crn' in field_name.lower():
            description = "Cloud Resource Name (CRN)"
        elif 'name' in field_name.lower():
            description = "Resource name"
        elif 'status' in field_name.lower():
            description = "Resource status"
        elif 'time' in field_name.lower() or 'date' in field_name.lower():
            description = "Timestamp"
            field_type = 'string'
        
        enriched = {
            'type': field_type,
            'description': description,
            'compliance_category': compliance_category,
            'operators': operators
        }
        
        # Add format for date-time fields
        if 'time' in field_name.lower() or 'date' in field_name.lower():
            enriched['format'] = 'date-time'
        
        return enriched
    
    def infer_output_fields(self, operation: Dict[str, Any], service_name: str) -> Dict[str, Any]:
        """Infer output_fields from operation"""
        op_name = operation.get('operation', '').lower()
        
        output_fields = {}
        main_output_field = None
        
        if any(x in op_name for x in ['list', 'get_all', 'enumerate']):
            # List operations typically return a list
            list_field = 'items' if 'items' not in op_name else 'resources'
            output_fields[list_field] = {
                'type': 'array',
                'description': f"List of {service_name} resources",
                'compliance_category': 'general',
                'operators': ['contains', 'not_empty', 'exists']
            }
            main_output_field = list_field
            
            # Add pagination fields
            output_fields['next_token'] = {
                'type': 'string',
                'description': 'Pagination token for next results',
                'compliance_category': 'general',
                'operators': ['equals', 'not_equals', 'contains'],
                'security_impact': 'high'
            }
        elif 'get' in op_name or 'describe' in op_name:
            # Get operations return a single item
            item_field = 'item' if 'item' not in op_name else 'resource'
            output_fields[item_field] = {
                'type': 'object',
                'description': f"{service_name} resource details",
                'compliance_category': 'general',
                'operators': ['exists']
            }
            main_output_field = item_field
        
        return output_fields, main_output_field
    
    def infer_item_fields(self, operation: Dict[str, Any], service_name: str) -> Dict[str, Any]:
        """Infer item_fields from operation name"""
        op_name = operation.get('operation', '').lower()
        item_fields = {}
        
        # Common fields for list/get operations
        if any(x in op_name for x in ['list', 'get', 'describe']):
            common_fields = ['id', 'name', 'crn', 'status', 'created_at', 'tags']
            item_fields = {
                field: self.enrich_item_field(field) 
                for field in common_fields
            }
        
        return item_fields
    
    def enrich_operation(self, operation: Dict[str, Any], service_name: str) -> Dict[str, Any]:
        """Enrich a single operation"""
        enriched = operation.copy()
        
        # Ensure yaml_action exists
        if 'yaml_action' not in enriched:
            enriched['yaml_action'] = enriched.get('python_method', '').replace('_', '-')
        
        # Infer output_fields if not present
        if 'output_fields' not in enriched or not enriched['output_fields']:
            output_fields, main_output_field = self.infer_output_fields(enriched, service_name)
            enriched['output_fields'] = output_fields
            enriched['main_output_field'] = main_output_field
        
        # Infer item_fields if not present or empty
        if 'item_fields' not in enriched or not enriched['item_fields']:
            enriched['item_fields'] = self.infer_item_fields(enriched, service_name)
        elif isinstance(enriched['item_fields'], dict):
            # Enrich existing item_fields
            enriched_item_fields = {}
            for field_name, field_value in enriched['item_fields'].items():
                if isinstance(field_value, dict) and 'type' in field_value:
                    # Already enriched
                    enriched_item_fields[field_name] = field_value
                else:
                    # Need enrichment
                    enriched_item_fields[field_name] = self.enrich_item_field(field_name)
            enriched['item_fields'] = enriched_item_fields
        
        return enriched
    
    def enrich_catalog(self, catalog: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich catalog with field metadata"""
        enriched_catalog = {}
        
        for service_name, service_data in catalog.items():
            enriched_service = service_data.copy()
            
            # Enrich operations
            if 'independent' in enriched_service:
                enriched_service['independent'] = [
                    self.enrich_operation(op, service_name) 
                    for op in enriched_service['independent']
                ]
            
            if 'dependent' in enriched_service:
                enriched_service['dependent'] = [
                    self.enrich_operation(op, service_name) 
                    for op in enriched_service['dependent']
                ]
            
            if 'operations' in enriched_service:
                enriched_service['operations'] = [
                    self.enrich_operation(op, service_name) 
                    for op in enriched_service['operations']
                ]
            
            enriched_catalog[service_name] = enriched_service
        
        return enriched_catalog
    
    def save_catalog(self, catalog: Dict[str, Any], filename: str = "ibm_dependencies_with_python_names_fully_enriched.json") -> Path:
        """Save enriched catalog to file"""
        output_file = self.base_dir / filename
        
        # Backup existing file if it exists
        if output_file.exists():
            backup_file = output_file.with_suffix('.json.backup')
            import shutil
            shutil.copy2(output_file, backup_file)
            print(f"💾 Backed up existing file to: {backup_file.name}")
        
        # Save enriched catalog
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(catalog, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Saved enriched catalog: {output_file}")
        return output_file
    
    def create_service_folders(self, catalog: Dict[str, Any]):
        """Create per-service folders and files"""
        for service_name, service_data in catalog.items():
            service_dir = self.base_dir / service_name
            service_dir.mkdir(exist_ok=True)
            
            service_file = service_dir / "ibm_dependencies_with_python_names_fully_enriched.json"
            service_catalog = {service_name: service_data}
            
            with open(service_file, 'w', encoding='utf-8') as f:
                json.dump(service_catalog, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Created {len(catalog)} service folders")


def main():
    """Main execution"""
    print("=" * 80)
    print("IBM Cloud SDK Auto-Discovery and Catalog Generation")
    print("=" * 80)
    print()
    
    # Step 1: Discover services
    discovery = IBMServiceDiscovery()
    discovered = discovery.discover_all_services()
    
    if not discovered:
        print("\n❌ No services discovered. Please install IBM Cloud SDK packages.")
        print("   Example: pip install ibm-vpc ibm-platform-services ibm-schematics")
        return
    
    # Step 2: Generate catalog
    print("\n" + "=" * 80)
    print("Generating Catalog")
    print("=" * 80)
    generator = IBMCatalogGenerator(discovery)
    catalog = discovered
    
    print(f"\n✅ Generated catalog with {len(catalog)} services")
    
    # Step 3: Enrich catalog
    print("\n" + "=" * 80)
    print("Enriching Catalog")
    print("=" * 80)
    enriched = generator.enrich_catalog(catalog)
    
    # Step 4: Save enriched catalog
    print("\n" + "=" * 80)
    print("Saving Enriched Catalog")
    print("=" * 80)
    output_file = generator.save_catalog(enriched, "ibm_dependencies_with_python_names_fully_enriched.json")
    
    # Step 5: Create per-service files
    generator.create_service_folders(enriched)
    
    # Final summary
    print("\n" + "=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    
    total_services = len(enriched)
    total_operations = sum(d.get('total_operations', 0) for d in enriched.values())
    total_independent = sum(len(d.get('independent', [])) for d in enriched.values())
    total_dependent = sum(len(d.get('dependent', [])) for d in enriched.values())
    
    print(f"\nTotal Services: {total_services}")
    print(f"Total Operations: {total_operations:,}")
    print(f"  - Independent: {total_independent:,}")
    print(f"  - Dependent: {total_dependent:,}")
    print(f"\nOutput File: {output_file}")
    print("=" * 80)


if __name__ == '__main__':
    main()

