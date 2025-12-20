#!/usr/bin/env python3
"""
Azure SDK Auto-Discovery and Catalog Generation

This script:
1. Discovers all Azure SDK packages installed
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

# Import functions from the existing generator
from generate_azure_dependencies_final import (
    to_snake_case,
    extract_model_fields_comprehensive,
    get_model_class_from_name,
    parse_docstring_for_return_info,
    get_method_parameters,
    parse_optional_params_from_docstring,
    is_list_operation,
    analyze_operations_class,
    get_operations_from_module,
    process_service
)


class AzureServiceDiscovery:
    """Discover all Azure services from installed SDK packages"""
    
    def __init__(self):
        self.discovered_services = {}
        self.stats = {
            'packages_found': 0,
            'services_discovered': 0,
            'operations_found': 0,
            'errors': []
        }
    
    def discover_azure_modules(self) -> Dict[str, str]:
        """Discover all azure.mgmt modules and map them to service names"""
        service_modules = {}
        versioned_modules = {}  # Track versioned modules separately
        
        try:
            import azure.mgmt
            # Walk through all azure.mgmt packages
            for importer, modname, ispkg in pkgutil.walk_packages(azure.mgmt.__path__, azure.mgmt.__name__ + '.'):
                if ispkg:
                    # Skip async, operations, models, and internal modules
                    if '.aio' in modname or '.operations' in modname or '.models' in modname or '._' in modname or 'core' in modname:
                        continue
                    
                    # Extract service name from module path
                    parts = modname.split('.')
                    if len(parts) >= 3:
                        service_parts = parts[2:]  # Skip azure.mgmt
                        
                        # Handle special cases
                        if len(service_parts) == 1:
                            service_name = service_parts[0]
                        elif service_parts[0] == 'rdbms':
                            # rdbms.postgresql -> rdbms_postgresql
                            service_name = '_'.join(service_parts)
                        else:
                            service_name = service_parts[0]
                        
                        # Check if module has operations
                        try:
                            test_module = importlib.import_module(modname)
                            # Check if it has operations module
                            has_operations = False
                            try:
                                ops_module = importlib.import_module(f"{modname}.operations")
                                if ops_module:
                                    has_operations = True
                            except:
                                pass
                            
                            if has_operations:
                                # Handle versioned vs non-versioned
                                if '.v' in modname:
                                    # Versioned module - use latest version
                                    if service_name not in versioned_modules:
                                        versioned_modules[service_name] = modname
                                    else:
                                        # Compare versions - prefer newer
                                        current = versioned_modules[service_name]
                                        # Simple comparison - prefer longer version strings (usually newer)
                                        if len(modname) > len(current):
                                            versioned_modules[service_name] = modname
                                else:
                                    # Non-versioned - prefer this
                                    if service_name not in service_modules:
                                        service_modules[service_name] = modname
                        except Exception as e:
                            pass
        except ImportError as e:
            print(f"⚠️  Could not import azure.mgmt: {e}")
            self.stats['errors'].append(f"Import error: {e}")
        
        # Merge versioned modules where non-versioned don't exist
        for service_name, module_path in versioned_modules.items():
            if service_name not in service_modules:
                service_modules[service_name] = module_path
        
        # Also check for specific versioned modules that might be needed
        specific_versioned = {
            'authorization': 'azure.mgmt.authorization.v2022_04_01',
            'eventhub': 'azure.mgmt.eventhub.v2024_01_01',
            'servicebus': 'azure.mgmt.servicebus.v2022_10_01_preview',
        }
        
        for service_name, module_path in specific_versioned.items():
            try:
                importlib.import_module(module_path)
                if service_name not in service_modules:
                    service_modules[service_name] = module_path
            except ImportError:
                pass
        
        self.stats['packages_found'] = len(service_modules)
        return service_modules
    
    def discover_all_services(self) -> Dict[str, str]:
        """Discover all Azure services"""
        print("=" * 80)
        print("Discovering Azure Services")
        print("=" * 80)
        
        service_modules = self.discover_azure_modules()
        
        print(f"\n✅ Found {len(service_modules)} Azure services")
        print("\nServices discovered:")
        for service_name in sorted(service_modules.keys()):
            print(f"  - {service_name}: {service_modules[service_name]}")
        
        self.discovered_services = service_modules
        self.stats['services_discovered'] = len(service_modules)
        
        return service_modules


class AzureCatalogGenerator:
    """Generate and enrich Azure SDK catalog"""
    
    def __init__(self, discovery: AzureServiceDiscovery):
        self.discovery = discovery
        self.base_dir = Path(__file__).parent
        
        # Find pythonsdk-database directory
        possible_paths = [
            Path(__file__).parent.parent.parent.parent / "pythonsdk-database" / "azure",
            Path(__file__).parent.parent.parent.parent.parent / "pythonsdk-database" / "azure",
            Path(__file__).parent.parent.parent / "pythonsdk-database" / "azure",
        ]
        
        self.pythonsdk_dir = None
        for path in possible_paths:
            if path.parent.exists():
                self.pythonsdk_dir = path
                break
        
        if not self.pythonsdk_dir:
            self.pythonsdk_dir = Path(__file__).parent.parent.parent.parent / "pythonsdk-database" / "azure"
        
        # Create directory if it doesn't exist
        self.pythonsdk_dir.mkdir(parents=True, exist_ok=True)
        print(f"📁 Output directory: {self.pythonsdk_dir}")
    
    def generate_catalog(self) -> Dict[str, Any]:
        """Generate catalog from discovered services"""
        azure_dependencies = {}
        
        service_modules = self.discovery.discovered_services
        
        for service_name, module_path in service_modules.items():
            result = process_service(service_name, module_path)
            if result:
                azure_dependencies[service_name] = result
        
        return azure_dependencies
    
    def enrich_item_fields(self, item_fields: Any) -> Dict[str, Any]:
        """Enrich item fields with compliance categories and operators"""
        enriched = {}
        
        # Handle list of field names (from extract_model_fields_comprehensive)
        if isinstance(item_fields, list):
            for field_name in item_fields:
                enriched[field_name] = self._enrich_single_field(field_name)
        # Handle dict of field_name -> field_value
        elif isinstance(item_fields, dict):
            for field_name, field_value in item_fields.items():
                if isinstance(field_value, dict):
                    # Already enriched
                    enriched[field_name] = field_value
                else:
                    enriched[field_name] = self._enrich_single_field(field_name, field_value)
        else:
            return {}
        
        return enriched
    
    def _enrich_single_field(self, field_name: str, field_value: Any = None) -> Dict[str, Any]:
        """Enrich a single field"""
        # Determine field type
        field_type = "string"
        if field_value is not None:
            if isinstance(field_value, list):
                field_type = "array"
            elif isinstance(field_value, (int, float)):
                field_type = "integer" if isinstance(field_value, int) else "number"
            elif isinstance(field_value, bool):
                field_type = "boolean"
        else:
            # Infer type from field name
            if any(keyword in field_name.lower() for keyword in ['count', 'size', 'number', 'id']):
                if 'id' in field_name.lower() and 'count' not in field_name.lower():
                    field_type = "string"
                else:
                    field_type = "integer"
            elif any(keyword in field_name.lower() for keyword in ['tags', 'list', 'array']):
                field_type = "array"
        
        # Determine compliance category based on field name
        compliance_category = "general"
        if any(keyword in field_name.lower() for keyword in ['id', 'name', 'arn', 'resource']):
            compliance_category = "identity"
        elif any(keyword in field_name.lower() for keyword in ['location', 'region', 'zone', 'availability']):
            compliance_category = "availability"
        elif any(keyword in field_name.lower() for keyword in ['encrypt', 'key', 'secret', 'password', 'certificate', 'credential']):
            compliance_category = "security"
        elif any(keyword in field_name.lower() for keyword in ['tag', 'label', 'metadata']):
            compliance_category = "governance"
        
        # Determine operators based on field type
        operators = ["equals", "not_equals", "contains", "in", "not_empty", "exists"]
        if field_type == "integer" or field_type == "number":
            operators.extend(["gt", "lt", "gte", "lte"])
        elif field_type == "array":
            operators = ["contains", "not_empty", "exists"]
        
        return {
            "type": field_type,
            "compliance_category": compliance_category,
            "operators": operators,
            "description": field_name.replace('_', ' ').title()
        }
    
    def enrich_catalog(self, catalog: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich catalog with field metadata"""
        enriched_catalog = {}
        
        for service_name, service_data in catalog.items():
            enriched_service = service_data.copy()
            
            # Enrich operations
            if 'operations_by_category' in enriched_service:
                for category, category_data in enriched_service['operations_by_category'].items():
                    # Enrich independent operations
                    for op in category_data.get('independent', []):
                        if 'item_fields' in op and op['item_fields']:
                            op['item_fields'] = self.enrich_item_fields(op['item_fields'])
                    
                    # Enrich dependent operations
                    for op in category_data.get('dependent', []):
                        if 'item_fields' in op and op['item_fields']:
                            op['item_fields'] = self.enrich_item_fields(op['item_fields'])
            
            # Enrich top-level independent and dependent
            for op in enriched_service.get('independent', []):
                if 'item_fields' in op and op['item_fields']:
                    op['item_fields'] = self.enrich_item_fields(op['item_fields'])
            
            for op in enriched_service.get('dependent', []):
                if 'item_fields' in op and op['item_fields']:
                    op['item_fields'] = self.enrich_item_fields(op['item_fields'])
            
            enriched_catalog[service_name] = enriched_service
        
        return enriched_catalog
    
    def save_catalog(self, catalog: Dict[str, Any], filename: str = "azure_dependencies_with_python_names_fully_enriched.json"):
        """Save catalog to file"""
        output_file = self.pythonsdk_dir / filename
        
        print(f"\n💾 Saving catalog to: {output_file}")
        with open(output_file, 'w') as f:
            json.dump(catalog, f, indent=2)
        
        file_size = output_file.stat().st_size
        print(f"✅ Saved {len(catalog)} services ({file_size:,} bytes)")
        
        return output_file
    
    def create_service_folders(self, catalog: Dict[str, Any]):
        """Create per-service folders and files"""
        print(f"\n📁 Creating per-service files...")
        
        for service_name, service_data in catalog.items():
            service_dir = self.pythonsdk_dir / service_name
            service_dir.mkdir(exist_ok=True)
            
            service_file = service_dir / "azure_dependencies_with_python_names_fully_enriched.json"
            service_catalog = {service_name: service_data}
            
            with open(service_file, 'w') as f:
                json.dump(service_catalog, f, indent=2)
        
        print(f"✅ Created {len(catalog)} service folders")
    
    def create_service_list(self, catalog: Dict[str, Any]):
        """Create service list file"""
        service_list = {
            "total_services": len(catalog),
            "total_operations": sum(d.get('total_operations', 0) for d in catalog.values()),
            "services": sorted(catalog.keys()),
            "services_detail": {
                svc: d.get('total_operations', 0) for svc, d in catalog.items()
            }
        }
        
        # Save JSON
        list_file = self.pythonsdk_dir / "all_services.json"
        with open(list_file, 'w') as f:
            json.dump(service_list, f, indent=2)
        
        # Save human-readable
        txt_file = self.pythonsdk_dir / "ALL_SERVICES_FINAL.txt"
        with open(txt_file, 'w') as f:
            f.write("Azure Services List\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Total Services: {service_list['total_services']}\n")
            f.write(f"Total Operations: {service_list['total_operations']}\n\n")
            f.write("Services:\n")
            for svc in sorted(catalog.keys()):
                ops = catalog[svc].get('total_operations', 0)
                f.write(f"  {svc:30s} - {ops:4d} operations\n")
        
        print(f"✅ Created service list files")
        return service_list


def main():
    """Main execution"""
    print("=" * 80)
    print("Azure SDK Auto-Discovery and Catalog Generation")
    print("=" * 80)
    print()
    
    # Step 1: Discover services
    discovery = AzureServiceDiscovery()
    discovered = discovery.discover_all_services()
    
    if not discovered:
        print("\n❌ No services discovered. Please install Azure SDK packages.")
        print("   Example: pip install azure-mgmt-compute azure-mgmt-storage")
        return
    
    # Step 2: Generate catalog
    print("\n" + "=" * 80)
    print("Generating Catalog")
    print("=" * 80)
    generator = AzureCatalogGenerator(discovery)
    catalog = generator.generate_catalog()
    
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
    output_file = generator.save_catalog(enriched, "azure_dependencies_with_python_names_fully_enriched.json")
    
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

