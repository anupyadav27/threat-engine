#!/usr/bin/env python3
"""
Enrich Azure SDK dependencies JSON files with possible values extracted from Azure SDK models.
"""

import json
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys
import re

class AzureEnumExtractor:
    """Extract enum values from Azure SDK models"""
    
    def __init__(self):
        self.stats = {
            'services_processed': 0,
            'operations_processed': 0,
            'fields_enriched': 0,
            'enums_found': 0,
            'errors': []
        }
    
    def extract_enum_from_model(self, model_class) -> Optional[List[str]]:
        """Extract enum values from an Azure SDK model class"""
        if model_class is None:
            return None
        
        # Check if it's an Enum class
        try:
            if inspect.isclass(model_class) and hasattr(model_class, '__members__'):
                # It's an Enum
                members = model_class.__members__
                if members:
                    # Get string values
                    values = []
                    for name, member in members.items():
                        if hasattr(member, 'value'):
                            values.append(str(member.value))
                        else:
                            values.append(name)
                    return sorted(list(set(values)))
        except Exception:
            pass
        
        # Check for enum-like attributes
        try:
            if hasattr(model_class, '_attribute_map'):
                # Check if any attribute references an enum
                pass
        except Exception:
            pass
        
        return None
    
    def find_enum_class(self, module_name: str, field_name: str) -> Optional[type]:
        """Find enum class for a field in Azure SDK models"""
        try:
            # Try common enum naming patterns
            enum_patterns = [
                f"{field_name}Type",
                f"{field_name}Types",
                f"{field_name}Enum",
                f"{field_name}State",
                f"{field_name}Status",
                f"{field_name}ProvisioningState",
            ]
            
            # Extract base module (e.g., azure.mgmt.compute from azure.mgmt.compute.models)
            if '.models' in module_name:
                base_module_name = module_name.replace('.models', '')
                models_module_name = module_name
            else:
                base_module_name = module_name
                models_module_name = f"{module_name}.models"
            
            try:
                models_module = importlib.import_module(models_module_name)
                
                for pattern in enum_patterns:
                    if hasattr(models_module, pattern):
                        enum_class = getattr(models_module, pattern)
                        if inspect.isclass(enum_class) and hasattr(enum_class, '__members__'):
                            return enum_class
            except Exception:
                pass
            
            # Try searching all attributes in models module
            try:
                models_module = importlib.import_module(models_module_name)
                for name in dir(models_module):
                    if name.upper() == field_name.upper() or field_name.upper() in name.upper():
                        obj = getattr(models_module, name)
                        if inspect.isclass(obj) and hasattr(obj, '__members__'):
                            # Check if it looks like an enum
                            members = obj.__members__
                            if members and len(members) > 0:
                                return obj
            except Exception:
                pass
            
        except Exception as e:
            pass
        
        return None
    
    def extract_enum_from_field(self, module_name: str, field_name: str, 
                               model_class=None) -> Optional[List[str]]:
        """Extract enum values for a specific field"""
        
        # Try to find enum class
        enum_class = self.find_enum_class(module_name, field_name)
        if enum_class:
            return self.extract_enum_from_model(enum_class)
        
        # Check if field_name itself is an enum in common patterns
        common_enums = {
            'status': ['Succeeded', 'Failed', 'InProgress', 'Canceled'],
            'state': ['Running', 'Stopped', 'Starting', 'Stopping', 'Deallocated', 'Deallocating'],
            'provisioning_state': ['Succeeded', 'Failed', 'Creating', 'Updating', 'Deleting'],
            'type': ['Microsoft.Compute/virtualMachines', 'Microsoft.Storage/storageAccounts'],
        }
        
        field_lower = field_name.lower()
        for key, values in common_enums.items():
            if key in field_lower:
                return sorted(values)
        
        return None
    
    def enrich_operation_fields(self, service_name: str, module_name: str,
                               enriched_data: Dict) -> Dict:
        """Enrich operation fields with enum values from Azure SDK"""
        
        try:
            # Enrich item_fields
            if 'item_fields' in enriched_data and isinstance(enriched_data['item_fields'], dict):
                for field_name, field_data in enriched_data['item_fields'].items():
                    # Skip if already has enum
                    if 'possible_values' in field_data:
                        continue
                    
                    enum_values = self.extract_enum_from_field(module_name, field_name)
                    if enum_values:
                        field_data['enum'] = True
                        field_data['possible_values'] = enum_values
                        self.stats['enums_found'] += 1
                        self.stats['fields_enriched'] += 1
            
            # Enrich output_fields (if they're dicts, not lists)
            if 'output_fields' in enriched_data:
                if isinstance(enriched_data['output_fields'], dict):
                    for field_name, field_data in enriched_data['output_fields'].items():
                        if isinstance(field_data, dict) and 'possible_values' not in field_data:
                            enum_values = self.extract_enum_from_field(module_name, field_name)
                            if enum_values:
                                field_data['enum'] = True
                                field_data['possible_values'] = enum_values
                                self.stats['enums_found'] += 1
                                self.stats['fields_enriched'] += 1
            
            self.stats['operations_processed'] += 1
            
        except Exception as e:
            error_msg = f"Error enriching {service_name}: {str(e)}"
            self.stats['errors'].append(error_msg)
        
        return enriched_data
    
    def enrich_service_file(self, service_path: Path) -> bool:
        """Enrich a single service's enriched dependencies file"""
        
        enriched_file = service_path / "azure_dependencies_with_python_names_fully_enriched.json"
        
        if not enriched_file.exists():
            return False
        
        try:
            with open(enriched_file, 'r') as f:
                data = json.load(f)
            
            service_name = service_path.name
            
            # Get module name from data
            module_name = None
            if service_name in data:
                module_name = data[service_name].get('module', '')
            
            if not module_name:
                return False
            
            fields_before = self.stats['fields_enriched']
            
            # Process operations_by_category
            if service_name in data and 'operations_by_category' in data[service_name]:
                for category, category_data in data[service_name]['operations_by_category'].items():
                    # Process independent operations
                    if 'independent' in category_data:
                        for op_data in category_data['independent']:
                            op_data = self.enrich_operation_fields(
                                service_name,
                                module_name,
                                op_data
                            )
                    
                    # Process dependent operations
                    if 'dependent' in category_data:
                        for op_data in category_data['dependent']:
                            op_data = self.enrich_operation_fields(
                                service_name,
                                module_name,
                                op_data
                            )
            
            # Process top-level independent/dependent
            if service_name in data:
                for op_type in ['independent', 'dependent']:
                    if op_type in data[service_name]:
                        for op_data in data[service_name][op_type]:
                            op_data = self.enrich_operation_fields(
                                service_name,
                                module_name,
                                op_data
                            )
            
            # Save enriched file
            with open(enriched_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            fields_added = self.stats['fields_enriched'] - fields_before
            self.stats['services_processed'] += 1
            
            if fields_added > 0:
                print(f"  ✓ {service_name}: Added {fields_added} enum values")
            
            return True
            
        except Exception as e:
            error_msg = f"Error processing {service_name}: {str(e)}"
            self.stats['errors'].append(error_msg)
            print(f"  ❌ {service_name}: {str(e)}")
            return False
    
    def enrich_main_consolidated_file(self, root_path: Path):
        """Enrich the main consolidated file"""
        main_file = root_path / "azure_dependencies_with_python_names_fully_enriched.json"
        
        if not main_file.exists():
            return False
        
        print(f"\nEnriching main consolidated file...")
        
        try:
            with open(main_file, 'r') as f:
                data = json.load(f)
            
            fields_before = self.stats['fields_enriched']
            
            # Process all services in main file
            for service_name, service_data in data.items():
                module_name = service_data.get('module', '')
                if not module_name:
                    continue
                
                # Process operations_by_category
                if 'operations_by_category' in service_data:
                    for category, category_data in service_data['operations_by_category'].items():
                        for op_type in ['independent', 'dependent']:
                            if op_type in category_data:
                                for op_data in category_data[op_type]:
                                    op_data = self.enrich_operation_fields(
                                        service_name,
                                        module_name,
                                        op_data
                                    )
                
                # Process top-level independent/dependent
                for op_type in ['independent', 'dependent']:
                    if op_type in service_data:
                        for op_data in service_data[op_type]:
                            op_data = self.enrich_operation_fields(
                                service_name,
                                module_name,
                                op_data
                            )
            
            # Save enriched file
            with open(main_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            fields_added = self.stats['fields_enriched'] - fields_before
            print(f"  ✓ Main file: Added {fields_added} enum values")
            
            return True
            
        except Exception as e:
            print(f"  ❌ Error enriching main file: {str(e)}")
            return False
    
    def enrich_all_services(self, root_path: Path):
        """Enrich all service files"""
        
        print(f"\n{'='*70}")
        print(f"ENRICHING AZURE SDK DEPENDENCIES WITH ENUM VALUES")
        print(f"{'='*70}\n")
        
        service_dirs = []
        for service_dir in root_path.iterdir():
            if service_dir.is_dir():
                enriched_file = service_dir / "azure_dependencies_with_python_names_fully_enriched.json"
                if enriched_file.exists():
                    service_dirs.append(service_dir)
        
        print(f"Found {len(service_dirs)} services to enrich\n")
        
        for i, service_path in enumerate(sorted(service_dirs), 1):
            service_name = service_path.name
            print(f"[{i}/{len(service_dirs)}] {service_name}", end=" ... ")
            
            self.enrich_service_file(service_path)
        
        # Also enrich main consolidated file
        self.enrich_main_consolidated_file(root_path)
        
        # Print summary
        print(f"\n{'='*70}")
        print(f"ENRICHMENT SUMMARY")
        print(f"{'='*70}")
        print(f"Services processed: {self.stats['services_processed']}")
        print(f"Operations processed: {self.stats['operations_processed']}")
        print(f"Fields enriched: {self.stats['fields_enriched']}")
        print(f"Enums found: {self.stats['enums_found']}")
        print(f"Errors: {len(self.stats['errors'])}")
        
        if self.stats['errors']:
            print(f"\nFirst 10 errors:")
            for error in self.stats['errors'][:10]:
                print(f"  - {error}")


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Enrich Azure SDK dependencies with enum values'
    )
    parser.add_argument(
        '--root',
        default='pythonsdk-database/azure',
        help='Root path for services (default: pythonsdk-database/azure)'
    )
    parser.add_argument(
        '--service',
        help='Enrich single service only'
    )
    
    args = parser.parse_args()
    
    root_path = Path(args.root)
    extractor = AzureEnumExtractor()
    
    if args.service:
        # Single service
        service_path = root_path / args.service
        if service_path.exists():
            extractor.enrich_service_file(service_path)
            print(f"\n✓ Enrichment complete for {args.service}")
        else:
            print(f"Error: Service path not found: {service_path}")
            sys.exit(1)
    else:
        # All services
        extractor.enrich_all_services(root_path)


if __name__ == '__main__':
    main()

