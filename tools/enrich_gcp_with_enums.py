#!/usr/bin/env python3
"""
Enrich GCP SDK dependencies JSON files with possible values extracted from GCP SDK (protobuf-based).
GCP uses Google Cloud SDK which is protobuf-based, so we extract enums from protobuf enum types.
"""

import json
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys
import re

class GCPEnumExtractor:
    """Extract enum values from GCP SDK (protobuf-based)"""
    
    def __init__(self):
        self.stats = {
            'services_processed': 0,
            'operations_processed': 0,
            'fields_enriched': 0,
            'enums_found': 0,
            'errors': []
        }
    
    def extract_enum_from_protobuf(self, enum_class) -> Optional[List[str]]:
        """Extract enum values from a protobuf enum class"""
        if enum_class is None:
            return None
        
        try:
            # Protobuf enums have DESCRIPTOR with values
            if hasattr(enum_class, 'DESCRIPTOR'):
                descriptor = enum_class.DESCRIPTOR
                if hasattr(descriptor, 'values'):
                    values = []
                    for value in descriptor.values:
                        values.append(value.name)
                    return sorted(values)
            
            # Alternative: Check for enum values directly
            if hasattr(enum_class, 'values'):
                values = []
                for name in dir(enum_class):
                    if not name.startswith('_') and name.isupper():
                        value = getattr(enum_class, name)
                        if isinstance(value, int):  # Protobuf enum values are integers
                            values.append(name)
                return sorted(values) if values else None
            
            # Check if it's a Python Enum
            if inspect.isclass(enum_class) and hasattr(enum_class, '__members__'):
                members = enum_class.__members__
                if members:
                    values = []
                    for name, member in members.items():
                        if hasattr(member, 'value'):
                            values.append(str(member.value))
                        else:
                            values.append(name)
                    return sorted(list(set(values)))
        
        except Exception:
            pass
        
        return None
    
    def find_enum_class(self, module_name: str, field_name: str) -> Optional[type]:
        """Find enum class for a field in GCP SDK"""
        try:
            # GCP protobuf enum naming patterns
            enum_patterns = [
                f"{field_name}",
                f"{field_name}Enum",
                f"{field_name}State",
                f"{field_name}Status",
                f"{field_name}Type",
                f"{field_name}Types",
            ]
            
            # Try to import the module
            try:
                module = importlib.import_module(module_name)
                
                # Search for enum in module
                for pattern in enum_patterns:
                    if hasattr(module, pattern):
                        enum_class = getattr(module, pattern)
                        if self.extract_enum_from_protobuf(enum_class):
                            return enum_class
                
                # Search all attributes
                for name in dir(module):
                    if name.upper() == field_name.upper() or field_name.upper() in name.upper():
                        obj = getattr(module, name)
                        enum_values = self.extract_enum_from_protobuf(obj)
                        if enum_values:
                            return obj
            
            except Exception:
                pass
            
        except Exception:
            pass
        
        return None
    
    def extract_enum_from_field(self, module_name: str, field_name: str) -> Optional[List[str]]:
        """Extract enum values for a specific field"""
        
        # Try to find enum class
        enum_class = self.find_enum_class(module_name, field_name)
        if enum_class:
            return self.extract_enum_from_protobuf(enum_class)
        
        # Check if field_name matches common GCP enum patterns
        common_enums = {
            'status': ['RUNNING', 'STOPPED', 'STARTING', 'STOPPING', 'TERMINATED', 'PROVISIONING', 'STAGING', 'STOPPED'],
            'state': ['ACTIVE', 'INACTIVE', 'PENDING', 'FAILED', 'SUCCEEDED'],
            'lifecycle_state': ['ACTIVE', 'DELETE_REQUESTED', 'DELETE_IN_PROGRESS'],
            'type': ['STANDARD', 'NEARLINE', 'COLDLINE', 'ARCHIVE'],
            'storage_class': ['STANDARD', 'NEARLINE', 'COLDLINE', 'ARCHIVE', 'REGIONAL', 'MULTI_REGIONAL'],
        }
        
        field_lower = field_name.lower()
        for key, values in common_enums.items():
            if key in field_lower:
                return sorted(values)
        
        return None
    
    def enrich_operation_fields(self, service_name: str, module_name: str,
                               enriched_data: Dict) -> Dict:
        """Enrich operation fields with enum values from GCP SDK"""
        
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
            
            # Enrich output_fields (if they're dicts)
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
        
        enriched_file = service_path / "gcp_dependencies_with_python_names_fully_enriched.json"
        
        if not enriched_file.exists():
            return False
        
        try:
            with open(enriched_file, 'r') as f:
                data = json.load(f)
            
            service_name = service_path.name
            
            # GCP uses service name as key, try to get module or construct from service name
            module_name = None
            if service_name in data:
                module_name = data[service_name].get('module', '')
                # If no module, try to construct from service name
                if not module_name:
                    # Common GCP module patterns
                    module_name = f"google.cloud.{service_name}"
            
            fields_before = self.stats['fields_enriched']
            
            # Process GCP structure: resources -> independent/dependent
            if service_name in data:
                service_data = data[service_name]
                
                # GCP structure: resources -> resource_name -> independent/dependent
                if 'resources' in service_data:
                    for resource_name, resource_data in service_data['resources'].items():
                        for op_type in ['independent', 'dependent']:
                            if op_type in resource_data:
                                for op_data in resource_data[op_type]:
                                    op_data = self.enrich_operation_fields(
                                        service_name,
                                        module_name,
                                        op_data
                                    )
                
                # Also check for direct operations list
                if 'operations' in service_data and isinstance(service_data['operations'], list):
                    for op_data in service_data['operations']:
                        op_data = self.enrich_operation_fields(
                            service_name,
                            module_name,
                            op_data
                        )
                
                # Check for operations_by_category
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
        main_file = root_path / "gcp_dependencies_with_python_names_fully_enriched.json"
        
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
                    # Try to construct from service name
                    module_name = f"google.cloud.{service_name}"
                
                # Process resources structure (GCP)
                if 'resources' in service_data:
                    for resource_name, resource_data in service_data['resources'].items():
                        for op_type in ['independent', 'dependent']:
                            if op_type in resource_data:
                                for op_data in resource_data[op_type]:
                                    op_data = self.enrich_operation_fields(
                                        service_name,
                                        module_name,
                                        op_data
                                    )
                
                # Process operations list
                if 'operations' in service_data and isinstance(service_data['operations'], list):
                    for op_data in service_data['operations']:
                        op_data = self.enrich_operation_fields(
                            service_name,
                            module_name,
                            op_data
                        )
                
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
        print(f"ENRICHING GCP SDK DEPENDENCIES WITH ENUM VALUES")
        print(f"{'='*70}\n")
        
        service_dirs = []
        for service_dir in root_path.iterdir():
            if service_dir.is_dir():
                enriched_file = service_dir / "gcp_dependencies_with_python_names_fully_enriched.json"
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
        description='Enrich GCP SDK dependencies with enum values'
    )
    parser.add_argument(
        '--root',
        default='pythonsdk-database/gcp',
        help='Root path for services (default: pythonsdk-database/gcp)'
    )
    parser.add_argument(
        '--service',
        help='Enrich single service only'
    )
    
    args = parser.parse_args()
    
    root_path = Path(args.root)
    extractor = GCPEnumExtractor()
    
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

