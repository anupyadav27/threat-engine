#!/usr/bin/env python3
"""
Enrich IBM SDK dependencies JSON files with possible values extracted from IBM SDK models.

IBM SDK uses a similar structure to Azure/OCI - Python packages with model classes.
"""

import json
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys
import re

# Check for IBM SDK availability
try:
    import ibm_cloud_sdk_core
    IBM_SDK_AVAILABLE = True
except ImportError:
    IBM_SDK_AVAILABLE = False
    print("⚠️  ibm_cloud_sdk_core package not installed. Install with: pip install ibm-cloud-sdk-core")


class IBMEnumExtractor:
    """Extract enum values from IBM SDK models"""
    
    def __init__(self):
        self.stats = {
            'services_processed': 0,
            'operations_processed': 0,
            'fields_enriched': 0,
            'enums_found': 0,
            'errors': []
        }
    
    def extract_enum_from_model(self, model_class) -> Optional[List[str]]:
        """Extract enum values from an IBM SDK model class"""
        if model_class is None:
            return None
        
        # Check if it's an Enum class (Python Enum)
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
        
        # IBM SDK may use class constants (uppercase attributes) or other patterns
        try:
            if inspect.isclass(model_class):
                # Look for uppercase class attributes (constants)
                constants = []
                for attr_name in dir(model_class):
                    if not attr_name.startswith('_') and attr_name.isupper():
                        try:
                            attr_value = getattr(model_class, attr_name)
                            # If it's a string constant, use it
                            if isinstance(attr_value, str):
                                constants.append(attr_value)
                            # If it's the same as the attribute name, use the name
                            elif attr_value == attr_name:
                                constants.append(attr_name)
                        except Exception:
                            pass
                
                if constants and len(constants) >= 2:  # At least 2 values to be an enum
                    return sorted(list(set(constants)))
        except Exception:
            pass
        
        return None
    
    def find_enum_class(self, module_name: str, field_name: str) -> Optional[type]:
        """Find an enum class by name within a module or its models submodule"""
        if not IBM_SDK_AVAILABLE:
            return None
        
        # Try common enum naming patterns
        enum_patterns = [
            f"{field_name}Type", f"{field_name}Types", f"{field_name}Enum",
            f"{field_name}State", f"{field_name}Status", f"{field_name}LifecycleState",
            f"{field_name}Class", f"{field_name}Level", f"{field_name}Kind",
            f"{field_name}Role", f"{field_name}Permission", f"{field_name}Action"
        ]
        
        # Convert snake_case to PascalCase for class names
        pascal_field_name = ''.join(word.capitalize() for word in field_name.split('_'))
        enum_patterns.extend([
            f"{pascal_field_name}Type", f"{pascal_field_name}Types", f"{pascal_field_name}Enum",
            f"{pascal_field_name}State", f"{pascal_field_name}Status", f"{pascal_field_name}LifecycleState",
            f"{pascal_field_name}Class", f"{pascal_field_name}Level", f"{pascal_field_name}Kind",
            f"{pascal_field_name}Role", f"{pascal_field_name}Permission", f"{pascal_field_name}Action"
        ])
        
        # IBM SDK models are typically in <module>.models or <module>.common
        # Try different module patterns
        base_module = module_name
        if '.models' not in module_name and '.common' not in module_name:
            models_module_names = [
                f"{module_name}.models",
                f"{module_name}.common",
                module_name
            ]
        else:
            models_module_names = [module_name]
        
        for models_module_name in models_module_names:
            for pattern in enum_patterns:
                try:
                    # Try direct import from models module
                    models_module = importlib.import_module(models_module_name)
                    if hasattr(models_module, pattern):
                        obj = getattr(models_module, pattern)
                        if inspect.isclass(obj):
                            # Check if it's an Enum
                            if hasattr(obj, '__members__'):
                                return obj
                            # Check for uppercase constants
                            elif any(attr.isupper() and not attr.startswith('_') for attr in dir(obj)):
                                return obj
                except Exception:
                    pass
                
                # Try searching all attributes in models module
                try:
                    models_module = importlib.import_module(models_module_name)
                    for name in dir(models_module):
                        if name.upper() == pattern.upper():
                            obj = getattr(models_module, name)
                            if inspect.isclass(obj):
                                # Check if it's an Enum
                                if hasattr(obj, '__members__'):
                                    return obj
                                # Check for uppercase constants
                                elif any(attr.isupper() and not attr.startswith('_') for attr in dir(obj)):
                                    return obj
                except Exception:
                    pass
        
        # Also try searching all enum-like classes in the models module
        for models_module_name in models_module_names:
            try:
                models_module = importlib.import_module(models_module_name)
                field_lower = field_name.lower()
                for name in dir(models_module):
                    if not name.startswith('_') and name[0].isupper():
                        obj = getattr(models_module, name)
                        if inspect.isclass(obj):
                            # Check if enum name relates to field name
                            name_lower = name.lower()
                            if field_lower in name_lower or name_lower in field_lower:
                                # Check if it's an Enum
                                if hasattr(obj, '__members__'):
                                    members = obj.__members__
                                    if members and len(members) > 0:
                                        return obj
                                # Check for uppercase constants
                                elif any(attr.isupper() and not attr.startswith('_') for attr in dir(obj)):
                                    return obj
            except Exception:
                pass
        
        return None
    
    def extract_enum_from_field(self, module_name: str, field_name: str, 
                                model_class=None) -> Optional[List[str]]:
        """Extract enum values for a specific field"""
        
        # Try to find enum class
        enum_class = self.find_enum_class(module_name, field_name)
        if enum_class:
            return self.extract_enum_from_model(enum_class)
        
        # Fallback to common patterns if no specific enum class found
        common_enums = {
            'status': ['ACTIVE', 'INACTIVE', 'PENDING', 'FAILED', 'SUCCEEDED'],
            'state': ['ACTIVE', 'INACTIVE', 'PENDING', 'FAILED', 'SUCCEEDED'],
            'lifecycle_state': ['ACTIVE', 'INACTIVE', 'PENDING', 'FAILED', 'SUCCEEDED'],
            'type': ['USER', 'SERVICE', 'GROUP', 'POLICY'],
        }
        
        field_lower = field_name.lower()
        for key, values in common_enums.items():
            if key in field_lower:
                return sorted(values)
        
        return None
    
    def enrich_operation_fields(self, service_name: str, module_name: str,
                                enriched_data: Dict) -> Dict:
        """Enrich operation fields with enum values from IBM SDK"""
        
        # Enrich item_fields
        if 'item_fields' in enriched_data and isinstance(enriched_data['item_fields'], dict):
            for field_name, field_data in enriched_data['item_fields'].items():
                if isinstance(field_data, dict) and 'possible_values' not in field_data:
                    enum_values = self.extract_enum_from_field(module_name, field_name)
                    if enum_values:
                        field_data['enum'] = True
                        field_data['possible_values'] = enum_values
                        self.stats['enums_found'] += 1
                        self.stats['fields_enriched'] += 1
        
        # Enrich output_fields (if they are not just references to item_fields)
        if 'output_fields' in enriched_data and isinstance(enriched_data['output_fields'], dict):
            for field_name, field_data in enriched_data['output_fields'].items():
                if isinstance(field_data, dict) and 'possible_values' not in field_data and field_data.get('type') == 'string':
                    enum_values = self.extract_enum_from_field(module_name, field_name)
                    if enum_values:
                        field_data['enum'] = True
                        field_data['possible_values'] = enum_values
                        self.stats['enums_found'] += 1
                        self.stats['fields_enriched'] += 1
        
        self.stats['operations_processed'] += 1
        return enriched_data
    
    def enrich_service_file(self, service_path: Path) -> bool:
        """Enrich a single service's enriched dependencies file"""
        
        enriched_file = service_path / "ibm_dependencies_with_python_names_fully_enriched.json"
        
        if not enriched_file.exists():
            return False
        
        try:
            with open(enriched_file, 'r') as f:
                data = json.load(f)
            
            service_name = service_path.name
            
            # IBM SDK structure is nested under service_name key
            if service_name not in data:
                return False
            
            service_data = data[service_name]
            # IBM uses 'package' instead of 'module'
            module_name = service_data.get('module') or service_data.get('package')
            
            if not module_name:
                self.stats['errors'].append(f"Missing module/package name for {service_name}")
                return False
            
            fields_before = self.stats['fields_enriched']
            
            # Process operations array (IBM structure)
            if 'operations' in service_data and isinstance(service_data['operations'], list):
                for op_data in service_data['operations']:
                    op_data = self.enrich_operation_fields(
                        service_name,
                        module_name,
                        op_data
                    )
            
            # Process operations_by_category (if present)
            if 'operations_by_category' in service_data:
                for category_name, category_data in service_data['operations_by_category'].items():
                    if 'independent' in category_data:
                        for op_data in category_data['independent']:
                            op_data = self.enrich_operation_fields(
                                service_name,
                                module_name,
                                op_data
                            )
                    
                    if 'dependent' in category_data:
                        for op_data in category_data['dependent']:
                            op_data = self.enrich_operation_fields(
                                service_name,
                                module_name,
                                op_data
                            )
            
            with open(enriched_file, 'w') as f:
                json.dump(data, f, indent=2)
            
            fields_added = self.stats['fields_enriched'] - fields_before
            self.stats['services_processed'] += 1
            
            if fields_added > 0:
                print(f"  ✓ {service_name}: Added {fields_added} enum values")
            else:
                print(f"  (no enum fields added)")
            
            return True
            
        except Exception as e:
            error_msg = f"Error processing {service_name}: {str(e)}"
            self.stats['errors'].append(error_msg)
            print(f"  ❌ {service_name}: {str(e)}")
            return False
    
    def enrich_main_consolidated_file(self, main_file_path: Path) -> bool:
        """Enrich the main consolidated IBM dependencies file"""
        if not main_file_path.exists():
            print(f"  ⚠️  Main consolidated file not found: {main_file_path}")
            return False
        
        print(f"Enriching main consolidated file...")
        
        try:
            with open(main_file_path, 'r') as f:
                main_data = json.load(f)
            
            fields_before = self.stats['fields_enriched']
            
            # Iterate through each service in the main consolidated file
            for service_name, service_info in main_data.items():
                if service_name in ["total_services", "metadata", "version"]:  # Skip metadata
                    continue
                
                # IBM uses 'package' instead of 'module'
                module_name = service_info.get('module') or service_info.get('package')
                if not module_name:
                    self.stats['errors'].append(f"Missing module/package name for {service_name} in main file")
                    continue
                
                # Process operations array (IBM structure)
                if 'operations' in service_info and isinstance(service_info['operations'], list):
                    for op_data in service_info['operations']:
                        op_data = self.enrich_operation_fields(
                            service_name,
                            module_name,
                            op_data
                        )
                
                # Process operations_by_category (if present)
                if 'operations_by_category' in service_info:
                    for category_name, category_data in service_info['operations_by_category'].items():
                        if 'independent' in category_data:
                            for op_data in category_data['independent']:
                                op_data = self.enrich_operation_fields(
                                    service_name,
                                    module_name,
                                    op_data
                                )
                        
                        if 'dependent' in category_data:
                            for op_data in category_data['dependent']:
                                op_data = self.enrich_operation_fields(
                                    service_name,
                                    module_name,
                                    op_data
                                )
            
            with open(main_file_path, 'w') as f:
                json.dump(main_data, f, indent=2)
            
            fields_added = self.stats['fields_enriched'] - fields_before
            if fields_added > 0:
                print(f"  ✓ Main file: Added {fields_added} enum values")
            else:
                print(f"  (no enum fields added to main file)")
            
            return True
            
        except Exception as e:
            error_msg = f"Error processing main consolidated file: {str(e)}"
            self.stats['errors'].append(error_msg)
            print(f"  ❌ Main file: {str(e)}")
            return False
    
    def enrich_all_services(self, root_path: Path):
        """Enrich all service files"""
        
        print(f"\n{'='*70}")
        print(f"ENRICHING IBM SDK DEPENDENCIES WITH ENUM VALUES")
        print(f"{'='*70}\n")
        
        if not IBM_SDK_AVAILABLE:
            print("⚠️  IBM SDK not installed. Install with: pip install ibm-cloud-sdk-core")
            print("   Continuing with fallback patterns only...")
        
        service_dirs = []
        for service_dir in root_path.iterdir():
            if service_dir.is_dir():
                enriched_file = service_dir / "ibm_dependencies_with_python_names_fully_enriched.json"
                if enriched_file.exists():
                    service_dirs.append(service_dir)
        
        print(f"Found {len(service_dirs)} services to enrich\n")
        
        for i, service_path in enumerate(sorted(service_dirs), 1):
            service_name = service_path.name
            print(f"[{i}/{len(service_dirs)}] {service_name}", end=" ... ")
            
            self.enrich_service_file(service_path)
        
        # Enrich the main consolidated file after all individual services
        main_consolidated_file = root_path / "ibm_dependencies_with_python_names_fully_enriched.json"
        self.enrich_main_consolidated_file(main_consolidated_file)
        
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
            print(f"\nErrors:")
            for error in self.stats['errors'][:10]:
                print(f"  - {error}")


def main():
    """CLI entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Enrich IBM dependencies with enum values from IBM SDK'
    )
    parser.add_argument(
        '--root',
        default='pythonsdk-database/ibm',
        help='Root path for services (default: pythonsdk-database/ibm)'
    )
    parser.add_argument(
        '--service',
        help='Enrich single service only'
    )
    
    args = parser.parse_args()
    
    root_path = Path(args.root)
    extractor = IBMEnumExtractor()
    
    if args.service:
        # Single service
        service_path = root_path / args.service
        if service_path.exists():
            extractor.enrich_service_file(service_path)
        else:
            print(f"Error: Service path not found: {service_path}")
            sys.exit(1)
    else:
        # All services
        extractor.enrich_all_services(root_path)


if __name__ == '__main__':
    main()

