#!/usr/bin/env python3
"""
Enrich AliCloud SDK dependencies JSON files with possible values extracted from AliCloud SDK.

AliCloud SDK uses request classes with API-based structure. Enums may be in:
1. Request class constants
2. Response model classes
3. Common patterns based on field names
"""

import json
import importlib
import inspect
from pathlib import Path
from typing import Dict, List, Any, Optional
import sys
import re
import pkgutil

# Check for AliCloud SDK availability
try:
    import aliyunsdkcore
    ALICLOUD_SDK_AVAILABLE = True
except ImportError:
    ALICLOUD_SDK_AVAILABLE = False
    print("⚠️  aliyunsdkcore not installed. Install with: pip install aliyun-python-sdk-core")


class AliCloudEnumExtractor:
    """Extract enum values from AliCloud SDK models"""
    
    def __init__(self):
        self.stats = {
            'services_processed': 0,
            'operations_processed': 0,
            'fields_enriched': 0,
            'enums_found': 0,
            'errors': []
        }
        self.service_modules = {}
    
    def discover_service_modules(self) -> Dict[str, str]:
        """Discover all AliCloud service modules"""
        modules = {}
        
        # Discover installed packages
        for importer, modname, ispkg in pkgutil.iter_modules():
            if modname.startswith('aliyunsdk') and '.' not in modname:
                # Extract service name (aliyunsdkecs -> ecs)
                service_name = modname.replace('aliyunsdk', '')
                if service_name and service_name != 'core':
                    modules[service_name] = modname
        
        return modules
    
    def extract_enum_from_model(self, model_class) -> Optional[List[str]]:
        """Extract enum values from an AliCloud SDK model class"""
        if model_class is None:
            return None
        
        # Check if it's an Enum class (Python Enum)
        try:
            if inspect.isclass(model_class) and hasattr(model_class, '__members__'):
                members = model_class.__members__
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
        
        # Check for class constants (uppercase attributes)
        try:
            if inspect.isclass(model_class):
                constants = []
                for attr_name in dir(model_class):
                    if not attr_name.startswith('_') and attr_name.isupper():
                        try:
                            attr_value = getattr(model_class, attr_name)
                            if isinstance(attr_value, str):
                                constants.append(attr_value)
                            elif attr_value == attr_name:
                                constants.append(attr_name)
                        except Exception:
                            pass
                
                if constants and len(constants) >= 2:
                    return sorted(list(set(constants)))
        except Exception:
            pass
        
        return None
    
    def find_enum_in_request_module(self, module_name: str, field_name: str) -> Optional[List[str]]:
        """Find enum values in request module"""
        try:
            # Try to import the request module
            request_module = importlib.import_module(module_name)
            
            # Look for enum classes or constants
            for name in dir(request_module):
                if not name.startswith('_'):
                    obj = getattr(request_module, name)
                    if inspect.isclass(obj):
                        enum_values = self.extract_enum_from_model(obj)
                        if enum_values:
                            # Check if field name matches
                            if field_name.lower() in name.lower() or name.lower() in field_name.lower():
                                return enum_values
        except Exception:
            pass
        
        return None
    
    def extract_enum_from_field(self, service_name: str, module_name: str, 
                                field_name: str) -> Optional[List[str]]:
        """Extract enum values for a specific field"""
        
        # Try to find enum in request module
        enum_values = self.find_enum_in_request_module(module_name, field_name)
        if enum_values:
            return enum_values
        
        # Common AliCloud enum patterns
        common_enums = {
            'status': ['Running', 'Stopped', 'Starting', 'Stopping', 'Pending', 'Available', 'Unavailable', 'Creating', 'Deleting', 'Deleted', 'Failed'],
            'state': ['Active', 'Inactive', 'Creating', 'Updating', 'Deleting', 'Deleted', 'Failed'],
            'lifecycle_state': ['Creating', 'Active', 'Deleting', 'Deleted', 'Failed', 'Updating'],
            'instance_status': ['Running', 'Stopped', 'Starting', 'Stopping', 'Pending', 'Expired'],
            'instance_charge_type': ['PrePaid', 'PostPaid'],
            'network_type': ['Vpc', 'Classic'],
            'disk_category': ['cloud', 'cloud_essd', 'cloud_ssd', 'cloud_efficiency', 'ephemeral_ssd'],
            'acl': ['private', 'public-read', 'public-read-write'],
            'storage_class': ['Standard', 'IA', 'Archive', 'ColdArchive'],
            'versioning': ['Enabled', 'Suspended'],
            'encryption': ['AES256', 'KMS'],
            'mfa_status': ['Enabled', 'Disabled'],
            'policy_type': ['System', 'Custom'],
            'user_type': ['RamUser', 'FederatedUser'],
        }
        
        field_lower = field_name.lower()
        for key, values in common_enums.items():
            if key in field_lower or field_lower in key:
                return sorted(values)
        
        # Pattern matching for common field names
        if 'status' in field_lower:
            return common_enums.get('status')
        elif 'state' in field_lower:
            return common_enums.get('state')
        elif 'type' in field_lower and 'charge' in field_lower:
            return common_enums.get('instance_charge_type')
        elif 'network' in field_lower and 'type' in field_lower:
            return common_enums.get('network_type')
        elif 'category' in field_lower and 'disk' in field_lower:
            return common_enums.get('disk_category')
        elif 'acl' in field_lower:
            return common_enums.get('acl')
        elif 'storage' in field_lower and 'class' in field_lower:
            return common_enums.get('storage_class')
        elif 'versioning' in field_lower:
            return common_enums.get('versioning')
        elif 'encryption' in field_lower:
            return common_enums.get('encryption')
        elif 'mfa' in field_lower:
            return common_enums.get('mfa_status')
        elif 'policy' in field_lower and 'type' in field_lower:
            return common_enums.get('policy_type')
        elif 'user' in field_lower and 'type' in field_lower:
            return common_enums.get('user_type')
        
        return None
    
    def enrich_operation_fields(self, service_name: str, module_name: str,
                                enriched_data: Dict) -> Dict:
        """Enrich operation fields with enum values from AliCloud SDK"""
        
        # Enrich item_fields
        if 'item_fields' in enriched_data and isinstance(enriched_data['item_fields'], dict):
            for field_name, field_data in enriched_data['item_fields'].items():
                if isinstance(field_data, dict) and 'possible_values' not in field_data:
                    enum_values = self.extract_enum_from_field(service_name, module_name, field_name)
                    if enum_values:
                        field_data['enum'] = True
                        field_data['possible_values'] = enum_values
                        self.stats['enums_found'] += 1
                        self.stats['fields_enriched'] += 1
        
        # Enrich output_fields
        if 'output_fields' in enriched_data and isinstance(enriched_data['output_fields'], dict):
            for field_name, field_data in enriched_data['output_fields'].items():
                if isinstance(field_data, dict) and 'possible_values' not in field_data and field_data.get('type') == 'string':
                    enum_values = self.extract_enum_from_field(service_name, module_name, field_name)
                    if enum_values:
                        field_data['enum'] = True
                        field_data['possible_values'] = enum_values
                        self.stats['enums_found'] += 1
                        self.stats['fields_enriched'] += 1
        
        self.stats['operations_processed'] += 1
        return enriched_data
    
    def enrich_service_file(self, service_path: Path) -> bool:
        """Enrich a single service's enriched dependencies file"""
        
        enriched_file = service_path / "alicloud_dependencies_with_python_names_fully_enriched.json"
        
        if not enriched_file.exists():
            return False
        
        try:
            with open(enriched_file, 'r') as f:
                data = json.load(f)
            
            service_name = service_path.name
            module_name = data.get('module', f'aliyunsdk{service_name}')
            
            # Enrich operations
            if 'operations' in data and isinstance(data['operations'], list):
                for operation in data['operations']:
                    self.enrich_operation_fields(service_name, module_name, operation)
            
            # Save enriched data
            with open(enriched_file, 'w') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            self.stats['services_processed'] += 1
            return True
            
        except Exception as e:
            error_msg = f"Error enriching {service_path}: {e}"
            self.stats['errors'].append(error_msg)
            print(f"❌ {error_msg}")
            return False
    
    def enrich_main_consolidated_file(self, root_path: Path) -> bool:
        """Enrich the main consolidated file"""
        
        main_file = root_path / "alicloud_dependencies_with_python_names_fully_enriched.json"
        
        if not main_file.exists():
            print(f"❌ Main file not found: {main_file}")
            return False
        
        try:
            print(f"📖 Loading main file: {main_file}")
            with open(main_file, 'r') as f:
                data = json.load(f)
            
            services = [k for k in data.keys() if k not in ['total_services', 'metadata', 'version']]
            print(f"📦 Found {len(services)} services in main file")
            
            for service_name in services:
                if service_name in ['total_services', 'metadata', 'version']:
                    continue
                
                service_data = data[service_name]
                module_name = service_data.get('module', f'aliyunsdk{service_name}')
                
                print(f"  🔍 Processing {service_name}...")
                
                # Enrich operations
                if 'operations' in service_data and isinstance(service_data['operations'], list):
                    for operation in service_data['operations']:
                        self.enrich_operation_fields(service_name, module_name, operation)
            
            # Save enriched data
            print(f"💾 Saving enriched main file...")
            with open(main_file, 'w') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            error_msg = f"Error enriching main file: {e}"
            self.stats['errors'].append(error_msg)
            print(f"❌ {error_msg}")
            import traceback
            traceback.print_exc()
            return False
    
    def enrich_all_services(self, root_path: Path):
        """Enrich all services"""
        
        print("🚀 Starting AliCloud enum enrichment...")
        print("=" * 70)
        
        if not ALICLOUD_SDK_AVAILABLE:
            print("⚠️  AliCloud SDK not available. Using pattern-based enrichment only.")
        
        # First enrich main consolidated file
        self.enrich_main_consolidated_file(root_path)
        
        # Then enrich individual service files
        service_dirs = [d for d in root_path.iterdir() if d.is_dir() and not d.name.startswith('.')]
        
        print(f"\n📁 Processing {len(service_dirs)} service directories...")
        
        for service_dir in sorted(service_dirs):
            self.enrich_service_file(service_dir)
        
        # Print statistics
        print("\n" + "=" * 70)
        print("📊 ENRICHMENT STATISTICS")
        print("=" * 70)
        print(f"Services processed: {self.stats['services_processed']}")
        print(f"Operations processed: {self.stats['operations_processed']}")
        print(f"Fields enriched: {self.stats['fields_enriched']}")
        print(f"Enums found: {self.stats['enums_found']}")
        print(f"Errors: {len(self.stats['errors'])}")
        
        if self.stats['errors']:
            print("\n⚠️  Errors encountered:")
            for error in self.stats['errors'][:10]:  # Show first 10 errors
                print(f"  - {error}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enrich AliCloud SDK dependencies with enum values")
    parser.add_argument("--root", default="/Users/apple/Desktop/threat-engine/pythonsdk-database/alicloud",
                       help="Root directory of AliCloud SDK database")
    
    args = parser.parse_args()
    
    root_path = Path(args.root)
    
    if not root_path.exists():
        print(f"❌ Root directory not found: {root_path}")
        sys.exit(1)
    
    extractor = AliCloudEnumExtractor()
    extractor.enrich_all_services(root_path)
    
    print("\n✅ AliCloud enum enrichment complete!")


if __name__ == "__main__":
    main()

