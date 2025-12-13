#!/usr/bin/env python3
"""
Improved Azure SDK dependencies generator with comprehensive output field extraction.
Uses multiple strategies to extract output_fields, main_output_field, and item_fields.
"""

import json
import inspect
import importlib
from typing import Dict, List, Any, Optional
import re

# Azure management libraries
AZURE_MGMT_MODULES = {
    'compute': 'azure.mgmt.compute',
    'network': 'azure.mgmt.network',
    'storage': 'azure.mgmt.storage',
    'sql': 'azure.mgmt.sql',
    'keyvault': 'azure.mgmt.keyvault',
    'web': 'azure.mgmt.web',
    'monitor': 'azure.mgmt.monitor',
    'containerservice': 'azure.mgmt.containerservice',
    'containerinstance': 'azure.mgmt.containerinstance',
    'cosmosdb': 'azure.mgmt.cosmosdb',
    'apimanagement': 'azure.mgmt.apimanagement',
    'recoveryservices': 'azure.mgmt.recoveryservices',
    'recoveryservicesbackup': 'azure.mgmt.recoveryservicesbackup',
    'subscription': 'azure.mgmt.subscription',
    'managementgroups': 'azure.mgmt.managementgroups',
    'automation': 'azure.mgmt.automation',
    'batch': 'azure.mgmt.batch',
    'authorization': 'azure.mgmt.authorization.v2022_04_01',
    'eventhub': 'azure.mgmt.eventhub.v2024_01_01',
    'servicebus': 'azure.mgmt.servicebus.v2022_10_01_preview',
    'rdbms_postgresql': 'azure.mgmt.rdbms.postgresql',
    'rdbms_mysql': 'azure.mgmt.rdbms.mysql',
    'rdbms_mariadb': 'azure.mgmt.rdbms.mariadb',
}


def to_snake_case(name: str) -> str:
    """Convert PascalCase to snake_case."""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def extract_model_fields_comprehensive(model_class) -> List[str]:
    """Extract field names from Azure model class using multiple strategies."""
    fields = []
    
    try:
        # Strategy 1: _attribute_map (primary for Azure SDK models)
        if hasattr(model_class, '_attribute_map'):
            attr_map = model_class._attribute_map
            fields = list(attr_map.keys())
        
        # Strategy 2: __annotations__ if available
        if not fields and hasattr(model_class, '__annotations__'):
            fields = list(model_class.__annotations__.keys())
        
        # Strategy 3: Public attributes from __dict__
        if not fields and hasattr(model_class, '__dict__'):
            fields = [k for k in model_class.__dict__.keys() if not k.startswith('_')]
        
        # Strategy 4: Try to instantiate with no args and get attributes
        if not fields:
            try:
                instance = model_class()
                fields = [k for k in dir(instance) if not k.startswith('_') and not callable(getattr(instance, k))]
            except:
                pass
        
        # Filter out internal fields and methods
        fields = [f for f in fields if not f.startswith('_') and f not in ['additional_properties']]
        
    except Exception:
        pass
    
    return fields


def get_model_class_from_name(model_name: str, module_name: str) -> Optional[type]:
    """Get model class from name by importing models module."""
    try:
        # Clean up the model name
        model_name = model_name.strip('[]~').split('.')[-1]
        
        # Try main models module
        try:
            models_module = importlib.import_module(f"{module_name}.models")
            if hasattr(models_module, model_name):
                return getattr(models_module, model_name)
        except:
            pass
        
        # Try versioned models
        if '.v' in module_name:
            base_module = module_name.rsplit('.', 1)[0]
            try:
                models_module = importlib.import_module(f"{base_module}.models")
                if hasattr(models_module, model_name):
                    return getattr(models_module, model_name)
            except:
                pass
                
    except Exception:
        pass
    
    return None


def parse_docstring_for_return_info(docstring: str, module_name: str) -> Dict[str, Any]:
    """Parse docstring to extract return type information."""
    output_info = {
        'output_fields': [],
        'main_output_field': None,
        'item_fields': []
    }
    
    if not docstring:
        return output_info
    
    try:
        # Pattern to match :rtype: ~azure.mgmt.service.models.ModelName
        rtype_pattern = r':rtype:\s+~?([^\s\n\[\]]+(?:\[[^\]]+\])?)'
        match = re.search(rtype_pattern, docstring)
        
        if match:
            type_str = match.group(1)
            
            # Handle ItemPaged[ModelName] or Iterator[ModelName]
            if '[' in type_str:
                # Extract the item type
                item_match = re.search(r'\[([^\]]+)\]', type_str)
                if item_match:
                    item_type_name = item_match.group(1).split('.')[-1]
                    model_class = get_model_class_from_name(item_type_name, module_name)
                    
                    if model_class:
                        item_fields = extract_model_fields_comprehensive(model_class)
                        if item_fields:
                            output_info['output_fields'] = ['value', 'next_link']
                            output_info['main_output_field'] = 'value'
                            output_info['item_fields'] = item_fields
                            return output_info
            
            # Handle regular model return type
            model_name = type_str.split('.')[-1]
            model_class = get_model_class_from_name(model_name, module_name)
            
            if model_class:
                fields = extract_model_fields_comprehensive(model_class)
                if fields:
                    output_info['output_fields'] = fields
                    
                    # Determine main output field
                    for field in fields:
                        if field in ['value', 'items', 'results', 'data']:
                            output_info['main_output_field'] = field
                            
                            # Try to get item fields if main field is a list
                            try:
                                if hasattr(model_class, '_attribute_map'):
                                    attr_map = model_class._attribute_map
                                    if field in attr_map:
                                        field_info = attr_map[field]
                                        if 'type' in field_info and field_info['type'].startswith('['):
                                            item_type_name = field_info['type'].strip('[]')
                                            item_class = get_model_class_from_name(item_type_name, module_name)
                                            if item_class:
                                                output_info['item_fields'] = extract_model_fields_comprehensive(item_class)
                            except:
                                pass
                            break
                    
                    if not output_info['main_output_field'] and fields:
                        output_info['main_output_field'] = fields[0]
                        
    except Exception as e:
        pass
    
    return output_info


def get_method_parameters(method) -> tuple:
    """Extract required and optional parameters."""
    try:
        sig = inspect.signature(method)
        required = []
        optional = []
        has_kwargs = False
        
        for param_name, param in sig.parameters.items():
            if param_name in ['self', 'cls', 'custom_headers', 
                             'raw', 'polling', 'content_type', 'api_version', 
                             'operation_config', '**operation_config',
                             'resource_group_name', 'subscription_id']:
                continue
            
            # Check if method accepts **kwargs
            if param_name in ['kwargs', 'args'] or param.kind == inspect.Parameter.VAR_KEYWORD:
                has_kwargs = True
                continue
            
            if param.default == inspect.Parameter.empty:
                required.append(param_name)
            else:
                optional.append(param_name)
        
        # Add common Azure optional parameters if method accepts kwargs
        if has_kwargs:
            # Parse docstring to find actual optional parameters
            doc_optional = parse_optional_params_from_docstring(method.__doc__)
            if doc_optional:
                optional.extend(doc_optional)
            
            # For list operations, add common Azure OData/REST parameters if not already present
            method_name = method.__name__ if hasattr(method, '__name__') else ''
            if any(indicator in method_name.lower() for indicator in ['list', 'get_all']):
                common_optional = ['filter', 'top', 'skip', 'orderby', 'expand', 'select']
                for param in common_optional:
                    if param not in optional:
                        optional.append(param)
        
        # Remove duplicates while preserving order
        seen = set()
        optional = [x for x in optional if not (x in seen or seen.add(x))]
        
        return required, optional
    except (ValueError, TypeError):
        return [], []


def parse_optional_params_from_docstring(docstring: str) -> List[str]:
    """Extract optional keyword parameters from docstring."""
    optional = []
    
    if not docstring:
        return optional
    
    try:
        # Look for :keyword or :param patterns that indicate optional params
        lines = docstring.split('\n')
        for line in lines:
            # Match :keyword param_name: or :param param_name: (optional)
            keyword_match = re.search(r':keyword\s+(\w+):', line)
            if keyword_match:
                param_name = keyword_match.group(1)
                # Exclude internal Azure parameters
                if param_name not in ['cls', 'continuation_token', 'raw']:
                    optional.append(param_name)
    except:
        pass
    
    return optional


def is_list_operation(method_name: str, required_params: List[str]) -> bool:
    """Check if operation is a list operation."""
    list_indicators = ['list', 'get_all', 'enumerate']
    is_list = any(method_name.lower().startswith(indicator) for indicator in list_indicators)
    return is_list and len(required_params) <= 1


def analyze_operations_class(operations_class_type, module_name: str) -> Dict[str, List[Dict]]:
    """Analyze methods in an operations class."""
    independent = []
    dependent = []
    
    for name in dir(operations_class_type):
        if name.startswith('_') or name in ['models', 'get_long_running_output', 'get', 'api_version']:
            continue
        
        try:
            member = getattr(operations_class_type, name)
            
            if not callable(member) or inspect.isclass(member) or inspect.ismodule(member):
                continue
            
            required_params, optional_params = get_method_parameters(member)
            
            # Extract output information from docstring
            output_info = parse_docstring_for_return_info(member.__doc__, module_name)
            
            operation_info = {
                'operation': name,
                'python_method': name,
                'yaml_action': to_snake_case(name) if name[0].isupper() else name,
                'required_params': required_params,
                'optional_params': optional_params,
                'total_optional': len(optional_params),
                'output_fields': output_info['output_fields'],
                'main_output_field': output_info['main_output_field'],
                'item_fields': output_info['item_fields']
            }
            
            if is_list_operation(name, required_params):
                independent.append(operation_info)
            else:
                dependent.append(operation_info)
                
        except Exception:
            continue
    
    return {'independent': independent, 'dependent': dependent}


def get_operations_from_module(module_name: str) -> List[tuple]:
    """Get operations classes from module."""
    operations_classes = []
    
    try:
        ops_module = importlib.import_module(f"{module_name}.operations")
        
        for name, obj in inspect.getmembers(ops_module):
            if inspect.isclass(obj) and 'Operations' in name and not name.startswith('_'):
                simple_name = name.replace('Operations', '').lower()
                operations_classes.append((simple_name, name, obj))
                
    except ImportError:
        pass
    
    return operations_classes


def process_service(service_name: str, module_path: str) -> Optional[Dict[str, Any]]:
    """Process a service."""
    print(f"\nProcessing {service_name} ({module_path})...")
    
    try:
        operations_classes = get_operations_from_module(module_path)
        
        if not operations_classes:
            print(f"  ✗ No operations classes found")
            return None
        
        operations_by_category = {}
        all_independent = []
        all_dependent = []
        
        for simple_name, full_name, ops_class in operations_classes:
            operations = analyze_operations_class(ops_class, module_path)
            
            if operations['independent'] or operations['dependent']:
                operations_by_category[simple_name] = {
                    'class_name': full_name,
                    'independent': operations['independent'],
                    'dependent': operations['dependent']
                }
                
                all_independent.extend(operations['independent'])
                all_dependent.extend(operations['dependent'])
        
        total_ops = len(all_independent) + len(all_dependent)
        
        if total_ops > 0:
            ops_with_output = sum(1 for op in all_independent + all_dependent if op['output_fields'])
            ops_with_items = sum(1 for op in all_independent + all_dependent if op['item_fields'])
            
            print(f"  ✓ {total_ops} operations ({len(all_independent)} ind, {len(all_dependent)} dep)")
            print(f"    - {ops_with_output} with output_fields, {ops_with_items} with item_fields")
            
            return {
                'service': service_name,
                'module': module_path,
                'total_operations': total_ops,
                'operations_by_category': operations_by_category,
                'independent': all_independent,
                'dependent': all_dependent
            }
        
    except Exception as e:
        print(f"  ✗ Error: {e}")
        import traceback
        traceback.print_exc()
    
    return None


def generate_azure_dependencies() -> Dict[str, Any]:
    """Generate Azure SDK dependencies."""
    azure_dependencies = {}
    
    for service_name, module_path in AZURE_MGMT_MODULES.items():
        result = process_service(service_name, module_path)
        if result:
            azure_dependencies[service_name] = result
    
    return azure_dependencies


def main():
    """Main execution."""
    print("=" * 80)
    print("Azure SDK Dependencies Generator - IMPROVED OUTPUT FIELD EXTRACTION")
    print("=" * 80)
    
    dependencies = generate_azure_dependencies()
    
    output_file = '/Users/apple/Desktop/threat-engine/azure_compliance_python_engine/framework/azure_sdk_dependencies_with_python_names.json'
    
    print(f"\n{'=' * 80}")
    print("Writing to file...")
    with open(output_file, 'w') as f:
        json.dump(dependencies, f, indent=2)
    
    # Summary
    print("\n" + "=" * 80)
    print("FINAL SUMMARY")
    print("=" * 80)
    
    total_services = len(dependencies)
    total_operations = sum(d['total_operations'] for d in dependencies.values())
    total_independent = sum(len(d['independent']) for d in dependencies.values())
    total_dependent = sum(len(d['dependent']) for d in dependencies.values())
    
    ops_with_output = 0
    ops_with_items = 0
    
    for service_data in dependencies.values():
        for op in service_data['independent'] + service_data['dependent']:
            if op['output_fields']:
                ops_with_output += 1
            if op['item_fields']:
                ops_with_items += 1
    
    print(f"\nTotal Services: {total_services}")
    print(f"Total Operations: {total_operations:,}")
    print(f"  - Independent: {total_independent:,}")
    print(f"  - Dependent: {total_dependent:,}")
    print()
    print(f"Output Field Coverage:")
    print(f"  - Operations with output_fields: {ops_with_output:,} ({100*ops_with_output/total_operations:.1f}%)")
    print(f"  - Operations with item_fields: {ops_with_items:,} ({100*ops_with_items/total_operations:.1f}%)")
    print()
    print(f"Output File: {output_file}")
    print(f"File Size: {len(json.dumps(dependencies, indent=2)):,} bytes")
    print("=" * 80)


if __name__ == '__main__':
    main()

