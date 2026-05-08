"""
Generate YAML discovery files for Azure services from minimal_operations_list.json.
Adapted for Azure structure.
"""

import json
import yaml
import re
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

def operation_to_action(operation: str) -> str:
    """Convert Azure operation name to action name.
    Azure operations are like 'availabilitysets.list' -> 'availabilitysets.list'
    """
    return operation

def entity_to_field_name(entity: str) -> str:
    """Convert entity name to field name for params."""
    # compute.availability_set__name -> availabilitySetName
    parts = entity.split('.')[-1].split('__')
    if len(parts) > 1:
        # Handle __ separator
        base = parts[0]
        rest = parts[1:]
        field_name = base + ''.join(word.capitalize() for word in rest)
    else:
        # Handle _ separator
        words = parts[0].split('_')
        field_name = words[0] + ''.join(word.capitalize() for word in words[1:])
    return field_name

def find_operation_producing_entity(entity: str, operations: List[Dict], service: str) -> Optional[str]:
    """Find the discovery_id of operation that produces this entity."""
    for op_info in operations:
        entities_covered = op_info.get("entities_covered", [])
        if entity in entities_covered:
            operation = op_info["operation"]
            action = operation_to_action(operation)
            return f"azure.{service}.{action}"
    return None

def get_azure_info(operation: str, azure_data: Dict) -> Optional[Dict]:
    """Get Azure action and main_output_field for an operation."""
    service_name = list(azure_data.keys())[0] if azure_data else None
    if not service_name:
        return None
    
    # Parse operation: category.operation (e.g., "availabilitysets.list")
    if '.' in operation:
        category, op_name = operation.split('.', 1)
    else:
        # Fallback: try to find in any category
        category = None
        op_name = operation
    
    ops_by_cat = azure_data.get(service_name, {}).get("operations_by_category", {})
    
    if category and category in ops_by_cat:
        category_data = ops_by_cat[category]
        for op_type in ['independent', 'dependent']:
            for op_data in category_data.get(op_type, []):
                if op_data.get("operation") == op_name:
                    return {
                        "action": op_data.get("yaml_action") or op_data.get("python_method", op_name),
                        "main_output_field": op_data.get("main_output_field"),
                        "required_params": op_data.get("required_params", []),
                        "category": category
                    }
    else:
        # Search all categories
        for cat, cat_data in ops_by_cat.items():
            for op_type in ['independent', 'dependent']:
                for op_data in cat_data.get(op_type, []):
                    if op_data.get("operation") == op_name:
                        return {
                            "action": op_data.get("yaml_action") or op_data.get("python_method", op_name),
                            "main_output_field": op_data.get("main_output_field"),
                            "required_params": op_data.get("required_params", []),
                            "category": cat
                        }
    
    return None

def build_params_from_dependencies(dependencies: List[str], for_each_discovery_id: Optional[str], 
                                   required_params: List[str], service: str) -> Dict:
    """Build params dict from dependencies."""
    params = {}
    
    for dep_entity in dependencies:
        entity_key = dep_entity.split('.')[-1]  # Get last part after service name
        field_name = entity_to_field_name(dep_entity)
        
        # Find matching param
        param_name = None
        
        # Strategy 1: If required_params has exactly one param, use it
        if len(required_params) == 1:
            param_name = required_params[0]
        else:
            # Strategy 2: Try to match against required_params
            for req_param in required_params:
                if req_param.lower() == field_name.lower():
                    param_name = req_param
                    break
                # Match first word
                req_first = req_param.lower().split()[0] if ' ' in req_param else req_param.lower()
                field_first = field_name.lower().split()[0] if ' ' in field_name else field_name.lower()
                if req_first == field_first:
                    param_name = req_param
                    break
        
        # Strategy 3: Use first required param as fallback
        if not param_name and required_params:
            param_name = required_params[0]
        
        # Strategy 4: Use field_name as last resort
        if not param_name:
            param_name = field_name
        
        if for_each_discovery_id:
            # Use item reference
            params[param_name] = f"{{{{ item.{field_name} }}}}"
    
    return params

def generate_discovery_entries(service_name: str, service_dir: Path) -> List[Dict]:
    """Generate discovery YAML entries from minimal_operations_list.json."""
    
    minimal_ops_file = service_dir / "minimal_operations_list.json"
    azure_file = service_dir / "azure_dependencies_with_python_names_fully_enriched.json"
    
    if not minimal_ops_file.exists():
        return []
    
    try:
        with open(minimal_ops_file, 'r') as f:
            minimal_ops_data = json.load(f)
        
        azure_data = {}
        if azure_file.exists():
            with open(azure_file, 'r') as f:
                azure_data = json.load(f)
    except Exception as e:
        return []
    
    operations = minimal_ops_data.get("minimal_operations", {}).get("selected_operations", [])
    discovery_entries = []
    
    # Process operations in order
    for op_info in operations:
        operation = op_info["operation"]
        dependencies = op_info.get("dependencies", [])
        is_dependent = op_info.get("type") == "DEPENDENT"
        
        # Get Azure info
        azure_info = get_azure_info(operation, azure_data)
        if not azure_info:
            # Fallback to operation name
            action = operation_to_action(operation)
            main_output = None
            required_params = []
            category = None
        else:
            action = azure_info["action"]
            main_output = azure_info.get("main_output_field")
            required_params = azure_info.get("required_params", [])
            category = azure_info.get("category")
        
        # Build discovery_id
        # Format: azure.service.category.action
        if category:
            discovery_id = f"azure.{service_name}.{category}.{action}"
        else:
            discovery_id = f"azure.{service_name}.{action}"
        
        # Build discovery entry
        discovery_entry = {
            "discovery_id": discovery_id
        }
        
        # Add for_each if dependent
        if is_dependent and dependencies:
            # Find the first dependency's producing operation
            for_each_id = None
            for dep_entity in dependencies:
                for_each_id = find_operation_producing_entity(dep_entity, operations, service_name)
                if for_each_id:
                    break
            
            if for_each_id:
                discovery_entry["for_each"] = for_each_id
        
        # Build calls
        call_entry = {
            "action": action,
            "save_as": "response",
            "on_error": "continue"
        }
        
        # Add params if dependent
        if is_dependent and dependencies:
            params = build_params_from_dependencies(
                dependencies, 
                discovery_entry.get("for_each"),
                required_params,
                service_name
            )
            if params:
                call_entry["params"] = params
        
        discovery_entry["calls"] = [call_entry]
        
        # Build emit
        if main_output:
            emit_entry = {
                "as": "item",
                "items_for": f"{{{{ response.{main_output} }}}}"
            }
        else:
            # Fallback if no main_output_field
            emit_entry = {
                "as": "item",
                "items_for": "{{ response }}"
            }
        
        discovery_entry["emit"] = emit_entry
        
        discovery_entries.append(discovery_entry)
    
    return discovery_entries

def get_azure_module(service_name: str, service_dir: Path) -> str:
    """Get Azure module path for service."""
    azure_file = service_dir / "azure_dependencies_with_python_names_fully_enriched.json"
    if azure_file.exists():
        try:
            with open(azure_file, 'r') as f:
                data = json.load(f)
            service_data = data.get(service_name, {})
            return service_data.get("module", f"azure.mgmt.{service_name}")
        except Exception:
            pass
    return f"azure.mgmt.{service_name}"

def generate_yaml_discovery_file(service_name: str, service_dir: Path, output_file: Path) -> bool:
    """Generate YAML file with discovery components."""
    
    discovery_entries = generate_discovery_entries(service_name, service_dir)
    
    if not discovery_entries:
        return False
    
    # Get Azure module
    azure_module = get_azure_module(service_name, service_dir)
    
    # Build full YAML structure
    yaml_data = {
        "version": "1.0",
        "provider": "azure",
        "service": service_name,
        "services": {
            "client": service_name,
            "module": azure_module
        },
        "discovery": discovery_entries,
        "checks": []  # Empty checks for now
    }
    
    # Write YAML file
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        yaml.dump(yaml_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    return True

def generate_all_services(base_dir: Path):
    """Generate YAML discovery files for all services."""
    
    print("="*80)
    print("GENERATING YAML DISCOVERY FILES FOR ALL AZURE SERVICES")
    print("="*80)
    
    # Get all service directories
    service_dirs = [d for d in base_dir.iterdir() 
                    if d.is_dir() and not d.name.startswith('.') 
                    and (d / 'minimal_operations_list.json').exists()]
    
    print(f"Found {len(service_dirs)} service directories")
    print()
    
    services_processed = 0
    services_with_errors = []
    
    for service_dir in sorted(service_dirs):
        service_name = service_dir.name
        try:
            output_file = service_dir / f"{service_name}_discovery.yaml"
            
            if generate_yaml_discovery_file(service_name, service_dir, output_file):
                with open(service_dir / 'minimal_operations_list.json') as f:
                    ops_count = len(json.load(f)['minimal_operations']['selected_operations'])
                print(f"✓ {service_name}: {ops_count} discovery entries")
                services_processed += 1
            else:
                services_with_errors.append((service_name, "No operations or error"))
                
            if services_processed % 20 == 0:
                print(f"  Progress: {services_processed} services processed...")
                
        except Exception as e:
            services_with_errors.append((service_name, str(e)))
            print(f"  ✗ {service_name}: Error - {e}")
    
    print(f"\n{'='*80}")
    print("GENERATION COMPLETE")
    print(f"{'='*80}")
    print(f"Services processed: {services_processed}")
    
    if services_with_errors:
        print(f"\nServices with errors: {len(services_with_errors)}")
        for service, error in services_with_errors[:10]:
            print(f"  - {service}: {error}")

def main():
    base_dir = Path('/Users/apple/Desktop/threat-engine/pythonsdk-database/azure')
    
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--all':
        generate_all_services(base_dir)
    else:
        # Generate for single service (compute) as test
        service_name = 'compute'
        service_dir = base_dir / service_name
        
        print(f"Generating discovery YAML for: {service_name}")
        print("="*80)
        
        output_file = service_dir / f"{service_name}_discovery.yaml"
        
        if generate_yaml_discovery_file(service_name, service_dir, output_file):
            print(f"\n✓ Saved to: {output_file}")
            
            # Show sample entries
            with open(output_file, 'r') as f:
                data = yaml.safe_load(f)
            entries = data.get('discovery', [])
            print(f"\nGenerated {len(entries)} discovery entries")
            print("\nFirst 3 entries:")
            for i, entry in enumerate(entries[:3], 1):
                print(f"  {i}. {entry.get('discovery_id')}")
                if entry.get('for_each'):
                    print(f"     for_each: {entry['for_each']}")
        else:
            print("Error: Could not generate discovery YAML")

if __name__ == '__main__':
    main()

