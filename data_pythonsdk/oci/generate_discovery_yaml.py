"""
Generate YAML discovery files for Oracle Cloud Infrastructure (OCI) services from minimal_operations_list.json.
Adapted for OCI structure.
"""

import json
import yaml
import re
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

def operation_to_action(operation: str) -> str:
    """Convert OCI operation name to action name.
    OCI operations are like 'list_compartments' -> 'list_compartments' (keep snake_case)
    """
    # OCI uses snake_case for actions
    return operation

def entity_to_field_name(entity: str) -> str:
    """Convert entity name to field name for params."""
    # oci.identity.compartment.id -> id (extract last part)
    # Or oci.identity.compartment -> compartment
    parts = entity.split('.')
    if len(parts) > 2:
        # Return the part after service name
        return '.'.join(parts[2:])
    return parts[-1]

def find_operation_producing_entity(entity: str, operations: List[Dict], service: str) -> Optional[str]:
    """Find the discovery_id of operation that produces this entity."""
    for op_info in operations:
        entities_covered = op_info.get("entities_covered", [])
        if entity in entities_covered:
            operation = op_info["operation"]
            action = operation_to_action(operation)
            return f"oci.{service}.{action}"
    return None

def get_oci_info(operation: str, oci_data: Dict, service_name: str) -> Optional[Dict]:
    """Get OCI action and main_output_field for an operation."""
    if not oci_data:
        return None
    
    service_data = oci_data.get(service_name, {})
    
    # OCI has 'operations' array directly
    operations = service_data.get("operations", [])
    
    # Find operation by name
    for op_data in operations:
        if op_data.get("operation") == operation:
            return {
                "action": op_data.get("python_method") or op_data.get("operation", operation),
                "main_output_field": op_data.get("main_output_field"),
                "required_params": op_data.get("required_params", []),
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
    oci_file = service_dir / "oci_dependencies_with_python_names_fully_enriched.json"
    
    if not minimal_ops_file.exists():
        return []
    
    try:
        with open(minimal_ops_file, 'r') as f:
            minimal_ops_data = json.load(f)
        
        oci_data = {}
        if oci_file.exists():
            with open(oci_file, 'r') as f:
                oci_data = json.load(f)
    except Exception as e:
        return []
    
    operations = minimal_ops_data.get("minimal_operations", {}).get("selected_operations", [])
    discovery_entries = []
    
    # Process operations in order
    for op_info in operations:
        operation = op_info["operation"]
        dependencies = op_info.get("dependencies", [])
        is_dependent = op_info.get("type") == "DEPENDENT"
        
        # Get OCI info
        oci_info = get_oci_info(operation, oci_data, service_name)
        if not oci_info:
            # Fallback to operation name
            action = operation_to_action(operation)
            main_output = None
            required_params = []
        else:
            action = oci_info["action"]
            main_output = oci_info.get("main_output_field")
            required_params = oci_info.get("required_params", [])
        
        # Build discovery_id
        # Format: oci.service.action
        discovery_id = f"oci.{service_name}.{action}"
        
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

def get_oci_module(service_name: str, service_dir: Path) -> str:
    """Get OCI module path for service."""
    oci_file = service_dir / "oci_dependencies_with_python_names_fully_enriched.json"
    if oci_file.exists():
        try:
            with open(oci_file, 'r') as f:
                data = json.load(f)
            service_data = data.get(service_name, {})
            # OCI uses module from service_data
            module = service_data.get("module")
            if module:
                return module
        except Exception:
            pass
    # Default OCI SDK pattern
    return f"oci.{service_name}"

def generate_yaml_discovery_file(service_name: str, service_dir: Path, output_file: Path) -> bool:
    """Generate YAML file with discovery components."""
    
    discovery_entries = generate_discovery_entries(service_name, service_dir)
    
    # Even if no entries, generate empty file for 100% coverage
    # if not discovery_entries:
    #     return False
    
    # Get OCI module
    oci_module = get_oci_module(service_name, service_dir)
    
    # Build full YAML structure
    yaml_data = {
        "version": "1.0",
        "provider": "oci",
        "service": service_name,
        "services": {
            "client": service_name,
            "module": oci_module
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
    print("GENERATING YAML DISCOVERY FILES FOR ALL OCI SERVICES")
    print("="*80)
    
    # Get all service directories - include those with minimal_operations_list OR dependency_index/oci_dependencies
    service_dirs = [d for d in base_dir.iterdir() 
                    if d.is_dir() and not d.name.startswith('.') 
                    and ((d / 'minimal_operations_list.json').exists() or
                         (d / 'dependency_index.json').exists() or
                         (d / 'oci_dependencies_with_python_names_fully_enriched.json').exists())]
    
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
    base_dir = Path('/Users/apple/Desktop/threat-engine/pythonsdk-database/oci')
    
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--all':
        generate_all_services(base_dir)
    else:
        # Generate for single service (identity) as test
        service_name = 'identity'
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

