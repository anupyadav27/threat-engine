"""
Generate YAML discovery file for accessanalyzer from minimal_operations_list.json
"""

import json
import yaml
import re
from pathlib import Path
from typing import Dict, List, Optional

def operation_to_action(operation: str) -> str:
    """Convert operation name to boto3 action name."""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', operation)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def entity_to_field_name(entity: str) -> str:
    """Convert entity name to field name for params."""
    # accessanalyzer.analyzer_arn -> analyzerArn
    parts = entity.split('.')[-1].split('_')
    return parts[0] + ''.join(word.capitalize() for word in parts[1:])

def find_operation_producing_entity(entity: str, operations: List[Dict], service: str) -> Optional[str]:
    """Find the discovery_id of operation that produces this entity."""
    for op_info in operations:
        entities_covered = op_info.get("entities_covered", [])
        if entity in entities_covered:
            operation = op_info["operation"]
            action = operation_to_action(operation)
            return f"aws.{service}.{action}"
    return None

def get_boto3_info(operation: str, boto3_data: Dict) -> Optional[Dict]:
    """Get boto3 action and main_output_field for an operation."""
    service_name = list(boto3_data.keys())[0] if boto3_data else None
    if not service_name:
        return None
    
    all_ops = boto3_data.get(service_name, {}).get("independent", []) + \
              boto3_data.get(service_name, {}).get("dependent", [])
    
    for op_data in all_ops:
        if op_data.get("operation") == operation:
            return {
                "action": op_data.get("yaml_action") or op_data.get("python_method", operation_to_action(operation)),
                "main_output_field": op_data.get("main_output_field"),
                "required_params": op_data.get("required_params", [])
            }
    return None

def build_params_from_dependencies(dependencies: List[str], for_each_discovery_id: Optional[str], 
                                   required_params: List[str], service: str) -> Dict:
    """Build params dict from dependencies."""
    params = {}
    
    # Map entity patterns to common item field names
    entity_to_item_field = {
        "analyzer_arn": "arn",
        "analyzer_name": "name",
        "access_preview_id": "id",
        "policy_generation_job_id": "jobId",
        "archive_rule_rule_name": "ruleName",
        "resource_resource_arn": "resource"
    }
    
    for dep_entity in dependencies:
        entity_key = dep_entity.split('.')[-1]  # Get last part after service name
        
        # Check if we have a direct mapping
        if entity_key in entity_to_item_field:
            field_name = entity_to_item_field[entity_key]
        else:
            # Convert entity to field name
            field_name = entity_to_field_name(dep_entity)
        
        # Check if this param is required
        param_name = None
        for req_param in required_params:
            if req_param.lower() == field_name.lower() or req_param.lower() == entity_key.lower().replace('_', ''):
                param_name = req_param
                break
        
        if not param_name:
            # Try to match by converting
            param_name = field_name
        
        if for_each_discovery_id:
            # Use item reference
            params[param_name] = f"{{{{ item.{field_name} }}}}"
        else:
            # Independent operation - shouldn't have params from dependencies
            pass
    
    return params

def generate_discovery_entries(service_name: str, service_dir: Path) -> List[Dict]:
    """Generate discovery YAML entries from minimal_operations_list.json."""
    
    minimal_ops_file = service_dir / "minimal_operations_list.json"
    boto3_file = service_dir / "boto3_dependencies_with_python_names_fully_enriched.json"
    
    if not minimal_ops_file.exists():
        return []
    
    try:
        with open(minimal_ops_file, 'r') as f:
            minimal_ops_data = json.load(f)
        
        boto3_data = {}
        if boto3_file.exists():
            with open(boto3_file, 'r') as f:
                boto3_data = json.load(f)
    except Exception as e:
        print(f"  ⚠️  Error reading files: {e}")
        return []
    
    operations = minimal_ops_data.get("minimal_operations", {}).get("selected_operations", [])
    discovery_entries = []
    
    # Build a map of operations by name for quick lookup
    ops_by_name = {op["operation"]: op for op in operations}
    
    # Process operations in order
    for op_info in operations:
        operation = op_info["operation"]
        dependencies = op_info.get("dependencies", [])
        is_dependent = op_info.get("type") == "DEPENDENT"
        
        # Get boto3 info
        boto3_info = get_boto3_info(operation, boto3_data)
        if not boto3_info:
            # Fallback to generated action name
            action = operation_to_action(operation)
            main_output = None
            required_params = []
        else:
            action = boto3_info["action"]
            main_output = boto3_info.get("main_output_field")
            required_params = boto3_info.get("required_params", [])
        
        # Build discovery_id
        discovery_id = f"aws.{service_name}.{action}"
        
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
        
        # Build emit - emit all output
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

def generate_yaml_discovery_file(service_name: str, service_dir: Path, output_file: Path):
    """Generate YAML file with discovery components."""
    
    discovery_entries = generate_discovery_entries(service_name, service_dir)
    
    if not discovery_entries:
        print(f"  ⚠️  No discovery entries generated")
        return False
    
    # Build full YAML structure
    yaml_data = {
        "version": "1.0",
        "provider": "aws",
        "service": service_name,
        "services": {
            "client": service_name,
            "module": "boto3.client"
        },
        "discovery": discovery_entries,
        "checks": []  # Empty checks for now
    }
    
    # Write YAML file
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w') as f:
        yaml.dump(yaml_data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
    
    return True

if __name__ == "__main__":
    service_name = "accessanalyzer"
    service_dir = Path("/Users/apple/Desktop/threat-engine/pythonsdk-database/aws/accessanalyzer")
    output_file = service_dir / "accessanalyzer_discovery.yaml"
    
    print("=" * 80)
    print(f"GENERATING YAML DISCOVERY FILE FOR {service_name.upper()}")
    print("=" * 80)
    
    if generate_yaml_discovery_file(service_name, service_dir, output_file):
        with open(service_dir / 'minimal_operations_list.json') as f:
            ops_count = len(json.load(f)['minimal_operations']['selected_operations'])
        print(f"  ✅ Generated successfully: {output_file}")
        print(f"  📄 Discovery entries: {ops_count}")
    else:
        print(f"  ❌ Failed to generate")

