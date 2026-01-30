"""
Generate prioritized resource operations file for all services.
Resources categorized as PRIMARY and OTHER, with operations prioritized:
1. Independent/Root operations
2. YAML discovery operations (from services folder)
3. Other operations
"""

import json
import yaml
import re
from pathlib import Path
from typing import Dict, List, Set, Optional
from datetime import datetime

def operation_to_action(operation: str) -> str:
    """Convert operation name to boto3 action name."""
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', operation)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()

def discovery_id_to_operation(discovery_id: str) -> str:
    """Convert discovery_id to operation name."""
    parts = discovery_id.split('.')
    if len(parts) >= 3:
        operation_part = parts[2]
        words = operation_part.split('_')
        operation = ''.join(word.capitalize() for word in words)
        return operation
    return discovery_id

def get_yaml_discovery_operations(service_name: str, services_dir: Path) -> Set[str]:
    """Get all operations from YAML discovery_id list in services folder."""
    service_yaml_dir = services_dir / service_name / "rules"
    yaml_file = service_yaml_dir / f"{service_name}.yaml"
    
    operations = set()
    if yaml_file.exists():
        try:
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)
            discovery = data.get("discovery", [])
            for disc in discovery:
                discovery_id = disc.get("discovery_id")
                if discovery_id:
                    op = discovery_id_to_operation(discovery_id)
                    operations.add(op)
        except Exception:
            pass
    
    return operations

def classify_resource_from_mapping(resource_type: str, resource_info: Dict, service: str) -> Dict:
    """Classify resource based on resource_arn_mapping data."""
    has_arn = resource_info.get("arn_entity") is not None
    can_get_from_roots = resource_info.get("can_get_arn_from_roots", False)
    
    # Simple classification logic
    resource_lower = resource_type.lower()
    
    # EPHEMERAL patterns
    ephemeral_patterns = [
        r'.*_job$', r'.*_jobs?$', r'.*_task$', r'.*_tasks?$', r'.*_workflow$',
        r'.*_preview$', r'.*_preview_.*', r'.*_finding$', r'.*_findings?$',
        r'.*_upload$', r'.*_uploads?$', r'.*_version$', r'.*_versions?$',
        r'.*_request$', r'.*_approval$', r'.*_delegation$'
    ]
    for pattern in ephemeral_patterns:
        if re.match(pattern, resource_lower):
            return {
                "classification": "EPHEMERAL",
                "should_inventory": False,
                "use_for_enrichment": False
            }
    
    # CONFIGURATION patterns
    config_patterns = [
        r'.*_configuration$', r'.*_config$', r'.*_rule$', r'.*_rules?$',
        r'.*_setting$', r'.*_settings?$', r'.*_topic$', r'.*_queue$',
        r'.*_lifecycle$', r'.*_versioning$', r'.*_encryption$', r'.*_replication$',
        r'.*_acl$', r'.*_permission$', r'.*_permissions?$'
    ]
    config_exceptions = {"iam": {"policy", "role", "user", "group"}, "s3": {"bucket"}}
    
    if service in config_exceptions:
        if resource_type not in config_exceptions[service]:
            for pattern in config_patterns:
                if re.match(pattern, resource_lower):
                    return {
                        "classification": "CONFIGURATION",
                        "should_inventory": False,
                        "use_for_enrichment": True
                    }
    else:
        for pattern in config_patterns:
            if re.match(pattern, resource_lower):
                return {
                    "classification": "CONFIGURATION",
                    "should_inventory": False,
                    "use_for_enrichment": True
                }
    
    # PRIMARY RESOURCE - has ARN and can get from roots
    if has_arn and can_get_from_roots:
        return {
            "classification": "PRIMARY_RESOURCE",
            "should_inventory": True,
            "use_for_enrichment": False
        }
    
    # PRIMARY RESOURCE - has ARN (even if requires dependent ops)
    if has_arn:
        return {
            "classification": "PRIMARY_RESOURCE",
            "should_inventory": True,
            "use_for_enrichment": False
        }
    
    # SUB_RESOURCE - no ARN
    return {
        "classification": "SUB_RESOURCE",
        "should_inventory": False,
        "use_for_enrichment": True
    }

def prioritize_operations_for_resource(resource_info: Dict, root_operations: List[str], 
                                       yaml_discovery_ops: Set[str]) -> Dict:
    """Prioritize operations for a resource."""
    # Get all operations that produce this resource
    arn_ops = resource_info.get("arn_producing_operations", [])
    id_ops = resource_info.get("id_producing_operations", [])
    all_ops = list(set(arn_ops + id_ops))
    
    # Categorize operations
    independent_ops = []
    yaml_ops = []
    other_ops = []
    
    for op in all_ops:
        if op in root_operations:
            independent_ops.append(op)
        elif op in yaml_discovery_ops:
            yaml_ops.append(op)
        else:
            other_ops.append(op)
    
    # Build prioritized list
    prioritized_operations = {
        "independent": sorted(independent_ops),
        "yaml_discovery": sorted(yaml_ops),
        "other": sorted(other_ops),
        "all": sorted(all_ops)
    }
    
    return prioritized_operations

def generate_resource_operations_file(service_name: str, service_dir: Path, services_dir: Path) -> Optional[Dict]:
    """Generate prioritized resource operations file for a service."""
    
    resource_arn_mapping_file = service_dir / "resource_arn_mapping.json"
    resource_inventory_file = service_dir / "resource_inventory_report.json"
    minimal_ops_file = service_dir / "minimal_operations_list.json"
    
    # Try resource_arn_mapping.json first (more services have this)
    if not resource_arn_mapping_file.exists():
        return None
    
    try:
        with open(resource_arn_mapping_file, 'r') as f:
            arn_mapping = json.load(f)
        
        # Get resource inventory if available (for better classification)
        resource_inventory = None
        if resource_inventory_file.exists():
            with open(resource_inventory_file, 'r') as f:
                resource_inventory = json.load(f)
        
        root_operations = []
        yaml_discovery_ops = set()
        
        if minimal_ops_file.exists():
            with open(minimal_ops_file, 'r') as f:
                minimal_ops_data = json.load(f)
            root_operations = minimal_ops_data.get("root_operations_available", [])
            yaml_discovery_ops = set(minimal_ops_data.get("yaml_discovery_operations", []))
        
        # Also check actual YAML files in services folder
        yaml_ops_from_folder = get_yaml_discovery_operations(service_name, services_dir)
        yaml_discovery_ops.update(yaml_ops_from_folder)
        
        # Get root operations from analysis if available
        analysis = arn_mapping.get("analysis", {})
        if not root_operations:
            root_operations = analysis.get("root_operations", [])
        
        resources_data = analysis.get("resources", {})
        
        # Build resource inventory map if available
        inventory_map = {}
        if resource_inventory:
            for res in resource_inventory.get("resources", []):
                inventory_map[res.get("resource_type")] = res
        
        # Process resources
        primary_resources = []
        other_resources = []
        
        for resource_type, resource_info in resources_data.items():
            # Get classification
            if resource_type in inventory_map:
                # Use classification from resource_inventory_report
                inv_res = inventory_map[resource_type]
                classification = inv_res.get("classification", "SUB_RESOURCE")
                should_inventory = inv_res.get("should_inventory", False)
                use_for_enrichment = inv_res.get("use_for_enrichment", False)
            else:
                # Infer classification
                class_info = classify_resource_from_mapping(resource_type, resource_info, service_name)
                classification = class_info["classification"]
                should_inventory = class_info["should_inventory"]
                use_for_enrichment = class_info["use_for_enrichment"]
            
            # Prioritize operations
            prioritized_ops = prioritize_operations_for_resource(
                resource_info, root_operations, yaml_discovery_ops
            )
            
            resource_entry = {
                "resource_type": resource_type,
                "classification": classification,
                "has_arn": resource_info.get("arn_entity") is not None,
                "arn_entity": resource_info.get("arn_entity"),
                "should_inventory": should_inventory,
                "use_for_enrichment": use_for_enrichment,
                "operations": prioritized_ops,
                "can_get_from_root_ops": resource_info.get("can_get_arn_from_roots", False),
                "requires_dependent_ops": resource_info.get("requires_dependent_ops", False)
            }
            
            if should_inventory or classification == "PRIMARY_RESOURCE":
                primary_resources.append(resource_entry)
            else:
                other_resources.append(resource_entry)
        
        # Build report
        report = {
            "service": service_name,
            "generated_at": datetime.now().isoformat(),
            "root_operations": sorted(root_operations),
            "yaml_discovery_operations": sorted(list(yaml_discovery_ops)),
            "primary_resources": sorted(primary_resources, key=lambda x: x["resource_type"]),
            "other_resources": sorted(other_resources, key=lambda x: x["resource_type"]),
            "summary": {
                "total_resources": len(resources_data),
                "primary_resources_count": len(primary_resources),
                "other_resources_count": len(other_resources),
                "resources_with_arn": sum(1 for r in resources_data.values() if r.get("arn_entity")),
                "resources_from_root_ops": sum(1 for r in resources_data.values() if r.get("can_get_arn_from_roots", False))
            }
        }
        
        return report
        
    except Exception as e:
        return {"error": str(e)}

def process_all_services(aws_dir: str, services_dir: str):
    """Process all services to generate prioritized resource operations files."""
    
    aws_path = Path(aws_dir)
    services_path = Path(services_dir)
    
    service_dirs = [d for d in aws_path.iterdir() if d.is_dir() and not d.name.startswith('.')]
    service_dirs.sort()
    
    print("=" * 80)
    print("GENERATING PRIORITIZED RESOURCE OPERATIONS FOR ALL SERVICES")
    print("=" * 80)
    print("")
    
    successful = 0
    failed = 0
    skipped = 0
    
    for service_dir in service_dirs:
        service_name = service_dir.name
        
        if not (service_dir / "resource_arn_mapping.json").exists():
            skipped += 1
            continue
        
        print(f"Processing: {service_name.upper()}")
        
        report = generate_resource_operations_file(service_name, service_dir, services_path)
        
        if not report:
            print(f"  ⚠️  Skipped (missing resource_arn_mapping.json)")
            skipped += 1
            continue
        
        if "error" in report:
            print(f"  ❌ Error: {report['error']}")
            failed += 1
            continue
        
        # Save file
        output_file = service_dir / "resource_operations_prioritized.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"  ✅ Generated: {output_file.name}")
        print(f"     Primary Resources: {report['summary']['primary_resources_count']}")
        print(f"     Other Resources: {report['summary']['other_resources_count']}")
        print(f"     Root Operations: {len(report['root_operations'])}")
        print(f"     YAML Discovery Operations: {len(report['yaml_discovery_operations'])}")
        
        successful += 1
    
    print(f"\n{'='*80}")
    print("GENERATION COMPLETE")
    print(f"{'='*80}")
    print(f"  ✅ Successful: {successful}")
    print(f"  ❌ Failed: {failed}")
    print(f"  ⚠️  Skipped: {skipped}")
    print(f"  📁 Total Services Checked: {len(service_dirs)}")

if __name__ == "__main__":
    aws_dir = "/Users/apple/Desktop/threat-engine/pythonsdk-database/aws"
    services_dir = "/Users/apple/Desktop/threat-engine/configScan_engines/aws-configScan-engine/services"
    
    process_all_services(aws_dir, services_dir)
