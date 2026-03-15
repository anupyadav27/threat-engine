"""
Generate prioritized resource operations file for ALL services.
Uses resource_arn_mapping.json if available, otherwise extracts from minimal_operations_list.json
"""

import json
import yaml
import re
from pathlib import Path
from typing import Dict, List, Set, Optional
from datetime import datetime
from collections import defaultdict

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

def infer_resource_type_from_arn_entity(arn_entity: str, service: str) -> str:
    """Infer resource type from ARN entity name."""
    if not arn_entity:
        return None
    
    # Remove service prefix (e.g., "acm.certificate_arn" -> "certificate_arn")
    parts = arn_entity.split('.')
    if len(parts) < 2:
        return None
    
    entity_name = parts[-1]
    
    # Remove common suffixes
    entity_name = entity_name.replace('_arn', '').replace('_id', '').replace('_name', '')
    
    # Handle patterns like "certificate_summary_list_certificate" -> "certificate"
    # or "analyzer_arn" -> "analyzer"
    words = entity_name.split('_')
    
    # Find the main resource word (usually the last significant word before common suffixes)
    # Common patterns:
    # - certificate_arn -> certificate
    # - analyzer_arn -> analyzer
    # - bucket_name -> bucket
    # - instance_id -> instance
    
    # Try to find a meaningful resource word
    resource_candidates = []
    skip_words = {'summary', 'list', 'detail', 'item', 'entry', 'data', 'info', 'metadata'}
    
    for word in words:
        if word not in skip_words and len(word) > 2:
            resource_candidates.append(word)
    
    if resource_candidates:
        # Use the last meaningful word as resource type
        return resource_candidates[-1]
    
    # Fallback: use the first word if it's meaningful
    if words and len(words[0]) > 2:
        return words[0]
    
    return None

def classify_resource_from_arn_data(resource_type: str, has_arn: bool, is_primary: bool, 
                                    service: str) -> Dict:
    """Classify resource based on ARN data."""
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
    
    # PRIMARY RESOURCE - has ARN and is marked as primary
    if has_arn and is_primary:
        return {
            "classification": "PRIMARY_RESOURCE",
            "should_inventory": True,
            "use_for_enrichment": False
        }
    
    # PRIMARY RESOURCE - has ARN (even if not explicitly marked, assume primary if it has ARN)
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

def extract_resources_from_minimal_ops(minimal_ops_data: Dict) -> Dict:
    """Extract resource information from minimal_operations_list.json."""
    resources = {}
    operations = minimal_ops_data.get("minimal_operations", {}).get("selected_operations", [])
    
    # Build resource map from ARNs produced
    resource_to_ops = defaultdict(lambda: {
        "arn_entity": None,
        "arn_producing_operations": [],
        "id_producing_operations": [],
        "can_get_arn_from_roots": False,
        "requires_dependent_ops": False,
        "is_primary": False
    })
    
    root_operations = set(minimal_ops_data.get("root_operations_available", []))
    
    for op_info in operations:
        operation = op_info["operation"]
        is_root = operation in root_operations
        is_dependent = op_info.get("type") == "DEPENDENT"
        
        # Process ARNs produced
        for arn_info in op_info.get("arns_produced", []):
            arn_entity = arn_info.get("arn_entity")
            resource_type = arn_info.get("resource_type")
            is_primary = arn_info.get("is_primary_resource", False)
            
            # If resource_type is null, infer it from ARN entity
            if not resource_type and arn_entity:
                resource_type = infer_resource_type_from_arn_entity(arn_entity, minimal_ops_data.get("service", ""))
            
            if resource_type:
                if resource_type not in resources:
                    resources[resource_type] = resource_to_ops[resource_type]
                    resources[resource_type]["resource_type"] = resource_type
                    resources[resource_type]["arn_entity"] = arn_entity
                    resources[resource_type]["is_primary"] = is_primary or False
                
                resources[resource_type]["arn_producing_operations"].append(operation)
                
                if is_root:
                    resources[resource_type]["can_get_arn_from_roots"] = True
                if is_dependent:
                    resources[resource_type]["requires_dependent_ops"] = True
        
        # Also check entities_covered for potential resources (entities ending in _arn)
        for entity in op_info.get("entities_covered", []):
            if "_arn" in entity.lower():
                # Extract resource type from entity
                resource_type = infer_resource_type_from_arn_entity(entity, minimal_ops_data.get("service", ""))
                
                if resource_type and resource_type not in resources:
                    # This is a resource we haven't seen yet
                    resources[resource_type] = resource_to_ops[resource_type]
                    resources[resource_type]["resource_type"] = resource_type
                    resources[resource_type]["arn_entity"] = entity
                    resources[resource_type]["is_primary"] = False  # Unknown, will be classified later
                
                if resource_type:
                    if operation not in resources[resource_type]["arn_producing_operations"]:
                        resources[resource_type]["arn_producing_operations"].append(operation)
                    
                    if is_root:
                        resources[resource_type]["can_get_arn_from_roots"] = True
                    if is_dependent:
                        resources[resource_type]["requires_dependent_ops"] = True
    
    # Remove duplicates from operation lists
    for resource_type, resource_info in resources.items():
        resource_info["arn_producing_operations"] = sorted(list(set(resource_info["arn_producing_operations"])))
        resource_info["id_producing_operations"] = sorted(list(set(resource_info["id_producing_operations"])))
    
    return resources

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
    
    # Must have at least minimal_operations_list.json
    if not minimal_ops_file.exists():
        return None
    
    try:
        with open(minimal_ops_file, 'r') as f:
            minimal_ops_data = json.load(f)
        
        # Try to get resources from resource_arn_mapping.json first
        resources_data = {}
        if resource_arn_mapping_file.exists():
            with open(resource_arn_mapping_file, 'r') as f:
                arn_mapping = json.load(f)
            analysis = arn_mapping.get("analysis", {})
            resources_data = analysis.get("resources", {})
        else:
            # Extract from minimal_operations_list.json
            resources_data = extract_resources_from_minimal_ops(minimal_ops_data)
        
        # Get resource inventory if available (for better classification)
        resource_inventory = None
        if resource_inventory_file.exists():
            with open(resource_inventory_file, 'r') as f:
                resource_inventory = json.load(f)
        
        root_operations = minimal_ops_data.get("root_operations_available", [])
        yaml_discovery_ops = set(minimal_ops_data.get("yaml_discovery_operations", []))
        
        # Also check actual YAML files in services folder
        yaml_ops_from_folder = get_yaml_discovery_operations(service_name, services_dir)
        yaml_discovery_ops.update(yaml_ops_from_folder)
        
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
                # Infer classification from resource data
                has_arn = resource_info.get("arn_entity") is not None
                is_primary = resource_info.get("is_primary", False)
                class_info = classify_resource_from_arn_data(resource_type, has_arn, is_primary, service_name)
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
        
        if not (service_dir / "minimal_operations_list.json").exists():
            skipped += 1
            continue
        
        print(f"Processing: {service_name.upper()}")
        
        report = generate_resource_operations_file(service_name, service_dir, services_path)
        
        if not report:
            print(f"  ⚠️  Skipped (missing minimal_operations_list.json)")
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
