"""
Generate minimal_operations_list.json for ALL services in the AWS directory.
Includes all enhancements: ARN mapping, deduplication, priority, dependencies logic.
"""

import json
import yaml
import re
from pathlib import Path
from typing import Dict, List, Set, Optional
from collections import defaultdict
from datetime import datetime
from enum import Enum

class ResourceCategory(Enum):
    PRIMARY_RESOURCE = "PRIMARY_RESOURCE"
    CONFIGURATION = "CONFIGURATION"
    EPHEMERAL = "EPHEMERAL"
    SUB_RESOURCE = "SUB_RESOURCE"

# Import all the functions from previous scripts
def get_all_fields_from_direct_vars(direct_vars_file: Path) -> Dict[str, Dict]:
    """Extract all fields and their producing operations from direct_vars.json."""
    if not direct_vars_file.exists():
        return {}
    try:
        with open(direct_vars_file, 'r') as f:
            data = json.load(f)
    except Exception:
        return {}
    fields = data.get("fields", {})
    field_info = {}
    for field_name, field_data in fields.items():
        operations = field_data.get("operations", [])
        dependency_entity = field_data.get("dependency_index_entity", "")
        produces = field_data.get("produces", [])
        field_info[field_name] = {
            "operations": operations,
            "dependency_index_entity": dependency_entity,
            "produces": produces,
            "field_name": field_name
        }
    return field_info

def get_entity_to_operations_mapping(dependency_index: Dict) -> Dict[str, Set[str]]:
    """Map each entity to all operations that produce it."""
    entity_to_ops = defaultdict(set)
    entity_paths = dependency_index.get("entity_paths", {})
    for entity_name, paths in entity_paths.items():
        for path_data in paths:
            operations = path_data.get("operations", [])
            entity_to_ops[entity_name].update(operations)
    roots = dependency_index.get("roots", [])
    for root in roots:
        op = root.get("op")
        produces = root.get("produces", [])
        for entity in produces:
            entity_to_ops[entity].add(op)
    return dict(entity_to_ops)

def get_operation_entities(operation: str, dependency_index: Dict) -> Set[str]:
    """Get all entities produced by an operation."""
    entities = set()
    roots = dependency_index.get("roots", [])
    for root in roots:
        if root.get("op") == operation:
            entities.update(root.get("produces", []))
    entity_paths = dependency_index.get("entity_paths", {})
    for entity_name, paths in entity_paths.items():
        for path_data in paths:
            if operation in path_data.get("operations", []):
                produces = path_data.get("produces", {})
                if operation in produces:
                    entities.update(produces[operation])
                entities.add(entity_name)
    return entities

def get_operation_dependencies(operation: str, dependency_index: Dict) -> Set[str]:
    """Get all entities that an operation consumes (dependencies)."""
    dependencies = set()
    entity_paths = dependency_index.get("entity_paths", {})
    for entity_name, paths in entity_paths.items():
        for path_data in paths:
            if operation in path_data.get("operations", []):
                consumes = path_data.get("consumes", {})
                if operation in consumes:
                    dependencies.update(consumes[operation])
    return dependencies

def classify_resource(resource_type: str, resource_info: Dict, service: str) -> Dict:
    """Classify a resource into one of the four categories."""
    resource_lower = resource_type.lower()
    
    # EPHEMERAL PATTERNS
    EPHEMERAL_PATTERNS = [
        r'.*_job$', r'.*_jobs?$', r'.*_task$', r'.*_tasks?$', r'.*_workflow$',
        r'.*_preview$', r'.*_preview_.*', r'.*_finding$', r'.*_findings?$',
        r'.*_upload$', r'.*_uploads?$', r'.*_version$', r'.*_versions?$',
        r'.*_request$', r'.*_approval$', r'.*_delegation$'
    ]
    for pattern in EPHEMERAL_PATTERNS:
        if re.match(pattern, resource_lower):
            return {"category": ResourceCategory.EPHEMERAL.value, "should_inventory": False, "use_for_enrichment": False}
    
    # CONFIGURATION PATTERNS
    CONFIGURATION_PATTERNS = [
        r'.*_configuration$', r'.*_config$', r'.*_rule$', r'.*_rules?$',
        r'.*_setting$', r'.*_settings?$', r'.*_topic$', r'.*_queue$',
        r'.*_lifecycle$', r'.*_versioning$', r'.*_encryption$', r'.*_replication$',
        r'.*_acl$', r'.*_permission$', r'.*_permissions?$'
    ]
    CONFIGURATION_EXCEPTIONS = {"iam": {"policy", "role", "user", "group"}, "s3": {"bucket"}}
    
    if service in CONFIGURATION_EXCEPTIONS:
        if resource_type not in CONFIGURATION_EXCEPTIONS[service]:
            for pattern in CONFIGURATION_PATTERNS:
                if re.match(pattern, resource_lower):
                    return {"category": ResourceCategory.CONFIGURATION.value, "should_inventory": False, "use_for_enrichment": True}
    else:
        for pattern in CONFIGURATION_PATTERNS:
            if re.match(pattern, resource_lower):
                return {"category": ResourceCategory.CONFIGURATION.value, "should_inventory": False, "use_for_enrichment": True}
    
    # SUB_RESOURCE PATTERNS
    parts = resource_type.split('_')
    if len(parts) >= 3:
        if len(parts) >= 2 and parts[0] == parts[1]:
            return {"category": ResourceCategory.SUB_RESOURCE.value, "should_inventory": False, "use_for_enrichment": True}
    
    SUB_RESOURCE_PATTERNS = [r'.*_metadata$', r'.*_detail$', r'.*_details?$', r'.*_principal$', r'.*_owner$', r'.*_approver$', r'.*_requestor$']
    for pattern in SUB_RESOURCE_PATTERNS:
        if re.match(pattern, resource_lower):
            if resource_info.get("requires_dependent_ops") and not resource_info.get("arn_entity"):
                return {"category": ResourceCategory.SUB_RESOURCE.value, "should_inventory": False, "use_for_enrichment": True}
    
    # PRIMARY RESOURCE
    SERVICE_PRIMARY_RESOURCES = {
        "accessanalyzer": {"analyzer", "resource"},
        "s3": {"bucket"},
        "ec2": {"instance", "volume", "snapshot", "vpc", "subnet", "security-group", "image", "launch-template", "network-interface", "nat-gateway"},
        "iam": {"user", "role", "group", "policy", "instance-profile"},
    }
    
    if service in SERVICE_PRIMARY_RESOURCES:
        if resource_type in SERVICE_PRIMARY_RESOURCES[service]:
            return {"category": ResourceCategory.PRIMARY_RESOURCE.value, "should_inventory": True, "use_for_enrichment": False}
    
    if resource_info.get("arn_entity"):
        return {"category": ResourceCategory.PRIMARY_RESOURCE.value, "should_inventory": True, "use_for_enrichment": False}
    else:
        return {"category": ResourceCategory.SUB_RESOURCE.value, "should_inventory": False, "use_for_enrichment": True}

def get_arn_entities_from_operation(operation: str, dependency_index: Dict) -> List[str]:
    """Get all ARN entities produced by an operation."""
    arn_entities = []
    roots = dependency_index.get("roots", [])
    for root in roots:
        if root.get("op") == operation:
            produces = root.get("produces", [])
            arn_entities.extend([e for e in produces if "_arn" in e.lower()])
    entity_paths = dependency_index.get("entity_paths", {})
    for entity_name, paths in entity_paths.items():
        if "_arn" not in entity_name.lower():
            continue
        for path_data in paths:
            if operation in path_data.get("operations", []):
                produces = path_data.get("produces", {})
                if operation in produces:
                    if entity_name in produces[operation]:
                        arn_entities.append(entity_name)
                if entity_name not in arn_entities:
                    arn_entities.append(entity_name)
    return sorted(list(set(arn_entities)))

def get_arn_field_name_from_boto3(operation: str, arn_entity: str, boto3_data: Dict) -> Optional[str]:
    """Get the actual ARN field name from boto3 operation response."""
    service_name = list(boto3_data.keys())[0] if boto3_data else None
    if not service_name:
        return None
    operations = boto3_data.get(service_name, {}).get("independent", []) + boto3_data.get(service_name, {}).get("dependent", [])
    for op_data in operations:
        if op_data.get("operation") == operation:
            item_fields = op_data.get("item_fields", {})
            for field_name, field_data in item_fields.items():
                field_lower = field_name.lower()
                if "arn" in field_lower or field_lower.endswith("arn"):
                    entity_suffix = arn_entity.split(".")[-1].replace("_arn", "")
                    field_suffix = field_name.lower().replace("arn", "").replace("_", "")
                    if entity_suffix in field_suffix or field_suffix in entity_suffix:
                        return field_name
            for field_name, field_data in item_fields.items():
                if "arn" in field_name.lower():
                    return field_name
    return None

def get_resource_info_for_arn(arn_entity: str, resource_inventory: Dict) -> Optional[Dict]:
    """Get resource information for an ARN entity."""
    for resource in resource_inventory.get("resources", []):
        if resource.get("arn_entity") == arn_entity:
            return {
                "resource_type": resource.get("resource_type"),
                "classification": resource.get("classification"),
                "is_primary": resource.get("classification") == "PRIMARY_RESOURCE",
                "should_inventory": resource.get("should_inventory", False)
            }
    return None

def extract_discovery_ids_from_yaml(yaml_file: Path) -> Set[str]:
    """Extract all discovery_id values from YAML file."""
    discovery_ids = set()
    if not yaml_file.exists():
        return discovery_ids
    try:
        with open(yaml_file, 'r') as f:
            data = yaml.safe_load(f)
        discovery = data.get("discovery", [])
        for disc in discovery:
            discovery_id = disc.get("discovery_id")
            if discovery_id:
                discovery_ids.add(discovery_id)
    except Exception:
        pass
    return discovery_ids

def discovery_id_to_operation(discovery_id: str) -> str:
    """Convert discovery_id to operation name."""
    parts = discovery_id.split('.')
    if len(parts) >= 3:
        operation_part = parts[2]
        words = operation_part.split('_')
        operation = ''.join(word.capitalize() for word in words)
        return operation
    return discovery_id

def get_yaml_operations(service_name: str, services_dir: Path) -> Set[str]:
    """Get all operations from YAML discovery_id list."""
    service_yaml_dir = services_dir / service_name / "rules"
    yaml_file = service_yaml_dir / f"{service_name}.yaml"
    discovery_ids = extract_discovery_ids_from_yaml(yaml_file)
    operations = set()
    for disc_id in discovery_ids:
        op = discovery_id_to_operation(disc_id)
        operations.add(op)
    return operations

def find_minimal_operations(all_fields: Dict[str, Dict], dependency_index: Dict, root_operations: List[str]) -> Dict:
    """Find minimal set of operations to cover all fields, preferring root operations."""
    field_to_entities = {}
    for field_name, field_data in all_fields.items():
        entities = set()
        if field_data.get("dependency_index_entity"):
            entities.add(field_data["dependency_index_entity"])
        entities.update(field_data.get("produces", []))
        field_to_entities[field_name] = entities
    
    all_entities_needed = set()
    for entities in field_to_entities.values():
        all_entities_needed.update(entities)
    
    entity_to_ops = get_entity_to_operations_mapping(dependency_index)
    root_ops_set = set(root_operations)
    
    operation_coverage = {}
    for op in set().union(*[ops for ops in entity_to_ops.values()]):
        entities_produced = get_operation_entities(op, dependency_index)
        dependencies = get_operation_dependencies(op, dependency_index)
        is_root = op in root_ops_set
        operation_coverage[op] = {
            "entities_produced": entities_produced,
            "dependencies": dependencies,
            "is_root": is_root,
            "coverage_count": len(entities_produced & all_entities_needed)
        }
    
    selected_operations = []
    covered_entities = set()
    remaining_entities = all_entities_needed.copy()
    
    root_ops_available = [op for op, info in operation_coverage.items() if info["is_root"]]
    root_ops_available.sort(key=lambda op: operation_coverage[op]["coverage_count"], reverse=True)
    
    for op in root_ops_available:
        entities = operation_coverage[op]["entities_produced"]
        new_entities = entities & remaining_entities
        if new_entities:
            selected_operations.append({
                "operation": op,
                "type": "INDEPENDENT",
                "entities_covered": sorted(new_entities),
                "dependencies": sorted(operation_coverage[op]["dependencies"])
            })
            covered_entities.update(new_entities)
            remaining_entities -= new_entities
    
    dependent_ops_available = [op for op, info in operation_coverage.items() if not info["is_root"]]
    dependent_ops_available.sort(key=lambda op: operation_coverage[op]["coverage_count"], reverse=True)
    
    available_entities = covered_entities.copy()
    
    while remaining_entities:
        best_op = None
        best_new_entities = set()
        for op in dependent_ops_available:
            if op in [s["operation"] for s in selected_operations]:
                continue
            entities = operation_coverage[op]["entities_produced"]
            deps = operation_coverage[op]["dependencies"]
            deps_satisfied = deps.issubset(available_entities)
            new_entities = entities & remaining_entities
            if new_entities and deps_satisfied:
                if len(new_entities) > len(best_new_entities):
                    best_op = op
                    best_new_entities = new_entities
        if best_op:
            selected_operations.append({
                "operation": best_op,
                "type": "DEPENDENT",
                "entities_covered": sorted(best_new_entities),
                "dependencies": sorted(operation_coverage[best_op]["dependencies"]),
                "requires": sorted(operation_coverage[best_op]["dependencies"] & available_entities)
            })
            available_entities.update(operation_coverage[best_op]["entities_produced"])
            remaining_entities -= best_new_entities
        else:
            break
    
    return {
        "selected_operations": selected_operations,
        "total_entities_needed": len(all_entities_needed),
        "entities_covered": len(covered_entities),
        "entities_remaining": len(remaining_entities),
        "coverage_percentage": (len(covered_entities) / len(all_entities_needed) * 100) if all_entities_needed else 0
    }

def enhance_operation_with_arns(op_info: Dict, dependency_index: Dict, resource_inventory: Dict, boto3_data: Dict) -> Dict:
    """Enhance operation info with ARN details."""
    operation = op_info["operation"]
    arn_entities = get_arn_entities_from_operation(operation, dependency_index)
    arns_produced = []
    for arn_entity in arn_entities:
        resource_info = get_resource_info_for_arn(arn_entity, resource_inventory)
        field_name = get_arn_field_name_from_boto3(operation, arn_entity, boto3_data)
        arn_info = {
            "arn_entity": arn_entity,
            "field_name": field_name or "unknown",
            "is_primary_resource": resource_info.get("is_primary", False) if resource_info else False,
            "resource_type": resource_info.get("resource_type") if resource_info else None,
            "classification": resource_info.get("classification") if resource_info else None,
            "should_inventory": resource_info.get("should_inventory", False) if resource_info else False
        }
        arns_produced.append(arn_info)
    
    enhanced = op_info.copy()
    enhanced["arns_produced"] = arns_produced
    enhanced["arn_count"] = len(arns_produced)
    enhanced["primary_arn_count"] = sum(1 for a in arns_produced if a["is_primary_resource"])
    return enhanced

def prioritize_operations_for_arn(arn_entity: str, operations_producing_arn: List[Dict], root_operations: List[str], yaml_operations: Set[str]) -> Optional[Dict]:
    """Select the best operation for an ARN based on priority."""
    if not operations_producing_arn:
        return None
    
    independent_ops = []
    yaml_ops = []
    other_ops = []
    
    for op_info in operations_producing_arn:
        operation = op_info["operation"]
        op_data = {
            "operation": operation,
            "field_name": op_info.get("field_name", "unknown"),
            "is_primary": op_info.get("is_primary_resource", False)
        }
        if operation in root_operations:
            independent_ops.append(op_data)
        elif operation in yaml_operations:
            yaml_ops.append(op_data)
        else:
            other_ops.append(op_data)
    
    if independent_ops:
        primary_ops = [op for op in independent_ops if op["is_primary"]]
        if primary_ops:
            return primary_ops[0]
        return independent_ops[0]
    
    if yaml_ops:
        primary_ops = [op for op in yaml_ops if op["is_primary"]]
        if primary_ops:
            return primary_ops[0]
        return yaml_ops[0]
    
    if other_ops:
        primary_ops = [op for op in other_ops if op["is_primary"]]
        if primary_ops:
            return primary_ops[0]
        return other_ops[0]
    
    return None

def deduplicate_arns_in_operations(minimal_ops_data: Dict, root_operations: List[str], yaml_operations: Set[str]) -> Dict:
    """Deduplicate ARNs and select best operation for each ARN."""
    arn_to_operations = defaultdict(list)
    
    for op_info in minimal_ops_data.get("minimal_operations", {}).get("selected_operations", []):
        operation = op_info["operation"]
        arns_produced = op_info.get("arns_produced", [])
        for arn_info in arns_produced:
            arn_entity = arn_info["arn_entity"]
            arn_to_operations[arn_entity].append({
                "operation": operation,
                "field_name": arn_info.get("field_name", "unknown"),
                "is_primary_resource": arn_info.get("is_primary_resource", False),
                "resource_type": arn_info.get("resource_type"),
                "classification": arn_info.get("classification"),
                "should_inventory": arn_info.get("should_inventory", False)
            })
    
    arn_selections = {}
    for arn_entity, operations in arn_to_operations.items():
        selected = prioritize_operations_for_arn(arn_entity, operations, root_operations, yaml_operations)
        if selected:
            arn_selections[arn_entity] = selected
    
    operation_arns_map = defaultdict(list)
    for arn_entity, selected_op in arn_selections.items():
        # Get full info from original operations
        for op_info in minimal_ops_data.get("minimal_operations", {}).get("selected_operations", []):
            for arn_info in op_info.get("arns_produced", []):
                if arn_info["arn_entity"] == arn_entity and op_info["operation"] == selected_op["operation"]:
                    operation_arns_map[selected_op["operation"]].append({
                        "arn_entity": arn_entity,
                        "field_name": selected_op["field_name"],
                        "is_primary_resource": arn_info.get("is_primary_resource", False),
                        "resource_type": arn_info.get("resource_type"),
                        "classification": arn_info.get("classification"),
                        "should_inventory": arn_info.get("should_inventory", False),
                        "selected_reason": "INDEPENDENT" if selected_op["operation"] in root_operations else 
                                          "YAML_DISCOVERY" if selected_op["operation"] in yaml_operations else 
                                          "OTHER"
                    })
                    break
    
    updated_operations = []
    for op_info in minimal_ops_data.get("minimal_operations", {}).get("selected_operations", []):
        operation = op_info["operation"]
        updated_op = op_info.copy()
        selected_arns = operation_arns_map.get(operation, [])
        updated_op["arns_produced"] = selected_arns
        updated_op["arn_count"] = len(selected_arns)
        updated_op["primary_arn_count"] = sum(1 for a in selected_arns if a["is_primary_resource"])
        
        if operation in root_operations:
            updated_op["priority"] = "INDEPENDENT"
        elif operation in yaml_operations:
            updated_op["priority"] = "YAML_DISCOVERY"
        else:
            updated_op["priority"] = "OTHER"
        
        # Add dependencies logic
        dependencies = updated_op.get("dependencies", [])
        if dependencies:
            updated_op["dependencies_logic"] = "AND"
            updated_op["dependencies_required"] = "ALL"
            updated_op["dependencies_count"] = len(dependencies)
            updated_op["dependencies_note"] = f"All {len(dependencies)} dependencies are required (AND logic)" if len(dependencies) > 1 else "This dependency is required"
        else:
            updated_op["dependencies_logic"] = "NONE"
            updated_op["dependencies_required"] = "NONE"
            updated_op["dependencies_count"] = 0
            updated_op["dependencies_note"] = "No dependencies - can be called independently"
        
        updated_operations.append(updated_op)
    
    total_unique_arns = len(arn_selections)
    primary_arns = sum(1 for a in arn_selections.values() if any(
        op.get("is_primary_resource") for op in arn_to_operations.get(list(arn_selections.keys())[list(arn_selections.values()).index(a)], [])
    ))
    
    deduplication_report = {}
    for arn_entity, operations in arn_to_operations.items():
        selected = arn_selections.get(arn_entity)
        if selected:
            deduplication_report[arn_entity] = {
                "selected_operation": selected["operation"],
                "selected_field_name": selected["field_name"],
                "priority": "INDEPENDENT" if selected["operation"] in root_operations else 
                           "YAML_DISCOVERY" if selected["operation"] in yaml_operations else 
                           "OTHER",
                "all_available_operations": [op["operation"] for op in operations],
                "operation_count": len(operations)
            }
    
    minimal_ops_data["minimal_operations"]["selected_operations"] = updated_operations
    
    # Initialize arn_summary if it doesn't exist
    if "arn_summary" not in minimal_ops_data:
        minimal_ops_data["arn_summary"] = {}
    
    minimal_ops_data["arn_summary"]["total_unique_arns"] = total_unique_arns
    minimal_ops_data["arn_summary"]["deduplicated"] = True
    minimal_ops_data["arn_deduplication"] = deduplication_report
    
    return minimal_ops_data

def generate_minimal_operations_for_service(service_name: str, service_dir: Path, services_dir: Path) -> Optional[Dict]:
    """Generate complete minimal_operations_list.json for a service."""
    
    direct_vars_file = service_dir / "direct_vars.json"
    dependency_index_file = service_dir / "dependency_index.json"
    resource_inventory_file = service_dir / "resource_inventory_report.json"
    boto3_file = service_dir / "boto3_dependencies_with_python_names_fully_enriched.json"
    
    # Check required files
    if not direct_vars_file.exists() or not dependency_index_file.exists():
        return None
    
    try:
        with open(direct_vars_file, 'r') as f:
            direct_vars = json.load(f)
        
        with open(dependency_index_file, 'r') as f:
            dependency_index = json.load(f)
        
        resource_inventory = {}
        if resource_inventory_file.exists():
            with open(resource_inventory_file, 'r') as f:
                resource_inventory = json.load(f)
        
        boto3_data = {}
        if boto3_file.exists():
            with open(boto3_file, 'r') as f:
                boto3_data = json.load(f)
    except Exception as e:
        return {"error": str(e)}
    
    # Get all fields
    all_fields = get_all_fields_from_direct_vars(direct_vars_file)
    
    # Get root operations
    roots = dependency_index.get("roots", [])
    root_operations = [r.get("op") for r in roots]
    
    # Get YAML operations
    yaml_operations = get_yaml_operations(service_name, services_dir)
    
    # Find minimal operations
    minimal_ops = find_minimal_operations(all_fields, dependency_index, root_operations)
    
    # Enhance with ARNs
    enhanced_operations = []
    for op_info in minimal_ops["selected_operations"]:
        enhanced = enhance_operation_with_arns(op_info, dependency_index, resource_inventory, boto3_data)
        enhanced_operations.append(enhanced)
    
    minimal_ops["selected_operations"] = enhanced_operations
    
    # Build report structure
    report = {
        "service": service_name,
        "generated_at": datetime.now().isoformat(),
        "total_fields": len(all_fields),
        "root_operations_available": root_operations,
        "yaml_discovery_operations": sorted(list(yaml_operations)),
        "minimal_operations": minimal_ops
    }
    
    # Deduplicate ARNs
    report = deduplicate_arns_in_operations(report, root_operations, yaml_operations)
    
    # Add summary
    total_arns = sum(op["arn_count"] for op in report["minimal_operations"]["selected_operations"])
    total_primary_arns = sum(op["primary_arn_count"] for op in report["minimal_operations"]["selected_operations"])
    
    report["arn_summary"] = {
        "total_arns_produced": total_arns,
        "primary_resource_arns": total_primary_arns,
        "other_arns": total_arns - total_primary_arns,
        "total_unique_arns": report["arn_summary"].get("total_unique_arns", 0),
        "deduplicated": True
    }
    
    report["summary"] = {
        "total_operations_needed": len(report["minimal_operations"]["selected_operations"]),
        "independent_operations": sum(1 for op in report["minimal_operations"]["selected_operations"] if op["type"] == "INDEPENDENT"),
        "dependent_operations": sum(1 for op in report["minimal_operations"]["selected_operations"] if op["type"] == "DEPENDENT"),
        "coverage_percentage": report["minimal_operations"]["coverage_percentage"]
    }
    
    return report

def process_all_services(aws_dir: str, services_dir: str):
    """Process all services to generate minimal_operations_list.json."""
    
    aws_path = Path(aws_dir)
    services_path = Path(services_dir)
    
    # Get all service directories
    service_dirs = [d for d in aws_path.iterdir() if d.is_dir() and not d.name.startswith('.')]
    service_dirs.sort()
    
    print("=" * 80)
    print("GENERATING MINIMAL OPERATIONS LIST FOR ALL SERVICES")
    print("=" * 80)
    print(f"\nFound {len(service_dirs)} service directories")
    print("")
    
    successful = 0
    failed = 0
    skipped = 0
    
    for service_dir in service_dirs:
        service_name = service_dir.name
        
        # Check if required files exist
        if not (service_dir / "direct_vars.json").exists() or not (service_dir / "dependency_index.json").exists():
            skipped += 1
            continue
        
        print(f"{'='*80}")
        print(f"Processing: {service_name.upper()}")
        print(f"{'='*80}")
        
        report = generate_minimal_operations_for_service(service_name, service_dir, services_path)
        
        if not report:
            print(f"  ⚠️  Skipped (missing required files)")
            skipped += 1
            continue
        
        if "error" in report:
            print(f"  ❌ Error: {report['error']}")
            failed += 1
            continue
        
        # Save file
        output_file = service_dir / "minimal_operations_list.json"
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"  ✅ Generated successfully")
        print(f"    Total Fields: {report['total_fields']}")
        print(f"    Operations Needed: {report['summary']['total_operations_needed']}")
        print(f"    Independent: {report['summary']['independent_operations']}")
        print(f"    Dependent: {report['summary']['dependent_operations']}")
        print(f"    Coverage: {report['summary']['coverage_percentage']:.1f}%")
        print(f"    Unique ARNs: {report['arn_summary']['total_unique_arns']}")
        print(f"    Primary ARNs: {report['arn_summary']['primary_resource_arns']}")
        print(f"    Saved to: {output_file}")
        
        successful += 1
    
    print(f"\n\n{'='*80}")
    print("GENERATION COMPLETE")
    print(f"{'='*80}")
    print(f"\nSummary:")
    print(f"  ✅ Successful: {successful}")
    print(f"  ❌ Failed: {failed}")
    print(f"  ⚠️  Skipped: {skipped}")
    print(f"  📁 Total Services: {len(service_dirs)}")

if __name__ == "__main__":
    aws_dir = "/Users/apple/Desktop/threat-engine/pythonsdk-database/aws"
    services_dir = "/Users/apple/Desktop/threat-engine/configScan_engines/aws-configScan-engine/services"
    
    process_all_services(aws_dir, services_dir)

