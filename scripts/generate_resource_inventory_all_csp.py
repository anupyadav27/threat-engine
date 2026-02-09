#!/usr/bin/env python3
"""
Generate resource_inventory_report.json for ALL CSPs.

AWS already has these files from pythonsdk-database.
For non-AWS CSPs, we derive resource classification from:
  - Azure: operations_by_category — category name IS the resource type
  - GCP: resources.{resource}.independent/dependent in dependency file
  - K8s: Each service IS a resource (deployment, pod, service, etc.)
  - IBM: independent/dependent operations grouped by inferred resource name
  - OCI/Alicloud: flat operations[] list analysis

Classification Rules:
  PRIMARY_RESOURCE:
    - Has independent List/Get/Describe operations (not requiring other resource IDs)
    - Has unique identifier fields (selfLink, id, name, arn)
    - Is a concrete cloud resource (VM, disk, network, etc.)
  SUB_RESOURCE:
    - Dependent operation that returns child/config of a primary resource
    - Requires parent resource ID as param
    - Access controls, attachments, extensions
  CONFIGURATION:
    - Get/Describe operations returning settings, policies, configurations
    - Catalog data (types, sizes, shapes, SKUs, families)
    - No unique resource identifier
  EPHEMERAL:
    - Temporary/transient data (logs, events, metrics, status checks)
    - Job/task outputs, operations, request results

Also generates enhancement_indexes (resource_id_mapping) per CSP.

Output: Writes JSON files locally and optionally uploads to DB.
"""

import os
import sys
import json
import re
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Set

# ─── Configuration ───────────────────────────────────────────────────────────
DATA_ROOT = Path("/Users/apple/Desktop/threat-engine/engine_input/engine_check_aws/data_pythonsdk")
OUTPUT_ROOT = Path("/Users/apple/.claude-worktrees/threat-engine/nervous-burnell/scripts/generated_pythonsdk")

CSP_CONFIGS = {
    "aws": {
        "dep_file": "boto3_dependencies_with_python_names_fully_enriched.json",
        "id_field_patterns": ["Arn", "ARN", "arn"],
        "skip": True,  # AWS already has resource_inventory_report.json
    },
    "azure": {
        "dep_file": "azure_dependencies_with_python_names_fully_enriched.json",
        "id_field_patterns": ["id", "resourceId", "name", "self"],
    },
    "gcp": {
        "dep_file": "gcp_dependencies_with_python_names_fully_enriched.json",
        "id_field_patterns": ["selfLink", "id", "name", "self"],
    },
    "alicloud": {
        "dep_file": "alicloud_dependencies_with_python_names_fully_enriched.json",
        "id_field_patterns": ["InstanceId", "Id", "ResourceId", "Name"],
    },
    "oci": {
        "dep_file": "oci_dependencies_with_python_names_fully_enriched.json",
        "id_field_patterns": ["id", "compartmentId", "displayName", "lifecycleState"],
    },
    "ibm": {
        "dep_file": "ibm_dependencies_with_python_names_fully_enriched.json",
        "id_field_patterns": ["id", "crn", "href", "name"],
    },
    "k8s": {
        "dep_file": "k8s_dependencies_with_python_names_fully_enriched.json",
        "id_field_patterns": ["uid", "name", "selfLink", "namespace"],
    },
}

# ─── Classification Patterns ────────────────────────────────────────────────
# Word-boundary aware patterns using (?:^|_|[a-z])(?=[A-Z]) for CamelCase

# Ephemeral: transient data, operations, jobs
EPHEMERAL_PATTERNS = re.compile(
    r'(?:^|[_.])'
    r'(log|event|metric|audit|alert|notification|job|task|'
    r'diagnostic|activity|usage|billing|cost|recommendation|'
    r'advisory|insight|finding|assessment|review|'
    r'history|archive|operation|update_domain|rolling_upgrade|'
    r'loganalytics|run_command|console_history)'
    r'(?:s|es)?(?:[_.]|$)',
    re.IGNORECASE
)

# Configuration: settings, policies, catalog data
CONFIG_PATTERNS = re.compile(
    r'(?:^|[_.])'
    r'(config|configuration|setting|policy|rule|acl|'
    r'access_control|option|preference|parameter|template|profile|'
    r'schema|definition|specification|plan|pricing|tier|sku|tag|'
    r'type|size|shape|family|capability|feature|delegation|'
    r'sharing_profile|resource_sku|machine_type|disk_type|'
    r'accelerator_type|zone|region|location|os_version|os_family|'
    r'bandwidth_shape|device_shape|publisher|offer|'
    r'compatibility_entry|notification|softdeletedresource)'
    r'(?:s|es)?(?:[_.]|$)',
    re.IGNORECASE
)

# Sub-resources: things attached to parent resources
SUB_PATTERNS = re.compile(
    r'(?:^|[_.])'
    r'(attachment|extension|vnic_attachment|boot_volume_attachment|'
    r'console_connection|db_home|db_node|data_guard_association|'
    r'plugin|addon|component|member|binding|association|'
    r'access_control|bucket_access_control|object_access_control|'
    r'default_object_access_control|disk_restore_point|'
    r'scale_set_vm|vm_extension|role_instance|'
    r'gallery_image_version|gallery_application_version|'
    r'restore_point|shared_gallery_image|'
    r'invm_access_control_profile|'
    r'community_gallery_image)'
    r'(?:s|es)?(?:[_.]|$)',
    re.IGNORECASE
)

# Primary resources: concrete cloud resources
PRIMARY_PATTERNS = re.compile(
    r'(?:^|[_.])'
    r'(instance|vm|virtual_machine|server|cluster|node|pool|group|'
    r'bucket|blob|container|volume|disk|database|db|table|queue|topic|'
    r'function|lambda|app|gateway|loadbalancer|load_balancer|'
    r'network|vpc|vnet|subnet|firewall|security_group|route_table|security_list|'
    r'user|role|identity|key|secret|certificate|vault|'
    r'registry|repository|image|workspace|project|account|subscription|'
    r'domain|zone_(?!type)|record|endpoint|api|pipeline|workflow|'
    r'address|forwarding_rule|target_pool|health_check|backend_service|'
    r'interconnect|peering|drg|vcn|nat_gateway|internet_gateway|'
    r'bare_metal|compartment|snapshot|backup|'
    r'availability_set|dedicated_host|gallery|ssh_public_key|'
    r'disk_access|disk_encryption_set|proximity_placement|'
    r'capacity_reservation|cloud_service|restore_point_collection|'
    r'virtual_machine_scale_set|virtual_machine_image|'
    r'application_gateway|application_security|'
    r'private_endpoint|public_ip|network_interface|'
    r'network_security|virtual_network|express_route|'
    r'load_balancer|traffic_manager|dns|front_door|'
    r'backup_policy|block_storage|boot_volume|cross_connect|'
    r'dhcp|drg_attachment|local_peering|service_gateway|'
    r'anywhere_cache)'
    r'(?:s|es)?(?:[_.]|$)',
    re.IGNORECASE
)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def load_json(path: Path) -> Optional[Dict]:
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None


def list_service_dirs(csp_dir: Path) -> List[Path]:
    if not csp_dir.exists():
        return []
    return sorted([
        e for e in csp_dir.iterdir()
        if e.is_dir() and not e.name.startswith(".") and e.name != "backup" and e.name != "__pycache__"
    ])


def has_id_field(item_fields: Dict, id_patterns: List[str]) -> bool:
    """Check if item_fields contain a resource identifier field."""
    if not item_fields:
        return False
    field_names = set(item_fields.keys())
    for pattern in id_patterns:
        if pattern in field_names:
            return True
        for fn in field_names:
            if fn.lower() == pattern.lower():
                return True
    return False


def classify_resource_type(resource_name: str, ops: List[Dict], id_patterns: List[str],
                           csp_id: str = "", has_independent_ops: bool = None,
                           only_dependent: bool = False) -> str:
    """Classify a resource type based on its name and operations."""
    name_lower = resource_name.lower()

    # 1. Ephemeral first (transient data)
    if EPHEMERAL_PATTERNS.search(name_lower):
        return "EPHEMERAL"

    # 2. Sub-resource patterns (attached to parent)
    if SUB_PATTERNS.search(name_lower):
        return "SUB_RESOURCE"

    # 3. Config patterns (settings, catalog, metadata)
    if CONFIG_PATTERNS.search(name_lower):
        return "CONFIGURATION"

    # 4. Primary resource patterns
    if PRIMARY_PATTERNS.search(name_lower):
        return "PRIMARY_RESOURCE"

    # 5. If only dependent ops (no independent list/get) → SUB_RESOURCE
    if only_dependent:
        return "SUB_RESOURCE"

    # 6. Heuristic: check operations for independent list/get with ID fields
    _has_indep = has_independent_ops
    has_id = False
    if _has_indep is None:
        _has_indep = False
        for op in ops:
            op_name = (op.get("operation") or "").lower()
            is_indep = not op.get("required_params") or len(op.get("required_params", [])) == 0
            if is_indep and ("list" in op_name or "get_all" in op_name or "describe" in op_name):
                _has_indep = True
            if has_id_field(op.get("item_fields", {}), id_patterns):
                has_id = True
    else:
        for op in ops:
            if has_id_field(op.get("item_fields", {}), id_patterns):
                has_id = True
                break

    if _has_indep and has_id:
        return "PRIMARY_RESOURCE"
    elif _has_indep:
        return "SUB_RESOURCE"
    elif has_id:
        return "CONFIGURATION"

    return "SUB_RESOURCE"


def should_inventory(classification: str) -> bool:
    return classification == "PRIMARY_RESOURCE"


def use_for_enrichment(classification: str) -> bool:
    return classification in ("CONFIGURATION", "SUB_RESOURCE")


def _make_resource_entry(resource_type: str, classification: str,
                         has_id: bool, id_entity: Optional[str],
                         indep_ops: List[Dict], dep_ops: List[Dict],
                         **extra) -> Dict:
    """Build a standard resource entry dict."""
    root_op_names = [o.get("operation", "") for o in indep_ops]
    dep_op_names = [o.get("operation", "") for o in dep_ops]
    entry = {
        "resource_type": resource_type,
        "classification": classification,
        "should_inventory": should_inventory(classification),
        "use_for_enrichment": use_for_enrichment(classification),
        "has_arn": has_id,
        "arn_entity": id_entity,
        "can_get_from_root_ops": len(indep_ops) > 0,
        "requires_dependent_ops": len(dep_ops) > 0 and len(indep_ops) == 0,
        "root_operations": root_op_names,
        "dependent_operations": dep_op_names,
        "all_operations": root_op_names + dep_op_names,
    }
    entry.update(extra)
    return entry


# ─── Azure Resource Extraction (operations_by_category) ─────────────────────

def extract_azure_category_resources(service_data: Dict, id_patterns: List[str]) -> List[Dict]:
    """Azure: resources are named by operations_by_category keys.

    Azure SDK groups operations by resource category (e.g., 'virtualmachines',
    'disks', 'availabilitysets'). Each category has independent/dependent lists.
    The category name IS the resource type.
    """
    categories = service_data.get("operations_by_category", {})
    if not isinstance(categories, dict):
        return []

    results = []
    for category_name, cat_data in categories.items():
        if not isinstance(cat_data, dict):
            continue
        if not category_name.strip():
            continue

        indep = cat_data.get("independent", [])
        dep = cat_data.get("dependent", [])
        all_ops = indep + dep
        if not all_ops:
            continue

        # Check for identifier fields
        has_id = False
        for op in all_ops:
            if has_id_field(op.get("item_fields", {}), id_patterns):
                has_id = True
                break

        only_dep = len(indep) == 0 and len(dep) > 0
        classification = classify_resource_type(
            category_name, all_ops, id_patterns,
            csp_id="azure", has_independent_ops=len(indep) > 0,
            only_dependent=only_dep
        )

        results.append(_make_resource_entry(
            resource_type=category_name,
            classification=classification,
            has_id=has_id,
            id_entity="id" if has_id else None,
            indep_ops=indep,
            dep_ops=dep,
        ))

    return results


# ─── K8s Resource Extraction ────────────────────────────────────────────────

def extract_k8s_resources(service_data: Dict, service_name: str, id_patterns: List[str]) -> List[Dict]:
    """K8s: Each service IS a resource type (deployment, pod, service, etc.).

    K8s dependency files have:
      { "deployment": { "resource": "deployment", "kind": "Deployment",
        "independent": [{"operation": "list"}, {"operation": "get"}],
        "dependent": [{"operation": "create"}, ...] } }

    The service/resource name IS the resource type.
    """
    resource_name = service_data.get("resource", service_name)
    kind = service_data.get("kind", resource_name.capitalize())
    indep = service_data.get("independent", [])
    dep = service_data.get("dependent", [])
    all_ops = indep + dep
    if not all_ops:
        return []

    # Check for identifier fields
    has_id = False
    for op in all_ops:
        item_fields = op.get("item_fields", {})
        if item_fields:
            for fn in item_fields:
                if "metadata" in fn or "uid" in fn.lower() or "name" in fn.lower():
                    has_id = True
                    break
            if has_id_field(item_fields, id_patterns):
                has_id = True
        if has_id:
            break

    # K8s resources with list/get are PRIMARY
    has_list_or_get = any(
        op.get("operation", "").lower() in ("list", "get", "watch")
        for op in indep
    )
    classification = "PRIMARY_RESOURCE" if has_list_or_get else "SUB_RESOURCE"

    return [_make_resource_entry(
        resource_type=resource_name,
        classification=classification,
        has_id=has_id,
        id_entity="metadata.uid" if has_id else None,
        indep_ops=indep,
        dep_ops=dep,
        k8s_kind=kind,
        k8s_api_version=service_data.get("api_version", ""),
    )]


# ─── GCP Resource Extraction ────────────────────────────────────────────────

def extract_gcp_resources(service_data: Dict, id_patterns: List[str]) -> List[Dict]:
    """GCP: resources are explicitly named under resources.{name}."""
    resources_data = service_data.get("resources", {})
    if not isinstance(resources_data, dict):
        return []

    results = []
    for resource_name, resource_ops in resources_data.items():
        if not isinstance(resource_ops, dict):
            continue

        indep = resource_ops.get("independent", [])
        dep = resource_ops.get("dependent", [])
        all_ops = indep + dep

        # Check for selfLink (GCP's resource identifier)
        has_self_link = False
        for op in all_ops:
            if "selfLink" in str(op.get("item_fields", {})):
                has_self_link = True
                break

        only_dep = len(indep) == 0 and len(dep) > 0
        classification = classify_resource_type(
            resource_name, all_ops, id_patterns,
            csp_id="gcp", has_independent_ops=len(indep) > 0,
            only_dependent=only_dep
        )

        # If has selfLink and independent ops and not already classified as non-PRIMARY
        if has_self_link and indep and classification == "SUB_RESOURCE":
            classification = "PRIMARY_RESOURCE"

        results.append(_make_resource_entry(
            resource_type=resource_name,
            classification=classification,
            has_id=has_self_link,
            id_entity="selfLink" if has_self_link else None,
            indep_ops=indep,
            dep_ops=dep,
        ))

    return results


# ─── IBM/Generic Flat Resource Extraction ────────────────────────────────────

def extract_flat_resources(service_data: Dict, id_patterns: List[str], csp_id: str) -> List[Dict]:
    """Extract resources from flat independent/dependent operation lists (IBM, etc)."""
    indep = service_data.get("independent", [])
    dep = service_data.get("dependent", [])

    # Group operations by inferred resource type
    resource_groups = {}
    for op in indep + dep:
        op_name = op.get("operation", "")
        if not op_name:
            continue
        resource_type = _infer_resource_type(op_name, csp_id)
        if resource_type not in resource_groups:
            resource_groups[resource_type] = {"independent": [], "dependent": []}
        is_indep = op in indep
        resource_groups[resource_type]["independent" if is_indep else "dependent"].append(op)

    results = []
    for resource_type, ops_dict in resource_groups.items():
        all_ops = ops_dict["independent"] + ops_dict["dependent"]
        has_id = any(has_id_field(op.get("item_fields", {}), id_patterns) for op in all_ops)
        only_dep = len(ops_dict["independent"]) == 0 and len(ops_dict["dependent"]) > 0

        classification = classify_resource_type(
            resource_type, all_ops, id_patterns,
            csp_id=csp_id, has_independent_ops=len(ops_dict["independent"]) > 0,
            only_dependent=only_dep
        )

        results.append(_make_resource_entry(
            resource_type=resource_type,
            classification=classification,
            has_id=has_id,
            id_entity=None,
            indep_ops=ops_dict["independent"],
            dep_ops=ops_dict["dependent"],
        ))

    return results


# ─── OCI/Alicloud Resource Extraction ───────────────────────────────────────

def extract_ops_list_resources(service_data: Dict, id_patterns: List[str], csp_id: str) -> List[Dict]:
    """Extract resources from flat operations[] list (OCI, Alicloud)."""
    ops_list = service_data.get("operations", [])
    if not isinstance(ops_list, list):
        return []

    # Group by inferred resource type
    resource_groups = {}
    for op in ops_list:
        op_name = op.get("operation", "")
        if not op_name:
            continue
        resource_type = _infer_resource_type(op_name, csp_id)
        if resource_type not in resource_groups:
            resource_groups[resource_type] = []
        resource_groups[resource_type].append(op)

    results = []
    for resource_type, ops in resource_groups.items():
        has_id = any(has_id_field(op.get("item_fields", {}), id_patterns) for op in ops)
        root_ops_list = [o for o in ops if not o.get("required_params")]
        dep_ops_list = [o for o in ops if o.get("required_params")]
        only_dep = len(root_ops_list) == 0 and len(dep_ops_list) > 0

        has_list = any(
            "list" in (op.get("operation") or "").lower() or
            "get_all" in (op.get("operation") or "").lower()
            for op in root_ops_list
        )

        classification = classify_resource_type(
            resource_type, ops, id_patterns,
            csp_id=csp_id, has_independent_ops=has_list,
            only_dependent=only_dep
        )

        results.append(_make_resource_entry(
            resource_type=resource_type,
            classification=classification,
            has_id=has_id,
            id_entity=None,
            indep_ops=root_ops_list,
            dep_ops=dep_ops_list,
        ))

    return results


# ─── Operation Name → Resource Type Inference ────────────────────────────────

def _infer_resource_type(operation_name: str, csp_id: str) -> str:
    """Infer resource type from operation name."""
    name = operation_name

    # Snake_case prefixes (more specific, try first)
    snake_prefixes = [
        "get_all_", "list_all_",
        "list_", "get_", "describe_", "create_", "delete_", "update_",
        "put_", "set_", "add_", "remove_", "attach_", "detach_",
        "enable_", "disable_", "start_", "stop_", "change_",
        "terminate_", "launch_", "reboot_",
    ]

    # CamelCase prefixes
    camel_prefixes = [
        "List", "Get", "Describe", "Create", "Delete", "Update",
        "Put", "Set", "Add", "Remove", "Attach", "Detach",
        "Enable", "Disable", "Start", "Stop", "Reboot",
        "Terminate", "Launch",
    ]

    matched = False
    # Try snake_case (case-insensitive)
    name_lower = name.lower()
    for prefix in snake_prefixes:
        if name_lower.startswith(prefix):
            name = name[len(prefix):]
            matched = True
            break

    if not matched:
        # Try CamelCase
        for prefix in camel_prefixes:
            if name.startswith(prefix) and len(name) > len(prefix):
                name = name[len(prefix):]
                break

    # Remove trailing 's' for plural (ListBuckets → Bucket)
    if name.endswith("s") and not name.endswith("ss") and len(name) > 3:
        name = name[:-1]

    # CamelCase to snake_case
    s = re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()

    # Clean up
    s = re.sub(r'_+', '_', s).strip('_')

    return s or "resource"


# ─── Enhancement Index Generation ───────────────────────────────────────────

def generate_resource_id_mapping(csp_id: str, all_services_resources: Dict[str, List[Dict]]) -> Dict:
    """Generate a resource_id_mapping enhancement index for a CSP."""
    mapping = {}
    for service_name, resources in all_services_resources.items():
        svc_mapping = {}
        for res in resources:
            if res.get("should_inventory"):
                rt = res["resource_type"]
                svc_mapping[rt] = {
                    "classification": res["classification"],
                    "has_identifier": res.get("has_arn", False),
                    "root_operations": res.get("root_operations", []),
                    "operation_count": len(res.get("all_operations", [])),
                }
        if svc_mapping:
            mapping[service_name] = svc_mapping
    return mapping


# ─── Main ────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate resource_inventory for all CSPs")
    parser.add_argument("--csp", type=str, default=None, help="Process single CSP")
    parser.add_argument("--upload", action="store_true", help="Upload to DB after generating")
    args = parser.parse_args()

    os.makedirs(OUTPUT_ROOT, exist_ok=True)

    grand_summary = {}

    for csp_id, config in CSP_CONFIGS.items():
        if args.csp and csp_id != args.csp:
            continue

        if config.get("skip"):
            print(f"Skipping {csp_id} (already has resource_inventory)")
            continue

        csp_dir = DATA_ROOT / csp_id
        if not csp_dir.exists():
            print(f"Skipping {csp_id}: directory not found")
            continue

        service_dirs = list_service_dirs(csp_dir)
        print(f"\n{'='*60}")
        print(f" {csp_id.upper()} -- {len(service_dirs)} services")
        print(f"{'='*60}")

        csp_output_dir = OUTPUT_ROOT / csp_id
        os.makedirs(csp_output_dir, exist_ok=True)

        all_services_resources = {}
        total_primary = 0
        total_sub = 0
        total_config = 0
        total_ephemeral = 0
        services_with_resources = 0

        for svc_dir in service_dirs:
            service_name = svc_dir.name
            dep_file = svc_dir / config["dep_file"]
            data = load_json(dep_file)
            if not data:
                continue

            # Get service data
            service_data = data.get(service_name) or data.get(list(data.keys())[0]) if data else None
            if not service_data:
                continue

            id_patterns = config["id_field_patterns"]

            # Extract resources based on CSP structure
            if csp_id == "azure" and "operations_by_category" in service_data:
                resources = extract_azure_category_resources(service_data, id_patterns)
            elif csp_id == "k8s":
                resources = extract_k8s_resources(service_data, service_name, id_patterns)
            elif csp_id == "gcp" or ("resources" in service_data and isinstance(service_data.get("resources"), dict)):
                resources = extract_gcp_resources(service_data, id_patterns)
            elif "operations" in service_data and isinstance(service_data.get("operations"), list):
                resources = extract_ops_list_resources(service_data, id_patterns, csp_id)
            else:
                resources = extract_flat_resources(service_data, id_patterns, csp_id)

            if not resources:
                continue

            services_with_resources += 1
            all_services_resources[service_name] = resources

            # Count classifications
            for r in resources:
                c = r["classification"]
                if c == "PRIMARY_RESOURCE":
                    total_primary += 1
                elif c == "SUB_RESOURCE":
                    total_sub += 1
                elif c == "CONFIGURATION":
                    total_config += 1
                elif c == "EPHEMERAL":
                    total_ephemeral += 1

            # Save per-service resource_inventory_report.json
            report = {
                "service": service_name,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "root_operations": list({
                    op for r in resources
                    for op in r.get("root_operations", [])
                }),
                "resources": resources,
            }

            svc_output_dir = csp_output_dir / service_name
            os.makedirs(svc_output_dir, exist_ok=True)
            output_path = svc_output_dir / "resource_inventory_report.json"
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)

        # Generate enhancement_index (resource_id_mapping)
        resource_id_mapping = generate_resource_id_mapping(csp_id, all_services_resources)
        enhancement_path = csp_output_dir / "resource_id_mapping.json"
        with open(enhancement_path, "w") as f:
            json.dump({
                "csp": csp_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_services": len(resource_id_mapping),
                "mapping": resource_id_mapping,
            }, f, indent=2)

        total_resources = total_primary + total_sub + total_config + total_ephemeral
        csp_summary = {
            "services_total": len(service_dirs),
            "services_with_resources": services_with_resources,
            "total_resources": total_resources,
            "primary_resources": total_primary,
            "sub_resources": total_sub,
            "configuration": total_config,
            "ephemeral": total_ephemeral,
            "enhancement_index_services": len(resource_id_mapping),
        }
        grand_summary[csp_id] = csp_summary

        print(f"  Services analyzed: {services_with_resources}/{len(service_dirs)}")
        print(f"  Resource types:    {total_resources}")
        print(f"    PRIMARY:         {total_primary}")
        print(f"    SUB_RESOURCE:    {total_sub}")
        print(f"    CONFIGURATION:   {total_config}")
        print(f"    EPHEMERAL:       {total_ephemeral}")
        print(f"  Enhancement index: {len(resource_id_mapping)} services with inventoriable resources")
        print(f"  Output: {csp_output_dir}")

    # Save grand summary
    summary_path = OUTPUT_ROOT / "generation_summary.json"
    with open(summary_path, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "csps": grand_summary,
        }, f, indent=2)
    print(f"\nSummary saved to: {summary_path}")

    # Print grand summary
    print(f"\n{'='*60}")
    print(f" GRAND SUMMARY")
    print(f"{'='*60}")
    print(f"{'CSP':<12} {'Services':>8} {'Resources':>10} {'PRIMARY':>8} {'SUB':>6} {'CONFIG':>7} {'EPHEM':>6}")
    print(f"{'-'*60}")
    for csp_id, s in grand_summary.items():
        print(f"{csp_id:<12} {s['services_with_resources']:>8} {s['total_resources']:>10} "
              f"{s['primary_resources']:>8} {s['sub_resources']:>6} {s['configuration']:>7} {s['ephemeral']:>6}")

    # Upload to DB if requested
    if args.upload:
        upload_to_db(grand_summary)


def upload_to_db(grand_summary: Dict):
    """Upload generated resource_inventory and enhancement_indexes to DB."""
    import psycopg2
    from psycopg2.extras import Json

    DB_HOST = "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"
    conn = psycopg2.connect(
        host=DB_HOST, port="5432", dbname="threat_engine_pythonsdk",
        user="postgres", password="jtv2BkJF8qoFtAKP",
    )
    print("\nUploading to DB...")

    for csp_id in grand_summary:
        csp_output_dir = OUTPUT_ROOT / csp_id
        if not csp_output_dir.exists():
            continue

        # Upload resource_inventory per service
        ri_count = 0
        for svc_dir in sorted(csp_output_dir.iterdir()):
            if not svc_dir.is_dir():
                continue
            report_path = svc_dir / "resource_inventory_report.json"
            if not report_path.exists():
                continue

            data = load_json(report_path)
            if not data:
                continue

            service_id = f"{csp_id}.{svc_dir.name}"
            resources = data.get("resources", [])

            cur = conn.cursor()
            try:
                cur.execute("""
                    INSERT INTO resource_inventory (
                        service_id, inventory_data, total_resource_types,
                        total_operations, discovery_operations, version, generated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (service_id) DO UPDATE SET
                        inventory_data = EXCLUDED.inventory_data,
                        total_resource_types = EXCLUDED.total_resource_types,
                        total_operations = EXCLUDED.total_operations,
                        discovery_operations = EXCLUDED.discovery_operations,
                        updated_at = now()
                """, (
                    service_id,
                    Json(data),
                    len(resources),
                    len({op for r in resources for op in r.get("all_operations", [])}),
                    len({op for r in resources for op in r.get("root_operations", [])}),
                    "1.0",
                    data.get("generated_at"),
                ))
                conn.commit()
                ri_count += 1
            except Exception as e:
                conn.rollback()
                print(f"  ERROR resource_inventory {service_id}: {e}")
            finally:
                cur.close()

        # Upload enhancement_index
        ei_path = csp_output_dir / "resource_id_mapping.json"
        ei_data = load_json(ei_path)
        if ei_data:
            cur = conn.cursor()
            try:
                cur.execute("""
                    INSERT INTO enhancement_indexes (
                        index_type, csp_id, index_data, version, total_entries, generated_at
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (index_type, csp_id) DO UPDATE SET
                        index_data = EXCLUDED.index_data,
                        total_entries = EXCLUDED.total_entries,
                        updated_at = now()
                """, (
                    "resource_id_mapping",
                    csp_id,
                    Json(ei_data.get("mapping", {})),
                    "1.0",
                    ei_data.get("total_services", 0),
                    ei_data.get("generated_at"),
                ))
                conn.commit()
            except Exception as e:
                conn.rollback()
                print(f"  ERROR enhancement_indexes {csp_id}: {e}")
            finally:
                cur.close()

        print(f"  {csp_id}: {ri_count} resource_inventory + 1 enhancement_index uploaded")

    conn.close()
    print("Upload complete!")


if __name__ == "__main__":
    main()
