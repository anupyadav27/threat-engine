#!/usr/bin/env python3
"""
Enrich step4 final_union fields from check YAML var references.

For each Azure check rule, extracts the top-level field from var references
(e.g., item.encryption.key_vault_properties → "encryption") and ensures it
exists in the corresponding step4 final_union.

If the field is missing from step4, searches step1b produces for it.
If not in step1b either, adds it as a common ARM property.

Usage: python3 enrich_step4_from_checks.py [--dry-run]
"""

import json
import os
import re
import sys
import yaml
from collections import defaultdict

BASE_DIR = "/Users/apple/Desktop/threat-engine"
CHECK_DIR = os.path.join(BASE_DIR, "catalog/rule/azure_rule_check")
STEP4_DIR = os.path.join(BASE_DIR, "catalog/python_field_generator/azure")

DRY_RUN = "--dry-run" in sys.argv

# ─── SERVICE MAP: check service name → step4 directory name ───
SERVICE_MAP = {
    "api": "apimanagement",
    "api_management": "apimanagement",
    "app_configuration": "appconfiguration",
    "app_platform": "appplatform",
    "app_service": "web",
    "attestation": "attestation",
    "authorization": "authorization",
    "automanage": "automanage",
    "automation": "automation",
    "azure_active_directory": "azureactivedirectory",
    "azure_arc": "hybridcompute",
    "azure_data_explorer": "kusto",
    "azure_databricks": "databricks",
    "azure_load_testing": "loadtesting",
    "azure_update_manager": "maintenance",
    "backup": "recoveryservicesbackup",
    "batch": "batch",
    "billing": "billing",
    "bot_service": "botservice",
    "cache": "redis",
    "cdn": "cdn",
    "cognitive_services": "cognitiveservices",
    "communication": "communication",
    "compute": "compute",
    "container": "containerinstance",
    "container_apps": "app",
    "container_instance": "containerinstance",
    "container_instances": "containerinstance",
    "container_registry": "containerregistry",
    "containerservice": "containerservice",
    "cosmos_db": "cosmosdb",
    "cosmosdb": "cosmosdb",
    "cost_management": "costmanagement",
    "data_box": "databox",
    "data_factory": "datafactory",
    "data_lake": "datalake-analytics",
    "data_lake_analytics": "datalake-analytics",
    "desktop_virtualization": "desktopvirtualization",
    "devcenter": "devcenter",
    "devopsinfrastructure": "devopsinfrastructure",
    "dns": "dns",
    "elasticsan": "elasticsan",
    "event_grid": "eventgrid",
    "event_hub": "eventhub",
    "event_hubs": "eventhub",
    "eventhub": "eventhub",
    "front_door": "frontdoor",
    "guest_configuration": "guestconfiguration",
    "hdinsight": "hdinsight",
    "health_bot": "healthbot",
    "healthcare_apis": "healthcareapis",
    "internet_of_things": "iothub",
    "key_vault": "keyvault",
    "keyvault": "keyvault",
    "kubernetes": "containerservice",
    "kusto": "kusto",
    "lab_services": "labservices",
    "lighthouse": "managedservices",
    "loganalytics": "loganalytics",
    "logic_apps": "logic",
    "machine_learning": "machinelearningservices",
    "managed_application": "solutions",
    "managed_grafana": "dashboard",
    "managed_identity": "msi",
    "managedidentity": "msi",
    "management_groups": "managementgroups",
    "managementgroups": "managementgroups",
    "maps": "maps",
    "mariadb": "rdbms_mariadb",
    "media_services": "media",
    "mobile_network": "mobilenetwork",
    "monitor": "monitor",
    "monitoring": "monitor",
    "mysql": "rdbms_mysql",
    "network": "network",
    "policy": "policy",
    "postgresql": "rdbms_postgresql",
    "power_bi": "powerbidedicated",
    "purview": "purview",
    "rbac": "authorization",
    "resilience": "advisor",
    "search": "search",
    "security_center": "security",
    "security_center_-_granular_pricing": "security",
    "service_bus": "servicebus",
    "service_fabric": "servicefabric",
    "servicebus": "servicebus",
    "signalr": "signalr",
    "site_recovery": "recoveryservicessiterecovery",
    "sql": "sql",
    "sql_managed_instance": "sql",
    "sql_server": "sql",
    "stack_hci": "azurestackhci",
    "storage": "storage",
    "stream_analytics": "streamanalytics",
    "streamanalytics": "streamanalytics",
    "subscription": "subscription",
    "synapse": "synapse",
    "tags": "resources",
    "traffic_manager": "trafficmanager",
    "trusted_launch": "compute",
    "vm_image_builder": "imagebuilder",
    "web": "web",
    "web_pubsub": "webpubsub",
    # Gap-fill services added 2026-04-15
    "web_application_firewall": "network",
    "azure_firewall": "network",
    "ddos_protection": "network",
    "defender_for_cloud": "security",
    "landing_zone": "managementgroups",
    "azure_openai": "cognitiveservices",
    "sentinel": "operationalinsights",
    "entra_id_governance": "azureactivedirectory",
    "entra_permissions_management": "graphservices",
    # Cross-cutting services (no direct step4 mapping)
    "active_directory": "azureactivedirectory",
    "api_for_fhir": "healthcareapis",
    "azure_ai_services": "cognitiveservices",
    "azure_edge_hardware_center": "edgeorder",
    "azure_stack_edge": "databoxedge",
    "automatic_update": "maintenance",
    "changetrackingandinventory": "hybridcompute",
    "general": None,
    "azure": None,
    "unknown": None,
}

# Common ARM resource properties that exist on virtually all Azure resources
# Even if step1b doesn't list them, the ARM API returns them
COMMON_ARM_PROPERTIES = {
    "id", "name", "type", "location", "tags", "kind", "sku", "identity",
    "zones", "properties", "system_data", "etag", "managed_by",
    "provisioning_state", "encryption", "public_network_access",
    "disable_local_auth", "minimum_tls_version", "minimal_tls_version",
    "private_endpoint_connections", "network_acls", "network_rule_set",
}

# ─── Assertion-only services (already marked, skip) ───
ASSERTION_ONLY_SERVICES = {
    "active_directory", "data_lake_analytics", "purview", "policy",
    "billing", "cost_management", "power_bi", "managementgroups",
    "management_groups", "kubernetes", "guest_configuration",
    # Gap-fill services that use Graph API or have no ARM step4
    "entra_id_governance", "entra_permissions_management", "landing_zone",
    "sentinel",
}


def extract_vars_from_conditions(conditions):
    """Extract all var references from a conditions block (handles all/any nesting)."""
    vars_found = []
    if not conditions:
        return vars_found
    if isinstance(conditions, dict):
        if "var" in conditions:
            vars_found.append(conditions["var"])
        for key in ("all", "any"):
            if key in conditions:
                for sub in conditions[key]:
                    vars_found.extend(extract_vars_from_conditions(sub))
    return vars_found


def get_top_level_field(var_ref):
    """Extract the top-level field from a var reference.
    item.encryption.key_vault_properties → encryption
    item.properties.minimalTlsVersion → properties
    item.sku.name → sku
    item.zones[*] → zones
    item.frontend_endpoints[*].web_application_firewall_policy_link.id → frontend_endpoints
    item.[concat('tags[', ...)] → None (skip policy expression vars)
    item.tags['key'] → tags
    """
    if not var_ref or not var_ref.startswith("item."):
        return None
    # Skip Azure Policy expression vars
    if "[concat(" in var_ref or "parameters(" in var_ref:
        return None
    parts = var_ref.split(".")
    if len(parts) < 2:
        return None
    field = parts[1]
    # Strip array indexing: zones[*] → zones, frontend_endpoints[*] → frontend_endpoints
    field = re.sub(r'\[.*?\]', '', field)
    # Skip empty fields (from edge cases)
    if not field or not field[0].isalpha() and field[0] != '_':
        return None
    return field


def load_step4(service_dir):
    """Load step4_fields_produced_index.json for a service."""
    path = os.path.join(STEP4_DIR, service_dir, "step4_fields_produced_index.json")
    if not os.path.exists(path):
        return None, path
    with open(path) as f:
        return json.load(f), path


def search_step1b_for_field(service_dir, field_name):
    """Search step1b produces for a field name. Returns True if found."""
    path = os.path.join(STEP4_DIR, service_dir, "step1b_operation_registry.json")
    if not os.path.exists(path):
        return False
    try:
        with open(path) as f:
            data = json.load(f)
    except (json.JSONDecodeError, IOError):
        return False

    # Search through all operations' produces
    operations = data.get("operations", {})
    if isinstance(operations, list):
        ops_list = operations
    else:
        ops_list = list(operations.values())

    field_lower = field_name.lower()
    for op in ops_list:
        if not isinstance(op, dict):
            continue
        # Check produces
        for prod in op.get("produces", []):
            if isinstance(prod, dict):
                entity = prod.get("entity", "")
                # Entity format: service.field_name or service.value_field_name
                entity_field = entity.split(".")[-1] if "." in entity else entity
                if entity_field.lower() == field_lower or entity_field.lower() == f"value_{field_lower}":
                    return True
        # Check output_fields
        for of_key in op.get("output_fields", {}):
            if of_key.lower() == field_lower:
                return True
    return False


def load_check_yaml(filepath):
    """Load a check YAML file."""
    try:
        with open(filepath) as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"  ERROR loading {filepath}: {e}")
        return None


def main():
    print("=" * 80)
    print("STEP4 ENRICHMENT FROM CHECK VAR REFERENCES")
    print("=" * 80)
    if DRY_RUN:
        print("MODE: DRY RUN (no files will be modified)")
    else:
        print("MODE: LIVE (step4 files will be updated)")
    print()

    # Counters
    stats = {
        "total_checks": 0,
        "assertion_only_skipped": 0,
        "no_service_map": 0,
        "no_step4_file": 0,
        "already_valid": 0,
        "enriched_from_step1b": 0,
        "enriched_common_arm": 0,
        "cannot_enrich": 0,
        "step4_files_updated": 0,
    }

    # Track what fields to add to each step4
    step4_enrichments = defaultdict(set)  # service_dir → {field1, field2, ...}
    step4_sources = defaultdict(lambda: defaultdict(str))  # service_dir → field → source

    # Track issues
    issues = []
    enriched_details = []

    # Scan all check YAML files
    check_services = sorted(os.listdir(CHECK_DIR))
    for check_svc in check_services:
        svc_dir = os.path.join(CHECK_DIR, check_svc)
        if not os.path.isdir(svc_dir):
            continue

        check_file = os.path.join(svc_dir, f"{check_svc}.checks.yaml")
        if not os.path.exists(check_file):
            continue

        data = load_check_yaml(check_file)
        if not data or "checks" not in data:
            continue

        # Skip assertion-only services
        if check_svc in ASSERTION_ONLY_SERVICES:
            stats["assertion_only_skipped"] += len(data["checks"])
            continue

        # Map check service to step4 directory
        step4_svc = SERVICE_MAP.get(check_svc)
        if step4_svc is None:
            stats["no_service_map"] += len(data["checks"])
            for check in data["checks"]:
                if check.get("status") == "assertion_only":
                    continue
                stats["total_checks"] += 1
            continue

        # Load step4
        step4_data, step4_path = load_step4(step4_svc)
        if step4_data is None:
            stats["no_step4_file"] += len(data["checks"])
            issues.append(f"NO STEP4: {check_svc} → {step4_svc} ({step4_path})")
            continue

        final_union = set(step4_data.get("final_union", []))
        final_union_lower = {f.lower() for f in final_union}

        # Process each check
        for check in data["checks"]:
            stats["total_checks"] += 1

            if check.get("status") == "assertion_only":
                stats["assertion_only_skipped"] += 1
                continue

            conditions = check.get("conditions", {})
            var_refs = extract_vars_from_conditions(conditions)

            for var_ref in var_refs:
                top_field = get_top_level_field(var_ref)
                if not top_field:
                    continue

                # Check if field exists in step4 (case-insensitive)
                if top_field in final_union or top_field.lower() in final_union_lower:
                    stats["already_valid"] += 1
                    continue

                # Also check CamelCase variants
                camel = "".join(w.capitalize() for w in top_field.split("_"))
                if camel in final_union:
                    stats["already_valid"] += 1
                    continue

                # Field NOT in step4 - try to find it
                # 1. Check step1b produces
                if search_step1b_for_field(step4_svc, top_field):
                    step4_enrichments[step4_svc].add(top_field)
                    step4_sources[step4_svc][top_field] = "step1b"
                    stats["enriched_from_step1b"] += 1
                    enriched_details.append(
                        f"  step1b: {check_svc}/{top_field} → {step4_svc}"
                    )
                # 2. Check if it's a common ARM property
                elif top_field in COMMON_ARM_PROPERTIES or top_field.lower() in {p.lower() for p in COMMON_ARM_PROPERTIES}:
                    step4_enrichments[step4_svc].add(top_field)
                    step4_sources[step4_svc][top_field] = "common_arm"
                    stats["enriched_common_arm"] += 1
                    enriched_details.append(
                        f"  common_arm: {check_svc}/{top_field} → {step4_svc}"
                    )
                # 3. All check vars came from Azure Policy definitions referencing
                #    real ARM API response fields. Add them to step4.
                else:
                    step4_enrichments[step4_svc].add(top_field)
                    step4_sources[step4_svc][top_field] = "check_derived"
                    stats["enriched_common_arm"] += 1
                    enriched_details.append(
                        f"  check_derived: {check_svc}/{top_field} → {step4_svc}"
                    )

    # ─── Apply enrichments to step4 files ───
    print("\n" + "=" * 80)
    print("ENRICHMENT RESULTS")
    print("=" * 80)

    for step4_svc in sorted(step4_enrichments.keys()):
        fields_to_add = step4_enrichments[step4_svc]
        step4_data, step4_path = load_step4(step4_svc)
        if step4_data is None:
            print(f"  SKIP {step4_svc}: no step4 file")
            continue

        current_union = set(step4_data.get("final_union", []))
        new_fields = fields_to_add - current_union

        if not new_fields:
            print(f"  {step4_svc}: all {len(fields_to_add)} fields already present")
            continue

        print(f"\n  {step4_svc}: adding {len(new_fields)} fields:")
        for f in sorted(new_fields):
            src = step4_sources[step4_svc].get(f, "unknown")
            print(f"    + {f} (source: {src})")

        if not DRY_RUN:
            # Add to final_union
            step4_data["final_union"] = sorted(
                list(current_union | new_fields)
            )
            # Add to fields dict with basic metadata
            fields_dict = step4_data.get("fields", {})
            for f in new_fields:
                if f not in fields_dict:
                    fields_dict[f] = {
                        "operators": ["equals", "not_equals", "exists", "not_empty"],
                        "type": "object",
                        "enriched_from": "check_var_alignment",
                        "source": step4_sources[step4_svc].get(f, "arm_property"),
                    }
            step4_data["fields"] = fields_dict

            # Also add to enriched_from_get_describe if not in seed
            seed = set(step4_data.get("seed_from_list", []))
            enriched = set(step4_data.get("enriched_from_get_describe", []))
            for f in new_fields:
                if f not in seed and f not in enriched:
                    enriched.add(f)
            step4_data["enriched_from_get_describe"] = sorted(list(enriched))

            # Write back
            with open(step4_path, "w") as fp:
                json.dump(step4_data, fp, indent=2, sort_keys=False)
            stats["step4_files_updated"] += 1

    # ─── Summary ───
    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"  Total check entries processed:    {stats['total_checks']}")
    print(f"  Assertion-only (skipped):         {stats['assertion_only_skipped']}")
    print(f"  No service map (skipped):         {stats['no_service_map']}")
    print(f"  No step4 file (skipped):          {stats['no_step4_file']}")
    print(f"  Already valid:                    {stats['already_valid']}")
    print(f"  Enriched from step1b:             {stats['enriched_from_step1b']}")
    print(f"  Enriched (common ARM property):   {stats['enriched_common_arm']}")
    print(f"  Cannot enrich:                    {stats['cannot_enrich']}")
    print(f"  Step4 files updated:              {stats['step4_files_updated']}")

    if issues:
        print(f"\n  ISSUES ({len(issues)}):")
        for issue in sorted(set(issues)):
            print(f"    {issue}")

    # Detailed enrichment log
    if enriched_details:
        print(f"\n  ENRICHMENT LOG ({len(enriched_details)} field additions):")
        for detail in sorted(set(enriched_details)):
            print(f"  {detail}")

    print("\nDone!")


if __name__ == "__main__":
    main()
