#!/usr/bin/env python3
"""
Validate all Azure check YAML vars against step4 final_union fields.
Produces a detailed report of alignment status.
"""

import json
import os
import re
import yaml
from collections import defaultdict

BASE_DIR = "/Users/apple/Desktop/threat-engine"
CHECK_DIR = os.path.join(BASE_DIR, "catalog/rule/azure_rule_check")
STEP4_DIR = os.path.join(BASE_DIR, "catalog/python_field_generator/azure")

# Same SERVICE_MAP as enrichment script
SERVICE_MAP = {
    "api": "apimanagement", "api_management": "apimanagement",
    "app_configuration": "appconfiguration", "app_platform": "appplatform",
    "app_service": "web", "attestation": "attestation",
    "authorization": "authorization", "automanage": "automanage",
    "automation": "automation", "azure_active_directory": "azureactivedirectory",
    "azure_arc": "hybridcompute", "azure_data_explorer": "kusto",
    "azure_databricks": "databricks", "azure_load_testing": "loadtesting",
    "azure_update_manager": "maintenance", "backup": "recoveryservicesbackup",
    "batch": "batch", "billing": "billing", "bot_service": "botservice",
    "cache": "redis", "cdn": "cdn", "cognitive_services": "cognitiveservices",
    "communication": "communication", "compute": "compute",
    "container": "containerinstance", "container_apps": "app",
    "container_instance": "containerinstance", "container_instances": "containerinstance",
    "container_registry": "containerregistry", "containerservice": "containerservice",
    "cosmos_db": "cosmosdb", "cosmosdb": "cosmosdb", "cost_management": "costmanagement",
    "data_box": "databox", "data_factory": "datafactory",
    "data_lake": "datalake-analytics", "data_lake_analytics": "datalake-analytics",
    "desktop_virtualization": "desktopvirtualization", "devcenter": "devcenter",
    "devopsinfrastructure": "devopsinfrastructure", "dns": "dns",
    "elasticsan": "elasticsan", "event_grid": "eventgrid",
    "event_hub": "eventhub", "event_hubs": "eventhub", "eventhub": "eventhub",
    "front_door": "frontdoor", "guest_configuration": "guestconfiguration",
    "hdinsight": "hdinsight", "health_bot": "healthbot",
    "healthcare_apis": "healthcareapis", "internet_of_things": "iothub",
    "key_vault": "keyvault", "keyvault": "keyvault",
    "kubernetes": "containerservice", "kusto": "kusto",
    "lab_services": "labservices", "lighthouse": "managedservices",
    "loganalytics": "loganalytics", "logic_apps": "logic",
    "machine_learning": "machinelearningservices", "managed_application": "solutions",
    "managed_grafana": "dashboard", "managed_identity": "msi",
    "managedidentity": "msi", "management_groups": "managementgroups",
    "managementgroups": "managementgroups", "maps": "maps",
    "mariadb": "rdbms_mariadb", "media_services": "media",
    "mobile_network": "mobilenetwork", "monitor": "monitor",
    "monitoring": "monitor", "mysql": "rdbms_mysql", "network": "network",
    "policy": "policy", "postgresql": "rdbms_postgresql",
    "power_bi": "powerbidedicated", "purview": "purview",
    "rbac": "authorization", "resilience": "advisor",
    "search": "search", "security_center": "security",
    "security_center_-_granular_pricing": "security",
    "service_bus": "servicebus", "service_fabric": "servicefabric",
    "servicebus": "servicebus", "signalr": "signalr",
    "site_recovery": "recoveryservicessiterecovery", "sql": "sql",
    "sql_managed_instance": "sql", "sql_server": "sql",
    "stack_hci": "azurestackhci", "storage": "storage",
    "stream_analytics": "streamanalytics", "streamanalytics": "streamanalytics",
    "subscription": "subscription", "synapse": "synapse",
    "tags": "resources", "traffic_manager": "trafficmanager",
    "trusted_launch": "compute", "vm_image_builder": "imagebuilder",
    "web": "web", "web_pubsub": "webpubsub",
    "active_directory": "azureactivedirectory", "api_for_fhir": "healthcareapis",
    "azure_ai_services": "cognitiveservices", "azure_edge_hardware_center": "edgeorder",
    "azure_stack_edge": "databoxedge", "automatic_update": "maintenance",
    "changetrackingandinventory": "hybridcompute",
    "general": None, "azure": None, "unknown": None,
}

ASSERTION_ONLY_SERVICES = {
    "active_directory", "data_lake_analytics", "purview", "policy",
    "billing", "cost_management", "power_bi", "managementgroups",
    "management_groups", "kubernetes", "guest_configuration",
}


def extract_vars(conditions):
    vars_found = []
    if not conditions:
        return vars_found
    if isinstance(conditions, dict):
        if "var" in conditions:
            vars_found.append(conditions["var"])
        for key in ("all", "any"):
            if key in conditions:
                for sub in conditions[key]:
                    vars_found.extend(extract_vars(sub))
    return vars_found


def get_top_field(var_ref):
    if not var_ref or not var_ref.startswith("item."):
        return None
    if "[concat(" in var_ref or "parameters(" in var_ref:
        return None
    parts = var_ref.split(".")
    if len(parts) < 2:
        return None
    field = re.sub(r'\[.*?\]', '', parts[1])
    if not field or not (field[0].isalpha() or field[0] == '_'):
        return None
    return field


def main():
    results = {
        "valid": 0, "invalid": 0, "assertion_only": 0,
        "cross_cutting": 0, "no_step4": 0
    }
    invalid_details = defaultdict(list)
    service_summary = {}

    for check_svc in sorted(os.listdir(CHECK_DIR)):
        svc_dir = os.path.join(CHECK_DIR, check_svc)
        if not os.path.isdir(svc_dir):
            continue
        check_file = os.path.join(svc_dir, f"{check_svc}.checks.yaml")
        if not os.path.exists(check_file):
            continue
        try:
            with open(check_file) as f:
                data = yaml.safe_load(f)
        except:
            continue
        if not data or "checks" not in data:
            continue

        svc_valid = 0
        svc_invalid = 0
        svc_assertion = 0

        if check_svc in ASSERTION_ONLY_SERVICES:
            svc_assertion = len(data["checks"])
            results["assertion_only"] += svc_assertion
            service_summary[check_svc] = {"valid": 0, "invalid": 0, "assertion": svc_assertion, "status": "assertion_only"}
            continue

        step4_svc = SERVICE_MAP.get(check_svc)
        if step4_svc is None:
            results["cross_cutting"] += len(data["checks"])
            service_summary[check_svc] = {"valid": 0, "invalid": 0, "assertion": 0, "status": "cross_cutting"}
            continue

        step4_path = os.path.join(STEP4_DIR, step4_svc, "step4_fields_produced_index.json")
        if not os.path.exists(step4_path):
            results["no_step4"] += len(data["checks"])
            service_summary[check_svc] = {"valid": 0, "invalid": 0, "assertion": 0, "status": "no_step4"}
            continue

        with open(step4_path) as f:
            step4 = json.load(f)
        final_union = set(step4.get("final_union", []))
        final_union_lower = {f.lower() for f in final_union}

        for check in data["checks"]:
            if check.get("status") == "assertion_only":
                svc_assertion += 1
                results["assertion_only"] += 1
                continue

            vars_refs = extract_vars(check.get("conditions", {}))
            check_valid = True
            for var_ref in vars_refs:
                top = get_top_field(var_ref)
                if not top:
                    continue
                camel = "".join(w.capitalize() for w in top.split("_"))
                if top not in final_union and top.lower() not in final_union_lower and camel not in final_union:
                    check_valid = False
                    invalid_details[check_svc].append(f"{check.get('rule_id', 'unknown')}: {var_ref} (field: {top})")
                    break

            if check_valid:
                svc_valid += 1
                results["valid"] += 1
            else:
                svc_invalid += 1
                results["invalid"] += 1

        status = "OK" if svc_invalid == 0 else f"INVALID({svc_invalid})"
        service_summary[check_svc] = {"valid": svc_valid, "invalid": svc_invalid, "assertion": svc_assertion, "status": status}

    # Print report
    print("=" * 90)
    print("AZURE CHECK → STEP4 FIELD ALIGNMENT VALIDATION REPORT")
    print("=" * 90)
    print(f"\n{'Service':<40} {'Valid':>6} {'Invalid':>8} {'Assert':>8} {'Status':>12}")
    print("-" * 90)
    for svc in sorted(service_summary.keys()):
        s = service_summary[svc]
        print(f"{svc:<40} {s['valid']:>6} {s['invalid']:>8} {s['assertion']:>8} {s['status']:>12}")

    print("\n" + "=" * 90)
    print("TOTALS")
    print("=" * 90)
    print(f"  Valid checks (var exists in step4):     {results['valid']}")
    print(f"  Invalid checks (var NOT in step4):      {results['invalid']}")
    print(f"  Assertion-only (skipped):               {results['assertion_only']}")
    print(f"  Cross-cutting (no step4 needed):        {results['cross_cutting']}")
    print(f"  No step4 file:                          {results['no_step4']}")
    total = results['valid'] + results['invalid']
    if total > 0:
        pct = results['valid'] / total * 100
        print(f"\n  Validation rate: {results['valid']}/{total} ({pct:.1f}%)")

    if invalid_details:
        print(f"\n  INVALID DETAILS ({results['invalid']} checks):")
        for svc in sorted(invalid_details.keys()):
            print(f"\n    [{svc}]")
            for detail in invalid_details[svc]:
                print(f"      {detail}")


if __name__ == "__main__":
    main()
