#!/usr/bin/env python3
"""
Enrich direct_vars.json for every OCI service by introspecting the OCI Python SDK.

Problem: current direct_vars.json only has basic summary fields (name, status, tags)
from list_ operations. Security fields (ssl_config, subnet_id, kms_key_id, endpoint_type,
backup_policy, platform_config, etc.) are only on get_ operation response models
and were never extracted.

This script:
  1. For each OCI service, finds the right SDK module + model classes
  2. Extracts ALL property fields from each model class
  3. Adds NEW fields to direct_vars.json (never overwrites existing entries)
  4. Creates direct_vars.json from scratch for services that had none
  5. Rebuilds oci_master_field_catalog.csv

Usage:
  python3 enrich_direct_vars_from_sdk.py [--dry-run] [--service analytics]
"""
from __future__ import annotations
import inspect, json, re, subprocess, sys
from collections import defaultdict
from pathlib import Path

BASE       = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/oci")
MERGE_SCRIPT = BASE / "merge_field_rule_catalog.py"
MASTER_SCRIPT = BASE / "generate_oci_master_catalog.py"

DRY_RUN       = "--dry-run" in sys.argv
SERVICE_FILTER = None
for i, a in enumerate(sys.argv[1:], 1):
    if a == "--service" and i < len(sys.argv):
        SERVICE_FILTER = sys.argv[i + 1]

# ── Service → OCI SDK module + primary resource models ────────────────────────
# Each entry: service_name → (oci_module_path, [ModelClassName, ...])
# Only list the PRIMARY resource model(s) for each service.

SERVICE_SDK_MAP: dict[str, tuple[str, list[str]]] = {
    "ai_anomaly_detection": ("oci.ai_vision.models",             ["ImageJob", "DocumentJob"]),    # no dedicated module
    "ai_language":          ("oci.ai_language.models",          ["Project", "Model", "Endpoint"]),
    "analytics":            ("oci.analytics.models",            ["AnalyticsInstance"]),
    "apigateway":           ("oci.apigateway.models",           ["Gateway", "Deployment", "Certificate", "Api"]),
    "artifacts":            ("oci.artifacts.models",            ["ContainerRepository", "ContainerImage", "GenericRepository"]),
    "audit":                ("oci.audit.models",                ["Configuration"]),
    "bds":                  ("oci.bds.models",                  ["BdsInstance", "BdsClusterVersion"]),
    "block_storage":        ("oci.core.models",                 ["Volume", "VolumeBackup", "BootVolume", "BootVolumeBackup"]),
    "certificates":         ("oci.certificates_management.models", ["Certificate", "CertificateAuthority", "CaBundleSummary"]),
    "cloud_guard":          ("oci.cloud_guard.models",          ["Target", "DetectorRecipe", "ResponderRecipe"]),
    "compute":              ("oci.core.models",                 ["Instance", "Image", "DedicatedVmHost"]),
    "container_engine":     ("oci.container_engine.models",     ["Cluster", "NodePool", "Addon"]),
    "container_instances":  ("oci.container_instances.models",  ["ContainerInstance", "Container"]),
    "data_catalog":         ("oci.data_catalog.models",         ["Catalog", "DataAsset", "Connection"]),
    "data_flow":            ("oci.data_flow.models",            ["Application", "Run", "Pool"]),
    "data_integration":     ("oci.data_integration.models",     ["Workspace"]),
    "data_safe":            ("oci.data_safe.models",            ["DataSafeConfiguration", "TargetDatabase", "AuditProfile"]),
    "data_science":         ("oci.data_science.models",         ["NotebookSession", "ModelDeployment", "Project", "Job"]),
    "database":             ("oci.database.models",             ["AutonomousDatabase", "DbSystem", "Database", "AutonomousContainerDatabase"]),
    "devops":               ("oci.devops.models",               ["Project", "Repository", "BuildPipeline", "DeployPipeline"]),
    "dns":                  ("oci.dns.models",                  ["Zone", "View", "Resolver", "Tsig"]),
    "edge_services":        ("oci.waas.models",                 ["WaasPolicy", "HttpRedirect"]),
    "events":               ("oci.events.models",               ["Rule"]),
    "file_storage":         ("oci.file_storage.models",         ["FileSystem", "MountTarget", "Export"]),
    "functions":            ("oci.functions.models",            ["Application", "Function"]),
    "generative_ai":        ("oci.generative_ai.models",        ["Model", "DedicatedAiCluster", "Endpoint"]),
    "golden_gate":          ("oci.golden_gate.models",          ["Deployment", "DatabaseRegistration", "Connection"]),
    "identity":             ("oci.identity.models",             ["User", "Group", "Policy", "AuthenticationPolicy", "TagNamespace"]),
    "key_management":       ("oci.key_management.models",       ["Vault", "Key", "KeyVersion"]),
    "load_balancer":        ("oci.load_balancer.models",        ["LoadBalancer", "Listener", "BackendSet", "Certificate", "SslCipherSuite"]),
    "logging":              ("oci.logging.models",              ["Log", "LogGroup", "UnifiedAgentConfiguration"]),
    "monitoring":           ("oci.monitoring.models",           ["Alarm", "AlarmStatus"]),
    "mysql":                ("oci.mysql.models",                ["DbSystem", "BackupSummary", "Configuration"]),
    "network_firewall":     ("oci.network_firewall.models",     ["NetworkFirewall", "NetworkFirewallPolicy"]),
    "network_load_balancer":("oci.network_load_balancer.models",["NetworkLoadBalancer"]),
    "nosql":                ("oci.nosql.models",                ["Table", "Index"]),
    "object_storage":       ("oci.object_storage.models",       ["Bucket"]),
    "ons":                  ("oci.ons.models",                  ["NotificationTopic", "Subscription"]),
    "psql":                 ("oci.psql.models",                 ["DbSystem", "Backup", "Configuration"]),
    "queue":                ("oci.queue.models",                ["Queue"]),
    "redis":                ("oci.redis.models",                ["RedisCluster"]),
    "resource_manager":     ("oci.resource_manager.models",     ["Stack", "Job", "Template"]),
    "service_catalog":      ("oci.service_catalog.models",      ["ServiceCatalog", "Application"]),
    "streaming":            ("oci.streaming.models",            ["Stream", "StreamPool", "ConnectHarness"]),
    "vault":                ("oci.vault.models",                ["Secret"]),
    "virtual_network":      ("oci.core.models",                 ["Vcn", "Subnet", "NetworkSecurityGroup", "SecurityList",
                                                                  "RouteTable", "InternetGateway", "NatGateway",
                                                                  "ServiceGateway", "LocalPeeringGateway"]),
    "waf":                  ("oci.waf.models",                  ["WebAppFirewall", "WebAppFirewallPolicy"]),
    "zpr":                  ("oci.zpr.models",                  ["ZprPolicy"]),
}

# ── Field type inference ───────────────────────────────────────────────────────

def _infer_type(field_name: str, prop: property) -> str:
    """Infer field type from property docstring or naming convention."""
    # Try docstring type annotation
    doc = (prop.fget.__doc__ or "") if prop.fget else ""
    m = re.search(r':type\s+' + re.escape(field_name) + r':\s+(\S+)', doc)
    if m:
        t = m.group(1).lower().strip("[]")
        if t in ("bool",):                return "boolean"
        if t in ("str", "string"):        return "string"
        if t in ("int", "float"):         return "number"
        if t.startswith("list"):          return "array"
        if t.startswith("dict"):          return "object"
        if t not in ("none", "nonetype"): return "object"
    # Name-based fallback
    n = field_name.lower()
    if n.startswith("is_") or n.endswith("_enabled") or n.endswith("_activated"):
        return "boolean"
    if "tags" in n or "config" in n or "details" in n or "policy" in n or "rules" in n:
        return "object"
    if n.endswith("_ids") or n.endswith("_keys"):
        return "array"
    if n.endswith("_id") or n == "ocid" or n == "id":
        return "string"
    if "time" in n or "date" in n:
        return "string"
    return "string"


def _operators(field_type: str, field_name: str) -> tuple[list[str], list[str]]:
    if "tags" in field_name:
        return ["exists", "not_empty"], ["exists", "not_empty"]
    if field_type == "boolean":
        return ["equals", "not_equals"], []
    if field_type == "array":
        return ["contains", "equals", "in", "not_empty", "not_equals"], ["not_empty"]
    if field_type == "object":
        return ["exists", "not_empty"], ["exists", "not_empty"]
    if field_name.endswith("_id") or field_name == "ocid":
        return ["equals", "exists", "not_equals"], ["exists"]
    if "time" in field_name or "date" in field_name:
        return ["contains", "equals", "exists", "in", "not_equals"], ["exists"]
    return ["contains", "equals", "in", "not_equals"], []


# ── SDK model field extractor ──────────────────────────────────────────────────

def get_model_fields(module_path: str, class_name: str) -> dict[str, dict]:
    """
    Import model class and extract all property fields.
    Returns: {field_path: field_meta_dict}
    """
    try:
        parts = module_path.split(".")
        import importlib
        mod = importlib.import_module(module_path)
    except ImportError as e:
        return {}

    cls = getattr(mod, class_name, None)
    if cls is None:
        return {}

    # Resource name: class CamelCase → snake_case prefix
    resource = re.sub(r'(?<!^)(?=[A-Z])', '_', class_name).lower()

    fields = {}
    for attr in dir(cls):
        if attr.startswith("_"):
            continue
        prop = getattr(cls, attr, None)
        if not isinstance(prop, property):
            continue
        ftype = _infer_type(attr, prop)
        ops, ops_no_val = _operators(ftype, attr)
        fp = f"{resource}.{attr}"
        fields[fp] = {
            "field_name":              fp,
            "type":                    ftype,
            "operators":               ops,
            "operators_no_value":      ops_no_val,
            "enum":                    False,
            "possible_values":         None,
            "compliance_category":     "security",
            "description":             f"OCI SDK {class_name}.{attr}",
            "dependency_index_entity": f"oci.{fp}",
            "operations":              [],
            "main_output_field":       "data",
            "discovery_id":            "",
            "for_each":                None,
            "consumes":                [],
            "produces":                [],
            "_sdk_class":              class_name,
        }
    return fields


# ── Merge into existing direct_vars.json ─────────────────────────────────────

def build_direct_vars(service: str, module_path: str, model_classes: list[str]) -> dict:
    """Extract fields from all model classes for a service."""
    all_fields = {}
    for cls_name in model_classes:
        fields = get_model_fields(module_path, cls_name)
        for fp, meta in fields.items():
            if fp not in all_fields:
                all_fields[fp] = meta
    return all_fields


def merge_into_direct_vars(svc_dir: Path, service: str,
                           new_fields: dict, dry_run: bool) -> tuple[int, int]:
    """
    Merge new_fields into existing direct_vars.json.
    Returns (added, skipped).
    """
    dv_path = svc_dir / "direct_vars.json"

    if dv_path.exists():
        existing = json.loads(dv_path.read_text())
    else:
        existing = {
            "service": service,
            "seed_from_list": True,
            "enriched_from_get_describe": True,
            "enriched_from_sdk": True,
            "fields": {},
        }

    existing_fields = existing.get("fields", {})

    added   = 0
    skipped = 0
    for fp, meta in new_fields.items():
        if fp in existing_fields:
            skipped += 1
        else:
            existing_fields[fp] = meta
            added += 1

    if not dry_run and added > 0:
        existing["fields"] = existing_fields
        existing["enriched_from_sdk"] = True
        dv_path.write_text(json.dumps(existing, indent=2))

    return added, skipped


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    import importlib

    # Test OCI SDK available
    try:
        import oci
    except ImportError:
        print("ERROR: oci SDK not installed. Run: pip install oci")
        sys.exit(1)

    grand_added   = 0
    grand_total   = 0

    print(f"\n{'Service':<30} {'Models':>8} {'New fields':>12} {'Existing':>10}")
    print("-" * 65)

    services = SERVICE_SDK_MAP.keys()
    if SERVICE_FILTER:
        services = [s for s in services if s == SERVICE_FILTER]

    for service in sorted(services):
        module_path, model_classes = SERVICE_SDK_MAP[service]

        # Skip if service directory doesn't exist
        svc_dir = BASE / service
        if not svc_dir.exists():
            continue

        # Extract from SDK
        new_fields = build_direct_vars(service, module_path, model_classes)
        grand_total += len(new_fields)

        if not new_fields:
            print(f"  {service:<28}  (no models found in {module_path})")
            continue

        added, skipped = merge_into_direct_vars(svc_dir, service, new_fields, DRY_RUN)
        grand_added += added

        flag = "(dry-run)" if DRY_RUN else ""
        print(f"  {service:<28} {len(model_classes):>8} {added:>12}  (existing: {skipped}) {flag}")

    print("-" * 65)
    print(f"  {'TOTAL':<28} {grand_total:>8}  {grand_added:>11} new fields added")
    print(f"  (dry_run={DRY_RUN})")

    if not DRY_RUN and grand_added > 0:
        print("\n[1/2] Rebuilding oci_master_field_catalog.csv ...")
        r = subprocess.run([sys.executable, str(MASTER_SCRIPT)],
                           capture_output=True, text=True)
        if r.returncode:
            print("WARN master catalog:", r.stderr[-300:])
        else:
            # Count rows
            import csv as csv_mod
            with open(BASE / "oci_master_field_catalog.csv") as f:
                n = sum(1 for _ in csv_mod.reader(f)) - 1
            print(f"  master catalog: {n} rows")

        print("\n[2/2] Rebuilding unified field_rule_catalog.csv ...")
        r2 = subprocess.run([sys.executable, str(MERGE_SCRIPT)],
                            capture_output=True, text=True)
        print(r2.stdout[-1500:])
        if r2.returncode:
            print("WARN merge:", r2.stderr[-300:])


if __name__ == "__main__":
    main()
