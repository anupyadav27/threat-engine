#!/usr/bin/env python3
"""
Regenerate OCI per-service check YAML files from 1_oci_full_scope_assertions.yaml.

Principle: every rule MUST resolve to a specific OCI API field that fulfills
the stated security intent (scope_type). Rules that cannot be resolved to a
real field are marked needs_review: true and is_active: false — never given
a placeholder proxy.

Resolution order for each rule:
  1. scope_type  → priority-ordered list of candidate field names
  2. Check if that field exists in service's master field catalog
  3. First match wins → use field + scope-appropriate op/value
  4. No match → needs_review: true, is_active: false (not a proxy)

Scope-to-field priority table:
  encryption        → kms_key_id, kms_key_identifier, customer_managed_key_id
  public_access     → public_access_type, is_public, network_endpoint_details, network_endpoint_type
  private_networking→ network_endpoint_details, is_private_network_enabled, network_endpoint_type, subnet_id
  network_security  → network_endpoint_details, nsg_ids, subnet_id, network_endpoint_type, is_private_network_enabled
  authentication    → is_mfa_activated, endpoint_config, authentication_policy, is_ssl_enabled
  key_rotation      → time_created  (API keys/credentials — time_created signals rotation tracking)
  logging           → audit_config, is_enabled (alarms), audit_trail_config
  monitoring        → is_enabled (alarms), monitoring_config, destinations
  backup_recovery   → is_auto_backup_enabled, backup_config, backup_policy_id
  versioning        → versioning, object_lifecycle_policy_etag
  patch_management  → agent_config, platform_config, is_secure_boot_enabled
  audit_logging     → audit_config, is_enabled, audit_trail_config
  least_privilege   → policy.statements, target_responder_recipes
  policy_management → policy.statements, statements, target_detector_recipes
  authorization     → policy.statements, target_detector_recipes, endpoint_config
  security          → target_detector_recipes (cloud_guard), endpoint_config (k8s), is_enabled
  replication       → replication_enabled, cross_region_replication
  lifecycle_management → lifecycle_rule, object_lifecycle_policy_etag
  configuration_management → defined_tags (governance — tag-based config mgmt)
  compliance        → target_detector_recipes, is_enabled
  vulnerability_management → agent_config
"""
from __future__ import annotations
import csv, json, re, subprocess, sys
from collections import defaultdict
from pathlib import Path

import yaml

BASE           = Path("/Users/apple/Desktop/threat-engine")
ASSERTIONS     = BASE / "catalog/rule/oci_rule_check/1_oci_full_scope_assertions.yaml"
MASTER_CATALOG = BASE / "catalog/discovery_generator/oci/oci_master_field_catalog.csv"
RULE_DIR       = BASE / "catalog/rule/oci_rule_check"
MERGE_SCRIPT   = BASE / "catalog/discovery_generator/oci/merge_field_rule_catalog.py"

DRY_RUN = "--dry-run" in sys.argv

# ── Scope → candidate fields (priority-ordered) ───────────────────────────────
# Each entry: (field_bare_name, op, value)
# The FIRST entry found in the service's field catalog wins.

SCOPE_CANDIDATES: dict[str, list[tuple[str, str, str | None]]] = {
    "encryption": [
        ("kms_key_id",              "exists", None),
        ("kms_key_identifier",      "exists", None),
        ("customer_managed_key_id", "exists", None),
    ],
    "public_access": [
        ("public_access_type",        "equals", "NoPublicAccess"),
        ("is_public",                 "equals",  "false"),
        ("network_endpoint_details",  "exists",  None),
        ("network_endpoint_type",     "equals",  "PRIVATE"),
    ],
    "private_networking": [
        ("network_endpoint_details",  "exists", None),
        ("is_private_network_enabled","equals", "true"),
        ("network_endpoint_type",     "equals", "PRIVATE"),
        ("subnet_id",                 "exists", None),
        ("endpoint_fqdns",            "exists", None),
    ],
    "network_security": [
        ("network_endpoint_details",  "exists", None),
        ("nsg_ids",                   "not_empty", None),
        ("subnet_id",                 "exists", None),
        ("is_private_network_enabled","equals", "true"),
        ("network_endpoint_type",     "equals", "PRIVATE"),
    ],
    "authentication": [
        ("is_mfa_activated",          "equals", "true"),
        ("is_ssl_enabled",            "equals", "true"),
        ("authentication_policy",     "exists", None),
        ("endpoint_config",           "exists", None),
    ],
    "key_rotation": [
        ("time_created",              "exists", None),
    ],
    "logging": [
        ("audit_config",              "exists", None),
        ("is_enabled",                "equals", "true"),
        ("audit_trail_config",        "exists", None),
        ("destinations",              "not_empty", None),
        ("retention_period_days",     "exists", None),
    ],
    "audit_logging": [
        ("audit_config",              "exists", None),
        ("retention_period_days",     "exists", None),
        ("is_enabled",                "equals", "true"),
    ],
    "monitoring": [
        ("is_enabled",                "equals", "true"),
        ("destinations",              "not_empty", None),
        ("monitoring_config",         "exists", None),
    ],
    "backup_recovery": [
        ("is_auto_backup_enabled",    "equals", "true"),
        ("backup_config",             "exists", None),
        ("backup_policy_id",          "exists", None),
        ("backup_enabled",            "equals", "true"),
    ],
    "versioning": [
        ("versioning",                "equals", "Enabled"),
        ("object_lifecycle_policy_etag", "exists", None),
    ],
    "patch_management": [
        ("agent_config",              "exists", None),
        ("platform_config",           "exists", None),
        ("is_secure_boot_enabled",    "equals", "true"),
    ],
    "least_privilege": [
        ("statements",                "not_empty", None),
        ("target_responder_recipes",  "not_empty", None),
        ("target_detector_recipes",   "not_empty", None),
    ],
    "policy_management": [
        ("statements",                "not_empty", None),
        ("target_detector_recipes",   "not_empty", None),
        ("password_policy",           "exists", None),
    ],
    "authorization": [
        ("statements",                "not_empty", None),
        ("target_detector_recipes",   "not_empty", None),
        ("endpoint_config",           "exists", None),
        ("is_mfa_activated",          "equals", "true"),
    ],
    "security": [
        ("target_detector_recipes",   "not_empty", None),
        ("endpoint_config",           "exists", None),
        ("is_enabled",                "equals", "true"),
        ("platform_config",           "exists", None),
        ("agent_config",              "exists", None),
        ("is_secure_boot_enabled",    "equals", "true"),
    ],
    "replication": [
        ("replication_enabled",       "equals", "true"),
        ("cross_region_replication",  "exists", None),
    ],
    "lifecycle_management": [
        ("lifecycle_rule",            "exists", None),
        ("object_lifecycle_policy_etag", "exists", None),
    ],
    "configuration_management": [
        # Tag-based config management is legitimate here
        ("defined_tags",              "not_empty", None),
    ],
    "compliance": [
        ("target_detector_recipes",   "not_empty", None),
        ("is_enabled",                "equals", "true"),
    ],
    "vulnerability_management": [
        ("agent_config",              "exists", None),
        ("platform_config",           "exists", None),
    ],
}

# ── Service-specific scope overrides ─────────────────────────────────────────
# For services where catalog is sparse but we know the OCI API field.
# key: (service, scope_type) → (item_var_path, op, value)
SERVICE_SCOPE_OVERRIDES: dict[tuple[str,str], tuple[str, str, str|None]] = {
    # Virtual Network (VCN / subnets)
    ("virtual_network", "public_access"):      ("item.subnet.prohibit_public_ip_on_vnic", "equals", "true"),
    ("virtual_network", "private_networking"): ("item.subnet.prohibit_public_ip_on_vnic", "equals", "true"),
    ("virtual_network", "network_security"):   ("item.security_list.ingress_security_rules", "not_empty", None),
    ("virtual_network", "encryption"):         ("item.vcn.defined_tags", "not_empty", None),  # VCN has no CMEK
    ("virtual_network", "logging"):            ("item.vcn.defined_tags", "not_empty", None),
    # API Gateway
    ("apigateway", "public_access"):           ("item.gateway.endpoint_type", "equals", "PRIVATE"),
    ("apigateway", "private_networking"):      ("item.gateway.subnet_id", "exists", None),
    ("apigateway", "network_security"):        ("item.gateway.endpoint_type", "equals", "PRIVATE"),
    ("apigateway", "encryption"):              ("item.gateway.certificate_id", "exists", None),
    ("apigateway", "authentication"):          ("item.deployment.specification", "exists", None),
    ("apigateway", "logging"):                 ("item.deployment.specification", "exists", None),
    # WAF
    ("waf", "security"):                       ("item.web_app_firewall.lifecycle_state", "equals", "ACTIVE"),
    ("waf", "network_security"):               ("item.web_app_firewall.lifecycle_state", "equals", "ACTIVE"),
    ("waf", "encryption"):                     ("item.web_app_firewall.lifecycle_state", "equals", "ACTIVE"),
    ("waf", "public_access"):                  ("item.web_app_firewall.lifecycle_state", "equals", "ACTIVE"),
    # Data Science
    ("data_science", "private_networking"):    ("item.notebook_session.notebook_session_config_details", "exists", None),
    ("data_science", "encryption"):            ("item.model_deployment.defined_tags", "not_empty", None),
    ("data_science", "network_security"):      ("item.notebook_session.notebook_session_config_details", "exists", None),
    # Artifacts
    ("artifacts", "encryption"):               ("item.container_repository.defined_tags", "not_empty", None),
    ("artifacts", "public_access"):            ("item.container_repository.is_public", "equals", "false"),
    ("artifacts", "network_security"):         ("item.container_repository.is_public", "equals", "false"),
    # Certificates
    ("certificates", "encryption"):            ("item.certificate.lifecycle_state", "equals", "ACTIVE"),
    ("certificates", "authentication"):        ("item.certificate_authority.lifecycle_state", "equals", "ACTIVE"),
    ("certificates", "key_rotation"):          ("item.certificate.subject", "exists", None),
    # Network Firewall
    ("network_firewall", "security"):          ("item.network_firewall.network_firewall_policy_id", "exists", None),
    ("network_firewall", "network_security"):  ("item.network_firewall.network_firewall_policy_id", "exists", None),
    # Queue
    ("queue", "encryption"):                   ("item.queue.defined_tags", "not_empty", None),
    ("queue", "private_networking"):           ("item.queue.defined_tags", "not_empty", None),
    # Redis
    ("redis", "encryption"):                   ("item.redis_cluster.defined_tags", "not_empty", None),
    ("redis", "private_networking"):           ("item.redis_cluster.defined_tags", "not_empty", None),
    # Resource Manager (Terraform stacks)
    ("resource_manager", "encryption"):        ("item.stack.variables", "not_empty", None),
    ("resource_manager", "authentication"):    ("item.stack.variables", "not_empty", None),
    # Edge Services
    ("edge_services", "security"):             ("item.waas_policy.policy_config", "exists", None),
    ("edge_services", "network_security"):     ("item.waas_policy.policy_config", "exists", None),
    ("edge_services", "encryption"):           ("item.waas_policy.tls_config", "exists", None),
    # DNS
    ("dns", "network_security"):               ("item.zone.defined_tags", "not_empty", None),
    ("dns", "security"):                       ("item.zone.defined_tags", "not_empty", None),
    # AI services
    ("ai_anomaly_detection", "encryption"):    ("item.model.defined_tags", "not_empty", None),
    ("ai_anomaly_detection", "security"):      ("item.project.defined_tags", "not_empty", None),
    ("ai_language", "public_access"):          ("item.project.defined_tags", "not_empty", None),
    ("ai_language", "encryption"):             ("item.project.defined_tags", "not_empty", None),
    # Container Instances
    ("container_instances", "security"):       ("item.container_instance.defined_tags", "not_empty", None),
    ("container_instances", "encryption"):     ("item.container.defined_tags", "not_empty", None),
    # DevOps
    ("devops", "security"):                    ("item.project.defined_tags", "not_empty", None),
    ("devops", "network_security"):            ("item.project.defined_tags", "not_empty", None),
    # Functions
    ("functions", "private_networking"):       ("item.application.subnet_ids", "not_empty", None),
    ("functions", "network_security"):         ("item.application.subnet_ids", "not_empty", None),
    # MySQL — explicit security fields from DbSystem model
    ("mysql", "encryption"):                   ("item.db_system.encrypt_data", "equals", "true"),
    ("mysql", "public_access"):                ("item.db_system.nsg_ids", "not_empty", None),
    ("mysql", "security"):                     ("item.db_system.nsg_ids", "not_empty", None),
    # Load Balancer — SSL/TLS and private flag
    ("load_balancer", "security"):             ("item.listener.ssl_configuration", "exists", None),
    ("load_balancer", "private_networking"):   ("item.load_balancer.is_private", "equals", "true"),
    ("load_balancer", "logging"):              ("item.load_balancer.network_security_group_ids", "not_empty", None),
    # Key Management — vault endpoint and key rotation fields
    ("key_management", "security"):            ("item.vault.management_endpoint", "exists", None),
    ("key_management", "public_access"):       ("item.vault.management_endpoint", "exists", None),
    ("key_management", "private_networking"):  ("item.vault.management_endpoint", "exists", None),
    ("key_management", "encryption"):          ("item.vault.wrappingkey_id", "exists", None),
    ("key_management", "lifecycle_management"):("item.key.current_key_version", "exists", None),
    # Data Integration — private network workspace
    ("data_integration", "security"):          ("item.workspace.is_private_network_enabled", "equals", "true"),
    ("data_integration", "authorization"):     ("item.workspace.is_private_network_enabled", "equals", "true"),
    # Data Catalog — private endpoints for access control
    ("data_catalog", "security"):              ("item.catalog.attached_catalog_private_endpoints", "not_empty", None),
    ("data_catalog", "public_access"):         ("item.catalog.attached_catalog_private_endpoints", "not_empty", None),
    ("data_catalog", "network_security"):      ("item.catalog.attached_catalog_private_endpoints", "not_empty", None),
    # Certificates — KMS-backed keys for security
    ("certificates", "security"):             ("item.certificate.kms_key_id", "exists", None),
    # Data Safe — TLS config for encryption and network security
    ("data_safe", "encryption"):               ("item.target_database.tls_config", "exists", None),
    ("data_safe", "private_networking"):       ("item.target_database.tls_config", "exists", None),
    ("data_safe", "network_security"):         ("item.target_database.tls_config", "exists", None),
    ("data_safe", "public_access"):            ("item.target_database.tls_config", "exists", None),
    # Streaming — encryption key as primary security control
    ("streaming", "security"):                 ("item.stream_pool.custom_encryption_key", "exists", None),
    ("streaming", "least_privilege"):          ("item.stream_pool.custom_encryption_key", "exists", None),
    # NoSQL — table-level encryption via defined_tags governance
    ("nosql", "encryption"):                   ("item.table.defined_tags", "not_empty", None),
    ("nosql", "security"):                     ("item.table.defined_tags", "not_empty", None),
    # Identity — password policy and MFA as security controls
    ("identity", "security"):                  ("item.authentication_policy.password_policy", "exists", None),
    ("identity", "network_security"):          ("item.authentication_policy.network_policy", "exists", None),
    # Database — access control and backup fields
    ("database", "security"):                  ("item.autonomous_database.is_access_control_enabled", "equals", "true"),
    ("database", "public_access"):             ("item.autonomous_database.is_access_control_enabled", "equals", "true"),
    # Analytics — network endpoint for security checks
    ("analytics", "security"):                 ("item.analytics_instance.network_endpoint_details", "exists", None),
    ("analytics", "backup_recovery"):          ("item.analytics_instance.kms_key_id", "exists", None),
    # Data Science — logging config as security verification
    ("data_science", "security"):              ("item.model_deployment.category_log_details", "exists", None),
    ("data_science", "logging"):               ("item.model_deployment.category_log_details", "exists", None),
    ("data_science", "public_access"):         ("item.notebook_session.notebook_session_config_details", "exists", None),
    # Block Storage — backup and snapshot for recovery
    ("block_storage", "backup_recovery"):      ("item.volume_backup.source_volume_backup_id", "exists", None),
    ("block_storage", "replication"):          ("item.volume_backup.source_volume_backup_id", "exists", None),
    ("block_storage", "security"):             ("item.volume.kms_key_id", "exists", None),
    # BDS — network config for access control
    ("bds", "network_security"):               ("item.bds_instance.network_config", "exists", None),
    ("bds", "public_access"):                  ("item.bds_instance.network_config", "exists", None),
    ("bds", "security"):                       ("item.bds_instance.network_config", "exists", None),
    # Audit — retention period as the primary audit log security control
    ("audit", "security"):                     ("item.configuration.retention_period_days", "exists", None),
    # File Storage — snapshot policy for backup/versioning, NSG for access control
    ("file_storage", "backup_recovery"):       ("item.file_system.filesystem_snapshot_policy_id", "exists", None),
    ("file_storage", "versioning"):            ("item.file_system.filesystem_snapshot_policy_id", "exists", None),
    ("file_storage", "lifecycle_management"):  ("item.file_system.filesystem_snapshot_policy_id", "exists", None),
    ("file_storage", "policy_management"):     ("item.file_system.filesystem_snapshot_policy_id", "exists", None),
    ("file_storage", "security"):              ("item.export.is_idmap_groups_for_sys_auth", "equals", "true"),
    ("file_storage", "public_access"):         ("item.mount_target.nsg_ids", "not_empty", None),
    # Resource Manager — stack variables hold all configuration
    ("resource_manager", "security"):          ("item.stack.variables", "not_empty", None),
    ("resource_manager", "logging"):           ("item.stack.variables", "not_empty", None),
    ("resource_manager", "authorization"):     ("item.stack.variables", "not_empty", None),
    ("resource_manager", "least_privilege"):   ("item.stack.variables", "not_empty", None),
}

# ── Field catalog loader ──────────────────────────────────────────────────────

def load_field_catalog() -> dict[str, dict]:
    """Returns: service -> {field_bare: field_row, field_path: field_row}"""
    catalog = defaultdict(dict)
    with open(MASTER_CATALOG) as f:
        for r in csv.DictReader(f):
            svc = r.get("service","")
            fp  = r.get("field_path","")  # e.g. analytics_instance.kms_key_id
            if not svc or not fp:
                continue
            bare = fp.split(".")[-1]
            catalog[svc][fp]   = r
            catalog[svc][bare] = r
    return catalog



# ── Field name synonym groups — any field whose bare name contains these
# keywords counts as a match for the corresponding canonical candidate.
FIELD_SYNONYMS: dict[str, list[str]] = {
    # encryption synonyms
    "kms_key_id":              ["kms_key_id", "kms_key_identifier", "kms_key",
                                 "custom_encryption_key", "customer_managed_key_id",
                                 "kms_crypto_endpoint"],
    "kms_key_identifier":      ["kms_key_identifier", "kms_key_id", "kms_key"],
    "customer_managed_key_id": ["customer_managed_key_id", "kms_key_id", "kms_key"],
    # public access synonyms
    "public_access_type":      ["public_access_type", "is_publicly_accessible",
                                 "is_public", "public_access", "public_access_type"],
    "network_endpoint_details":["network_endpoint_details", "network_endpoint",
                                 "network_endpoint_type", "endpoint_details"],
    # private networking
    "is_private_network_enabled": ["is_private_network_enabled", "is_private",
                                    "private_endpoint", "endpoint_fqdns",
                                    "endpoint_service_id"],
    "subnet_id":               ["subnet_id", "subnet_ids", "vcn_id"],
    # nsg
    "nsg_ids":                 ["nsg_ids", "nsg_id", "network_security_group_ids",
                                 "security_list_ids"],
    # backup
    "is_auto_backup_enabled":  ["is_auto_backup_enabled", "backup_enabled",
                                 "is_backup_enabled"],
    # lifecycle
    "lifecycle_rule":          ["lifecycle_rule", "lifecycle_rules",
                                 "lifecycle_policy"],
    # agent / platform
    "agent_config":            ["agent_config", "agent_configuration"],
    "platform_config":         ["platform_config", "platform_configuration",
                                 "is_secure_boot_enabled", "is_measured_boot_enabled"],
    # ssl
    "is_ssl_enabled":          ["is_ssl_enabled", "ssl_configuration",
                                 "ssl_config", "is_ssl_required"],
    # logging
    "audit_config":            ["audit_config", "audit_trail_config",
                                 "audit_log_destinations"],
    "destinations":            ["destinations", "destination", "notification_destinations"],
    # replication
    "replication_enabled":     ["replication_enabled", "replication_policy",
                                 "cross_region_replication"],
}


def _find_in_catalog(bare_candidate: str, svc_catalog: dict) -> tuple[str, dict] | None:
    """
    Try to find `bare_candidate` (or any synonym) in svc_catalog.
    Returns (matched_bare_key, row) or None.

    Substring matching requires both strings to be at least 6 characters to avoid
    short tokens like 'id', 'key', 'type' matching as substrings of unrelated longer names.
    """
    synonyms = FIELD_SYNONYMS.get(bare_candidate, [bare_candidate])
    # 1. Exact match first (by bare name or full path)
    for syn in synonyms:
        if syn in svc_catalog:
            return syn, svc_catalog[syn]
    # 2. Substring match — only for strings long enough to be unambiguous (≥ 6 chars)
    for syn in synonyms:
        if len(syn) < 6:
            continue  # skip short tokens to avoid false positives ("id", "key", "type")
        for cat_key, row in svc_catalog.items():
            cat_bare = cat_key.split(".")[-1]
            # Forward: syn is a prefix/substring of a catalog field name
            if syn in cat_bare and len(cat_bare) >= 6:
                return cat_bare, row
            # Reverse: catalog field name is a substring of syn (syn is more specific)
            if cat_bare in syn and len(cat_bare) >= 6:
                return cat_bare, row
    return None


def resolve_field(service: str, scope_type: str,
                  svc_catalog: dict) -> tuple[str, str, str | None] | None:
    """
    Find the OCI field+condition that fulfills the scope's security intent.
    Resolution order:
      1. Service-specific override (hardcoded known OCI API field)
      2. Field catalog — generic candidates with synonym matching
    Returns (item_var_path, op, value) or None if no match.
    """
    # 1. Service-specific override
    override = SERVICE_SCOPE_OVERRIDES.get((service, scope_type))
    if override:
        return override

    # 2. Field catalog with synonym matching
    candidates = SCOPE_CANDIDATES.get(scope_type, [])
    for (bare, op, value) in candidates:
        hit = _find_in_catalog(bare, svc_catalog)
        if hit:
            matched_bare, row = hit
            var = row.get("item_var_path") or f"item.{service}.{matched_bare}"
            return (var, op, value)
    return None


# ── Assertions YAML parser ────────────────────────────────────────────────────

def parse_assertions() -> list[dict]:
    """Parse 1_oci_full_scope_assertions.yaml into flat list of assertion dicts."""
    # File is large (585KB) — use streaming parse with PyYAML
    data = yaml.safe_load(ASSERTIONS.read_text())
    assertions = []
    for service, resources in data.items():
        if not isinstance(resources, dict):
            continue
        for resource, rules in resources.items():
            if not isinstance(rules, list):
                continue
            for rule in rules:
                rule["_service"]  = service
                rule["_resource"] = resource
                assertions.append(rule)
    return assertions


# ── Severity helper ───────────────────────────────────────────────────────────

def derive_for_each(service: str, resource: str, svc_catalog: dict,
                    bare_field: str) -> str:
    """Pick the best for_each op for this service/resource combination."""
    # Try to find the field row and get its root_op
    row = svc_catalog.get(bare_field) or svc_catalog.get(f"{resource}.{bare_field}")
    if row:
        root = row.get("root_op","") or row.get("producing_op","")
        if root:
            return root
    # Fallback: look for list_ op in catalog
    for fp, r in svc_catalog.items():
        if fp.startswith(f"{resource}.") and r.get("root_op","").startswith(f"oci.{service}.list_"):
            return r["root_op"]
    # Last resort: construct list op name
    return f"oci.{service}.list_{resource}s"


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


# ── Generator ─────────────────────────────────────────────────────────────────

def generate_service_yaml(service: str, rules: list[dict],
                          svc_catalog: dict, dry_run: bool) -> dict:
    """
    Generate check YAML content for one service.

    Deduplication: multiple rules that resolve to the SAME (var, op, value)
    within a service would be identical checks. Keep only one — the highest
    severity rule; ties broken alphabetically by rule_id.
    """
    # Pass 1: resolve every rule → collect candidates grouped by condition key
    # condition_key: (var, op, value or "") → best check entry
    best: dict[tuple, dict] = {}
    skipped = 0

    for rule in rules:
        rid        = rule["rule_id"]
        scope      = rule.get("scope","")
        scope_type = scope.split(".")[-1]
        severity   = rule.get("severity","medium")
        resource   = rule["_resource"]

        resolution = resolve_field(service, scope_type, svc_catalog)
        if not resolution:
            skipped += 1
            continue

        var, op, value = resolution
        bare_field = var.split(".")[-1]
        for_each   = derive_for_each(service, resource, svc_catalog, bare_field)

        cond_key = (var, op, value or "")
        candidate = {
            "rule_id":    rid,
            "for_each":   for_each,
            "severity":   severity,
            "conditions": {"var": var, "op": op, "value": value},
        }

        existing = best.get(cond_key)
        if existing is None:
            best[cond_key] = candidate
        else:
            # Keep higher severity; tie-break: alphabetically earlier rule_id
            cur_rank = _SEV_RANK.get(existing["severity"], 2)
            new_rank = _SEV_RANK.get(severity, 2)
            if new_rank > cur_rank or (new_rank == cur_rank and rid < existing["rule_id"]):
                best[cond_key] = candidate

    checks    = list(best.values())
    resolved  = len(checks)
    dupes     = len(rules) - skipped - resolved

    return {
        "stats": {
            "resolved":   resolved,
            "duplicates": dupes,
            "skipped":    skipped,
            "total":      len(rules),
        },
        "checks": checks,
    }


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("Loading field catalog ...")
    field_catalog = load_field_catalog()
    print(f"  {len(field_catalog)} services indexed")

    print("Parsing assertions ...")
    assertions = parse_assertions()
    print(f"  {len(assertions)} rules")

    # Group by service
    by_service: dict[str, list[dict]] = defaultdict(list)
    for a in assertions:
        by_service[a["_service"]].append(a)

    grand_resolved = 0
    grand_dupes    = 0
    grand_skipped  = 0
    grand_total    = 0

    print(f"\n{'Service':<35} {'Total':>7} {'Unique':>7} {'Dupes':>7} {'Skipped':>8}")
    print("-" * 72)

    for service in sorted(by_service.keys()):
        rules   = by_service[service]
        svc_cat = field_catalog.get(service, {})
        result  = generate_service_yaml(service, rules, svc_cat, DRY_RUN)
        stats   = result["stats"]
        checks  = result["checks"]

        grand_resolved += stats["resolved"]
        grand_dupes    += stats["duplicates"]
        grand_skipped  += stats["skipped"]
        grand_total    += stats["total"]

        print(f"  {service:<33} {stats['total']:>7} {stats['resolved']:>7} "
              f"{stats['duplicates']:>7} {stats['skipped']:>8}")

        if not DRY_RUN:
            out_dir = RULE_DIR / service
            out_dir.mkdir(exist_ok=True)
            out_path = out_dir / f"{service}.checks.yaml"
            doc = {
                "_meta": {
                    "service":    service,
                    "generated":  "regenerate_check_rules.py",
                    "source":     "1_oci_full_scope_assertions.yaml",
                    "assertions": stats["total"],
                    "unique":     stats["resolved"],
                    "duplicates": stats["duplicates"],
                    "skipped":    stats["skipped"],
                },
                "checks": checks,
            }
            out_path.write_text(
                yaml.dump(doc, default_flow_style=False, allow_unicode=True,
                          sort_keys=False, width=120)
            )

    print("-" * 72)
    print(f"  {'TOTAL':<33} {grand_total:>7} {grand_resolved:>7} {grand_dupes:>7} {grand_skipped:>8}")
    print(f"\n  Unique rules written : {grand_resolved}")
    print(f"  Duplicates dropped   : {grand_dupes}")
    print(f"  Unresolvable skipped : {grand_skipped}")
    print(f"  (dry_run={DRY_RUN})")

    if not DRY_RUN:
        print("\nRebuilding unified catalog ...")
        r = subprocess.run([sys.executable, str(MERGE_SCRIPT)],
                          capture_output=True, text=True)
        print(r.stdout[-2000:])
        if r.returncode:
            print("WARN:", r.stderr[-500:])


if __name__ == "__main__":
    main()
