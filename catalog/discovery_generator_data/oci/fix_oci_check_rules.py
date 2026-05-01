#!/usr/bin/env python3
"""
Fix OCI check rule conditions to match actual security intent.

Steps:
  1. Add missing security fields to step2 output_fields registries
  2. Add those fields as new rows to the master field catalog CSV
  3. Update check rule YAML conditions with correct var/op/value
  4. Rebuild the unified oci_field_rule_catalog.csv

Run:
  python3 fix_oci_check_rules.py
  python3 fix_oci_check_rules.py --dry-run    # show changes only
  python3 fix_oci_check_rules.py --service analytics
"""

from __future__ import annotations
import argparse, csv, json, re, yaml
from collections import defaultdict
from pathlib import Path

BASE_OCI   = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/oci")
MASTER_CSV = BASE_OCI / "oci_master_field_catalog.csv"
RULES_BASE = Path("/Users/apple/Desktop/threat-engine/catalog/rule/oci_rule_check")

# ── New security fields to add per service ────────────────────────────────────
# Each entry: service → list of {op, resource, field, type, description}
# op = the producing operation bare name (e.g. 'get_analytics_instance')
# resource = prefix for field_path (e.g. 'analytics_instance')
# field = field name (e.g. 'kms_key_id')
# type = string | boolean | object | array | integer

NEW_SECURITY_FIELDS: dict[str, list[dict]] = {
    "analytics": [
        {"op": "get_analytics_instance", "resource": "analytics_instance", "field": "kms_key_id",              "type": "string",  "desc": "CMK encryption key OCID"},
        {"op": "get_analytics_instance", "resource": "analytics_instance", "field": "network_endpoint_details","type": "object",  "desc": "Network endpoint config (PUBLIC/PRIVATE)"},
        {"op": "get_analytics_instance", "resource": "analytics_instance", "field": "license_type",             "type": "string",  "desc": "LICENSE_INCLUDED or BRING_YOUR_OWN_LICENSE"},
        {"op": "get_analytics_instance", "resource": "analytics_instance", "field": "feature_set",              "type": "string",  "desc": "SELF_SERVICE_ANALYTICS or ENTERPRISE_ANALYTICS"},
    ],
    "database": [
        {"op": "get_autonomous_database",           "resource": "autonomous_database",           "field": "kms_key_id",                        "type": "string",  "desc": "CMK encryption key OCID"},
        {"op": "get_autonomous_database",           "resource": "autonomous_database",           "field": "is_auto_backup_enabled",            "type": "boolean", "desc": "Auto backup enabled"},
        {"op": "get_autonomous_database",           "resource": "autonomous_database",           "field": "backup_retention_period_in_days",   "type": "integer", "desc": "Backup retention days"},
        {"op": "get_autonomous_database",           "resource": "autonomous_database",           "field": "subnet_id",                         "type": "string",  "desc": "Private subnet OCID"},
        {"op": "get_autonomous_database",           "resource": "autonomous_database",           "field": "private_endpoint",                  "type": "string",  "desc": "Private endpoint hostname"},
        {"op": "get_autonomous_database",           "resource": "autonomous_database",           "field": "nsg_ids",                           "type": "array",   "desc": "Network security group OCIDs"},
        {"op": "get_autonomous_database",           "resource": "autonomous_database",           "field": "whitelisted_ips",                   "type": "array",   "desc": "IP allowlist"},
        {"op": "get_autonomous_database",           "resource": "autonomous_database",           "field": "data_safe_status",                  "type": "string",  "desc": "Data Safe registration status"},
        {"op": "get_autonomous_database",           "resource": "autonomous_database",           "field": "operations_insights_status",        "type": "string",  "desc": "Operations Insights status"},
        {"op": "get_autonomous_database",           "resource": "autonomous_database",           "field": "database_management_status",        "type": "string",  "desc": "Database Management status"},
        {"op": "get_autonomous_database",           "resource": "autonomous_database",           "field": "db_version",                        "type": "string",  "desc": "Database version"},
        {"op": "get_autonomous_database",           "resource": "autonomous_database",           "field": "is_auto_scaling_enabled",           "type": "boolean", "desc": "Auto-scaling enabled"},
        {"op": "get_autonomous_database",           "resource": "autonomous_database",           "field": "customer_contacts",                 "type": "array",   "desc": "Customer contact emails"},
        {"op": "get_autonomous_database",           "resource": "autonomous_database",           "field": "open_mode",                         "type": "string",  "desc": "READ_ONLY or READ_WRITE"},
        {"op": "get_autonomous_database",           "resource": "autonomous_database",           "field": "permission_level",                  "type": "string",  "desc": "RESTRICTED or UNRESTRICTED"},
        {"op": "get_autonomous_container_database", "resource": "autonomous_container_database", "field": "kms_key_id",                        "type": "string",  "desc": "CMK encryption key OCID"},
        {"op": "get_autonomous_container_database", "resource": "autonomous_container_database", "field": "backup_config",                     "type": "object",  "desc": "Backup configuration"},
    ],
    "compute": [
        {"op": "get_instance",      "resource": "instance", "field": "kms_key_id",                              "type": "string",  "desc": "CMK for boot volume"},
        {"op": "get_instance",      "resource": "instance", "field": "is_pv_encryption_in_transit_enabled",     "type": "boolean", "desc": "Paravirtualized encryption in transit"},
        {"op": "get_instance",      "resource": "instance", "field": "platform_config",                         "type": "object",  "desc": "Platform config (secure boot, TPM, measured boot)"},
        {"op": "get_instance",      "resource": "instance", "field": "agent_config",                            "type": "object",  "desc": "OCI Agent config (monitoring, management plugins)"},
        {"op": "get_instance",      "resource": "instance", "field": "launch_options",                          "type": "object",  "desc": "Launch options (firmware, network, encryption)"},
        {"op": "get_instance",      "resource": "instance", "field": "metadata",                                "type": "object",  "desc": "Instance metadata (user data, ssh keys)"},
        {"op": "get_instance",      "resource": "instance", "field": "subnet_id",                               "type": "string",  "desc": "Primary VNIC subnet OCID"},
        {"op": "get_boot_volume",   "resource": "boot_volume", "field": "kms_key_id",                           "type": "string",  "desc": "CMK for boot volume encryption"},
        {"op": "get_boot_volume",   "resource": "boot_volume", "field": "is_auto_tune_enabled",                 "type": "boolean", "desc": "Auto-tune performance enabled"},
        {"op": "get_volume",        "resource": "volume",      "field": "kms_key_id",                           "type": "string",  "desc": "CMK for block volume encryption"},
        {"op": "get_instance_configuration", "resource": "instance_configuration", "field": "instance_details", "type": "object", "desc": "Launch template details"},
    ],
    "container_engine": [
        {"op": "get_cluster",       "resource": "cluster", "field": "kms_key_id",                              "type": "string",  "desc": "CMK for Kubernetes secrets encryption"},
        {"op": "get_cluster",       "resource": "cluster", "field": "endpoint_config",                         "type": "object",  "desc": "API server endpoint config (public/private)"},
        {"op": "get_cluster",       "resource": "cluster", "field": "options",                                  "type": "object",  "desc": "Cluster options (pod security, networking)"},
        {"op": "get_cluster",       "resource": "cluster", "field": "image_policy_config",                     "type": "object",  "desc": "Image signature policy config"},
        {"op": "get_cluster",       "resource": "cluster", "field": "kubernetes_version",                      "type": "string",  "desc": "Kubernetes version"},
        {"op": "get_node_pool",     "resource": "node_pool",   "field": "node_config_details",                 "type": "object",  "desc": "Node pool config (shape, subnet, NSG)"},
        {"op": "get_node_pool",     "resource": "node_pool",   "field": "kubernetes_version",                  "type": "string",  "desc": "Node pool k8s version"},
    ],
    "object_storage": [
        {"op": "get_bucket",        "resource": "bucket", "field": "kms_key_id",                               "type": "string",  "desc": "CMK for bucket encryption"},
        {"op": "get_bucket",        "resource": "bucket", "field": "public_access_type",                       "type": "string",  "desc": "NoPublicAccess/ObjectRead/ObjectReadWithoutList"},
        {"op": "get_bucket",        "resource": "bucket", "field": "storage_tier",                             "type": "string",  "desc": "Standard or Archive"},
        {"op": "get_bucket",        "resource": "bucket", "field": "versioning",                               "type": "string",  "desc": "Enabled/Suspended/Disabled"},
        {"op": "get_bucket",        "resource": "bucket", "field": "object_lifecycle_policy_etag",             "type": "string",  "desc": "Set if lifecycle policy exists"},
        {"op": "get_bucket",        "resource": "bucket", "field": "replication_enabled",                      "type": "boolean", "desc": "Cross-region replication enabled"},
    ],
    "block_storage": [
        {"op": "get_volume",        "resource": "volume",       "field": "kms_key_id",                         "type": "string",  "desc": "CMK for volume encryption"},
        {"op": "get_volume",        "resource": "volume",       "field": "volume_backup_policy_assignment_id", "type": "string",  "desc": "Backup policy assignment OCID"},
        {"op": "get_volume",        "resource": "volume",       "field": "is_auto_tune_enabled",               "type": "boolean", "desc": "Auto-tune enabled"},
        {"op": "get_boot_volume",   "resource": "boot_volume",  "field": "kms_key_id",                         "type": "string",  "desc": "CMK for boot volume encryption"},
        {"op": "get_boot_volume",   "resource": "boot_volume",  "field": "volume_backup_policy_assignment_id", "type": "string",  "desc": "Backup policy assignment OCID"},
    ],
    "key_management": [
        {"op": "get_key",           "resource": "key",   "field": "algorithm",                                 "type": "string",  "desc": "AES/RSA/ECDSA"},
        {"op": "get_key",           "resource": "key",   "field": "key_shape",                                 "type": "object",  "desc": "Key algorithm + length"},
        {"op": "get_key",           "resource": "key",   "field": "protection_mode",                           "type": "string",  "desc": "HSM or SOFTWARE"},
        {"op": "get_key",           "resource": "key",   "field": "current_key_version",                       "type": "string",  "desc": "Current key version OCID"},
        {"op": "get_vault",         "resource": "vault", "field": "vault_type",                                "type": "string",  "desc": "DEFAULT/VIRTUAL_PRIVATE"},
        {"op": "get_vault",         "resource": "vault", "field": "crypto_endpoint",                           "type": "string",  "desc": "Crypto API endpoint"},
        {"op": "get_vault",         "resource": "vault", "field": "management_endpoint",                       "type": "string",  "desc": "Management API endpoint"},
    ],
    "virtual_network": [
        {"op": "get_security_list", "resource": "security_list", "field": "ingress_security_rules",            "type": "array",   "desc": "Ingress security rules"},
        {"op": "get_security_list", "resource": "security_list", "field": "egress_security_rules",             "type": "array",   "desc": "Egress security rules"},
        {"op": "get_subnet",        "resource": "subnet",         "field": "prohibit_public_ip_on_vnic",       "type": "boolean", "desc": "Block public IPs on subnet"},
        {"op": "get_subnet",        "resource": "subnet",         "field": "prohibit_internet_ingress",        "type": "boolean", "desc": "Block internet ingress on subnet"},
        {"op": "get_vcn",           "resource": "vcn",            "field": "dns_label",                        "type": "string",  "desc": "VCN DNS label"},
        {"op": "get_vcn",           "resource": "vcn",            "field": "ipv6_cidr_blocks",                 "type": "array",   "desc": "IPv6 CIDRs"},
        {"op": "get_network_security_group", "resource": "network_security_group", "field": "security_rules",  "type": "array",   "desc": "NSG security rules"},
    ],
    "mysql": [
        {"op": "get_db_system",     "resource": "db_system", "field": "kms_key_id",                            "type": "string",  "desc": "CMK for MySQL data at rest"},
        {"op": "get_db_system",     "resource": "db_system", "field": "is_deletion_protected",                 "type": "boolean", "desc": "Deletion protection enabled"},
        {"op": "get_db_system",     "resource": "db_system", "field": "backup_policy",                         "type": "object",  "desc": "Backup policy config"},
        {"op": "get_db_system",     "resource": "db_system", "field": "crash_recovery",                        "type": "string",  "desc": "ENABLED/DISABLED"},
        {"op": "get_db_system",     "resource": "db_system", "field": "maintenance",                           "type": "object",  "desc": "Maintenance window config"},
    ],
    "functions": [
        {"op": "get_application",   "resource": "application", "field": "config",                              "type": "object",  "desc": "Application config key-value pairs"},
        {"op": "get_application",   "resource": "application", "field": "network_security_group_ids",         "type": "array",   "desc": "NSG OCIDs"},
        {"op": "get_application",   "resource": "application", "field": "subnet_ids",                         "type": "array",   "desc": "Subnet OCIDs (private)"},
        {"op": "get_application",   "resource": "application", "field": "syslog_url",                         "type": "string",  "desc": "Syslog endpoint"},
        {"op": "get_application",   "resource": "application", "field": "trace_config",                       "type": "object",  "desc": "Tracing configuration"},
        {"op": "get_application",   "resource": "application", "field": "image_policy_config",                "type": "object",  "desc": "Container image policy config"},
    ],
    "nosql": [
        {"op": "get_table",         "resource": "table", "field": "ddl_statement",                             "type": "string",  "desc": "DDL that created the table"},
        {"op": "get_table",         "resource": "table", "field": "schema",                                    "type": "object",  "desc": "Table schema"},
        {"op": "get_table",         "resource": "table", "field": "is_auto_reclaimable",                       "type": "boolean", "desc": "Auto reclaim enabled"},
        {"op": "get_table",         "resource": "table", "field": "kms_key",                                   "type": "object",  "desc": "Customer-managed encryption key"},
    ],
    "bds": [
        {"op": "get_bds_instance",  "resource": "bds_instance", "field": "kms_key_id",                        "type": "string",  "desc": "CMK encryption key OCID"},
        {"op": "get_bds_instance",  "resource": "bds_instance", "field": "is_high_availability",              "type": "boolean", "desc": "High availability cluster"},
        {"op": "get_bds_instance",  "resource": "bds_instance", "field": "is_secure",                         "type": "boolean", "desc": "Kerberos security enabled"},
        {"op": "get_bds_instance",  "resource": "bds_instance", "field": "cluster_details",                   "type": "object",  "desc": "Cluster metadata (URLs, versions)"},
        {"op": "get_bds_instance",  "resource": "bds_instance", "field": "network_config",                    "type": "object",  "desc": "Network configuration"},
    ],
    "streaming": [
        {"op": "get_stream_pool",   "resource": "stream_pool", "field": "kms_key",                             "type": "object",  "desc": "CMK config"},
        {"op": "get_stream_pool",   "resource": "stream_pool", "field": "custom_encryption_key",               "type": "object",  "desc": "Custom encryption key details"},
        {"op": "get_stream_pool",   "resource": "stream_pool", "field": "private_endpoint_settings",          "type": "object",  "desc": "Private endpoint config"},
        {"op": "get_stream",        "resource": "stream",      "field": "stream_pool_id",                      "type": "string",  "desc": "Parent stream pool OCID"},
        {"op": "get_stream",        "resource": "stream",      "field": "messages_endpoint",                   "type": "string",  "desc": "Messages API endpoint"},
    ],
    "events": [
        {"op": "get_rule",          "resource": "rule", "field": "actions",                                    "type": "object",  "desc": "Rule action config (destinations)"},
        {"op": "get_rule",          "resource": "rule", "field": "condition",                                   "type": "string",  "desc": "Rule filter condition"},
        {"op": "get_rule",          "resource": "rule", "field": "is_enabled",                                  "type": "boolean", "desc": "Rule is enabled"},
    ],
    "logging": [
        {"op": "get_log",           "resource": "log", "field": "configuration",                               "type": "object",  "desc": "Log configuration"},
        {"op": "get_log",           "resource": "log", "field": "is_enabled",                                   "type": "boolean", "desc": "Log is enabled"},
        {"op": "get_log",           "resource": "log", "field": "retention_duration",                          "type": "integer", "desc": "Retention in days"},
        {"op": "get_log",           "resource": "log", "field": "log_type",                                    "type": "string",  "desc": "CUSTOM/SERVICE"},
        {"op": "get_log_group",     "resource": "log_group", "field": "configuration",                         "type": "object",  "desc": "Log group configuration"},
    ],
    "monitoring": [
        {"op": "get_alarm",         "resource": "alarm", "field": "destinations",                              "type": "array",   "desc": "OCID of notification topics"},
        {"op": "get_alarm",         "resource": "alarm", "field": "is_notifications_per_metric_dimension_enabled", "type": "boolean", "desc": "Per-dimension notifications"},
        {"op": "get_alarm",         "resource": "alarm", "field": "suppression",                               "type": "object",  "desc": "Alarm suppression config"},
        {"op": "get_alarm",         "resource": "alarm", "field": "query",                                     "type": "string",  "desc": "MQL query string"},
        {"op": "get_alarm",         "resource": "alarm", "field": "resolution",                                "type": "string",  "desc": "Evaluation interval"},
    ],
    "file_storage": [
        {"op": "get_file_system",   "resource": "file_system", "field": "kms_key_id",                         "type": "string",  "desc": "CMK for file system encryption"},
        {"op": "get_file_system",   "resource": "file_system", "field": "is_clone_parent",                     "type": "boolean", "desc": "Is clone parent"},
        {"op": "get_mount_target",  "resource": "mount_target", "field": "idmap_type",                        "type": "string",  "desc": "Identity mapping type"},
        {"op": "get_mount_target",  "resource": "mount_target", "field": "kerberos",                          "type": "object",  "desc": "Kerberos authentication config"},
        {"op": "get_mount_target",  "resource": "mount_target", "field": "ldap_idmap",                        "type": "object",  "desc": "LDAP identity mapping config"},
        {"op": "get_export",        "resource": "export",       "field": "export_options",                    "type": "array",   "desc": "NFS export options (access, auth)"},
    ],
    "data_science": [
        {"op": "get_notebook_session", "resource": "notebook_session", "field": "notebook_session_runtime_config_details", "type": "object", "desc": "Runtime config"},
        {"op": "get_notebook_session", "resource": "notebook_session", "field": "notebook_session_config_details",          "type": "object", "desc": "Subnet/NSG/block storage config"},
        {"op": "get_model_deployment", "resource": "model_deployment",  "field": "model_deployment_configuration_details",  "type": "object", "desc": "Deployment config"},
        {"op": "get_model_deployment", "resource": "model_deployment",  "field": "category_log_details",                    "type": "object", "desc": "Log category config"},
    ],
    "data_flow": [
        {"op": "get_application",   "resource": "application", "field": "private_endpoint_id",                "type": "string",  "desc": "Private endpoint OCID"},
        {"op": "get_application",   "resource": "application", "field": "logs_bucket_uri",                    "type": "string",  "desc": "Logs destination bucket"},
        {"op": "get_application",   "resource": "application", "field": "warehouse_bucket_uri",               "type": "string",  "desc": "Warehouse bucket URI"},
        {"op": "get_application",   "resource": "application", "field": "driver_shape_config",                "type": "object",  "desc": "Driver shape config"},
    ],
    "waf": [
        {"op": "get_web_app_firewall", "resource": "web_app_firewall", "field": "web_app_firewall_policy_id",  "type": "string",  "desc": "Attached WAF policy OCID"},
        {"op": "get_web_app_firewall", "resource": "web_app_firewall", "field": "backend_type",                "type": "string",  "desc": "LOAD_BALANCER or other"},
    ],
}


# ── Rule condition mapping: pattern → (field_suffix, op, value) ───────────────
# Evaluated in order; first match wins.
# field_suffix is appended to resource prefix: item.{resource}.{field_suffix}
# Use None to mark NEEDS_NEW_OP or MANUAL (no auto-fix).

RULE_PATTERNS: list[tuple[list[str], str | None, str | None, str | None]] = [
    # ── Encryption / CMK ──────────────────────────────────────────────────────
    (["customer_managed_key", "cmek", "cmk", "kms_key",
      "encrypted_at_rest", "encryption_at_rest",
      "encrypt"],                                          "kms_key_id",            "exists", None),

    # ── Encryption in transit ─────────────────────────────────────────────────
    (["pv_encryption_in_transit", "encryption_in_transit",
      "encrypted_in_transit"],                             "is_pv_encryption_in_transit_enabled", "equals", "true"),

    # ── Backup ────────────────────────────────────────────────────────────────
    (["auto_backup_enabled", "backup_enabled",
      "backup_coverage"],                                  "is_auto_backup_enabled",  "equals", "true"),
    (["backup_retention_days", "backup_retention"],        "backup_retention_period_in_days", "exists", None),
    (["deletion_protected", "delete_protection"],          "is_deletion_protected",   "equals", "true"),

    # ── Network / Private access ──────────────────────────────────────────────
    (["public_ip_enabled", "publicly_accessible",
      "public_access_blocked", "public_access_disabled",
      "not_publicly_shared", "public_sharing_disabled",
      "public_embeds_disabled", "public_access"],          "network_endpoint_details", "exists", None),
    (["private_networking_enforced", "private_subnets_only",
      "private_restricted", "private_networking",
      "private_access", "network_endpoint_access"],        "network_endpoint_details", "exists", None),
    (["prohibit_public_ip"],                               "prohibit_public_ip_on_vnic", "equals", "true"),
    (["prohibit_internet_ingress"],                        "prohibit_internet_ingress",  "equals", "true"),

    # ── SSL / TLS ─────────────────────────────────────────────────────────────
    (["ssl_required", "ssl_enabled", "tls_required", "tls_enabled"], "is_ssl_enabled", "equals", "true"),

    # ── Platform security ─────────────────────────────────────────────────────
    (["secure_boot"],                                      "platform_config", "exists", None),
    (["trusted_platform_module", "tpm_enabled"],           "platform_config", "exists", None),
    (["imdsv2_enabled", "imds_v2"],                        "metadata",        "exists", None),

    # ── Object storage ────────────────────────────────────────────────────────
    (["versioning_enabled", "versioning"],                 "versioning",              "equals", "Enabled"),
    (["public_access_type"],                               "public_access_type",      "equals", "NoPublicAccess"),
    (["lifecycle_policy"],                                 "object_lifecycle_policy_etag", "exists", None),
    (["replication_enabled", "cross_region_replication"],  "replication_enabled",     "equals", "true"),

    # ── Tags / Governance ─────────────────────────────────────────────────────
    (["defined_tags"],                                     "defined_tags",            "not_empty", None),

    # ── Data Safe (database) ─────────────────────────────────────────────────
    (["data_safe"],                                        "data_safe_status",        "equals", "REGISTERED"),

    # ── Container / K8s security ─────────────────────────────────────────────
    (["pod_security_policy"],                              "options",                 "exists", None),
    (["image_policy", "signed_images"],                    "image_policy_config",     "exists", None),
    (["endpoint_access_restricted", "endpoint_config"],    "endpoint_config",         "exists", None),

    # ── File storage ─────────────────────────────────────────────────────────
    (["export_options", "nfs_access"],                     "export_options",          "exists", None),

    # ── Logging / Audit (NEEDS_NEW_OP — separate service calls) ──────────────
    # These cannot be checked via the resource's own get_ API.
    (["audit_log", "audit_logging", "audit_retention",
      "centralized_log", "cloudwatch_logging",
      "monitoring_logs", "monitoring_logging",
      "monitoring_admin_activity", "monitoring_query_access",
      "monitoring_outputs", "monitoring_private_networking",
      "logs_retention", "retention_days"],                 None, None, None),

    # ── IAM / Identity (NEEDS_NEW_OP) ────────────────────────────────────────
    (["mfa_required", "mfa_enforced", "mfa_enabled",
      "sso_required", "sso_enforced",
      "least_privilege", "roles_minimal",
      "access_policies", "group_roles",
      "rbac_least_privilege", "external_sharing_restricted"],
                                                           None, None, None),

    # ── Application-layer / MANUAL ────────────────────────────────────────────
    # These are app-level settings not surfaced via OCI infrastructure API.
    (["dashboard", "workgroup", "query_definition",
      "dataset_public", "dataset_row_level",
      "event_subscription", "snapshot_cmk_policy",
      "traffic_analysis_ids", "allowed_data_sources",
      "anomaly_destination", "anomaly_alert",
      "custom_identifier", "service_domains"],             None, None, None),
]


# ── Resource prefix detection ─────────────────────────────────────────────────

def infer_resource(var: str) -> str:
    """'item.analytics_instance.status' → 'analytics_instance'"""
    parts = var.replace("item.", "", 1).split(".")
    return parts[0] if len(parts) > 1 else ""


# ── Step 1: Enrich step2 output_fields ───────────────────────────────────────

def enrich_step2(service: str, new_fields: list[dict], dry_run: bool) -> int:
    """Add missing fields to step2_read_operation_registry.json."""
    s2_path = BASE_OCI / service / "step2_read_operation_registry.json"
    if not s2_path.exists():
        print(f"  [SKIP] {service}: no step2 file")
        return 0

    data = json.loads(s2_path.read_text())
    ops  = data.get("operations", {})
    added = 0

    for nf in new_fields:
        op_name = nf["op"]
        if op_name not in ops:
            continue  # op not in registry
        op_data = ops[op_name]
        out_flds = op_data.get("output_fields", {})

        if isinstance(out_flds, list):
            if nf["field"] not in out_flds:
                if not dry_run:
                    out_flds.append(nf["field"])
                added += 1
        elif isinstance(out_flds, dict):
            if nf["field"] not in out_flds:
                if not dry_run:
                    out_flds[nf["field"]] = {
                        "type": nf["type"],
                        "path": f"_{nf['resource']}.{nf['field']}",
                        "entity": f"oci.{service}.{nf['resource']}.{nf['field']}"
                    }
                added += 1

    if not dry_run and added:
        s2_path.write_text(json.dumps(data, indent=2))
    return added


# ── Step 2: Add rows to master field catalog ──────────────────────────────────

def get_existing_field_paths(service: str) -> set[str]:
    existing = set()
    for r in csv.DictReader(open(MASTER_CSV)):
        if r["service"] == service:
            existing.add(r["field_path"])
    return existing


def build_catalog_rows(service: str, new_fields: list[dict],
                       existing_fields: set[str]) -> list[dict]:
    """Build master catalog rows for new security fields."""
    rows = []
    # Find the root_op for each get_ op (needs list_ parent)
    s2_path = BASE_OCI / service / "step2_read_operation_registry.json"
    if not s2_path.exists():
        return rows
    ops = json.loads(s2_path.read_text()).get("operations", {})

    for nf in new_fields:
        fp = f"{nf['resource']}.{nf['field']}"
        if fp in existing_fields:
            continue  # already in catalog

        op_name  = nf["op"]
        op_data  = ops.get(op_name, {})
        op_full  = f"oci.{service}.{op_name}"
        is_indep = op_data.get("independent", False)

        # Find the list_ op that feeds this get_
        # Look for a list_ op whose output_fields contain ocid and that is independent
        root_op = op_full  # fallback
        for list_op, list_meta in ops.items():
            if list_meta.get("kind") == "read_list" and list_meta.get("independent", False):
                of = list_meta.get("output_fields", {})
                if isinstance(of, dict) and "ocid" in of:
                    root_op = f"oci.{service}.{list_op}"
                    break
                elif isinstance(of, list) and "ocid" in of:
                    root_op = f"oci.{service}.{list_op}"
                    break

        # Determine chain
        if is_indep:
            chain_ops    = op_full
            chain_length = "1"
            hop_distance = "0"
        else:
            chain_ops    = f"{root_op} → {op_full}"
            chain_length = "2"
            hop_distance = "1"

        # Operators based on type
        ftype = nf["type"]
        if ftype == "boolean":
            operators = "equals, not_equals"
            ops_no_val = ""
        elif ftype == "array":
            operators = "exists, not_empty, contains"
            ops_no_val = "exists, not_empty"
        elif ftype == "object":
            operators = "exists, not_empty"
            ops_no_val = "exists, not_empty"
        else:
            operators = "equals, exists, not_equals"
            ops_no_val = "exists"

        rows.append({
            "csp":                    "oci",
            "service":                service,
            "field_path":             fp,
            "item_var_path":          f"item.{fp}",
            "field_type":             ftype,
            "is_id":                  "No",
            "producing_op":           op_full,
            "op_kind":                "read_get",
            "is_independent":         "Yes" if is_indep else "No",
            "root_op":                root_op,
            "chain_ops":              chain_ops,
            "chain_length":           chain_length,
            "hop_distance":           hop_distance,
            "chain_ops_with_fields":  chain_ops,
            "operators":              operators,
            "operators_no_value":     ops_no_val,
            "python_call":            "",
            "http_path":              "",
            "resource_type":          nf["resource"],
            "resource_id_field":      "ocid",
            "resource_id_param":      "",
        })
    return rows


def append_to_master_catalog(new_rows: list[dict], dry_run: bool) -> int:
    """Append new field rows to master catalog CSV."""
    if not new_rows:
        return 0
    if dry_run:
        return len(new_rows)

    # Read existing to get fieldnames
    existing = list(csv.DictReader(open(MASTER_CSV)))
    fieldnames = list(existing[0].keys()) if existing else list(new_rows[0].keys())

    with open(MASTER_CSV, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        for r in new_rows:
            # Fill missing columns with ""
            row = {k: "" for k in fieldnames}
            row.update(r)
            w.writerow(row)
    return len(new_rows)


# ── Step 3: Fix check rule YAML conditions ────────────────────────────────────

def match_rule_pattern(check_name: str) -> tuple[str | None, str | None, str | None]:
    """
    Returns (field_suffix, op, value) or (None, None, None) if can't auto-fix.
    check_name = last segment of rule_id.
    """
    low = check_name.lower()
    for keywords, field, op, value in RULE_PATTERNS:
        if any(kw in low for kw in keywords):
            return field, op, value
    return None, None, None


def fix_check_yaml(service: str, dry_run: bool) -> dict[str, int]:
    """Fix placeholder conditions in a service's check YAML. Returns stats."""
    chk_file = RULES_BASE / service / f"{service}.checks.yaml"
    if not chk_file.exists():
        return {}

    data = yaml.safe_load(chk_file.read_text()) or {}
    checks = data.get("checks", [])
    stats  = defaultdict(int)
    changed = False

    for chk in checks:
        rule_id  = chk.get("rule_id", "")
        cond     = chk.get("conditions", {})
        curr_var = cond.get("var", "")
        check_name = rule_id.split(".")[-1]
        resource   = infer_resource(curr_var)

        field_sfx, new_op, new_val = match_rule_pattern(check_name)

        if field_sfx is None:
            # Cannot auto-fix (NEEDS_NEW_OP or MANUAL)
            stats["skip"] += 1
            continue

        new_var = f"item.{resource}.{field_sfx}" if resource else f"item.{field_sfx}"

        # Check if already correct
        if cond.get("var") == new_var and cond.get("op") == new_op:
            stats["already_correct"] += 1
            continue

        # Update condition
        stats["fixed"] += 1
        if not dry_run:
            cond["var"]   = new_var
            cond["op"]    = new_op
            cond["value"] = new_val
            changed = True
            if new_val is None:
                cond.pop("value", None)

    if changed and not dry_run:
        # Write back with preserved structure
        out = yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)
        chk_file.write_text(out)

    return stats


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run",  action="store_true")
    ap.add_argument("--service",  default=None, help="Process single service only")
    args = ap.parse_args()

    services = list(NEW_SECURITY_FIELDS.keys())
    if args.service:
        services = [s for s in services if s == args.service]

    total_s2   = 0
    total_cat  = 0
    total_yaml = 0
    total_skip = 0

    for svc in services:
        nf_list = NEW_SECURITY_FIELDS[svc]
        print(f"\n{'='*60}")
        print(f"Service: {svc}  ({len(nf_list)} new fields)")

        # Step 1: step2
        s2_added = enrich_step2(svc, nf_list, args.dry_run)
        print(f"  step2 fields added  : {s2_added}")
        total_s2 += s2_added

        # Step 2: master catalog
        existing = get_existing_field_paths(svc)
        new_rows = build_catalog_rows(svc, nf_list, existing)
        cat_added = append_to_master_catalog(new_rows, args.dry_run)
        print(f"  master catalog rows : {cat_added}")
        total_cat += cat_added

        # Step 3: fix check YAMLs
        stats = fix_check_yaml(svc, args.dry_run)
        fixed = stats.get("fixed", 0)
        skip  = stats.get("skip", 0)
        corr  = stats.get("already_correct", 0)
        print(f"  check YAML fixed    : {fixed}  (already correct: {corr}  skipped: {skip})")
        total_yaml += fixed
        total_skip += skip

    print(f"\n{'='*60}")
    print(f"TOTALS  (dry_run={args.dry_run})")
    print(f"  step2 fields added     : {total_s2}")
    print(f"  master catalog rows    : {total_cat}")
    print(f"  check YAML conditions  : {total_yaml} fixed  |  {total_skip} skipped (MANUAL/NEEDS_NEW_OP)")

    if not args.dry_run:
        # Rebuild unified catalog
        print(f"\nRebuilding unified catalog...")
        import subprocess, sys
        r = subprocess.run(
            [sys.executable, str(BASE_OCI / "merge_field_rule_catalog.py")],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            print(r.stdout)
        else:
            print("ERROR:", r.stderr[:500])
    else:
        print("\n(dry-run: no files written, no catalog rebuild)")


if __name__ == "__main__":
    main()
