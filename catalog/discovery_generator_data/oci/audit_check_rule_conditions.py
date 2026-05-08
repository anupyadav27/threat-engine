#!/usr/bin/env python3
"""
Audit OCI check rule conditions vs. actual security intent.

For each rule whose condition is a placeholder (all rules using the same var),
infer the correct field and operation from the rule_id keyword semantics.

Output:
  oci_rule_condition_audit.csv  — one row per rule, shows:
    current_var, intended_field, intended_op, status

Status values:
  CORRECT         — condition already maps to right field
  FIXABLE         — correct field exists in master catalog, condition wrong
  NEEDS_NEW_FIELD — field not in catalog; must add to step2 + rebuild catalog
  NEEDS_NEW_OP    — needs additional discovery op (different service, e.g. logging)
  MANUAL          — app-layer setting, not checkable via OCI infrastructure API
"""

from __future__ import annotations
import csv, json, re, yaml
from collections import defaultdict
from pathlib import Path

BASE_OCI   = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/oci")
RULES_BASE = Path("/Users/apple/Desktop/threat-engine/catalog/rule/oci_rule_check")
MASTER_CSV = BASE_OCI / "oci_master_field_catalog.csv"
OUTPUT_CSV = BASE_OCI / "oci_rule_condition_audit.csv"

# ── Load master catalog field paths per service ───────────────────────────────

def load_catalog_fields() -> dict[str, set[str]]:
    """service → set of field_path values in master catalog."""
    result: dict[str, set[str]] = defaultdict(set)
    for r in csv.DictReader(open(MASTER_CSV)):
        result[r["service"]].add(r["field_path"])
    return result


# ── OCI API fields known but NOT yet in our catalog ──────────────────────────
# These exist in the real OCI API but weren't put into step2 output_fields.
# Keyed by service → set of field names.

OCI_KNOWN_FIELDS: dict[str, set[str]] = {
    "analytics": {
        "analytics_instance.kms_key_id",
        "analytics_instance.network_endpoint_details",
        "analytics_instance.network_endpoint_details.network_endpoint_type",
        "analytics_instance.license_type",
        "analytics_instance.feature_set",
        "analytics_instance.email_notification",
        "analytics_instance.capacity",
        "analytics_instance.private_access_channels",
        "analytics_instance.vanity_url_details",
    },
    "database": {
        "autonomous_database.kms_key_id",
        "autonomous_database.is_auto_backup_enabled",
        "autonomous_database.backup_retention_period_in_days",
        "autonomous_database.subnet_id",
        "autonomous_database.private_endpoint",
        "autonomous_database.private_endpoint_ip",
        "autonomous_database.private_endpoint_label",
        "autonomous_database.nsg_ids",
        "autonomous_database.whitelisted_ips",
        "autonomous_database.are_primary_whitelisted_ips_used",
        "autonomous_database.data_safe_status",
        "autonomous_database.operations_insights_status",
        "autonomous_database.database_management_status",
        "autonomous_database.db_version",
        "autonomous_database.db_workload",
        "autonomous_database.is_auto_scaling_enabled",
        "autonomous_database.is_free_tier",
        "autonomous_database.customer_contacts",
        "autonomous_database.open_mode",
        "autonomous_database.permission_level",
    },
    "compute": {
        "instance.kms_key_id",
        "instance.is_pv_encryption_in_transit_enabled",
        "instance.launch_options.is_consistent_volume_naming_enabled",
        "instance.launch_options.is_pv_encryption_in_transit_enabled",
        "instance.platform_config.is_secure_boot_enabled",
        "instance.platform_config.is_trusted_platform_module_enabled",
        "instance.platform_config.is_measured_boot_enabled",
        "instance.agent_config.is_monitoring_disabled",
        "instance.agent_config.is_management_disabled",
        "instance.agent_config.plugins_config",
    },
    "container_engine": {
        "cluster.kms_key_id",
        "cluster.endpoint_config.is_public_ip_enabled",
        "cluster.endpoint_config.nsg_ids",
        "cluster.options.is_pod_security_policy_enabled",
        "cluster.options.kubernetes_network_config",
        "cluster.image_policy_config.is_policy_enabled",
        "cluster.kubernetes_version",
    },
    "object_storage": {
        "bucket.kms_key_id",
        "bucket.public_access_type",
        "bucket.storage_tier",
        "bucket.versioning",
        "bucket.replication_enabled",
        "bucket.object_lifecycle_policy_etag",
    },
    "key_management": {
        "key.algorithm",
        "key.key_shape",
        "key.protection_mode",
        "key.current_key_version",
        "key.vault_id",
        "vault.vault_type",
        "vault.crypto_endpoint",
        "vault.management_endpoint",
    },
    "virtual_network": {
        "vcn.default_security_list_id",
        "vcn.dns_label",
        "vcn.ipv6_cidr_blocks",
        "security_list.ingress_security_rules",
        "security_list.egress_security_rules",
        "network_security_group.security_rules",
        "subnet.prohibit_public_ip_on_vnic",
        "subnet.prohibit_internet_ingress",
    },
    "bds": {
        "bds_instance.kms_key_id",
        "bds_instance.is_cloud_sql_configured",
        "bds_instance.is_high_availability",
        "bds_instance.is_secure",
        "bds_instance.cluster_version",
        "bds_instance.cluster_details",
        "bds_instance.network_config",
    },
    "mysql": {
        "db_system.kms_key_id",
        "db_system.is_deletion_protected",
        "db_system.backup_policy",
        "db_system.configuration_id",
        "db_system.crash_recovery",
        "db_system.database_management",
        "db_system.maintenance",
        "db_system.point_in_time_recovery_details",
    },
    "nosql": {
        "table.ddl_statement",
        "table.is_auto_reclaimable",
        "table.lifecycle_details",
        "table.schema",
    },
    "data_catalog": {
        "catalog.service_api_url",
        "catalog.service_console_url",
        "catalog.attached_catalog_private_endpoints",
    },
    "functions": {
        "application.config",
        "application.network_security_group_ids",
        "application.subnet_ids",
        "application.syslog_url",
        "application.trace_config",
        "application.image_policy_config.is_policy_enabled",
    },
    "monitoring": {
        "alarm.body",
        "alarm.destinations",
        "alarm.is_notifications_per_metric_dimension_enabled",
        "alarm.message_format",
        "alarm.query",
        "alarm.resolution",
        "alarm.suppression",
    },
    "events": {
        "rule.actions",
        "rule.condition",
        "rule.description",
        "rule.is_enabled",
    },
    "logging": {
        "log_group.configuration",
        "log.configuration",
        "log.is_enabled",
        "log.retention_duration",
        "log.log_type",
    },
    "data_flow": {
        "application.archive_uri",
        "application.driver_shape",
        "application.executor_shape",
        "application.logs_bucket_uri",
        "application.private_endpoint_id",
        "application.warehouse_bucket_uri",
    },
    "cloud_guard": {
        "target.recipe_count",
        "target.target_resource_type",
        "target.target_detector_recipes",
        "target.target_responder_recipes",
    },
}


# ── Keyword → (intended_field_suffix, op, value) ─────────────────────────────
# Ordered from most-specific to least-specific.
# field_suffix is appended to the resource prefix (e.g. "analytics_instance.")
# Use None for NEEDS_NEW_OP or MANUAL.

KEYWORD_RULES: list[tuple[list[str], str | None, str | None, str | None]] = [
    # Encryption / KMS (most specific first)
    (["customer_managed_key", "cmek", "kms_key"],
        "kms_key_id", "exists", None),
    (["encrypted_at_rest", "encryption_at_rest", "encrypted_and_private", "encrypted_in_transit"],
        "kms_key_id", "exists", None),
    (["encrypted", "encryption_enabled", "encrypt"],
        "kms_key_id", "exists", None),

    # Backup
    (["auto_backup", "backup_enabled", "backup_retention_days", "backup_policy"],
        "is_auto_backup_enabled", "equals", "true"),

    # Network / Private access
    (["public_access_blocked", "not_publicly_shared", "publicly_accessible",
      "public_access_disabled", "public_sharing_disabled", "public_embeds_disabled",
      "public_access"],
        "network_endpoint_details", "exists", None),
    (["private_networking_enforced", "private_subnets_only", "private_restricted",
      "private_networking", "private_access", "private"],
        "network_endpoint_details", "exists", None),
    (["network_endpoint_access_restricted", "network_access_private"],
        "network_endpoint_details", "exists", None),

    # SSL / TLS
    (["ssl_required", "tls_required", "ssl_enabled", "tls_enabled"],
        "is_ssl_enabled", "equals", "true"),

    # Secure boot / platform security
    (["secure_boot"],
        "platform_config.is_secure_boot_enabled", "equals", "true"),
    (["trusted_platform_module", "tpm"],
        "platform_config.is_trusted_platform_module_enabled", "equals", "true"),

    # Encryption in transit (compute)
    (["pv_encryption_in_transit", "encryption_in_transit"],
        "is_pv_encryption_in_transit_enabled", "equals", "true"),

    # Tags / governance
    (["defined_tags_populated", "defined_tags_required", "tagging_enforced", "tagged"],
        "defined_tags", "not_empty", None),

    # Data classification / data safe (database)
    (["data_safe"],
        "data_safe_status", "equals", "REGISTERED"),

    # Pod security policy
    (["pod_security_policy"],
        "options.is_pod_security_policy_enabled", "equals", "true"),

    # Image policy (container)
    (["image_policy", "signed_images"],
        "image_policy_config.is_policy_enabled", "equals", "true"),

    # High availability / fault tolerant
    (["high_availability", "fault_tolerant", "multi_az"],
        "is_high_availability", "equals", "true"),

    # Deletion protection
    (["deletion_protected", "delete_protection"],
        "is_deletion_protected", "equals", "true"),

    # --- Fields that need additional discovery ops (NEEDS_NEW_OP) ---

    # Audit / logging (requires Logging service call)
    (["audit_log", "audit_logging", "audit_retention", "centralized_log",
      "cloudwatch_logging"],
        None, None, None),   # NEEDS_NEW_OP: Logging service

    # Monitoring / CloudWatch logs
    (["monitoring_logs", "monitoring_logging", "monitoring_admin_activity",
      "monitoring_query_access", "monitoring_roles", "monitoring_outputs",
      "monitoring_private_networking"],
        None, None, None),   # NEEDS_NEW_OP: Monitoring/Logging service

    # Alerts / notifications / destinations
    (["alert_destination", "notification_destination", "sns_topic"],
        "destinations", "not_empty", None),

    # Retention days
    (["retention_days", "logs_retention"],
        None, None, None),   # NEEDS_NEW_OP: Logging service

    # IAM / identity checks (require IAM service calls)
    (["mfa_required", "mfa_enforced", "mfa_enabled"],
        None, None, None),   # NEEDS_NEW_OP: Identity service
    (["sso_required", "sso_enforced"],
        None, None, None),   # NEEDS_NEW_OP: Identity/IDCS service
    (["least_privilege", "rbac", "access_policies", "roles_minimal",
      "external_sharing", "group_roles", "access_control"],
        None, None, None),   # NEEDS_NEW_OP: IAM/groups

    # Dashboard / workgroup / query / dataset (app-layer, not in infra API)
    (["dashboard", "workgroup", "query_definition", "dataset", "snapshot",
      "table_cmk", "service_domains", "traffic_analysis",
      "anomaly_destination", "anomaly_alert", "custom_identifier",
      "event_subscription", "allowed_data_sources", "row_level_security",
      "subnet_group"],
        None, None, None),   # MANUAL: app-layer setting
]

STATUS_NEEDS_NEW_OP = "NEEDS_NEW_OP"
STATUS_NEEDS_NEW_FIELD = "NEEDS_NEW_FIELD"
STATUS_FIXABLE = "FIXABLE"
STATUS_CORRECT = "CORRECT"
STATUS_MANUAL = "MANUAL"


def match_keyword(check_name: str) -> tuple[str | None, str | None, str | None, str]:
    """
    Returns (field_suffix, op, value, status) for a given check name.
    check_name = last segment of rule_id (e.g. 'snapshot_encrypted_at_rest_cmek')
    """
    low = check_name.lower()
    for keywords, field, op, value in KEYWORD_RULES:
        if any(kw in low for kw in keywords):
            if field is None:
                # Distinguish NEEDS_NEW_OP vs MANUAL
                app_layer = ["dashboard", "workgroup", "query_definition", "dataset",
                             "snapshot", "table_cmk", "service_domains", "traffic_analysis",
                             "anomaly_destination", "anomaly_alert", "custom_identifier",
                             "event_subscription", "allowed_data_sources", "row_level_security",
                             "subnet_group"]
                needs_new_op = ["audit_log", "audit_logging", "audit_retention",
                                "centralized_log", "cloudwatch_logging",
                                "monitoring_logs", "monitoring_logging",
                                "monitoring_admin_activity", "monitoring_query_access",
                                "monitoring_roles", "monitoring_outputs",
                                "monitoring_private_networking",
                                "alert_destination", "notification_destination",
                                "retention_days", "logs_retention",
                                "mfa_required", "mfa_enforced", "mfa_enabled",
                                "sso_required", "sso_enforced",
                                "least_privilege", "rbac", "access_policies",
                                "roles_minimal", "external_sharing", "group_roles",
                                "access_control"]
                if any(kw in low for kw in app_layer):
                    return None, None, None, STATUS_MANUAL
                elif any(kw in low for kw in needs_new_op):
                    return None, None, None, STATUS_NEEDS_NEW_OP
                else:
                    return None, None, None, STATUS_MANUAL
            return field, op, value, "NEEDS_FIELD_LOOKUP"
    # No keyword matched — if it's a plain "enabled/active" check it may be CORRECT
    if any(k in low for k in ["_enabled", "_active", "status"]) and "logging" not in low:
        return "status", "equals", "ACTIVE", "NEEDS_FIELD_LOOKUP"
    return None, None, None, STATUS_MANUAL


def resolve_status(
    service: str,
    resource_prefix: str,
    field_suffix: str | None,
    current_var: str,
    catalog_fields: dict[str, set[str]],
    intended_var: str | None,
) -> str:
    """Determine STATUS given intent vs. current catalog state."""
    if field_suffix is None:
        return STATUS_MANUAL  # already decided above

    # Build full intended field_path: resource_prefix + "." + field_suffix
    intended_fp = f"{resource_prefix}.{field_suffix}" if resource_prefix else field_suffix

    # Check if current var is already correct
    current_fp = current_var.replace("item.", "", 1) if current_var.startswith("item.") else current_var
    if current_fp == intended_fp:
        return STATUS_CORRECT

    # Is the intended field in the master catalog for this service?
    if intended_fp in catalog_fields.get(service, set()):
        return STATUS_FIXABLE

    # Is it in our OCI_KNOWN_FIELDS (real API, not yet in catalog)?
    known = OCI_KNOWN_FIELDS.get(service, set())
    # partial match: intended_fp might be a sub-field
    if any(intended_fp == kf or kf.startswith(intended_fp + ".") for kf in known):
        return STATUS_NEEDS_NEW_FIELD

    # Not in catalog or known fields
    return STATUS_NEEDS_NEW_FIELD


def infer_resource_prefix(var: str) -> str:
    """
    'item.analytics_instance.status' → 'analytics_instance'
    'item.status' → ''
    """
    parts = var.replace("item.", "").split(".")
    return parts[0] if len(parts) > 1 else ""


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    catalog_fields = load_catalog_fields()

    out_rows = []
    service_summary: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for svc_dir in sorted(RULES_BASE.iterdir()):
        chk_file = svc_dir / f"{svc_dir.name}.checks.yaml"
        if not chk_file.exists():
            continue
        data = yaml.safe_load(chk_file.read_text()) or {}
        checks = data.get("checks", [])
        if not checks:
            continue

        for chk in checks:
            rule_id  = chk.get("rule_id", "")
            cond     = chk.get("conditions", {})
            curr_var = cond.get("var", "")
            curr_op  = cond.get("op", "")
            curr_val = str(cond.get("value", "")) if cond.get("value") is not None else ""

            check_name = rule_id.split(".")[-1]   # e.g. 'snapshot_encrypted_at_rest_cmek'
            svc        = svc_dir.name
            rtype      = infer_resource_prefix(curr_var)

            field_suffix, int_op, int_val, status = match_keyword(check_name)

            intended_var = None
            if field_suffix is not None:
                intended_var = f"item.{rtype}.{field_suffix}" if rtype else f"item.{field_suffix}"
                # Resolve status
                status = resolve_status(
                    svc, rtype, field_suffix, curr_var,
                    catalog_fields, intended_var
                )
            else:
                # status is already STATUS_MANUAL or NEEDS_NEW_OP
                pass

            # Determine if current condition is already matching intent
            if curr_var == intended_var and curr_op == int_op:
                status = STATUS_CORRECT

            out_rows.append({
                "service":         svc,
                "rule_id":         rule_id,
                "check_name":      check_name,
                "current_var":     curr_var,
                "current_op":      curr_op,
                "current_value":   curr_val,
                "intended_var":    intended_var or "",
                "intended_op":     int_op or "",
                "intended_value":  int_val or "",
                "status":          status,
            })
            service_summary[svc][status] += 1

    # ── Write CSV ─────────────────────────────────────────────────────────────
    cols = ["service", "rule_id", "check_name",
            "current_var", "current_op", "current_value",
            "intended_var", "intended_op", "intended_value",
            "status"]
    with open(OUTPUT_CSV, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(out_rows)

    # ── Summary ───────────────────────────────────────────────────────────────
    total_by_status: dict[str, int] = defaultdict(int)
    print(f"\nAudit complete → {OUTPUT_CSV}")
    print(f"\n{'Service':<35} {'CORRECT':>8} {'FIXABLE':>8} {'NEW_FLD':>8} {'NEW_OP':>8} {'MANUAL':>8}  TOTAL")
    print("-" * 95)
    for svc in sorted(service_summary):
        s = service_summary[svc]
        tot = sum(s.values())
        print(f"  {svc:<33} "
              f"{s[STATUS_CORRECT]:>8} "
              f"{s[STATUS_FIXABLE]:>8} "
              f"{s[STATUS_NEEDS_NEW_FIELD]:>8} "
              f"{s[STATUS_NEEDS_NEW_OP]:>8} "
              f"{s[STATUS_MANUAL]:>8}  {tot}")
        for k, v in s.items():
            total_by_status[k] += v

    tot = sum(total_by_status.values())
    print("-" * 95)
    print(f"  {'TOTAL':<33} "
          f"{total_by_status[STATUS_CORRECT]:>8} "
          f"{total_by_status[STATUS_FIXABLE]:>8} "
          f"{total_by_status[STATUS_NEEDS_NEW_FIELD]:>8} "
          f"{total_by_status[STATUS_NEEDS_NEW_OP]:>8} "
          f"{total_by_status[STATUS_MANUAL]:>8}  {tot}")

    print(f"\nStatus legend:")
    print(f"  CORRECT         — condition already maps to right field ({total_by_status[STATUS_CORRECT]})")
    print(f"  FIXABLE         — right field exists in catalog; just update condition ({total_by_status[STATUS_FIXABLE]})")
    print(f"  NEEDS_NEW_FIELD — field must be added to step2 + catalog rebuild ({total_by_status[STATUS_NEEDS_NEW_FIELD]})")
    print(f"  NEEDS_NEW_OP    — needs additional discovery op (logging/IAM service) ({total_by_status[STATUS_NEEDS_NEW_OP]})")
    print(f"  MANUAL          — app-layer setting, not checkable via OCI infra API ({total_by_status[STATUS_MANUAL]})")

    # Print sample FIXABLE rows so user can see what will change
    fixable = [r for r in out_rows if r["status"] == STATUS_FIXABLE]
    if fixable:
        print(f"\nSample FIXABLE rows (can fix now):")
        for r in fixable[:10]:
            print(f"  {r['rule_id']}")
            print(f"    was : {r['current_var']} {r['current_op']} {r['current_value'] or '(none)'}")
            print(f"    fix : {r['intended_var']} {r['intended_op']} {r['intended_value'] or '(none)'}")

    needs_new = [r for r in out_rows if r["status"] == STATUS_NEEDS_NEW_FIELD]
    if needs_new:
        # Show unique new fields needed
        new_fields: dict[str, set[str]] = defaultdict(set)
        for r in needs_new:
            if r["intended_var"]:
                fp = r["intended_var"].replace("item.", "").strip(".")
                new_fields[r["service"]].add(fp)
        print(f"\nNew fields to add to step2 catalogs ({len(needs_new)} rules need them):")
        for svc in sorted(new_fields)[:10]:
            print(f"  {svc}:")
            for f in sorted(new_fields[svc]):
                print(f"    + {f}")


if __name__ == "__main__":
    main()
