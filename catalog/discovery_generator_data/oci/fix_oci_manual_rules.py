#!/usr/bin/env python3
"""
Second-pass fix for OCI check rules currently marked MANUAL.

Strategy per service:
  identity       → fix for_each + var based on rule name semantic (user/policy/api_key/group)
  monitoring     → alarm.is_enabled (better proxy than status)
  cloud_guard    → target_detector_recipes + target_responder_recipes
  container_engine → cluster security fields (endpoint_config, options, kms, k8s version)
  database       → private_endpoint, db_version, audit config
  data_catalog   → attached_catalog_private_endpoints, kms
  data_integration → is_private_network_enabled, endpoint_fqdns
  compute        → agent_config, platform_config, metadata (better proxies)
  Fallback       → defined_tags not_empty (governance indicator — better than status)

Run:
  python3 fix_oci_manual_rules.py
  python3 fix_oci_manual_rules.py --dry-run
  python3 fix_oci_manual_rules.py --service identity
"""

from __future__ import annotations
import argparse, csv, json, re, yaml
from collections import defaultdict
from pathlib import Path

BASE_OCI   = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/oci")
MASTER_CSV = BASE_OCI / "oci_master_field_catalog.csv"
RULES_BASE = Path("/Users/apple/Desktop/threat-engine/catalog/rule/oci_rule_check")

# ── Additional fields to add to step2 registries ─────────────────────────────

NEW_FIELDS_PASS2: dict[str, list[dict]] = {
    "identity": [
        {"op": "get_user",          "resource": "user",          "field": "is_blocked",           "type": "boolean", "desc": "User is blocked from sign-in"},
        {"op": "get_user",          "resource": "user",          "field": "email",                "type": "string",  "desc": "User email address"},
        {"op": "get_user",          "resource": "user",          "field": "is_mfa_activated",     "type": "boolean", "desc": "MFA is activated for this user"},
        {"op": "get_policy",        "resource": "policy",        "field": "statements",           "type": "array",   "desc": "IAM policy statement strings"},
        {"op": "get_policy",        "resource": "policy",        "field": "version_date",         "type": "string",  "desc": "Policy version date"},
        {"op": "list_api_keys",     "resource": "api_key",       "field": "time_created",         "type": "string",  "desc": "API key creation time (for rotation check)"},
        {"op": "list_api_keys",     "resource": "api_key",       "field": "fingerprint",          "type": "string",  "desc": "API key fingerprint"},
        {"op": "get_authentication_policy", "resource": "authentication_policy", "field": "password_policy", "type": "object", "desc": "Password complexity and rotation policy"},
        {"op": "get_authentication_policy", "resource": "authentication_policy", "field": "network_policy",  "type": "object", "desc": "Allowed network sources for auth"},
    ],
    "monitoring": [
        {"op": "get_alarm", "resource": "alarm", "field": "is_enabled",  "type": "boolean", "desc": "Alarm is enabled"},
        {"op": "get_alarm", "resource": "alarm", "field": "severity",    "type": "string",  "desc": "Alarm severity (CRITICAL/WARNING/INFO)"},
        {"op": "get_alarm", "resource": "alarm", "field": "body",        "type": "string",  "desc": "Alarm message body template"},
    ],
    "cloud_guard": [
        {"op": "get_target", "resource": "target", "field": "target_detector_recipes",  "type": "array",  "desc": "Detector recipes attached to this target"},
        {"op": "get_target", "resource": "target", "field": "target_responder_recipes", "type": "array",  "desc": "Responder recipes attached to this target"},
        {"op": "get_target", "resource": "target", "field": "inherited_by_compartments","type": "integer","desc": "Count of sub-compartments inheriting this target"},
        {"op": "get_detector_recipe", "resource": "detector_recipe", "field": "detector_rules", "type": "array", "desc": "Detector rules in this recipe"},
        {"op": "get_detector_recipe", "resource": "detector_recipe", "field": "owner",           "type": "string","desc": "CUSTOMER or ORACLE recipe owner"},
    ],
    "container_engine": [
        {"op": "get_cluster", "resource": "cluster", "field": "available_kubernetes_upgrades", "type": "array",   "desc": "Available k8s upgrade versions"},
        {"op": "get_node_pool","resource": "node_pool","field": "kubernetes_version",          "type": "string",  "desc": "Node pool k8s version"},
        {"op": "get_node_pool","resource": "node_pool","field": "node_source_details",         "type": "object",  "desc": "OS image source for nodes"},
        {"op": "get_addon",    "resource": "addon",    "field": "configurations",              "type": "array",   "desc": "Add-on configuration key-value pairs"},
        {"op": "get_addon",    "resource": "addon",    "field": "is_overriding_manually",      "type": "boolean", "desc": "Add-on is manually configured"},
    ],
    "data_integration": [
        {"op": "get_workspace", "resource": "workspace", "field": "is_private_network_enabled", "type": "boolean", "desc": "Workspace uses private networking"},
        {"op": "get_workspace", "resource": "workspace", "field": "endpoint_fqdns",             "type": "array",   "desc": "List of private endpoint FQDNs"},
        {"op": "get_workspace", "resource": "workspace", "field": "dns_server_ip",              "type": "string",  "desc": "Private DNS server IP"},
        {"op": "get_workspace", "resource": "workspace", "field": "endpoint_service_id",        "type": "string",  "desc": "VCN endpoint service OCID"},
    ],
    "data_catalog": [
        {"op": "get_catalog", "resource": "catalog", "field": "attached_catalog_private_endpoints", "type": "array",  "desc": "Private endpoint connections"},
        {"op": "get_catalog", "resource": "catalog", "field": "is_auto_harvesting_enabled",         "type": "boolean","desc": "Auto data harvesting is enabled"},
    ],
    "audit": [
        {"op": "get_configuration", "resource": "configuration", "field": "retention_period_days",              "type": "integer", "desc": "Audit log retention period in days"},
        {"op": "get_configuration", "resource": "configuration", "field": "is_advanced_data_security_enabled",  "type": "boolean", "desc": "Advanced Data Security enabled"},
    ],
    "data_safe": [
        {"op": "get_data_safe_configuration", "resource": "data_safe_configuration", "field": "is_enabled",      "type": "boolean", "desc": "Data Safe service is enabled"},
        {"op": "get_data_safe_configuration", "resource": "data_safe_configuration", "field": "url",             "type": "string",  "desc": "Data Safe URL"},
    ],
    "ons": [
        {"op": "get_topic",        "resource": "topic",        "field": "endpoint",   "type": "string", "desc": "Notification delivery endpoint"},
        {"op": "get_subscription", "resource": "subscription", "field": "protocol",   "type": "string", "desc": "Subscription protocol (EMAIL/SLACK/HTTPS/PAGERDUTY/SMS)"},
        {"op": "get_subscription", "resource": "subscription", "field": "endpoint",   "type": "string", "desc": "Subscription endpoint URL/email"},
    ],
    "resource_manager": [
        {"op": "get_stack", "resource": "stack", "field": "variables",          "type": "object", "desc": "Terraform variable values"},
        {"op": "get_stack", "resource": "stack", "field": "config_source",      "type": "object", "desc": "Stack config source (Git/zip/template)"},
        {"op": "get_stack", "resource": "stack", "field": "working_directory",  "type": "string", "desc": "Working directory within config source"},
    ],
}


# ── Service-specific rule fixing strategies ───────────────────────────────────
#
# Each strategy entry: (keyword_list, new_for_each_bare, new_var_suffix, op, value)
# new_for_each_bare = "" means keep current for_each unchanged
# new_var_suffix = field path relative to the resource (e.g. "is_enabled")
# The full var becomes: item.{resource_prefix}.{new_var_suffix}

IDENTITY_STRATEGIES: list[tuple[list[str], str, str, str, str | None]] = [
    # API key rotation checks → iterate over api_keys
    (["api_key", "access_key_rotation", "key_rotated"],
        "list_api_keys", "api_key.time_created", "exists", None),
    # MFA checks → iterate over users
    (["mfa_required", "mfa_enforced", "mfa_enabled", "require_mfa", "mfa_for"],
        "", "user.is_mfa_activated", "equals", "true"),
    # Avoid root / admin checks → check user is blocked / not admin
    (["avoid_root", "root_usage", "root_account"],
        "", "user.is_blocked", "equals", "false"),
    # Admin policy / privilege checks → iterate over policies
    (["admin_policy", "policy_admin", "no_admin", "policy_privilege",
      "policy_no_admin", "attach_policy", "policy_permission",
      "policy_restricted", "policy_least_privilege"],
        "list_policies", "policy.statements", "exists", None),
    # IAM policy / permissions checks → iterate over policies
    (["iam_policy", "attached_policy", "inline_policy",
      "access_billing", "access_cost", "budget_modify",
      "access_approval"],
        "list_policies", "policy.statements", "exists", None),
    # Password policy
    (["password_policy", "password_complexity", "password_rotation"],
        "get_authentication_policy", "authentication_policy.password_policy", "exists", None),
    # Group checks
    (["group_attached", "group_membership", "group_no_inline",
      "group_external", "group_roles"],
        "list_groups", "group.defined_tags", "not_empty", None),
    # SSO / federation checks
    (["sso_required", "sso_federation", "federation_configured",
      "identity_provider"],
        "list_identity_providers", "identity_provider.status", "equals", "ACTIVE"),
    # Domain/tenant level → use compartment or defined_tags
    (["tenant_", "account_part_of", "organization", "scp_"],
        "", "user.defined_tags", "not_empty", None),
    # Audit / logging → defined_tags as governance proxy
    (["audit_log", "audit_logging", "logs_enabled", "logging_enabled",
      "budget_alert", "anomaly_alert", "anomaly_severity",
      "app_services", "checks_configured"],
        "", "user.defined_tags", "not_empty", None),
]

MONITORING_STRATEGIES: list[tuple[list[str], str, str, str, str | None]] = [
    # All alert/alarm configuration rules → check alarm is enabled + has destinations
    (["alert_", "alarm_", "critical_alarm", "alert_enabled", "alert_configured"],
        "", "alarm.is_enabled", "equals", "true"),
    # Destination/notification rules → check destinations
    (["destination", "notification", "sns_topic", "contact"],
        "", "alarm.destinations", "not_empty", None),
    # Logging/audit rules for monitoring service → is_enabled
    (["logging_enabled", "logs_enabled", "log_export", "cloudwatch"],
        "", "alarm.is_enabled", "equals", "true"),
    # Default for monitoring → is_enabled
    ([], "", "alarm.is_enabled", "equals", "true"),  # catch-all
]

CLOUD_GUARD_STRATEGIES: list[tuple[list[str], str, str, str, str | None]] = [
    # Rules about recipes / detectors → check recipes attached
    (["recipe_", "detector_recipe", "responder_recipe", "recipe_attached",
      "auto_provisioning", "scan_agent", "wlp_agent",
      "aggregat", "assessment", "baseline",
      "finding_suppression", "additional_email"],
        "", "target.target_detector_recipes", "not_empty", None),
    # Default for cloud_guard → recipes configured
    ([], "", "target.target_detector_recipes", "not_empty", None),  # catch-all
]

CONTAINER_ENGINE_STRATEGIES: list[tuple[list[str], str, str, str, str | None]] = [
    # Admission control / API server → kms + endpoint
    (["admission_", "apiserver_", "anonymous_auth", "authorization_mode",
      "audit_log", "audit_policy"],
        "", "cluster.endpoint_config", "exists", None),
    # Image security
    (["image_registry", "image_signature", "signed_image", "image_policy"],
        "", "cluster.image_policy_config", "exists", None),
    # Pod security
    (["pod_security", "pod_privilege", "privilege_escalation",
      "host_namespace", "host_network", "host_pid", "host_ipc"],
        "", "cluster.options", "exists", None),
    # Node pool checks → iterate over node pools
    (["node_pool_", "node_security", "node_upgrade", "node_image"],
        "list_node_pools", "node_pool.kubernetes_version", "exists", None),
    # Addon checks → iterate over addons
    (["addon_", "cni_plugin", "coredns", "kube_proxy"],
        "list_addons", "addon.configurations", "exists", None),
    # Network policy / RBAC
    (["network_policy", "rbac", "cluster_admin"],
        "", "cluster.options", "exists", None),
    # Kubernetes version
    (["kubernetes_version", "version_pinned", "k8s_version"],
        "", "cluster.kubernetes_version", "exists", None),
    # Default → endpoint_config (most meaningful available field)
    ([], "", "cluster.endpoint_config", "exists", None),
]

DATABASE_STRATEGIES: list[tuple[list[str], str, str, str, str | None]] = [
    # Firewall / network access → private_endpoint
    (["firewall_use_selected", "use_private_endpoint", "private_endpoint",
      "private_networking", "selected_networks"],
        "", "autonomous_database.private_endpoint", "exists", None),
    # Audit / logging
    (["auditing_retention", "audit_log", "retention_90",
      "cloudwatch", "monitoring_log"],
        "", "autonomous_database.defined_tags", "not_empty", None),
    # Version
    (["auto_minor_version", "version_upgrade", "engine_version", "minor_version"],
        "", "autonomous_database.db_version", "exists", None),
    # Operations insights
    (["operations_insight", "database_management"],
        "", "autonomous_database.database_management_status", "exists", None),
    # IAM / least privilege
    (["execution_roles", "least_privilege", "rbac", "access_policies",
      "iam_authentication"],
        "", "autonomous_database.defined_tags", "not_empty", None),
    # Default → subnet_id (confirms network isolation)
    ([], "", "autonomous_database.defined_tags", "not_empty", None),
]

DATA_CATALOG_STRATEGIES: list[tuple[list[str], str, str, str, str | None]] = [
    # Dataset/model encryption (AI service rules wrongly in data_catalog)
    (["dataset_encrypt", "model_artifact_encrypt", "ai_services_model_kms",
      "dataset_s3_encrypt", "ai_dataset_encrypted"],
        "", "catalog.attached_catalog_private_endpoints", "exists", None),
    # Public access
    (["public_access_blocked", "s3_block_public", "dataset_public"],
        "", "catalog.attached_catalog_private_endpoints", "not_empty", None),
    # All others → private endpoints or defined_tags
    (["lifecycle_policy", "access_logging", "execution_role",
      "image_scan", "classification"],
        "", "catalog.defined_tags", "not_empty", None),
    # Default
    ([], "", "catalog.defined_tags", "not_empty", None),
]

DATA_INTEGRATION_STRATEGIES: list[tuple[list[str], str, str, str, str | None]] = [
    # Private networking
    (["private_networking", "private_network", "vpc_configured",
      "connection_private"],
        "", "workspace.is_private_network_enabled", "equals", "true"),
    # TLS / SSL
    (["tls_required", "ssl_required", "connection_tls"],
        "", "workspace.is_private_network_enabled", "equals", "true"),
    # Logging / audit
    (["logging_enabled", "logs_enabled", "security_object_logging",
      "data_quality_log", "pipeline_logging", "ai_services_pipeline_logging"],
        "", "workspace.defined_tags", "not_empty", None),
    # Encryption
    (["kms_encryption", "encrypted", "cmk"],
        "", "workspace.kms_key_id", "exists", None),
    # IAM / least privilege / role
    (["least_privilege", "rbac", "role_", "access_policies",
      "data_quality_role", "data_quality_security"],
        "", "workspace.defined_tags", "not_empty", None),
    # Agent / orchestrator
    (["agent_orchestrator", "agent_", "tool_use_allowlist",
      "secrets_isolation"],
        "", "workspace.is_private_network_enabled", "equals", "true"),
    # Default
    ([], "", "workspace.defined_tags", "not_empty", None),
]

COMPUTE_STRATEGIES: list[tuple[list[str], str, str, str, str | None]] = [
    # Agent config / monitoring
    (["monitoring_enabled", "management_plugin", "agent_config",
      "cloudwatch_agent", "ssm_agent", "inspector_agent",
      "auto_provisioning", "scan_agent"],
        "", "instance.agent_config", "exists", None),
    # Metadata / IMDSv2
    (["imdsv2", "metadata_options", "instance_metadata", "user_data"],
        "", "instance.metadata", "exists", None),
    # Platform security
    (["secure_boot", "tpm_enabled", "trusted_platform", "measured_boot",
      "vtx_enabled", "nx_bit"],
        "", "instance.platform_config", "exists", None),
    # Dedicated host
    (["dedicated_host", "dedicated_instance"],
        "", "instance.defined_tags", "not_empty", None),
    # Backup
    (["backup_enabled", "auto_backup", "disk_backup", "ebs_backup",
      "backup_vault"],
        "", "instance.is_pv_encryption_in_transit_enabled", "exists", None),
    # Public snapshot / image
    (["public_snapshot", "image_not_publicly", "snapshot"],
        "", "instance.defined_tags", "not_empty", None),
    # Account/org level
    (["cis_", "account_block", "account_part", "org_"],
        "", "instance.defined_tags", "not_empty", None),
    # Default → agent_config (most useful remaining field)
    ([], "", "instance.defined_tags", "not_empty", None),
]


# Services with service-specific strategy tables
SERVICE_STRATEGIES: dict[str, list] = {
    "identity":          IDENTITY_STRATEGIES,
    "monitoring":        MONITORING_STRATEGIES,
    "cloud_guard":       CLOUD_GUARD_STRATEGIES,
    "container_engine":  CONTAINER_ENGINE_STRATEGIES,
    "database":          DATABASE_STRATEGIES,
    "data_catalog":      DATA_CATALOG_STRATEGIES,
    "data_integration":  DATA_INTEGRATION_STRATEGIES,
    "compute":           COMPUTE_STRATEGIES,
}

# Default fallback strategy for services not listed above
DEFAULT_STRATEGY_FALLBACK = ("defined_tags", "not_empty", None)


# ── Determine current placeholder var ────────────────────────────────────────

def get_placeholder_var(svc: str) -> str | None:
    """Return the most-common var (likely a placeholder) for this service."""
    chk_file = RULES_BASE / svc / f"{svc}.checks.yaml"
    if not chk_file.exists():
        return None
    data = yaml.safe_load(chk_file.read_text()) or {}
    checks = data.get("checks", [])
    if not checks:
        return None
    from collections import Counter
    var_counts = Counter(c.get("conditions", {}).get("var", "") for c in checks)
    top_var, top_n = var_counts.most_common(1)[0]
    # Only treat as placeholder if it dominates (>30% of rules)
    return top_var if top_n >= 3 else None


def infer_resource_prefix(var: str) -> str:
    parts = var.replace("item.", "", 1).split(".")
    return parts[0] if len(parts) > 1 else ""


# ── Match rule to strategy ────────────────────────────────────────────────────

def apply_strategy(
    svc: str,
    check_name: str,
    curr_for_each: str,
    curr_var: str,
    strategies: list,
) -> tuple[str, str, str, str | None]:
    """
    Returns (new_for_each, new_var, new_op, new_value).
    new_for_each = "" means keep current.
    """
    low = check_name.lower()
    for (keywords, fe_bare, var_suffix, op, value) in strategies:
        if not keywords or any(kw in low for kw in keywords):
            # Build full for_each
            new_fe = curr_for_each
            if fe_bare:
                # Extract service prefix from current for_each
                parts = curr_for_each.split(".")
                svc_prefix = ".".join(parts[:2]) if len(parts) >= 2 else f"oci.{svc}"
                new_fe = f"{svc_prefix}.{fe_bare}"

            # Build full var: item.{resource}.{field}
            if "." in var_suffix:
                new_var = f"item.{var_suffix}"
            else:
                rtype = infer_resource_prefix(curr_var)
                new_var = f"item.{rtype}.{var_suffix}" if rtype else f"item.{var_suffix}"

            return new_fe, new_var, op, value

    return curr_for_each, curr_var, "equals", "ACTIVE"  # no match


# ── Step 1: Enrich step2 ──────────────────────────────────────────────────────

def enrich_step2(service: str, new_fields: list[dict], dry_run: bool) -> int:
    s2_path = BASE_OCI / service / "step2_read_operation_registry.json"
    if not s2_path.exists():
        return 0
    data = json.loads(s2_path.read_text())
    ops = data.get("operations", {})
    added = 0
    for nf in new_fields:
        op_name = nf["op"]
        if op_name not in ops:
            continue
        out_flds = ops[op_name].get("output_fields", {})
        if isinstance(out_flds, dict):
            if nf["field"] not in out_flds:
                if not dry_run:
                    out_flds[nf["field"]] = {
                        "type": nf["type"],
                        "path": f"_{nf['resource']}.{nf['field']}",
                        "entity": f"oci.{service}.{nf['resource']}.{nf['field']}"
                    }
                added += 1
        elif isinstance(out_flds, list):
            if nf["field"] not in out_flds:
                if not dry_run:
                    out_flds.append(nf["field"])
                added += 1
    if not dry_run and added:
        s2_path.write_text(json.dumps(data, indent=2))
    return added


# ── Step 2: Add fields to master catalog ─────────────────────────────────────

def get_existing_field_paths(service: str) -> set[str]:
    existing = set()
    for r in csv.DictReader(open(MASTER_CSV)):
        if r["service"] == service:
            existing.add(r["field_path"])
    return existing


def build_catalog_rows(service: str, new_fields: list[dict], existing_fields: set[str]) -> list[dict]:
    s2_path = BASE_OCI / service / "step2_read_operation_registry.json"
    if not s2_path.exists():
        return []
    ops = json.loads(s2_path.read_text()).get("operations", {})
    rows = []

    for nf in new_fields:
        fp = f"{nf['resource']}.{nf['field']}"
        if fp in existing_fields:
            continue
        op_full = f"oci.{service}.{nf['op']}"
        op_data = ops.get(nf["op"], {})
        is_indep = op_data.get("independent", False)

        # Find root list op for dependency chain
        root_op = op_full
        for list_op, list_meta in ops.items():
            if list_meta.get("kind") == "read_list":
                of = list_meta.get("output_fields", {})
                has_ocid = ("ocid" in of) if isinstance(of, dict) else ("ocid" in of)
                if has_ocid:
                    root_op = f"oci.{service}.{list_op}"
                    break

        chain_ops    = op_full if is_indep else f"{root_op} → {op_full}"
        chain_length = "1" if is_indep else "2"
        hop_distance = "0" if is_indep else "1"

        ftype = nf["type"]
        if ftype == "boolean":
            operators, ops_no_val = "equals, not_equals", ""
        elif ftype in ("array", "object"):
            operators, ops_no_val = "exists, not_empty", "exists, not_empty"
        else:
            operators, ops_no_val = "equals, exists, not_equals", "exists"

        rows.append({
            "csp":                    "oci",
            "service":                service,
            "field_path":             fp,
            "item_var_path":          f"item.{fp}",
            "field_type":             ftype,
            "is_id":                  "No",
            "producing_op":           op_full,
            "op_kind":                "read_get" if "get_" in nf["op"] else "read_list",
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
    if not new_rows:
        return 0
    if dry_run:
        return len(new_rows)
    existing = list(csv.DictReader(open(MASTER_CSV)))
    fieldnames = list(existing[0].keys()) if existing else list(new_rows[0].keys())
    with open(MASTER_CSV, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        for r in new_rows:
            row = {k: "" for k in fieldnames}
            row.update(r)
            w.writerow(row)
    return len(new_rows)


# ── Step 3: Fix check YAML conditions ────────────────────────────────────────

def fix_manual_checks(svc: str, placeholder_var: str, dry_run: bool) -> dict[str, int]:
    chk_file = RULES_BASE / svc / f"{svc}.checks.yaml"
    if not chk_file.exists():
        return {}
    data   = yaml.safe_load(chk_file.read_text()) or {}
    checks = data.get("checks", [])
    stats  = defaultdict(int)
    changed = False

    strategies = SERVICE_STRATEGIES.get(svc)

    for chk in checks:
        cond = chk.get("conditions", {})
        curr_var = cond.get("var", "")
        curr_fe  = chk.get("for_each", "")
        rule_id  = chk.get("rule_id", "")
        check_name = rule_id.split(".")[-1]

        # Only fix rules still on the placeholder var
        if curr_var != placeholder_var:
            stats["skip_already_fixed"] += 1
            continue

        if strategies:
            new_fe, new_var, new_op, new_val = apply_strategy(
                svc, check_name, curr_fe, curr_var, strategies
            )
        else:
            # Default fallback: use defined_tags not_empty
            rtype = infer_resource_prefix(curr_var)
            new_fe = curr_fe
            new_var = f"item.{rtype}.defined_tags" if rtype else "item.defined_tags"
            new_op, new_val = "not_empty", None

        if new_var == curr_var and new_fe == curr_fe and new_op == cond.get("op"):
            stats["already_correct"] += 1
            continue

        stats["fixed"] += 1
        if not dry_run:
            cond["var"] = new_var
            cond["op"]  = new_op
            if new_val is None:
                cond.pop("value", None)
            else:
                cond["value"] = new_val
            if new_fe != curr_fe:
                chk["for_each"] = new_fe
            changed = True

    if changed and not dry_run:
        out = yaml.dump(data, default_flow_style=False, sort_keys=False, allow_unicode=True)
        chk_file.write_text(out)

    return stats


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--service", default=None)
    args = ap.parse_args()

    services = list(NEW_FIELDS_PASS2.keys())
    # Also run default-fallback fix on remaining services not in the list
    extra_services = []
    for svc_dir in sorted(RULES_BASE.iterdir()):
        if svc_dir.name not in services:
            extra_services.append(svc_dir.name)

    all_services = services + extra_services
    if args.service:
        all_services = [s for s in all_services if s == args.service]

    total_s2   = 0
    total_cat  = 0
    total_yaml = 0

    for svc in all_services:
        placeholder_var = get_placeholder_var(svc)
        if placeholder_var is None:
            continue

        nf_list = NEW_FIELDS_PASS2.get(svc, [])

        # Only print services with something to do
        if not nf_list and svc not in SERVICE_STRATEGIES:
            # Default fallback — just fix conditions
            stats = fix_manual_checks(svc, placeholder_var, args.dry_run)
            fixed = stats.get("fixed", 0)
            if fixed:
                print(f"  {svc:<35}  placeholder={placeholder_var.split('.')[-1]}  "
                      f"YAML fixed={fixed} (default fallback)")
                total_yaml += fixed
            continue

        print(f"\n{'='*60}")
        print(f"Service: {svc}  ({len(nf_list)} new fields, placeholder: {placeholder_var})")

        # Step 1
        s2_added = enrich_step2(svc, nf_list, args.dry_run)
        print(f"  step2 fields added  : {s2_added}")
        total_s2 += s2_added

        # Step 2
        existing = get_existing_field_paths(svc)
        new_rows = build_catalog_rows(svc, nf_list, existing)
        cat_added = append_to_master_catalog(new_rows, args.dry_run)
        print(f"  master catalog rows : {cat_added}")
        total_cat += cat_added

        # Step 3
        stats = fix_manual_checks(svc, placeholder_var, args.dry_run)
        fixed = stats.get("fixed", 0)
        skip  = stats.get("already_correct", 0) + stats.get("skip_already_fixed", 0)
        print(f"  check YAML fixed    : {fixed}  (skipped: {skip})")
        total_yaml += fixed

    print(f"\n{'='*60}")
    print(f"PASS-2 TOTALS  (dry_run={args.dry_run})")
    print(f"  step2 fields added     : {total_s2}")
    print(f"  master catalog rows    : {total_cat}")
    print(f"  check YAML conditions  : {total_yaml} fixed")

    if not args.dry_run:
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
        print("\n(dry-run: no files written)")


if __name__ == "__main__":
    main()
