#!/usr/bin/env python3
"""
Precise fix for AliCloud check rule var values.

Strategy:
  - Multi-condition (all:/any:) rules: PRESERVE original vars (source is semantically correct)
  - Single-condition rules: Fix only where the current var is demonstrably wrong
    based on the rule_id intent.

Only applies changes where the semantic mismatch is clear.
"""

import yaml
from pathlib import Path
from collections import defaultdict

CATALOG = Path("/Users/apple/Desktop/threat-engine/catalog/alicloud")
CHECK_ENGINE = Path("/Users/apple/Desktop/threat-engine/engines/check/engine_check_alicloud/services")


def classify_rule(rule_id: str) -> tuple[str, str, str | None]:
    """
    Return (var, op, value) for the most appropriate condition for this rule.
    Uses rule_id semantic keywords in priority order.
    """
    r = rule_id.lower()

    # ── TLS minimum version ───────────────────────────────────────────────────
    if any(x in r for x in ["tls_1_2", "tls_1_3", "tlsv1_2", "tlsv1_3", "min_tls",
                              "minimum_tls", "tls_12", "tls_13", "1_2_enforced",
                              "tls_min_1_2", "tls_min_1_3"]):
        return ("item.min_tls_version", "gte", "1.2")

    # ── SSL / TLS / HTTPS / In-transit encryption ─────────────────────────────
    if any(x in r for x in ["ssl_enabled", "tls_enabled", "in_transit_tls",
                              "https_only", "https_enforce", "transit_tls",
                              "in_transit_encrypt", "encryption_in_transit",
                              "transit_encryption"]):
        return ("item.ssl_enabled", "equals", "true")

    # ── CMEK / CMK (customer-managed key, means both encrypted + kms_key_id) ──
    # Single-condition CMEK rules → use encrypted (kms_key_id is second in all:)
    if any(x in r for x in ["cmek", "cmk_key", "kms_cmk", "cmek_key",
                              "customer_managed_key"]):
        return ("item.encrypted", "equals", "true")

    # ── Encryption at rest (generic) ──────────────────────────────────────────
    if any(x in r for x in ["encrypt", "at_rest", "disk_encrypt", "volume_encrypt",
                              "data_encrypt", "storage_encrypt", "encryption_enabled",
                              "encryption_at_rest", "encrypted"]):
        return ("item.encrypted", "equals", "true")

    # ── No public IP specifically ─────────────────────────────────────────────
    if any(x in r for x in ["no_public_ip", "public_ip_blocked",
                              "public_ip_assigned", "public_ip_restricted",
                              "public_ip_address"]):
        return ("item.public_ip_address", "not_exists", None)

    # ── Public access / internet-facing blocked ───────────────────────────────
    if any(x in r for x in ["public_access_block", "restrict_public",
                              "block_public", "internet_facing",
                              "internet_access_blocked", "internet_exposure",
                              "publicly_exposed", "public_exposed",
                              "no_internet", "public_facing", "public",
                              "exposure_to_shodan", "shodan"]):
        return ("item.internet_facing", "not_equals", "true")

    # ── Security group / Firewall rules ───────────────────────────────────────
    if any(x in r for x in ["security_group", "securitygroup", "ingress_tcp",
                              "ingress_udp", "egress", "inbound_restrict",
                              "port_22", "port_3389", "port_80", "port_443",
                              "tcp_22", "tcp_3389", "tcp_80", "tcp_443",
                              "default_deny", "deny_all_traffic",
                              "unrestricted_ingress", "unrestricted_access",
                              "firewall_rule", "network_acl", "networkacl",
                              "network_policy"]):
        return ("item.security_group_rules", "not_contains", "0.0.0.0/0")

    # ── Permissions / IAM / Policy ────────────────────────────────────────────
    if any(x in r for x in ["least_privilege", "overpermissive",
                              "cross_account_restrict", "cross_account_blocked",
                              "public_policy_blocked", "permission",
                              "policy_restrict", "policy_blocked",
                              "roles_least", "auth_roles",
                              "role_has_permission", "admin_access",
                              "wildcard", "star_policy", "admin_privilege",
                              "privilege_escalation", "rbac",
                              "authorization"]):
        return ("item.permissions", "not_contains", "*")

    # ── Backup / Recovery / Snapshot / Point-in-time ──────────────────────────
    if any(x in r for x in ["backup_enabled", "backup_configured",
                              "automated_backup", "point_in_time", "pitr",
                              "cross_region_backup", "backup_retention",
                              "backup_storage", "snapshot_enabled",
                              "regular_backup", "recovery", "dr_plan",
                              "dr_drills", "immutability", "replication"]):
        return ("item.backup_enabled", "equals", "true")

    # ── MFA ───────────────────────────────────────────────────────────────────
    if "mfa" in r:
        return ("item.mfa_enabled", "equals", "true")

    # ── Versioning ────────────────────────────────────────────────────────────
    if "versioning" in r:
        return ("item.versioning_enabled", "equals", "true")

    # ── VPC / Private network ─────────────────────────────────────────────────
    if any(x in r for x in ["vpc_routing", "custom_vpc", "private_subnet",
                              "vpc_required", "private_access", "private_only",
                              "private_ip_required", "private_node",
                              "endpoint_private", "private_endpoint", "_in_vpc",
                              "private_network"]):
        return ("item.vpc_id", "exists", None)

    # ── Tags ──────────────────────────────────────────────────────────────────
    if any(x in r for x in ["tagged", "tag_policy", "tags_copied", "resource_tag"]):
        return ("item.tags", "exists", None)

    # ── Logging / Monitoring / Audit / Alerting ───────────────────────────────
    if any(x in r for x in ["logging_enabled", "log_enabled", "logs_enabled",
                              "log_collection", "access_log", "audit_log",
                              "audit_trail", "access_logging", "log_metric",
                              "metric_filter", "log_metric_filter",
                              "diagnostic_setting", "flow_log", "activity_log",
                              "field_level_log", "monitoring_alert",
                              "alert_configured", "alarm_configured",
                              "retention_90", "90_day_retention",
                              "monitoring_enabled", "cloudwatch_log",
                              "log_archive"]):
        return ("item.logging_enabled", "equals", "true")

    # ── Status / Enabled / Configured (resource is active) ───────────────────
    if any(x in r for x in ["_enabled", "_configured", "_active", "_deployed",
                              "_operational", "without_findings", "_compliant",
                              "_installed", "_activated", "_registered",
                              "service_enabled", "protection_enabled",
                              "detection_enabled", "_enabled_for",
                              "assessment_enabled", "scanner_enabled",
                              "health_check", "kubeconfig", "webhook",
                              "expiration_check", "not_expired",
                              "certificate_expir"]):
        return ("item.status", "equals", "Active")

    return ("item.status", "exists", None)


def is_simple_condition(cond: dict) -> bool:
    """True if this is a plain {var, op, value} with no all/any."""
    return isinstance(cond, dict) and "var" in cond and "all" not in cond and "any" not in cond


def should_fix(rule_id: str, current_var: str, op: str) -> bool:
    """
    Return True only when the current var is clearly wrong for this rule.
    Conservative: don't fix if the current var is plausibly correct.
    """
    r = rule_id.lower()
    var_field = current_var.replace("item.", "")

    # Case 1: var=logging_enabled but rule has NO log/monitor/audit/alert context
    if var_field == "logging_enabled":
        log_words = ["log", "monitor", "audit", "alert", "alarm", "metric",
                     "trail", "diagnos", "flow_log", "retention"]
        if not any(w in r for w in log_words):
            return True

    # Case 2: var=id is always wrong for a check rule — the resource was already
    # discovered, so item.id exists is a tautology. Fix all of them.
    if var_field == "id":
        return True

    return False


def process_all() -> None:
    step7_files = sorted(CATALOG.glob("*/step7_*.checks.yaml"))

    total_rules = 0
    total_fixed = 0
    fix_log = defaultdict(list)

    for step7 in step7_files:
        svc = step7.parent.name
        data = yaml.safe_load(step7.read_text())
        if not data:
            continue
        checks = data.get("checks", []) or []
        file_changed = False

        for rule in checks:
            total_rules += 1
            rule_id = rule.get("rule_id", "")
            cond = rule.get("conditions", {})

            # ONLY fix simple single-condition rules
            if not is_simple_condition(cond):
                continue  # preserve multi-condition rules exactly as-is

            old_var = cond.get("var", "")
            old_op = cond.get("op", "")
            old_val = cond.get("value")

            if not should_fix(rule_id, old_var, old_op):
                continue

            # Get the correct var/op/value
            new_var, new_op, new_val = classify_rule(rule_id)

            if new_var == old_var and new_op == old_op:
                continue  # already correct

            # Apply fix
            new_cond = {"var": new_var, "op": new_op}
            if new_val is not None:
                new_cond["value"] = new_val

            rule["conditions"] = new_cond
            file_changed = True
            total_fixed += 1
            fix_log[svc].append(
                f"  {rule_id}\n"
                f"    {old_var!r} {old_op!r} → {new_var!r} {new_op!r}"
                + (f" value={new_val!r}" if new_val else "")
            )

        if file_changed:
            data["checks"] = checks
            step7.write_text(
                yaml.dump(data, default_flow_style=False, allow_unicode=True,
                          sort_keys=False, width=120)
            )

    # ── Report ────────────────────────────────────────────────────────────────
    print(f"\n{'='*65}")
    print("AliCloud Check Rule Var Fix — Results")
    print(f"{'='*65}")
    print(f"\nTotal rules processed  : {total_rules}")
    print(f"Single-condition fixed : {total_fixed}")
    print(f"Multi-condition kept   : (unchanged — source already correct)\n")

    for svc in sorted(fix_log):
        print(f"\n[{svc}]  {len(fix_log[svc])} rules fixed:")
        for line in fix_log[svc]:
            print(line)

    # Final var distribution
    from collections import Counter
    var_counter = Counter()
    for step7 in step7_files:
        data = yaml.safe_load(step7.read_text())
        for rule in (data.get("checks") or []):
            def collect(c):
                if isinstance(c, dict):
                    if "var" in c: var_counter[c["var"]] += 1
                    for k in ("all", "any"):
                        if k in c:
                            for s in c[k]: collect(s)
                elif isinstance(c, list):
                    for s in c: collect(s)
            collect(rule.get("conditions", {}))

    print(f"\n{'='*65}")
    print("Final var distribution across all 1,400 rules:")
    print(f"{'='*65}")
    for var, cnt in var_counter.most_common():
        print(f"  {cnt:4d}  {var}")


if __name__ == "__main__":
    process_all()
