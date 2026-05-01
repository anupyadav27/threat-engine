#!/usr/bin/env python3
"""
AliCloud Security Expert: Fix var/op/value in all check rule conditions.

For every condition, the current `var` is often wrong (e.g. item.logging_enabled
for an encryption rule). This script analyses the rule_id semantics and selects
the correct field, operator and value.

Decision logic (in priority order):
  1. Rule name → intent → correct security field
  2. Existing op/value hints guide sub-condition assignment (CMEK rules)
  3. Fallback: item.status / exists
"""

import copy
import yaml
from pathlib import Path
from collections import defaultdict

CATALOG = Path("/Users/apple/Desktop/threat-engine/catalog/alicloud")

# ─── Available emit fields (all step6 files now emit these) ──────────────────
VALID_FIELDS = {
    "id", "name", "resource_type", "region", "encrypted", "kms_key_id",
    "public_ip_address", "vpc_id", "status", "tags", "internet_facing",
    "permissions", "security_group_rules", "backup_enabled", "logging_enabled",
    "mfa_enabled", "ssl_enabled", "versioning_enabled", "min_tls_version",
}


# ─── Intent → (var, op, value) mapping ───────────────────────────────────────

def classify_rule(rule_id: str) -> str:
    """Return the primary intent category for a rule_id."""
    r = rule_id.lower()

    # ── TLS / SSL ─────────────────────────────────────────────────────────────
    if any(x in r for x in ["tls_1_2", "tls_1_3", "tlsv1_2", "tlsv1_3",
                              "min_tls", "minimum_tls", "tls_min", "1_2_enforced",
                              "tls_12", "tls_13"]):
        return "min_tls"

    if any(x in r for x in ["ssl_enabled", "tls_enabled", "in_transit_tls",
                              "https_only", "https_enforced", "https_enforce",
                              "in_transit_encrypt", "transit_tls", "ssl_tls",
                              "transit_encryption", "in_transit"]):
        return "ssl"

    # ── CMEK / KMS (encryption with customer key) ─────────────────────────────
    if any(x in r for x in ["cmek", "cmk", "customer_managed_key",
                              "kms_cmk", "cmek_key", "kms_key_configured",
                              "kms_encryption"]):
        return "cmek"

    # ── Encryption at rest (generic) ─────────────────────────────────────────
    if any(x in r for x in ["encrypt", "at_rest", "storage_encrypt",
                              "disk_encrypt", "volume_encrypt", "data_encrypt",
                              "encryption_enabled", "encryption_at_rest"]):
        return "encrypted"

    # ── Public access / internet exposure ─────────────────────────────────────
    if any(x in r for x in ["no_public_ip", "public_ip_blocked", "public_ip_restricted",
                              "public_ip_assigned", "public_address_blocked"]):
        return "no_public_ip"

    if any(x in r for x in ["public_access_block", "public_access_restrict",
                              "restrict_public", "block_public", "public_access_blocked"]):
        return "internet_facing_block"

    if any(x in r for x in ["internet_facing", "internet_access_blocked",
                              "internet_exposure", "public_exposed",
                              "exposure_to_shodan", "publicly_exposed",
                              "public_facing", "internet_exposed",
                              "no_internet", "internet_access_blocked"]):
        return "internet_facing_block"

    # ── Security group / Firewall rules ───────────────────────────────────────
    if any(x in r for x in ["security_group", "securitygroup", "ingress_tcp",
                              "ingress_udp", "egress", "inbound_restrict",
                              "port_22", "port_3389", "port_80", "port_443",
                              "tcp_22", "tcp_3389", "tcp_80", "tcp_443",
                              "default_deny", "deny_all_traffic",
                              "inbound_unrestricted", "unrestricted_ingress",
                              "firewall_rule", "network_acl", "networkacl"]):
        return "security_group_rules"

    # ── Permissions / IAM / Policy ────────────────────────────────────────────
    if any(x in r for x in ["least_privilege", "overpermissive", "over_permissive",
                              "cross_account_restrict", "cross_account_blocked",
                              "public_policy_blocked", "permission",
                              "policy_restrict", "policy_blocked",
                              "roles_least", "auth_roles",
                              "role_has_permission", "admin_access",
                              "wildcard", "star_policy", "admin_privilege",
                              "privileged", "privilege_escalation"]):
        return "permissions"

    # ── Logging / Monitoring / Audit ──────────────────────────────────────────
    if any(x in r for x in ["logging_enabled", "log_enabled", "logs_enabled",
                              "log_collection", "access_log", "audit_log",
                              "audit_trail", "access_logging",
                              "log_metric", "metric_filter", "log_metric_filter",
                              "diagnostic_setting", "flow_log",
                              "activity_log", "field_level_log",
                              "cloudtrail", "actiontrail", "monitoring_alert",
                              "alert_configured", "alarm_configured",
                              "retention_90", "retention_days", "90_day_retention"]):
        return "logging"

    if any(x in r for x in ["monitoring_enabled", "monitoring_configured",
                              "cloudwatch", "cloudmonitor", "log_archive",
                              "log_storage"]):
        return "logging"

    # ── Backup / Recovery / Snapshot ──────────────────────────────────────────
    if any(x in r for x in ["backup_enabled", "backup_configured",
                              "automated_backup", "point_in_time",
                              "pitr", "cross_region_backup",
                              "cross_region_replication", "backup_retention",
                              "backup_storage", "backup_encryption",
                              "snapshot_enabled", "regular_backup",
                              "recovery", "dr_plan", "dr_drills",
                              "immutability"]):
        return "backup"

    # ── MFA ───────────────────────────────────────────────────────────────────
    if "mfa" in r:
        return "mfa"

    # ── Versioning ────────────────────────────────────────────────────────────
    if "versioning" in r:
        return "versioning"

    # ── VPC / Private network ─────────────────────────────────────────────────
    if any(x in r for x in ["in_vpc", "custom_vpc", "private_subnet",
                              "vpc_required", "private_access", "private_only",
                              "private_ip_required", "private_node",
                              "endpoint_private", "private_endpoint"]):
        return "vpc"

    # ── Tags ──────────────────────────────────────────────────────────────────
    if any(x in r for x in ["tagged", "tag_policy", "tags_copied",
                              "resource_tag", "tag_enforced"]):
        return "tags"

    # ── KMS key ID (standalone, not CMEK encryption) ─────────────────────────
    if any(x in r for x in ["kms_key_id", "key_configured", "key_rotation",
                              "key_expiry"]):
        return "kms_key_id"

    # ── Status / Enabled / Configured (resource health) ──────────────────────
    if any(x in r for x in ["enabled", "configured", "active", "deployed",
                              "operational", "without_findings", "compliant",
                              "installed", "activated", "registered",
                              "service_enabled", "scanner_enabled",
                              "assessment_enabled", "protection_enabled",
                              "detection_enabled", "guardduty", "security_hub",
                              "security_center", "vulnerability_scan",
                              "patch_compliance", "inventory_enabled",
                              "agent_installed", "kubeconfig", "webhook"]):
        return "status"

    return "status"  # default


def make_condition(intent: str, existing_op: str, existing_value: str,
                   position: int = 0) -> dict:
    """
    Given an intent category, return the correct {var, op, value} dict.
    position is used for multi-condition intents (e.g. CMEK needs 2 conditions).
    """
    def c(var, op, value=None):
        d = {"var": f"item.{var}", "op": op}
        if value is not None:
            d["value"] = str(value)
        return d

    if intent == "min_tls":
        # Prefer existing value if it looks like a TLS version
        val = existing_value if existing_value and "1." in str(existing_value) else "1.2"
        return c("min_tls_version", "gte", val)

    if intent == "ssl":
        return c("ssl_enabled", "equals", "true")

    if intent == "cmek":
        # Two-condition rule: pos 0 = encrypted, pos 1 = kms_key_id
        if position == 0 or existing_op in ("equals",) and existing_value in ("true", "True"):
            return c("encrypted", "equals", "true")
        else:
            d = {"var": "item.kms_key_id", "op": "exists"}
            return d

    if intent == "encrypted":
        return c("encrypted", "equals", "true")

    if intent == "no_public_ip":
        d = {"var": "item.public_ip_address", "op": "not_exists"}
        return d

    if intent == "internet_facing_block":
        return c("internet_facing", "not_equals", "true")

    if intent == "security_group_rules":
        op = existing_op if existing_op in ("not_contains", "contains", "equals") else "not_contains"
        val = existing_value if existing_value not in ("true", "True", "false", "*", "") else "0.0.0.0/0"
        return c("security_group_rules", op, val)

    if intent == "permissions":
        op = existing_op if existing_op in ("not_contains", "contains", "not_exists", "exists") else "not_contains"
        val = existing_value if existing_value not in ("true", "True", "false", "") else "*"
        return c("permissions", op, val)

    if intent == "logging":
        return c("logging_enabled", "equals", "true")

    if intent == "backup":
        return c("backup_enabled", "equals", "true")

    if intent == "mfa":
        return c("mfa_enabled", "equals", "true")

    if intent == "versioning":
        return c("versioning_enabled", "equals", "true")

    if intent == "vpc":
        d = {"var": "item.vpc_id", "op": "exists"}
        return d

    if intent == "tags":
        d = {"var": "item.tags", "op": "exists"}
        return d

    if intent == "kms_key_id":
        d = {"var": "item.kms_key_id", "op": "exists"}
        return d

    # status / default
    op = existing_op if existing_op in ("equals", "not_equals", "exists", "not_exists") else "equals"
    val = existing_value if existing_value not in ("true", "True", "false") else "Active"
    if op in ("exists", "not_exists"):
        return {"var": "item.status", "op": op}
    return c("status", op, val)


def fix_simple_condition(cond: dict, rule_id: str, position: int = 0) -> tuple[dict, bool]:
    """Fix a single {var, op, value} condition. Returns (new_cond, changed)."""
    if "var" not in cond:
        return cond, False

    old_var = cond.get("var", "")
    old_op = cond.get("op", "")
    old_val = str(cond.get("value", ""))

    # Skip if var is already correct (field makes semantic sense for this rule)
    # We'll check against the inferred intent
    intent = classify_rule(rule_id)
    new_cond = make_condition(intent, old_op, old_val, position)

    # Preserve any extra keys in original (shouldn't be any, but safe)
    changed = (new_cond.get("var") != old_var or new_cond.get("op") != old_op)
    return new_cond, changed


def fix_conditions(conditions, rule_id: str) -> tuple[any, bool, list]:
    """
    Recursively fix all conditions in a rule.
    Returns (fixed_conditions, was_changed, change_log).
    """
    changes = []

    if isinstance(conditions, dict):
        # Check for all: / any: nested
        if "all" in conditions or "any" in conditions:
            new_cond = {}
            changed = False
            key = "all" if "all" in conditions else "any"
            sub_list = conditions[key]
            new_list = []
            for i, sub in enumerate(sub_list):
                fixed, sub_changed, sub_changes = fix_conditions(sub, rule_id)
                new_list.append(fixed)
                changed = changed or sub_changed
                changes.extend(sub_changes)
            new_cond[key] = new_list
            return new_cond, changed, changes

        # Simple condition
        if "var" in conditions:
            intent = classify_rule(rule_id)
            old_var = conditions.get("var", "")
            old_op = conditions.get("op", "")
            old_val = str(conditions.get("value", ""))
            # Determine position from op/value hint
            # If this condition has op:exists it's likely a secondary CMEK check
            position = 1 if (intent == "cmek" and old_op == "exists") else 0
            new_c, changed = fix_simple_condition(conditions, rule_id, position)
            if changed:
                changes.append(f"  var: {old_var!r}→{new_c.get('var')!r}  op:{old_op!r}→{new_c.get('op')!r}")
            return new_c, changed, changes

    elif isinstance(conditions, list):
        new_list = []
        changed = False
        for i, item in enumerate(conditions):
            # For list-style all (some older YAML formats)
            if isinstance(item, dict) and "var" in item:
                intent = classify_rule(rule_id)
                old_var = item.get("var", "")
                old_op = item.get("op", "")
                old_val = str(item.get("value", ""))
                position = i  # position in list determines cmek assignment
                new_c, item_changed = fix_simple_condition(item, rule_id, position)
                if item_changed:
                    changes.append(f"  [{i}] var:{old_var!r}→{new_c.get('var')!r}")
                new_list.append(new_c)
                changed = changed or item_changed
            else:
                fixed, sub_changed, sub_changes = fix_conditions(item, rule_id)
                new_list.append(fixed)
                changed = changed or sub_changed
                changes.extend(sub_changes)
        return new_list, changed, changes

    return conditions, False, changes


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def process_all() -> None:
    step7_files = sorted(CATALOG.glob("*/step7_*.checks.yaml"))

    total_rules = 0
    total_changed = 0
    intent_counts = defaultdict(int)

    for step7 in step7_files:
        data = yaml.safe_load(step7.read_text())
        if not data:
            continue
        checks = data.get("checks", []) or []
        file_changed = False

        for rule in checks:
            total_rules += 1
            rule_id = rule.get("rule_id", "")
            intent = classify_rule(rule_id)
            intent_counts[intent] += 1

            old_conds = copy.deepcopy(rule.get("conditions", {}))
            new_conds, changed, changes = fix_conditions(old_conds, rule_id)

            if changed:
                rule["conditions"] = new_conds
                file_changed = True
                total_changed += 1

        if file_changed:
            data["checks"] = checks
            step7.write_text(
                yaml.dump(data, default_flow_style=False, allow_unicode=True,
                          sort_keys=False, width=120)
            )

    # ── Report ────────────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("AliCloud Check Rule Var Fix — Summary")
    print(f"{'='*60}")
    print(f"\n  Total rules processed : {total_rules}")
    print(f"  Rules with var updated: {total_changed}")
    print(f"\n  Intent distribution:")
    for intent, cnt in sorted(intent_counts.items(), key=lambda x: -x[1]):
        print(f"    {intent:<25} {cnt:>5}")

    # ── Final distribution ────────────────────────────────────────────────────
    from collections import Counter
    var_counter = Counter()
    for step7 in step7_files:
        data = yaml.safe_load(step7.read_text())
        for rule in (data.get("checks") or []):
            def collect(c):
                if isinstance(c, dict):
                    if "var" in c: var_counter[c["var"]] += 1
                    for k in ("all","any"):
                        if k in c:
                            for s in c[k]: collect(s)
                elif isinstance(c, list):
                    for s in c: collect(s)
            collect(rule.get("conditions", {}))

    print(f"\n  Final var distribution:")
    for var, cnt in var_counter.most_common():
        print(f"    {cnt:4d}  {var}")


if __name__ == "__main__":
    process_all()
