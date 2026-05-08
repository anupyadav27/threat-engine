#!/usr/bin/env python3
"""
fix_azure_wrong_for_each.py — Fix FIELD_MISSING rules where for_each points to a wrong op.

Strategy:
  1. For each FIELD_MISSING rule, score every op in the catalog against
     how many of the rule's condition vars it actually produces.
  2. If a SAME-SERVICE op (or a cross-service op per EXPLICIT_CROSS_MAP)
     scores higher than the current op, propose the winner as the new for_each.
  3. Apply the change to YAML files in-place.

Also handles AAD / Entra / Graph rules:
  • Maps rule_id patterns to azure.graph.* ops that should be the correct for_each
    (these will become OP_MISSING, which is more accurate than FIELD_MISSING for
     rules that require Microsoft Graph API).

Usage:
    python3 catalog/discovery_generator/scripts/fix_azure_wrong_for_each.py
    python3 ...  --dry-run
    python3 ...  --service network,web,compute
    python3 ...  --min-score 2   # only fix when winner covers ≥ N missing vars
"""

from __future__ import annotations

import argparse
import csv
import re
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

# ── paths ───────────────────────────────────────────────────────────────────────

REPO_ROOT   = Path(".")
RULES_DIR   = REPO_ROOT / "catalog/rule/azure_rule_check"
CATALOG_CSV = REPO_ROOT / "catalog/discovery_generator/azure/azure_master_field_catalog.csv"
REPORT_CSV  = REPO_ROOT / "catalog/discovery_generator/azure/check_rule_validation_report.csv"
FIX_REPORT  = REPO_ROOT / "catalog/discovery_generator/azure/wrong_foreach_fix_report.csv"

# ── AAD / Entra / Graph rule_id → correct for_each ─────────────────────────────
# These rules require Microsoft Graph API (not Azure ARM). Changing for_each to
# azure.graph.* makes them OP_MISSING (accurate) instead of FIELD_MISSING (wrong).

AAD_RULE_PREFIXES: Dict[str, str] = {
    # format: rule_id_prefix → correct_for_each
    "azure.aad.user.":                          "azure.graph.users.list",
    "azure.aad.app_registration.":              "azure.graph.applications.list",
    "azure.aad.identity_service_principal.":    "azure.graph.serviceprincipals.list",
    "azure.aad.directory_tenant.":              "azure.graph.organization.list",
    "azure.aad.group.":                         "azure.graph.groups.list",
    "azure.aad.enterprise_application.":        "azure.graph.serviceprincipals.list",
    "azure.aad.identity_user_assigned_identity.": "azure.graph.users.list",
    "azure.aad.lustre.":                        "azure.graph.organization.list",
    "azure.entra.id.user.":                     "azure.graph.users.list",
    "azure.entra.id.conditional_access.":       "azure.graph.identity_conditional_access_policies.list",
    "azure.entra.id.group.":                    "azure.graph.groups.list",
    "azure.entra.id.app.":                      "azure.graph.applications.list",
    "azure.entra.id.service_principal.":        "azure.graph.serviceprincipals.list",
    "azure.graph.api.":                         "azure.graph.organization.list",
}

# ── Field → preferred correct op (cross-service overrides) ─────────────────────
# When missing fields clearly belong to a DIFFERENT service's resource type.

FIELD_TO_OP: Dict[str, str] = {
    # Application Gateway fields
    "item.backend_address_pools":        "azure.network.applicationgateways.list",
    "item.frontend_ip_configurations":   "azure.network.applicationgateways.list",
    "item.authentication_certificates":  "azure.network.applicationgateways.list",
    "item.ssl_certificates":             "azure.network.applicationgateways.list",
    "item.http_listeners":               "azure.network.applicationgateways.list",
    "item.frontend_ports":               "azure.network.applicationgateways.list",
    "item.gateway_ip_configurations":    "azure.network.applicationgateways.list",
    "item.backend_settings_collection":  "azure.network.applicationgateways.list",

    # App Service Environment fields
    "item.cluster_settings":               "azure.web.appserviceenvironments.list",
    "item.networking_configuration":       "azure.web.appserviceenvironments.list",
    "item.custom_dns_suffix_configuration":"azure.web.appserviceenvironments.list",
    "item.elastic_scale_enabled":          "azure.web.appserviceenvironments.list",
    "item.upgrade_preference":             "azure.web.appserviceenvironments.list",

    # Monitor Action Group fields
    "item.arm_role_receivers":        "azure.monitor.actiongroups.list_by_subscription_id",
    "item.logic_app_receivers":       "azure.monitor.actiongroups.list_by_subscription_id",
    "item.email_receivers":           "azure.monitor.actiongroups.list_by_subscription_id",
    "item.sms_receivers":             "azure.monitor.actiongroups.list_by_subscription_id",
    "item.webhook_receivers":         "azure.monitor.actiongroups.list_by_subscription_id",
    "item.azure_function_receivers":  "azure.monitor.actiongroups.list_by_subscription_id",
    "item.azure_app_push_receivers":  "azure.monitor.actiongroups.list_by_subscription_id",
    "item.itsm_receivers":            "azure.monitor.actiongroups.list_by_subscription_id",
    "item.automation_runbook_receivers": "azure.monitor.actiongroups.list_by_subscription_id",

    # Dedicated Host fields
    "item.virtual_machines":          "azure.compute.dedicatedhosts.list_by_host_group",
    "item.sharing_profile":           "azure.compute.galleries.list",

    # VM Availability Set / instance view
    "item.statuses":                  "azure.compute.availabilitysets.list",

    # Role Definition (not Role Assignment)
    "item.permissions":               "azure.authorization.roledefinitions.list",

    # Policy fields
    "item.policy_definitions":        "azure.authorization.policydefinitions.list",
    "item.policy_assignments":        "azure.authorization.policyassignments.list",
    "item.policy_set_definitions":    "azure.authorization.policysetdefinitions.list",

    # CDN AFD custom domains (endpoints rules checking tls_settings → afdcustomdomains)
    "item.tls_settings":                     "azure.cdn.afdcustomdomains.list_by_profile",
    "item.tls_settings.minimum_tls_version": "azure.cdn.afdcustomdomains.list_by_profile",
    "item.tls_settings.certificate_type":    "azure.cdn.afdcustomdomains.list_by_profile",
    "item.tls_settings.secret":              "azure.cdn.afdcustomdomains.list_by_profile",

    # App Gateway — TLS/SSL and routing fields used by network/CDN/DNS rules
    # pointing to wrong ops (virtualnetworks.list, cdn.profiles.list, dns.zones.list)
    "item.ssl_policy":                        "azure.network.applicationgateways.list",
    "item.ssl_policy.cipher_suites":          "azure.network.applicationgateways.list",
    "item.ssl_policy.min_protocol_version":   "azure.network.applicationgateways.list",
    "item.operational_state":                 "azure.network.applicationgateways.list",
    "item.backend_http_settings_collection":  "azure.network.applicationgateways.list",
    "item.trusted_root_certificates":         "azure.network.applicationgateways.list",
    "item.web_application_firewall_configuration": "azure.network.applicationgateways.list",
    "item.request_routing_rules":             "azure.network.applicationgateways.list",
    "item.url_path_maps":                     "azure.network.applicationgateways.list",
    "item.redirect_configurations":           "azure.network.applicationgateways.list",
    "item.rewrite_rule_sets":                 "azure.network.applicationgateways.list",
}

# ── Direct op-to-op redirects for CSV_GAP rules ────────────────────────────────
# When a rule's for_each uses an op that exists in step1b but has no produces entries
# (CSV_GAP), redirect to the correct enriched op. These are direct op substitutions.
CSV_GAP_REDIRECT: Dict[str, str] = {
    # mysql step1b (azure.mgmt.mysql) SDK not installed → use rdbms_mysql SDK
    "azure.mysql.servers.servers_list":         "azure.rdbms_mysql.servers.list",
    # postgresql step1b SDK not installed → use rdbms_postgresql
    "azure.postgresql.servers.servers_list":    "azure.rdbms_postgresql.servers.list",
    # mariadb step1b SDK not installed → use rdbms_mariadb
    "azure.mariadb.servers.servers_list":       "azure.rdbms_mariadb.servers.list",
    # operationalinsights SDK not installed → use loganalytics (same resource, different SDK)
    "azure.operationalinsights.workspaces.workspaces_list": "azure.loganalytics.workspaces.list",
    # appplatform.apms.list_secret_keys returns credentials, not service resources
    # monitoring rules check item.location which is on the service, not the APM keys
    "azure.appplatform.apms.list_secret_keys":  "azure.appplatform.services.list_by_subscription",
    # media.assets.list_container_sas returns SAS tokens, not media service resources
    "azure.media.assets.list_container_sas":    "azure.media.mediaservices.list",
    # machinelearningservices.list_skus returns SKU metadata, not workspace resources
    "azure.machinelearningservices.azuremachinelearningworkspacesmixin.list_skus":
        "azure.machinelearningservices.workspaces.list_by_subscription",
}


# ── Catalog loader ──────────────────────────────────────────────────────────────

def load_catalog() -> Tuple[Dict[str, Set[str]], Dict[str, Set[str]], Set[str]]:
    """Returns (op_to_fields, field_to_ops, all_ops)."""
    op_to_fields:  Dict[str, Set[str]] = defaultdict(set)
    field_to_ops:  Dict[str, Set[str]] = defaultdict(set)

    with open(CATALOG_CSV) as f:
        for row in csv.DictReader(f):
            op   = row["producing_op"]
            ivar = row["item_var_path"]
            if ivar:
                op_to_fields[op].add(ivar)
                field_to_ops[ivar].add(op)

    return dict(op_to_fields), dict(field_to_ops), set(op_to_fields)


def load_report() -> List[dict]:
    """Return all FIELD_MISSING rows (NOT deduplicated — keep all)."""
    with open(REPORT_CSV) as f:
        return [r for r in csv.DictReader(f) if r["status"] == "FIELD_MISSING"]


def load_csv_gap_report() -> List[dict]:
    """Return all CSV_GAP rows for op-to-op redirect processing."""
    with open(REPORT_CSV) as f:
        return [r for r in csv.DictReader(f) if r["status"] == "CSV_GAP"]


def build_csv_gap_corrections(gap_rows: List[dict]) -> Dict[str, str]:
    """
    Returns {rule_id: new_for_each} for CSV_GAP rules whose resolved_op
    is in CSV_GAP_REDIRECT.
    """
    result: Dict[str, str] = {}
    for row in gap_rows:
        resolved_op = row.get("resolved_op", "")
        redirect = CSV_GAP_REDIRECT.get(resolved_op)
        if redirect and redirect != row.get("for_each", ""):
            result[row["rule_id"]] = redirect
    return result


# ── op scoring ──────────────────────────────────────────────────────────────────

def score_op(
    op: str,
    condition_vars: List[str],
    op_to_fields: Dict[str, Set[str]],
) -> int:
    """How many condition vars does this op cover (exact + sub-path)?"""
    fields = op_to_fields.get(op, set())
    count = 0
    for v in condition_vars:
        if v in fields:
            count += 1
        elif any(v.startswith(p + ".") for p in fields if p):
            count += 1
    return count


def find_better_op(
    rule_id:        str,
    for_each:       str,
    condition_vars: List[str],
    missing_vars:   List[str],
    op_to_fields:   Dict[str, Set[str]],
    field_to_ops:   Dict[str, Set[str]],
    all_ops:        Set[str],
    min_score:      int = 1,
) -> Optional[str]:
    """
    Try to find a better op using 2 reliable strategies only:
      1. AAD/Entra rule_id prefix → Graph op (accurate, manually curated)
      2. FIELD_TO_OP cross-service override (accurate, manually curated)
    Note: same-service scoring is NOT used — it causes false positives.
    """

    # ── Strategy 1: AAD / Graph rule prefix ─────────────────────────────────
    for prefix, graph_op in AAD_RULE_PREFIXES.items():
        if rule_id.startswith(prefix):
            return graph_op

    # ── Strategy 2: Field-based cross-service override ───────────────────────
    # Check missing vars first (highest confidence), then all condition vars.
    # ALL missing vars must map to the SAME override op for it to be applied —
    # prevents partial-match false positives.
    override_votes: Dict[str, int] = defaultdict(int)
    for var in missing_vars:
        if var in FIELD_TO_OP:
            override_votes[FIELD_TO_OP[var]] += 1

    if override_votes:
        best_candidate = max(override_votes, key=override_votes.get)
        # Only apply if the winning candidate covers at least min_score missing vars
        if override_votes[best_candidate] >= min_score:
            # Don't suggest the same op we already have
            if best_candidate != for_each:
                return best_candidate

    return None


# ── build per-rule corrections ──────────────────────────────────────────────────

def build_corrections(
    fm_rows:      List[dict],
    op_to_fields: Dict[str, Set[str]],
    field_to_ops: Dict[str, Set[str]],
    all_ops:      Set[str],
    min_score:    int = 1,
) -> Dict[str, str]:
    """
    Returns {rule_id: new_for_each} for rules where a better op was found.
    """
    result: Dict[str, str] = {}

    for row in fm_rows:
        rule_id   = row["rule_id"]
        for_each  = row["for_each"]
        cond_vars = [v.strip() for v in row["condition_vars"].split(" | ") if v.strip()]
        miss_vars = [v.strip() for v in row["missing_vars"].split(" | ") if v.strip()]

        if not for_each:
            continue

        better = find_better_op(
            rule_id, for_each, cond_vars, miss_vars,
            op_to_fields, field_to_ops, all_ops, min_score
        )
        if better and better != for_each:
            result[rule_id] = better

    return result


# ── YAML updater ────────────────────────────────────────────────────────────────

def update_yaml_for_each(
    yaml_path:   Path,
    fixes:       Dict[str, str],   # rule_id → new_for_each
    dry_run:     bool,
) -> List[dict]:
    """Update for_each values in YAML. Returns list of change records."""
    changes: List[dict] = []

    try:
        text = yaml_path.read_text()
        data = yaml.safe_load(text) or {}
    except Exception as e:
        return [{"file": str(yaml_path), "rule_id": "", "action": "PARSE_ERROR",
                 "old_for_each": "", "new_for_each": str(e)}]

    new_text  = text
    modified  = False

    for check in data.get("checks", []):
        rule_id = str(check.get("rule_id", ""))
        new_fe  = fixes.get(rule_id)
        if not new_fe:
            continue
        old_fe = str(check.get("for_each", ""))
        if new_fe == old_fe:
            continue

        # Targeted string replacement
        idx = new_text.find(f"rule_id: {rule_id}")
        if idx == -1:
            idx = new_text.find(f"rule_id: '{rule_id}'")
        if idx == -1:
            continue

        fe_idx = new_text.find(f"for_each: {old_fe}", idx)
        if fe_idx == -1 or fe_idx > idx + 600:
            continue

        new_text = (
            new_text[:fe_idx]
            + f"for_each: {new_fe}"
            + new_text[fe_idx + len(f"for_each: {old_fe}"):]
        )
        modified = True
        changes.append({
            "file":       str(yaml_path),
            "rule_id":    rule_id,
            "action":     "UPDATED",
            "old_for_each": old_fe,
            "new_for_each": new_fe,
        })

    if modified and not dry_run:
        yaml_path.write_text(new_text)

    return changes


# ── main ────────────────────────────────────────────────────────────────────────

FIX_COLS = ["file", "rule_id", "action", "old_for_each", "new_for_each"]


def main() -> None:
    parser = argparse.ArgumentParser(description="Fix wrong for_each ops in FIELD_MISSING rules")
    parser.add_argument("--dry-run",   action="store_true")
    parser.add_argument("--service",   help="Comma-separated service dirs to limit scope")
    parser.add_argument("--min-score", type=int, default=1,
                        help="Minimum missing vars that the new op must cover (default: 1)")
    args = parser.parse_args()

    print("Loading catalog…")
    op_to_fields, field_to_ops, all_ops = load_catalog()
    print(f"  {len(op_to_fields)} ops, {len(field_to_ops)} fields")

    print("Loading FIELD_MISSING rows…")
    fm_rows = load_report()
    print(f"  {len(fm_rows)} FIELD_MISSING rule-rows")

    print(f"Computing corrections (min_score={args.min_score})…")
    corrections = build_corrections(fm_rows, op_to_fields, field_to_ops, all_ops, args.min_score)
    print(f"  {len(corrections)} rules have a better op candidate")

    print("Loading CSV_GAP rows and applying op redirects…")
    gap_rows = load_csv_gap_report()
    gap_corrections = build_csv_gap_corrections(gap_rows)
    print(f"  {len(gap_rows)} CSV_GAP rows, {len(gap_corrections)} redirectable rules")
    corrections.update(gap_corrections)

    service_filter = None
    if args.service:
        service_filter = {s.strip() for s in args.service.split(",")}

    yaml_files = sorted(RULES_DIR.rglob("*.yaml"))
    yaml_files = [f for f in yaml_files if not f.name.startswith("1_")]
    if service_filter:
        yaml_files = [f for f in yaml_files if f.parent.name in service_filter]

    mode = "DRY RUN" if args.dry_run else "WRITING"
    print(f"\nProcessing {len(yaml_files)} YAML files [{mode}]…")

    # Build per-file correction maps
    from collections import defaultdict as dd
    file_corrections: Dict[Path, Dict[str, str]] = dd(dict)

    # Need original report to find file paths
    with open(REPORT_CSV) as f:
        report_rows = list(csv.DictReader(f))
    rule_to_file: Dict[str, Path] = {}
    for r in report_rows:
        if r["status"] in ("FIELD_MISSING", "CSV_GAP"):
            rule_to_file[r["rule_id"]] = Path(r["file"])

    for rule_id, new_fe in corrections.items():
        yaml_path = rule_to_file.get(rule_id)
        if yaml_path:
            file_corrections[yaml_path][rule_id] = new_fe

    all_changes: List[dict] = []
    files_changed = 0

    for yaml_path in yaml_files:
        rule_fixes = file_corrections.get(yaml_path)
        if not rule_fixes:
            continue

        changes = update_yaml_for_each(yaml_path, rule_fixes, args.dry_run)
        if changes:
            updated = [c for c in changes if c["action"] == "UPDATED"]
            if updated:
                files_changed += 1
                print(f"  {yaml_path.name:<55} {len(updated):>3} rules updated")
        all_changes.extend(changes)

    # Write fix report
    with open(FIX_REPORT, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIX_COLS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(all_changes)

    updated = sum(1 for c in all_changes if c["action"] == "UPDATED")
    print()
    print("=" * 60)
    print(f"Rules updated:  {updated}")
    print(f"Files changed:  {files_changed}")
    print(f"Fix report:     {FIX_REPORT}")
    if args.dry_run:
        print("\n[DRY RUN] No files written.")


if __name__ == "__main__":
    main()
