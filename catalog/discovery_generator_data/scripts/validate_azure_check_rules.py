#!/usr/bin/env python3
"""
Validate Azure check rules against the azure_master_field_catalog.csv.

For every rule in catalog/rule/azure_rule_check/**/*.yaml:
  1. Resolve for_each op_id → best 4-part op in the CSV
  2. Check every conditions.var (item.xxx) is produced by that op
  3. Suggest the correct op (if resolvable) and correct fields

Output:
  catalog/discovery_generator/azure/check_rule_validation_report.csv
  catalog/discovery_generator/azure/check_rule_validation_summary.txt

Usage:
    python3 catalog/discovery_generator/scripts/validate_azure_check_rules.py
    python3 ...  --service keyvault,storage   # limit to specific service dirs
    python3 ...  --fix                        # write fixed YAMLs (dry-run by default)
"""

import argparse
import csv
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

# ── paths ─────────────────────────────────────────────────────────────────────

REPO_ROOT   = Path(".")
RULES_DIR   = REPO_ROOT / "catalog/rule/azure_rule_check"
CATALOG_CSV = REPO_ROOT / "catalog/discovery_generator/azure/azure_master_field_catalog.csv"
REPORT_CSV  = REPO_ROOT / "catalog/discovery_generator/azure/check_rule_validation_report.csv"
SUMMARY_TXT = REPO_ROOT / "catalog/discovery_generator/azure/check_rule_validation_summary.txt"

# ── status codes ──────────────────────────────────────────────────────────────

STATUS_OK            = "OK"            # op resolved, all vars valid
STATUS_FIELD_MISSING = "FIELD_MISSING" # op resolved, ≥1 var not in produced fields (wrong op/field)
STATUS_CSV_GAP       = "CSV_GAP"       # op in CSV but step1b lacks resource-level field breakdown
STATUS_OP_RESOLVED   = "OP_RESOLVED"   # 3-part resolved to 4-part; fields valid
STATUS_OP_AMBIGUOUS  = "OP_AMBIGUOUS"  # multiple 4-part candidates, cannot pick one
STATUS_OP_MISSING    = "OP_MISSING"    # 4-part ID not in CSV at all (graph, k8s, …)
STATUS_OP_UNRESOLVED = "OP_UNRESOLVED" # 3-part and no candidate found

# Fields that indicate an op's step1b only has metadata, not resource sub-fields
_METADATA_ONLY_FIELDS: Set[str] = {"item.count", "item.next_link", "item.value"}


def _is_csv_gap(fields_produced: Set[str]) -> bool:
    """True when the op is in CSV but only has metadata-level fields (no real resource fields).
    These are step1b gaps — the resource's actual fields aren't enumerated yet.
    """
    if not fields_produced:
        return True
    # If every produced field is metadata-only, treat as gap
    resource_fields = fields_produced - _METADATA_ONLY_FIELDS
    if not resource_fields:
        return True
    # If the only resource-level field is something like item.count or nothing meaningful
    # (no id, name, properties, location, tags)
    basic = {"item.id", "item.name", "item.properties", "item.location", "item.tags",
             "item.type", "item.etag", "item.kind"}
    if not (resource_fields & basic):
        # No basic resource identifiers — likely just metadata
        return True
    return False

# ── explicit 3-part → 4-part overrides ───────────────────────────────────────
# For cases where the resolver picks the wrong candidate, override manually.
# Key = 3-part for_each; Value = correct 4-part op_id.
EXPLICIT_OVERRIDES: Dict[str, str] = {
    "azure.aks.list":                          "azure.containerservice.managedclusters.list",
    "azure.machine.list":                      "azure.compute.virtualmachines.list",
    "azure.machine.list_by_resource_group":    "azure.compute.virtualmachines.list_by_resource_group",
    "azure.backup.list":                       "azure.recoveryservices.vaults.list_by_subscription_id",
    "azure.cosmosdb.list":                     "azure.cosmosdb.databaseaccounts.list",
    "azure.network.list":                      "azure.network.virtualnetworks.list",
    "azure.sql.list":                          "azure.sql.servers.list",
    "azure.storage.list":                      "azure.storage.storageaccounts.list",
    "azure.container.list":                    "azure.containerinstance.containergroups.list",
    "azure.kubernetes.list":                   "azure.containerservice.managedclusters.list",
    "azure.aad.list":                          "azure.authorization.roleassignments.list",
    "azure.aad.list_for_resource_group":       "azure.authorization.roleassignments.list_for_resource_group",
    "azure.rbac.list":                         "azure.authorization.roleassignments.list",
    "azure.rbac.list_for_resource_group":      "azure.authorization.roleassignments.list_for_resource_group",
    "azure.iam.list":                          "azure.authorization.roleassignments.list",
    "azure.policy.list":                       "azure.authorization.root.list",
    "azure.policy.list_for_resource_group":    "azure.authorization.root.list_for_resource_group",
    "azure.security.list":                     "azure.security.root.list",
    "azure.webapp.list":                       "azure.web.webapps.list",
    "azure.function.list":                     "azure.web.webapps.list",
    "azure.logic.list":                        "azure.logic.workflows.list_by_subscription",
    "azure.databricks.list":                   "azure.databricks.workspaces.list_by_subscription",
    "azure.hdinsight.list":                    "azure.hdinsight.clusters.list",
    "azure.compute.list":                      "azure.compute.virtualmachines.list",
    "azure.compute.list_by_resource_group":    "azure.compute.virtualmachines.list",   # fallback
    "azure.data.list_by_resource_group":       "azure.datafactory.factories.list_by_resource_group",
    "azure.keyvault.list_by_resource_group":   "azure.keyvault.vaults.list_by_resource_group",
    "azure.key.list_by_resource_group":        "azure.keyvault.keys.list",
    "azure.certificates.list_by_resource_group": "azure.keyvault.vaults.list_by_resource_group",  # no certs op in CSV
    "azure.monitor.list":                      "azure.monitor.activitylogalerts.list",  # best available
    "azure.monitor.list_by_resource_group":    "azure.monitor.activitylogalerts.list_by_resource_group",
    "azure.synapse.list":                      "azure.synapse.workspaces.list",
    "azure.purview.list_by_resource_group":    "azure.purview.accounts.list_by_resource_group",
    "azure.automation.list":                   "azure.automation.automationaccount.list",
    "azure.batch.list":                        "azure.batch.batchaccount.list",
    "azure.cdn.list":                          "azure.cdn.profiles.list",
    "azure.dns.list":                          "azure.dns.zones.list",
    "azure.event.list_by_resource_group":      "azure.eventhub.namespaces.list_by_resource_group",
    "azure.event.list_available_cluster_region": "azure.eventhub.clusters.list_available_cluster_region",
    "azure.servicebus.list":                   "azure.servicebus.namespaces.list",
    "azure.signalr.list":                      "azure.signalr.root.list_by_subscription",
    "azure.subscription.list":                 "azure.subscription.subscriptions.list",
    "azure.mariadb.list":                      "azure.mariadb.servers.servers_list",
    "azure.mysql.list":                        "azure.mysql.servers.servers_list",
    "azure.postgresql.list":                   "azure.postgresql.servers.servers_list",
    "azure.kusto.list":                        "azure.kusto.clusters.list",
    "azure.loganalytics.list":                 "azure.loganalytics.workspaces.list",
    "azure.managedidentity.list":              "azure.managedidentity.userassignedidentities.list_by_subscription",
    "azure.management.list":                   "azure.managementgroups.managementgroups.list",
    "azure.managementgroup.list":              "azure.managementgroups.managementgroups.list",
    "azure.streamanalytics.list":              "azure.streamanalytics.streamingjobs.list",
    "azure.front.list":                        "azure.frontdoor.frontdoors.list",
    "azure.traffic.list":                      "azure.trafficmanager.profiles.list_by_subscription",
    "azure.dataprotection.list":               "azure.dataprotection.backupinstances.list",
    "azure.api.list":                          "azure.apimanagement.apimanagementservice.list",
    "azure.resource.list":                     "azure.resources.resources.list",
    "azure.log.list_by_resource_group":        "azure.monitor.activitylogalerts.list_by_resource_group",
    "azure.cost.list_by_resource_group":       "azure.costmanagement.exports.list",
    "azure.billing.list_by_resource_group":    "azure.billing.billingaccounts.list",
    "azure.devops.list_by_resource_group":     "azure.monitor.root.list_by_resource_group",  # no devops in CSV
    "azure.intune.list_by_resource_group":     "azure.monitor.root.list_by_resource_group",  # no intune in CSV
    "azure.iot.list_by_resource_group":        "azure.iothub.iothubresource.list_by_resource_group",
    "azure.power.list_by_resource_group":      "azure.powerbidedicated.capacities.list",
    "azure.redis.list_by_resource_group":      "azure.redis.redis.list_by_resource_group",
    "azure.search.list_by_resource_group":     "azure.search.services.list_by_resource_group",
    "azure.containerregistry.list":            "azure.containerregistry.root.list",
    "azure.notification.list_available_cluster_region": "azure.eventhub.clusters.list_available_cluster_region",
    "azure.config.list":                       "azure.appconfiguration.configurationstores.configurationstores_list",
}

# ── load catalog ──────────────────────────────────────────────────────────────

def load_catalog() -> Tuple[
    Dict[str, Set[str]],    # op_id → item_var_paths
    Dict[str, Set[str]],    # svc_name → op_ids
    Dict[str, bool],        # op_id → is_independent
    Set[str],               # all op_ids
]:
    op_to_fields: Dict[str, Set[str]] = defaultdict(set)
    svc_to_ops:   Dict[str, Set[str]] = defaultdict(set)
    op_is_indep:  Dict[str, bool]     = {}

    with open(CATALOG_CSV) as f:
        for row in csv.DictReader(f):
            op   = row["producing_op"]
            svc  = row["service"]
            ivar = row["item_var_path"]
            if ivar:
                op_to_fields[op].add(ivar)
            svc_to_ops[svc].add(op)
            if op not in op_is_indep:
                op_is_indep[op] = row["is_independent"] == "Yes"

    all_ops = set(op_to_fields) | set(op_is_indep)
    return dict(op_to_fields), dict(svc_to_ops), op_is_indep, all_ops


# ── op resolver ───────────────────────────────────────────────────────────────

def _op_method(op_id: str) -> str:
    """Extract method suffix from full op_id."""
    return op_id.split(".")[-1]


def resolve_op(
    for_each: str,
    yaml_svc_dir: str,
    svc_to_ops: Dict[str, Set[str]],
    op_is_indep: Dict[str, bool],
    all_ops: Set[str],
) -> Tuple[Optional[str], str, List[str]]:
    """
    Returns (resolved_op_or_None, resolution_status, candidates_list).
    resolution_status ∈ {EXACT, RESOLVED_UNIQUE, RESOLVED_BEST, AMBIGUOUS, MISSING, UNRESOLVED}
    """
    # ── explicit override ────────────────────────────────────────────────────
    if for_each in EXPLICIT_OVERRIDES:
        target = EXPLICIT_OVERRIDES[for_each]
        if target in all_ops:
            return target, "RESOLVED_UNIQUE", [target]
        # Override target not in CSV (service not yet implemented)
        return None, "MISSING", []

    # ── 4-part exact match ───────────────────────────────────────────────────
    if for_each in all_ops:
        return for_each, "EXACT", [for_each]

    parts = for_each.split(".")
    n_parts = len(parts)

    # ── 4-part not in CSV ────────────────────────────────────────────────────
    if n_parts >= 4:
        return None, "MISSING", []

    # ── 3-part resolution ────────────────────────────────────────────────────
    # parts = ["azure", svc_hint, method]
    svc_hint = parts[1] if n_parts >= 2 else ""
    method   = parts[2] if n_parts >= 3 else ""

    candidates: List[str] = []

    # Strategy 1: same YAML service dir, matching method suffix
    for op in svc_to_ops.get(yaml_svc_dir, set()):
        if _op_method(op) == method:
            candidates.append(op)

    # Strategy 2: svc_hint as prefix of CSV service name, matching method
    if not candidates:
        for svc, ops in svc_to_ops.items():
            if svc.startswith(svc_hint) or svc_hint.startswith(svc):
                for op in ops:
                    if _op_method(op) == method:
                        candidates.append(op)

    # Strategy 3: any service in YAML dir, method contains hint
    if not candidates:
        for op in svc_to_ops.get(yaml_svc_dir, set()):
            if method in _op_method(op):
                candidates.append(op)

    # Strategy 4: broader — yaml_svc_dir ops with method containing "list"
    if not candidates and method.startswith("list"):
        for op in svc_to_ops.get(yaml_svc_dir, set()):
            if "list" in _op_method(op):
                candidates.append(op)

    if not candidates:
        return None, "UNRESOLVED", []

    # Deduplicate and prefer independent ops
    candidates = list(dict.fromkeys(candidates))
    indep = [c for c in candidates if op_is_indep.get(c, False)]
    preferred = indep if indep else candidates

    if len(preferred) == 1:
        return preferred[0], "RESOLVED_UNIQUE", candidates
    if len(candidates) == 1:
        return candidates[0], "RESOLVED_UNIQUE", candidates

    # Still ambiguous — pick the one whose category best matches svc_hint
    best = sorted(preferred or candidates, key=lambda op: (
        0 if svc_hint in op.split(".")[2] else 1,
        len(op)
    ))
    return best[0], "RESOLVED_BEST", candidates


# ── condition var extractor ───────────────────────────────────────────────────

def extract_vars(conditions: object) -> List[str]:
    """Recursively extract all 'var' values from a conditions block."""
    result: List[str] = []
    if isinstance(conditions, dict):
        if "var" in conditions:
            result.append(str(conditions["var"]))
        for key in ("and", "or", "not"):
            if key in conditions:
                val = conditions[key]
                if isinstance(val, list):
                    for item in val:
                        result.extend(extract_vars(item))
                else:
                    result.extend(extract_vars(val))
    elif isinstance(conditions, list):
        for item in conditions:
            result.extend(extract_vars(item))
    return result


# ── per-YAML validation ───────────────────────────────────────────────────────

def validate_yaml(
    yaml_path: Path,
    op_to_fields: Dict[str, Set[str]],
    svc_to_ops: Dict[str, Set[str]],
    op_is_indep: Dict[str, bool],
    all_ops: Set[str],
) -> List[dict]:
    svc_dir = yaml_path.parent.name

    try:
        with open(yaml_path) as f:
            data = yaml.safe_load(f) or {}
    except Exception as e:
        return [{"file": str(yaml_path), "service_dir": svc_dir,
                 "rule_id": "", "for_each": "", "resolved_op": "",
                 "status": "PARSE_ERROR", "condition_vars": "",
                 "missing_vars": str(e), "candidates": "", "suggested_for_each": "",
                 "fields_produced_by_op": ""}]

    results = []
    for check in data.get("checks", []):
        rule_id  = str(check.get("rule_id", ""))
        for_each = str(check.get("for_each", ""))
        conds    = check.get("conditions", {})
        vars_    = list(dict.fromkeys(extract_vars(conds)))   # dedup, preserve order

        # Derive a service hint from rule_id (e.g. "azure.purview.catalog.*" → "purview")
        # This helps when a rule is mis-filed in the wrong yaml_dir
        rule_svc_hint = ""
        rule_parts = rule_id.split(".")
        if len(rule_parts) >= 2 and rule_parts[0] == "azure":
            rule_svc_hint = rule_parts[1]

        # Try resolving with rule_id hint first, fall back to yaml_dir
        resolved_op, res_status, candidates = resolve_op(
            for_each, rule_svc_hint or svc_dir, svc_to_ops, op_is_indep, all_ops
        )
        if resolved_op is None and rule_svc_hint and rule_svc_hint != svc_dir:
            resolved_op, res_status, candidates = resolve_op(
                for_each, svc_dir, svc_to_ops, op_is_indep, all_ops
            )

        # Check fields
        missing_vars: List[str] = []
        valid_vars:   List[str] = []
        fields_produced: Set[str] = op_to_fields.get(resolved_op or "", set())

        for v in vars_:
            if not v.startswith("item."):
                valid_vars.append(v)
                continue
            if v in fields_produced:
                valid_vars.append(v)
            elif any(v.startswith(p + ".") for p in fields_produced if p):
                # v is a sub-path of a produced field (e.g. item.sku.name → item.sku produced)
                valid_vars.append(v)
            else:
                missing_vars.append(v)

        # Determine final status
        if res_status == "EXACT":
            if missing_vars:
                if _is_csv_gap(fields_produced):
                    status = STATUS_CSV_GAP
                else:
                    status = STATUS_FIELD_MISSING
            else:
                status = STATUS_OK
        elif res_status in ("RESOLVED_UNIQUE", "RESOLVED_BEST"):
            if missing_vars:
                if _is_csv_gap(fields_produced):
                    status = STATUS_CSV_GAP
                else:
                    status = STATUS_FIELD_MISSING
            else:
                status = STATUS_OP_RESOLVED   # op changed, fields OK
        elif res_status == "AMBIGUOUS":
            status = STATUS_OP_AMBIGUOUS
        elif res_status == "MISSING":
            status = STATUS_OP_MISSING
        else:
            status = STATUS_OP_UNRESOLVED

        # Suggest better for_each: use the resolved op if different
        suggested_for_each = ""
        if resolved_op and resolved_op != for_each:
            suggested_for_each = resolved_op

        # Suggest field fixes: list what the op actually produces
        fields_sorted = sorted(fields_produced) if fields_produced else []

        results.append({
            "file":                   str(yaml_path),
            "service_dir":            svc_dir,
            "rule_id":                rule_id,
            "for_each":               for_each,
            "resolved_op":            resolved_op or "",
            "status":                 status,
            "condition_vars":         " | ".join(vars_),
            "missing_vars":           " | ".join(missing_vars),
            "candidates":             " | ".join(candidates[:5]),
            "suggested_for_each":     suggested_for_each,
            "fields_produced_by_op":  " | ".join(fields_sorted),
        })

    return results


# ── main ──────────────────────────────────────────────────────────────────────

REPORT_COLUMNS = [
    "file", "service_dir", "rule_id", "for_each", "resolved_op",
    "status", "condition_vars", "missing_vars",
    "candidates", "suggested_for_each", "fields_produced_by_op",
]


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate Azure check rules vs master CSV")
    parser.add_argument("--service", help="Comma-separated service dirs to limit scope")
    args = parser.parse_args()

    if not CATALOG_CSV.exists():
        sys.exit(f"ERROR: {CATALOG_CSV} not found — run generate_azure_master_field_catalog.py first")

    print("Loading catalog…", flush=True)
    op_to_fields, svc_to_ops, op_is_indep, all_ops = load_catalog()
    print(f"  {len(all_ops)} ops, {len(svc_to_ops)} services")

    service_filter: Optional[Set[str]] = None
    if args.service:
        service_filter = set(s.strip() for s in args.service.split(","))

    yaml_files = sorted(RULES_DIR.rglob("*.yaml"))
    yaml_files = [f for f in yaml_files if not f.name.startswith("1_")]
    if service_filter:
        yaml_files = [f for f in yaml_files if f.parent.name in service_filter]

    print(f"Validating {len(yaml_files)} YAML files…", flush=True)

    all_results: List[dict] = []
    for yf in yaml_files:
        rows = validate_yaml(yf, op_to_fields, svc_to_ops, op_is_indep, all_ops)
        all_results.extend(rows)

    # Write report CSV
    with open(REPORT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=REPORT_COLUMNS)
        writer.writeheader()
        writer.writerows(all_results)

    # Build summary
    from collections import Counter
    status_counts = Counter(r["status"] for r in all_results)
    total = len(all_results)

    # Breakdown by service_dir for FIELD_MISSING
    field_missing = [r for r in all_results if r["status"] == STATUS_FIELD_MISSING]
    by_svc: Counter = Counter(r["service_dir"] for r in field_missing)

    op_missing = [r for r in all_results if r["status"] == STATUS_OP_MISSING]
    op_unresolved = [r for r in all_results if r["status"] == STATUS_OP_UNRESOLVED]
    op_resolved = [r for r in all_results if r["status"] == STATUS_OP_RESOLVED]

    lines = [
        "Azure Check Rule Validation Report",
        "=" * 60,
        f"Total rules:          {total}",
        "",
        "Status breakdown:",
    ]
    for st in [STATUS_OK, STATUS_OP_RESOLVED, STATUS_FIELD_MISSING, STATUS_CSV_GAP,
               STATUS_OP_UNRESOLVED, STATUS_OP_AMBIGUOUS, STATUS_OP_MISSING, "PARSE_ERROR"]:
        cnt = status_counts.get(st, 0)
        pct = 100 * cnt / total if total else 0
        lines.append(f"  {st:<22} {cnt:>5}  ({pct:.1f}%)")

    lines += [
        "",
        f"OK + OP_RESOLVED (for_each changed but fields valid):  "
        f"{status_counts.get(STATUS_OK,0) + status_counts.get(STATUS_OP_RESOLVED,0)}",
        "",
        "─" * 60,
        "FIELD_MISSING breakdown by service:",
    ]
    for svc, cnt in by_svc.most_common(20):
        lines.append(f"  {svc:<30} {cnt}")

    if op_missing:
        lines += ["", "─" * 60, "OP_MISSING (4-part but not in CSV) — unimplemented services:"]
        missing_ops = sorted(set(r["for_each"] for r in op_missing))
        for op in missing_ops:
            cnt = sum(1 for r in op_missing if r["for_each"] == op)
            lines.append(f"  {op:<55} {cnt} rules")

    if op_unresolved:
        lines += ["", "─" * 60, "OP_UNRESOLVED — 3-part IDs with no candidate in CSV:"]
        unres = sorted(set(r["for_each"] for r in op_unresolved))
        for op in unres:
            cnt = sum(1 for r in op_unresolved if r["for_each"] == op)
            lines.append(f"  {op:<55} {cnt} rules")

    if op_resolved:
        lines += ["", "─" * 60, "OP_RESOLVED — 3-part IDs resolved to 4-part (need update in YAML):"]
        resolved_pairs = sorted(set(
            (r["for_each"], r["resolved_op"]) for r in op_resolved
        ))
        for fe, res in resolved_pairs:
            cnt = sum(1 for r in op_resolved if r["for_each"] == fe)
            lines.append(f"  {fe:<40} → {res}  ({cnt} rules)")

    summary = "\n".join(lines)
    with open(SUMMARY_TXT, "w") as f:
        f.write(summary + "\n")

    print(summary)
    print(f"\nReport CSV:  {REPORT_CSV}")
    print(f"Summary:     {SUMMARY_TXT}")


if __name__ == "__main__":
    main()
