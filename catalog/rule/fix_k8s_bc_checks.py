#!/usr/bin/env python3
"""
Fix Category B (argument-flag rules) and Category C (real field checks with wrong for_each/var).

Category B — argument-flag rules:
  - Fix for_each to the service's correct catalog operation
  - Keep arguments.* var path (synthetic notation for check engine arg resolution)
  - For kubelet/node-based services, use k8s.node.list or k8s.kubelet.list_node

Category C — real K8s field checks with wrong for_each or var:
  - Fix for_each using catalog producing_op for that field+service
  - Fix var by looking up the field path in the master catalog
  - Normalize containers[0].* → containers[].* to match catalog
"""

import csv
import re
import yaml
from pathlib import Path

CATALOG_CSV = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/k8s/k8s_master_field_catalog.csv")
CHECKS_ROOT = Path("/Users/apple/Desktop/threat-engine/catalog/rule/k8s_rule_check")

# ── Service → correct catalog for_each op (Category B) ──────────────────────
# Each system-component service maps to its best catalog list operation
SERVICE_CATALOG_OP = {
    "apiserver":    "k8s.apiserver.list_component_status",
    "etcd":         "k8s.etcd.list_component_status",
    "kubelet":      "k8s.kubelet.list_node",
    "scheduler":    "k8s.scheduler.list_component_status",
    "controlplane": "k8s.controlplane.list_component_status",
    "cluster":      "k8s.cluster.list_node",
    "federation":   "k8s.pod.list",     # federation uses pod-based checks
    "secret":       "k8s.secret.list",
}

# Argument-flag names that are vague/abstract — leave as-is (no fix needed)
VAGUE_ARGS = {
    "arguments.enabled", "arguments.configured", "arguments.review-scheduled",
    "arguments.protection-enabled", "arguments.protection-configured",
    "arguments.availability-configured", "arguments.backup-configured",
    "arguments.captures-metadata", "arguments.limiting-enabled",
    "arguments.upgrade-enabled", "arguments.flags-configured",
    "arguments.configuration-applied", "arguments.high-availability-enabled",
    "arguments.only", "arguments.configuration-review-scheduled",
    "arguments.ddos-protection-configured", "arguments.secure-configuration-enforced",
    "arguments.strong-mechanism-enabled", "arguments.verification-configured",
    "arguments.scheduled",
}

# ── Category C: field path normalization helpers ─────────────────────────────
def normalize_var(var: str) -> str:
    """
    Normalize legacy var paths to catalog-compatible paths.
    item.containers[0].x  →  item.spec.containers[].x
    item.hostIPC           →  item.spec.hostIPC  (for pod)
    item.labels            →  item.metadata.labels
    item.policyTypes       →  item.spec.policyTypes
    item.policy_types      →  item.spec.policyTypes
    """
    # Strip item. prefix for lookup
    path = var[5:] if var.startswith("item.") else var

    # containers[0].* → spec.containers[].* (pod-level)
    path = re.sub(r"containers\[\d+\]\.", "spec.containers[].", path)
    # If path starts directly with spec.containers[] it's fine
    # If item.hostIPC / item.hostPID etc → spec.hostIPC
    if path in ("hostIPC", "hostPID", "hostNetwork"):
        path = f"spec.{path}"
    # item.labels → metadata.labels
    if path == "labels":
        path = "metadata.labels"
    # item.annotations → metadata.annotations
    if path == "annotations":
        path = "metadata.annotations"
    # policy_types → spec.policyTypes
    if path in ("policy_types", "policyTypes"):
        path = "spec.policyTypes"
    # item.volumes → spec.volumes
    if path == "volumes":
        path = "spec.volumes"
    # item.subjects → subjects (clusterrolebinding)
    # item.roleRef → roleRef
    # item.rules → rules (role/clusterrole)
    # item.storage_class_name → spec.storageClassName
    if path == "storage_class_name":
        path = "spec.storageClassName"
    # item.hostNetwork (pod-level) → spec.hostNetwork
    return path


def find_in_catalog(svc_catalog: dict, field_path: str) -> dict | None:
    """Look up a field path in service catalog, with fuzzy fallback."""
    # Exact match
    if field_path in svc_catalog:
        return svc_catalog[field_path]
    # Suffix match (e.g. spec.containers[].command matches .command suffix)
    for cat_path, row in svc_catalog.items():
        if cat_path.endswith(field_path) or field_path.endswith(cat_path):
            return row
    return None


# ── Load catalog ─────────────────────────────────────────────────────────────
def load_catalog():
    catalog: dict[str, dict[str, dict]] = {}
    with open(CATALOG_CSV) as f:
        for row in csv.DictReader(f):
            svc  = row["service"]
            path = row["field_path"]
            existing = catalog.setdefault(svc, {}).get(path)
            if existing is None:
                catalog[svc][path] = row
            elif row.get("is_independent", "Yes") == "Yes" and existing.get("is_independent") == "No":
                catalog[svc][path] = row
    return catalog


# ── Process checks ────────────────────────────────────────────────────────────
def fix_checks(catalog: dict):
    stats = {"b_fixed": 0, "b_skipped": 0, "c_fixed": 0, "c_skipped": 0, "files_updated": 0}

    for check_file in sorted(CHECKS_ROOT.glob("*/*.checks.yaml")):
        if check_file.name.startswith("1_"):
            continue

        with open(check_file) as f:
            doc = yaml.safe_load(f)

        svc = doc.get("service", check_file.parent.name)
        svc_catalog = catalog.get(svc, {})
        changed = False
        new_checks = []

        for check in doc.get("checks", []):
            rule_id = check.get("rule_id", "")
            fe      = check.get("for_each", "")
            cond    = check.get("conditions", {})

            if not isinstance(cond, dict) or "var" not in cond:
                new_checks.append(check)
                continue

            var = cond.get("var", "")
            op  = cond.get("op", "")
            val = cond.get("value")

            # ── Category B: argument-flag rules ──────────────────────────────
            if var.startswith("arguments."):
                if var in VAGUE_ARGS:
                    stats["b_skipped"] += 1
                    new_checks.append(check)
                    continue

                correct_fe = SERVICE_CATALOG_OP.get(svc)
                if not correct_fe:
                    stats["b_skipped"] += 1
                    new_checks.append(check)
                    continue

                if fe == correct_fe:
                    # Already correct
                    stats["b_skipped"] += 1
                    new_checks.append(check)
                    continue

                # Fix: update for_each to correct catalog op, keep var/op/val
                new_check = dict(check)
                new_check["for_each"] = correct_fe
                new_checks.append(new_check)
                stats["b_fixed"] += 1
                changed = True
                continue

            # ── Category C: real field checks ────────────────────────────────
            # Normalize var path and look up in catalog
            norm_field = normalize_var(var)
            row = find_in_catalog(svc_catalog, norm_field) if svc_catalog else None

            if not row:
                # No catalog entry — can't fix
                stats["c_skipped"] += 1
                new_checks.append(check)
                continue

            correct_fe  = row["producing_op"]
            correct_var = row["item_var_path"]

            if fe == correct_fe and var == correct_var:
                # Already exactly right
                stats["c_skipped"] += 1
                new_checks.append(check)
                continue

            # Something is wrong (for_each, var, or both) — apply fix
            new_check = {
                "rule_id":    rule_id,
                "for_each":   correct_fe,
                "conditions": {
                    "var": correct_var,
                    "op":  op,
                },
            }
            if val is not None:
                new_check["conditions"]["value"] = val

            new_checks.append(new_check)
            stats["c_fixed"] += 1
            changed = True

        if changed:
            backup = check_file.with_suffix(".yaml.bak")
            backup.write_text(check_file.read_text())
            doc["checks"] = new_checks
            with open(check_file, "w") as f:
                yaml.dump(doc, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            stats["files_updated"] += 1
            print(f"  Updated: {svc}/{check_file.name}")
        else:
            print(f"  OK:      {svc}/{check_file.name}")

    return stats


def main():
    print("Loading master field catalog...")
    catalog = load_catalog()
    print(f"  {sum(len(v) for v in catalog.values()):,} fields, {len(catalog)} services\n")

    print("Fixing Category B + C checks...")
    stats = fix_checks(catalog)

    print()
    print("=" * 55)
    print("FIX SUMMARY")
    print("=" * 55)
    print(f"  Category B (arg-flag) fixed  : {stats['b_fixed']}")
    print(f"  Category B skipped/vague     : {stats['b_skipped']}")
    print(f"  Category C (field) fixed     : {stats['c_fixed']}")
    print(f"  Category C skipped/no-match  : {stats['c_skipped']}")
    print(f"  Files updated                : {stats['files_updated']}")
    print()
    print("Run generate_k8s_assertions.py next to refresh 1_k8s_full_scope_assertions.yaml")


if __name__ == "__main__":
    main()
