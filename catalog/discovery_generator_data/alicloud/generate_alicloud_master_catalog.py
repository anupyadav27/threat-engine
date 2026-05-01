#!/usr/bin/env python3
"""
Generate AliCloud master field catalog from step6 discovery YAMLs.

For each service with a step6 discovery YAML:
  - Reads all discovery entries (discovery_id + calls + emit.item fields)
  - Emits one CSV row per standard field per discovery_id
  - Derives SDK metadata from alicloud_dependencies JSON

Outputs:
  alicloud_master_field_catalog.csv   — all services combined (master)
  <service>/field_operator_value_table.csv  — per-service split

Usage:
  python3 generate_alicloud_master_catalog.py [--service ack]
"""
from __future__ import annotations
import csv, json, sys
from pathlib import Path

import yaml

BASE     = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/alicloud")
OUT_CSV  = BASE / "alicloud_master_field_catalog.csv"
DEPS_KEY = "alicloud_dependencies_with_python_names_fully_enriched.json"

SERVICE_FILTER = None
for i, a in enumerate(sys.argv[1:], 1):
    if a == "--service" and i < len(sys.argv):
        SERVICE_FILTER = sys.argv[i + 1]

# ── Standard field schema (18 fields emitted by every AliCloud resource) ──────
# (field_name, field_type, operators, operators_no_value)
STANDARD_FIELDS: list[tuple[str, str, list[str], list[str]]] = [
    ("id",                   "string",  ["equals", "not_equals", "exists"],                     ["exists"]),
    ("name",                 "string",  ["equals", "contains", "not_equals", "in"],              []),
    ("resource_type",        "string",  ["equals", "not_equals"],                                []),
    ("region",               "string",  ["equals", "not_equals", "in"],                          []),
    ("encrypted",            "boolean", ["equals", "not_equals"],                                []),
    ("kms_key_id",           "string",  ["exists", "not_exists", "equals"],                      ["exists", "not_exists"]),
    ("public_ip_address",    "string",  ["exists", "not_exists", "equals"],                      ["exists", "not_exists"]),
    ("vpc_id",               "string",  ["exists", "not_exists", "equals"],                      ["exists", "not_exists"]),
    ("status",               "string",  ["equals", "not_equals", "in"],                          []),
    ("tags",                 "object",  ["exists", "not_empty"],                                  ["exists", "not_empty"]),
    ("internet_facing",      "boolean", ["equals", "not_equals"],                                []),
    ("permissions",          "array",   ["contains", "not_contains", "equals", "not_empty"],     ["not_empty"]),
    ("security_group_rules", "array",   ["contains", "not_contains", "not_empty"],               ["not_empty"]),
    ("backup_enabled",       "boolean", ["equals", "not_equals"],                                []),
    ("logging_enabled",      "boolean", ["equals", "not_equals"],                                []),
    ("mfa_enabled",          "boolean", ["equals", "not_equals"],                                []),
    ("ssl_enabled",          "boolean", ["equals", "not_equals"],                                []),
    ("versioning_enabled",   "boolean", ["equals", "not_equals"],                                []),
    ("min_tls_version",      "string",  ["equals", "not_equals", "gte"],                        []),
]

FIELD_IS_ID = {"id", "kms_key_id", "vpc_id"}

# ── CSV columns (matches OCI master catalog format) ───────────────────────────
COLS = [
    "csp", "service", "field_path", "item_var_path",
    "field_type", "is_id", "producing_op", "op_kind",
    "is_independent", "root_op", "chain_ops", "chain_length",
    "hop_distance", "chain_ops_with_fields",
    "operators", "operators_no_value",
    "python_call", "http_path",
    "resource_type",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def load_deps(svc_dir: Path) -> dict:
    """Load alicloud_dependencies JSON for a service (local or global)."""
    local = svc_dir / DEPS_KEY
    if local.exists():
        try:
            return json.loads(local.read_text())
        except Exception:
            pass
    # fallback to top-level merged file
    top = BASE / DEPS_KEY
    if top.exists():
        try:
            raw = json.loads(top.read_text())
            svc = svc_dir.name
            if svc in raw:
                return {svc: raw[svc]}
        except Exception:
            pass
    return {}


def get_module(deps: dict, service: str) -> str:
    svc_data = deps.get(service, {})
    return svc_data.get("module", f"alibabacloud_python_sdk.{service}")


def make_python_call(module: str, action: str) -> str:
    """e.g. alibabacloud_python_sdk.ack.Client().DescribeAddons().data"""
    return f"{module}.Client().{action}().data"


def ops_for_action(deps: dict, service: str, action: str) -> dict:
    """Return operation metadata dict from deps for a given action."""
    for op in deps.get(service, {}).get("operations", []):
        if op.get("operation") == action or op.get("python_method") == action:
            return op
    return {}


def chain_label(discovery_id: str, action: str, fields: list[str]) -> str:
    """Format: alicloud.ack.DescribeAddons[id|name|status|...]"""
    tag = "|".join(fields[:6]) + ("|..." if len(fields) > 6 else "")
    return f"{discovery_id}[{tag}]"


# ── Per-service generator ─────────────────────────────────────────────────────

def process_service(svc_dir: Path) -> list[dict]:
    """Return list of field rows for one service."""
    service = svc_dir.name

    # Find step6 YAML
    step6_files = list(svc_dir.glob("step6_*.yaml"))
    if not step6_files:
        return []
    step6_path = step6_files[0]

    try:
        data = yaml.safe_load(step6_path.read_text())
    except Exception:
        return []

    if not isinstance(data, dict):
        return []

    discoveries = data.get("discovery") or []
    if not discoveries:
        return []

    module = data.get("services", {}).get("module", f"alibabacloud_python_sdk.{service}")
    deps   = load_deps(svc_dir)

    std_field_names = [f[0] for f in STANDARD_FIELDS]
    rows = []

    for disc in discoveries:
        discovery_id = disc.get("discovery_id", "")
        if not discovery_id:
            continue

        # Primary action for this discovery
        calls = disc.get("calls") or []
        action = calls[0].get("action", "") if calls else ""

        # Determine resource_type from emit block
        emit      = disc.get("emit", {}) or {}
        emit_item = emit.get("item", {}) or {}
        resource_type = emit_item.get("resource_type", "")
        # strip template syntax if literal
        if resource_type.startswith("'"):
            resource_type = resource_type.strip("'")
        elif "{{" in resource_type:
            resource_type = ""

        # Chain details
        for_each    = disc.get("for_each") or None
        is_indep    = for_each is None
        root_op     = discovery_id   # discovery_id acts as the root op reference
        chain_label_str = chain_label(discovery_id, action, std_field_names)

        if for_each:
            chain_ops    = f"{for_each} → {discovery_id}"
            chain_length = 2
            hop_distance = 1
            chain_ops_wf = f"{for_each}[...] → {chain_label_str}"
            op_kind      = "read_get"
        else:
            chain_ops    = discovery_id
            chain_length = 1
            hop_distance = 0
            chain_ops_wf = chain_label_str
            op_kind      = "read_list"

        python_call = make_python_call(module, action) if action else ""

        for (fname, ftype, ops, ops_no_val) in STANDARD_FIELDS:
            field_path   = f"{resource_type}.{fname}" if resource_type else fname
            item_var_path = f"item.{fname}"

            row = {
                "csp":                  "alicloud",
                "service":              service,
                "field_path":           field_path,
                "item_var_path":        item_var_path,
                "field_type":           ftype,
                "is_id":                "Yes" if fname in FIELD_IS_ID else "No",
                "producing_op":         discovery_id,
                "op_kind":              op_kind,
                "is_independent":       "Yes" if is_indep else "No",
                "root_op":              root_op,
                "chain_ops":            chain_ops,
                "chain_length":         chain_length,
                "hop_distance":         hop_distance,
                "chain_ops_with_fields": chain_ops_wf,
                "operators":            ", ".join(ops),
                "operators_no_value":   ", ".join(ops_no_val),
                "python_call":          python_call,
                "http_path":            "",
                "resource_type":        resource_type,
            }
            rows.append(row)

    return rows


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    svc_dirs = sorted(
        d for d in BASE.iterdir()
        if d.is_dir() and not d.name.startswith("_") and not d.name.startswith(".")
    )

    if SERVICE_FILTER:
        svc_dirs = [d for d in svc_dirs if d.name == SERVICE_FILTER]

    all_rows: list[dict] = []
    stats: list[tuple] = []

    print(f"\n{'Service':<30} {'Discoveries':>12} {'Fields':>8}")
    print("-" * 55)

    for svc_dir in svc_dirs:
        rows = process_service(svc_dir)
        if not rows:
            continue

        # Count distinct discovery_ids
        n_disc = len(set(r["producing_op"] for r in rows))
        all_rows.extend(rows)
        stats.append((svc_dir.name, n_disc, len(rows)))
        print(f"  {svc_dir.name:<28} {n_disc:>12} {len(rows):>8}")

        # Per-service field_operator_value_table.csv
        svc_csv = svc_dir / "field_operator_value_table.csv"
        with open(svc_csv, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=COLS)
            w.writeheader()
            w.writerows(rows)

    print("-" * 55)
    total_disc = sum(s[1] for s in stats)
    print(f"  {'TOTAL':<28} {total_disc:>12} {len(all_rows):>8}")
    print(f"\n  Services processed : {len(stats)}")
    print(f"  Master catalog rows: {len(all_rows)}")

    # Write master catalog
    with open(OUT_CSV, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS)
        w.writeheader()
        w.writerows(all_rows)

    print(f"  Written: {OUT_CSV}")


if __name__ == "__main__":
    main()
