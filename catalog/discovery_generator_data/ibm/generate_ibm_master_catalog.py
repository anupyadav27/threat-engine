#!/usr/bin/env python3
"""
Generate IBM Cloud master field catalog from direct_vars.json + ibm_dependencies.

Data sources per service:
  1. direct_vars.json               — field metadata (type, operators, discovery_id, for_each)
  2. ibm_dependencies_with_python_names_fully_enriched.json
                                    — operation metadata (python_method, yaml_action, independent)
  3. step6_*.discovery.yaml         — actual emitted item fields (supplemental)

Output:
  ibm_master_field_catalog.csv      — all services combined (master)
  <service>/field_operator_value_table.csv  — per-service split

Usage:
  python3 generate_ibm_master_catalog.py [--service vpc]
"""
from __future__ import annotations
import csv, json, re, sys
from pathlib import Path

import yaml

BASE    = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/ibm")
OUT_CSV = BASE / "ibm_master_field_catalog.csv"
DEPS_FILE = "ibm_dependencies_with_python_names_fully_enriched.json"

SERVICE_FILTER = None
for i, a in enumerate(sys.argv[1:], 1):
    if a == "--service" and i < len(sys.argv):
        SERVICE_FILTER = sys.argv[i + 1]

# ── Output columns (matches OCI/AliCloud master catalog format) ───────────────
COLS = [
    "csp", "service", "field_path", "item_var_path",
    "field_type", "is_id", "producing_op", "op_kind",
    "is_independent", "root_op", "chain_ops", "chain_length",
    "hop_distance", "chain_ops_with_fields",
    "operators", "operators_no_value",
    "python_call", "http_path", "resource_type",
]

# Fields whose bare name signals an ID
ID_FIELD_PATTERNS = re.compile(r'(^id$|_id$|^crn$|_crn$|^href$)')

# Default operators by type (fallback when not specified in direct_vars)
DEFAULT_OPS: dict[str, tuple[list[str], list[str]]] = {
    "string":  (["equals", "not_equals", "contains", "in"],  []),
    "boolean": (["equals", "not_equals"],                     []),
    "number":  (["equals", "not_equals", "gte", "lte"],       []),
    "array":   (["contains", "not_contains", "not_empty"],    ["not_empty"]),
    "object":  (["exists", "not_empty"],                      ["exists", "not_empty"]),
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def snake_to_kebab(s: str) -> str:
    return s.replace("_", "-")


def kebab_to_snake(s: str) -> str:
    return s.replace("-", "_")


def bare_name(field_path: str) -> str:
    """Last segment of dot-notation path."""
    return field_path.split(".")[-1]


def is_id_field(name: str) -> bool:
    return bool(ID_FIELD_PATTERNS.search(name))


def op_kind(for_each: str | None) -> str:
    return "read_get" if for_each else "read_list"


def infer_type(field_meta: dict) -> str:
    t = field_meta.get("type", "string")
    # Normalise IBM type names
    t = str(t).lower()
    if t in ("str",):            return "string"
    if t in ("bool",):           return "boolean"
    if t in ("int", "float", "number"): return "number"
    if t.startswith("list") or t == "array":  return "array"
    if t in ("dict", "object"):  return "object"
    return t if t in ("string","boolean","number","array","object") else "string"


def ops_from_meta(field_meta: dict, field_type: str) -> tuple[str, str]:
    """Return (operators_str, operators_no_value_str)."""
    ops = field_meta.get("operators")
    if ops and isinstance(ops, list):
        ops_list = [o for o in ops if o]
    else:
        ops_list, _ = DEFAULT_OPS.get(field_type, DEFAULT_OPS["string"])

    # operators_no_value = subset that don't need a value
    no_val = [o for o in ops_list if o in ("exists", "not_exists", "not_empty")]
    return ", ".join(ops_list), ", ".join(no_val)


def make_python_call(module: str, python_method: str) -> str:
    """Build SDK call string, e.g. VpcV1().list_backup_policies().get_result()"""
    if not module or not python_method:
        return ""
    # Derive client class: last segment of module, title-cased + "V1"
    parts = module.split(".")
    svc_part = parts[-1]
    # Convert to CamelCase client class name
    client = "".join(p.capitalize() for p in re.split(r"[_\-]", svc_part)) + "V1"
    return f"{module}.{client}().{python_method}().get_result()"


def chain_label(discovery_id: str, fields: list[str]) -> str:
    tag = "|".join(fields[:6]) + ("|..." if len(fields) > 6 else "")
    return f"{discovery_id}[{tag}]"


# ── Load IBM dependencies for a service ──────────────────────────────────────

def load_deps(svc_dir: Path) -> dict:
    """
    Load ibm_dependencies JSON. Returns:
      { operation_name (snake_case) -> {python_method, yaml_action, is_independent, item_fields} }
    """
    deps_path = svc_dir / DEPS_FILE
    if not deps_path.exists():
        return {}
    try:
        raw = json.loads(deps_path.read_text())
    except Exception:
        return {}

    svc_data = raw.get(svc_dir.name, {})
    if not svc_data:
        # Try first key
        if raw:
            svc_data = next(iter(raw.values()), {})

    ops_index: dict[str, dict] = {}

    def _add(op_list: list, is_indep: bool) -> None:
        if not isinstance(op_list, list):
            return
        for op in op_list:
            if not isinstance(op, dict):
                continue
            name = kebab_to_snake(op.get("operation", "") or "")
            if not name:
                continue
            ops_index[name] = {
                "python_method":  op.get("python_method", name),
                "yaml_action":    op.get("yaml_action", snake_to_kebab(name)),
                "is_independent": is_indep,
                "item_fields":    op.get("item_fields", {}),
                "description":    op.get("description", ""),
            }

    _add(svc_data.get("independent", []), True)
    _add(svc_data.get("dependent", []),   False)
    return ops_index


def load_module(svc_dir: Path) -> str:
    """Get SDK module from step6 YAML or fallback."""
    for step6 in svc_dir.glob("step6_*.yaml"):
        try:
            data = yaml.safe_load(step6.read_text())
            mod = data.get("services", {}).get("module", "")
            if mod:
                return mod
        except Exception:
            pass
    return f"ibm_platform_services.{svc_dir.name}"


# ── Load step6 emitted fields (supplemental) ─────────────────────────────────

def load_step6_fields(svc_dir: Path) -> dict[str, set[str]]:
    """
    Returns: discovery_id (kebab) → set of emitted item field names.
    """
    result: dict[str, set[str]] = {}
    for step6 in svc_dir.glob("step6_*.yaml"):
        try:
            data = yaml.safe_load(step6.read_text())
        except Exception:
            continue
        for disc in (data.get("discovery") or []):
            did = disc.get("discovery_id", "")
            if not did:
                continue
            emit = disc.get("emit") or {}
            item = emit.get("item") or {}
            if isinstance(item, dict):
                result[did] = set(item.keys())
    return result


# ── Per-service generator ─────────────────────────────────────────────────────

def process_service(svc_dir: Path) -> list[dict]:
    service = svc_dir.name

    # Load direct_vars.json
    dv_path = svc_dir / "direct_vars.json"
    if not dv_path.exists():
        return []
    try:
        dv = json.loads(dv_path.read_text())
    except Exception:
        return []

    fields = dv.get("fields", {})
    if not fields:
        return []

    module   = load_module(svc_dir)
    deps     = load_deps(svc_dir)
    step6    = load_step6_fields(svc_dir)   # discovery_id → emitted fields

    # Flip step6 for quick lookup: kebab discovery_id → emitted field set
    # Normalise direct_vars discovery_ids (snake) to match step6 keys (kebab)
    def disc_id_kebab(did: str) -> str:
        # ibm.service.op_name → ibm.service.op-name
        parts = did.split(".")
        return ".".join(parts[:-1] + [snake_to_kebab(parts[-1])]) if parts else did

    rows: list[dict] = []

    # Group fields by discovery_id so we can build chain labels
    by_disc: dict[str, list[tuple[str, dict]]] = {}
    for fp, meta in fields.items():
        did = meta.get("discovery_id", "")
        by_disc.setdefault(did, []).append((fp, meta))

    for discovery_id_raw, field_list in by_disc.items():
        discovery_id_kb = disc_id_kebab(discovery_id_raw)   # kebab version

        # Resolve operation name (snake) from discovery_id
        # discovery_id format: ibm.<service>.<operation_snake>
        parts      = discovery_id_raw.split(".")
        op_snake   = parts[-1] if len(parts) >= 3 else discovery_id_raw

        dep_meta   = deps.get(op_snake, {})
        python_meth= dep_meta.get("python_method", op_snake)
        yaml_act   = dep_meta.get("yaml_action", snake_to_kebab(op_snake))
        is_indep   = dep_meta.get("is_independent", True)

        python_call= make_python_call(module, python_meth)

        # field names in this discovery for chain label
        field_names = [bare_name(fp) for fp, _ in field_list]
        chain_lbl   = chain_label(discovery_id_kb, field_names)

        for (fp, meta) in field_list:
            for_each_raw = meta.get("for_each")   # None or discovery_id string

            if for_each_raw:
                # Dependent op
                chain_ops    = f"{disc_id_kebab(for_each_raw)} → {discovery_id_kb}"
                chain_length = 2
                hop_distance = 1
                chain_wf     = f"{disc_id_kebab(for_each_raw)}[...] → {chain_lbl}"
                kind         = "read_get"
                root_op      = disc_id_kebab(for_each_raw)
            else:
                chain_ops    = discovery_id_kb
                chain_length = 1
                hop_distance = 0
                chain_wf     = chain_lbl
                kind         = "read_list"
                root_op      = discovery_id_kb

            ftype      = infer_type(meta)
            ops_str, ops_no_val = ops_from_meta(meta, ftype)

            bare       = bare_name(fp)
            # resource_type = first segment of field_path (entity prefix)
            resource_type = fp.split(".")[0] if "." in fp else ""

            rows.append({
                "csp":                   "ibm",
                "service":               service,
                "field_path":            fp,
                "item_var_path":         f"item.{bare}",
                "field_type":            ftype,
                "is_id":                 "Yes" if is_id_field(bare) else "No",
                "producing_op":          discovery_id_kb,
                "op_kind":               kind,
                "is_independent":        "Yes" if not for_each_raw else "No",
                "root_op":               root_op,
                "chain_ops":             chain_ops,
                "chain_length":          chain_length,
                "hop_distance":          hop_distance,
                "chain_ops_with_fields": chain_wf,
                "operators":             ops_str,
                "operators_no_value":    ops_no_val,
                "python_call":           python_call,
                "http_path":             "",
                "resource_type":         resource_type,
            })

    # Supplement: fields from step6 emit that aren't in direct_vars
    dv_field_bares = {bare_name(fp) for fp in fields}
    for did_kb, emitted_names in step6.items():
        dep_meta  = {}
        op_snake  = kebab_to_snake(did_kb.split(".")[-1])
        dep_meta  = deps.get(op_snake, {})
        python_meth = dep_meta.get("python_method", op_snake)
        python_call = make_python_call(module, python_meth)
        is_indep  = dep_meta.get("is_independent", True)

        for fname in emitted_names:
            if fname in dv_field_bares or fname in ("id", "name"):
                # id/name already covered; skip to avoid huge duplication
                if fname in ("id", "name") and did_kb not in {
                    disc_id_kebab(d) for d in by_disc
                }:
                    pass  # new discovery not in dv at all — add below
                else:
                    continue

            ftype = "boolean" if fname.endswith("_enabled") else "string"
            ops_list, no_val = DEFAULT_OPS.get(ftype, DEFAULT_OPS["string"])
            rows.append({
                "csp":                   "ibm",
                "service":               service,
                "field_path":            fname,
                "item_var_path":         f"item.{fname}",
                "field_type":            ftype,
                "is_id":                 "Yes" if is_id_field(fname) else "No",
                "producing_op":          did_kb,
                "op_kind":               "read_list" if is_indep else "read_get",
                "is_independent":        "Yes" if is_indep else "No",
                "root_op":               did_kb,
                "chain_ops":             did_kb,
                "chain_length":          1,
                "hop_distance":          0,
                "chain_ops_with_fields": f"{did_kb}[{fname}]",
                "operators":             ", ".join(ops_list),
                "operators_no_value":    ", ".join(no_val),
                "python_call":           python_call,
                "http_path":             "",
                "resource_type":         fname.split(".")[0] if "." in fname else "",
            })

    return rows


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    svc_dirs = sorted(
        d for d in BASE.iterdir()
        if d.is_dir() and not d.name.startswith("_") and not d.name.startswith(".")
        # skip tooling dirs that are libraries/utilities not IBM services
        and d.name not in {"botocore", "s3transfer", "cloud_sdk_core", "tools", "stub"}
    )

    if SERVICE_FILTER:
        svc_dirs = [d for d in svc_dirs if d.name == SERVICE_FILTER]

    all_rows: list[dict] = []

    print(f"\n{'Service':<35} {'Fields':>8}")
    print("-" * 48)

    for svc_dir in svc_dirs:
        rows = process_service(svc_dir)
        if not rows:
            continue
        all_rows.extend(rows)
        print(f"  {svc_dir.name:<33} {len(rows):>8}")

        # Per-service field_operator_value_table.csv
        with open(svc_dir / "field_operator_value_table.csv", "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=COLS)
            w.writeheader()
            w.writerows(rows)

    print("-" * 48)
    svcs = len(set(r["service"] for r in all_rows))
    print(f"  {'TOTAL':<33} {len(all_rows):>8}")
    print(f"\n  Services processed : {svcs}")
    print(f"  Master catalog rows: {len(all_rows)}")

    with open(OUT_CSV, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS)
        w.writeheader()
        w.writerows(all_rows)

    print(f"  Written: {OUT_CSV}")


if __name__ == "__main__":
    main()
