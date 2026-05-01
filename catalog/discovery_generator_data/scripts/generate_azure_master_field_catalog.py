#!/usr/bin/env python3
"""
Generate azure_master_field_catalog.csv matching the GCP master field catalog format.

Output: catalog/discovery_generator/azure/azure_master_field_catalog.csv

Columns (identical to gcp_master_field_catalog.csv):
  csp, service, field_path, item_var_path, field_type, is_id,
  producing_op, op_kind, is_independent,
  root_op, chain_ops, chain_length, hop_distance, chain_ops_with_fields,
  operators, operators_no_value, python_call, http_path

Sources:
  step1b_operation_registry.json      → ops, fields, python_call, class_name
  step4a_field_operator_value_table.csv → field_type, operators (per service, where available)
  step3_read_operation_dependency_chain.json → dependency chains
  step4_fields_produced_index.json    → fallback type info

Usage:
    python3 catalog/discovery_generator/scripts/generate_azure_master_field_catalog.py
    python3 ...  --service keyvault          # single service
    python3 ...  --service keyvault,storage  # multiple
"""

import argparse
import csv
import json
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

AZURE_DIR  = Path("catalog/discovery_generator/azure")
OUTPUT_CSV = AZURE_DIR / "azure_master_field_catalog.csv"

CSV_COLUMNS = [
    "csp", "service",
    "field_path", "item_var_path", "field_type", "is_id",
    "producing_op", "op_kind", "is_independent",
    "root_op", "chain_ops", "chain_length", "hop_distance", "chain_ops_with_fields",
    "operators", "operators_no_value",
    "python_call", "http_path",
]

READ_KINDS = {"read_list", "read_get", "read_describe", "read_search", "read_query"}

# Scan-time params Azure scanner supplies — ops requiring only these are independent
SCAN_TIME: Set[str] = {
    "subscription_id", "subscriptionId",
    "resource_group_name", "resourceGroupName", "resource_group",
    "location", "region",
}

# ── type inference ────────────────────────────────────────────────────────────

_BOOL_PREFIXES  = ("enable_", "is_", "has_", "allow_", "require_",
                   "support_", "disable_", "use_", "enforce_")
_INT_SUFFIXES   = ("_count", "_size", "_port", "_timeout", "_max", "_min",
                   "_limit", "_quota", "_days", "_bytes")
_OBJ_NAMES      = {"properties", "tags", "identity", "sku", "network_rule_set",
                   "network_acls", "encryption", "access_policy", "config",
                   "configuration", "settings", "metadata", "parameters",
                   "extended_location", "system_data", "managed_by", "plan"}

_TYPE_OPS: Dict[str, Tuple[str, str]] = {
    "string":  ("contains, equals, exists, in, not_equals",
                "exists"),
    "boolean": ("equals, not_equals", ""),
    "integer": ("equals, greater_than, greater_than_or_equal, "
                "less_than, less_than_or_equal, not_equals", ""),
    "number":  ("equals, greater_than, greater_than_or_equal, "
                "less_than, less_than_or_equal, not_equals", ""),
    "object":  ("equals, exists, not_equals", "exists"),
    "array":   ("contains, equals, exists, in, not_equals", "exists"),
}
_DEFAULT_OPS = ("contains, equals, exists, in, not_equals", "exists")

ID_FIELDS: Set[str] = {
    "id", "name", "arn", "ocid", "crn", "resource_id", "resource_uid",
    "compartment_id", "tenant_id", "subscription_id",
}


def _infer_type(field_name: str) -> str:
    fn = field_name.lower()
    if fn in ID_FIELDS or fn.endswith("_id") or fn.endswith("_name") or fn.endswith("_uri"):
        return "string"
    if any(fn.startswith(p) for p in _BOOL_PREFIXES):
        return "boolean"
    if any(fn.endswith(s) for s in _INT_SUFFIXES):
        return "integer"
    if fn in _OBJ_NAMES or fn.endswith("_policy") or fn.endswith("_rule") or fn.endswith("_config"):
        return "object"
    if fn.endswith("_list") or fn.endswith("s") and not fn.endswith("_status"):
        pass  # could be array, but too risky — fall through
    return "string"


def _is_id(field_name: str) -> str:
    fn = field_name.lower()
    if fn in ID_FIELDS:
        return "Yes"
    if fn.endswith("_id") or fn.endswith("_arn") or fn.endswith("_name"):
        return "Yes"
    return "No"


def _ops_for_type(ftype: str) -> Tuple[str, str]:
    return _TYPE_OPS.get(ftype, _DEFAULT_OPS)


def _item_var(field_path: str) -> str:
    """value[].foo.bar  →  item.foo.bar;  foo  →  item.foo"""
    s = field_path
    for pfx in ("value[].", "items[].", "results[].", "data[]."):
        if s.startswith(pfx):
            s = s[len(pfx):]
            break
    if s in ("value", "next_link", "items", "results", "data", ""):
        return ""
    return f"item.{s}"


# ── loaders ───────────────────────────────────────────────────────────────────

def _load_json(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def _load_step4a_types(svc_path: Path) -> Dict[str, dict]:
    """field_name (lower) → {field_type, operators, operators_no_value}"""
    result: Dict[str, dict] = {}
    csv_path = svc_path / "step4a_field_operator_value_table.csv"
    if not csv_path.exists():
        return result
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            fn = (row.get("field_name") or "").strip()
            if not fn:
                continue
            result[fn.lower()] = {
                "field_type":          row.get("field_type", "string") or "string",
                "operators":           row.get("operators", "") or "",
                "operators_no_value":  row.get("operators_no_value", "") or "",
            }
    return result


def _load_step4_types(svc_path: Path) -> Dict[str, str]:
    """field_name (lower) → type  — from step4 as fallback"""
    result: Dict[str, str] = {}
    s4 = _load_json(svc_path / "step4_fields_produced_index.json")
    if not s4:
        return result
    for fn, fd in s4.get("fields", {}).items():
        t = fd.get("type") or fd.get("field_type") or fd.get("produces_type")
        if t:
            result[fn.lower()] = t
    return result


def _build_op_field_map(s1b_ops: dict) -> Dict[str, List[str]]:
    """op_id → list of item-level field_paths (value[].xxx)"""
    result: Dict[str, List[str]] = {}
    for op_id, op in s1b_ops.items():
        paths = []
        for p in op.get("produces", []):
            path = p.get("path", "")
            if "[]." not in path:
                continue
            fn = path.split("[].")[-1]
            if fn in ("", "value", "next_link"):
                continue
            paths.append(path)
        result[op_id] = paths
    return result


def _chain_with_fields(chain_op_ids: List[str],
                       op_field_map: Dict[str, List[str]]) -> str:
    """op1[f1|f2|...] -> op2[f1|f2|...]"""
    parts = []
    for op_id in chain_op_ids:
        fields = op_field_map.get(op_id, [])
        fstr = "|".join(fields)
        parts.append(f"{op_id}[{fstr}]" if fstr else op_id)
    return " -> ".join(parts)


# ── chain resolver ────────────────────────────────────────────────────────────

def _build_chains(svc_path: Path,
                  short_to_full: Dict[str, str]) -> Dict[str, dict]:
    """
    Returns op_id → {hop_distance, root_op, chain_ops_list}
    Uses step3 entity_paths; falls back to 0/self for independent ops.
    """
    chains: Dict[str, dict] = {}
    s3 = _load_json(svc_path / "step3_read_operation_dependency_chain.json")
    if s3:
        for paths in s3.get("entity_paths", {}).values():
            if not isinstance(paths, list):
                continue
            for entry in paths:
                short_chain = entry.get("operations", [])
                if not short_chain:
                    continue
                full_chain = [short_to_full.get(s, s) for s in short_chain]
                target = full_chain[-1]
                if target not in chains:
                    chains[target] = {
                        "hop_distance": len(full_chain) - 1,
                        "root_op": full_chain[0],
                        "chain_ops_list": full_chain,
                    }
    return chains


# ── per-service processing ────────────────────────────────────────────────────

def _is_effectively_independent(required: List[str]) -> bool:
    return all(p in SCAN_TIME for p in required)


def process_service(svc: str, svc_path: Path) -> List[dict]:
    s1b = _load_json(svc_path / "step1b_operation_registry.json")
    if not s1b:
        return []

    ops: dict = s1b.get("operations", {})
    if not ops:
        return []

    # Build short_name (category.method) → full op_id lookup
    short_to_full: Dict[str, str] = {}
    for full_id, op in ops.items():
        cat  = op.get("category", "")
        meth = op.get("operation", "")
        short = f"{cat}.{meth}" if cat else meth
        if short not in short_to_full:
            short_to_full[short] = full_id

    chains       = _build_chains(svc_path, short_to_full)
    op_field_map = _build_op_field_map(ops)
    s4a_types    = _load_step4a_types(svc_path)
    s4_types     = _load_step4_types(svc_path)

    rows = []

    for op_id, op in ops.items():
        kind = op.get("kind", "")
        if kind not in READ_KINDS:
            continue
        if op.get("class_name") == "Operations":   # skip API-metadata ops
            continue

        required   = op.get("required_params", [])
        is_indep   = _is_effectively_independent(required)
        category   = op.get("category", "")
        method     = op.get("python_method", op.get("operation", ""))
        py_call    = (f"client.{category}.{method}(**params)"
                      if category else f"client.{method}(**params)")

        chain_info     = chains.get(op_id, {})
        hop            = chain_info.get("hop_distance", 0 if is_indep else 1)
        root           = chain_info.get("root_op", op_id)
        chain_ops_list = chain_info.get("chain_ops_list", [op_id])

        cow      = _chain_with_fields(chain_ops_list, op_field_map)
        chain_str = " -> ".join(chain_ops_list)
        chain_len = len(chain_ops_list)

        item_paths = op_field_map.get(op_id, [])
        if not item_paths:
            # Op has no item-level fields — still record the op with blank field
            rows.append(_make_row(
                svc, "", "", "string", "No",
                op_id, kind, is_indep, root,
                chain_str, chain_len, hop, cow,
                "contains, equals, exists, in, not_equals", "exists",
                py_call, "",
                s4a_types, s4_types,
            ))
            continue

        for field_path in item_paths:
            fn    = field_path.split("[].")[-1]   # leaf field name
            ivar  = _item_var(field_path)
            if not ivar:
                continue

            rows.append(_make_row(
                svc, field_path, ivar, "", "",
                op_id, kind, is_indep, root,
                chain_str, chain_len, hop, cow,
                "", "",
                py_call, "",
                s4a_types, s4_types,
                field_name_hint=fn,
            ))

    return rows


def _make_row(
    svc: str,
    field_path: str,
    item_var_path: str,
    ftype_override: str,
    is_id_override: str,
    producing_op: str,
    op_kind: str,
    is_indep: bool,
    root_op: str,
    chain_ops: str,
    chain_length: int,
    hop_distance: int,
    chain_ops_with_fields: str,
    ops_override: str,
    ops_nv_override: str,
    python_call: str,
    http_path: str,
    s4a_types: Dict[str, dict],
    s4_types: Dict[str, str],
    field_name_hint: str = "",
) -> dict:

    fn_lower = (field_name_hint or "").lower()

    # Resolve type: heuristic wins for known object-type names; else step4a → step4 → infer
    if ftype_override:
        ftype = ftype_override
    elif fn_lower in _OBJ_NAMES:
        # step4a often misclassifies these as string/array — use structural heuristic
        ftype = "object"
    else:
        s4a = s4a_types.get(fn_lower, {})
        ftype = (s4a.get("field_type")
                 or s4_types.get(fn_lower)
                 or _infer_type(field_name_hint))

    # Resolve is_id
    is_id = is_id_override if is_id_override else _is_id(field_name_hint)

    # Resolve operators
    if ops_override:
        ops_str, ops_nv = ops_override, ops_nv_override
    else:
        s4a = s4a_types.get(fn_lower, {})
        if s4a.get("operators"):
            ops_str = s4a["operators"]
            ops_nv  = s4a.get("operators_no_value", "")
        else:
            ops_str, ops_nv = _ops_for_type(ftype)

    return {
        "csp":                   "azure",
        "service":               svc,
        "field_path":            field_path,
        "item_var_path":         item_var_path,
        "field_type":            ftype,
        "is_id":                 is_id,
        "producing_op":          producing_op,
        "op_kind":               op_kind,
        "is_independent":        "Yes" if is_indep else "No",
        "root_op":               root_op,
        "chain_ops":             chain_ops,
        "chain_length":          chain_length,
        "hop_distance":          hop_distance,
        "chain_ops_with_fields": chain_ops_with_fields,
        "operators":             ops_str,
        "operators_no_value":    ops_nv,
        "python_call":           python_call,
        "http_path":             http_path,
    }


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", default="",
                        help="Comma-separated services (default: all)")
    parser.add_argument("--output", default=str(OUTPUT_CSV))
    args = parser.parse_args()

    filter_svcs: Set[str] = (
        {s.strip() for s in args.service.split(",") if s.strip()}
        if args.service else set()
    )

    skip = {".DS_Store", "__pycache__", "scripts", "step4a_outputs"}
    svc_dirs = sorted(
        d for d in AZURE_DIR.iterdir()
        if d.is_dir() and d.name not in skip and not d.name.startswith(".")
    )
    if filter_svcs:
        svc_dirs = [d for d in svc_dirs if d.name in filter_svcs]

    all_rows: List[dict] = []
    for svc_path in svc_dirs:
        rows = process_service(svc_path.name, svc_path)
        all_rows.extend(rows)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(all_rows)

    # Summary
    svcs   = len({r["service"] for r in all_rows})
    ops    = len({r["producing_op"] for r in all_rows})
    fields = len({(r["service"], r["field_path"])
                  for r in all_rows if r["field_path"]})
    indep  = sum(1 for r in all_rows if r["is_independent"] == "Yes" and r["field_path"])
    dep    = sum(1 for r in all_rows if r["is_independent"] == "No"  and r["field_path"])
    chains2 = sum(1 for r in all_rows if int(r["chain_length"] or 1) >= 2 and r["field_path"])

    print(f"Azure master field catalog → {out_path}")
    print(f"  Services:            {svcs}")
    print(f"  Ops:                 {ops}")
    print(f"  (svc, field) pairs:  {fields}")
    print(f"  Independent rows:    {indep}")
    print(f"  Dependent rows:      {dep}")
    print(f"  Chain-length ≥ 2:    {chains2}")
    print(f"  Total rows:          {len(all_rows)}")


if __name__ == "__main__":
    main()
