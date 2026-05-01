#!/usr/bin/env python3
"""
Generate step4a_field_op_table.csv for all CSPs, matching the GCP master
field catalog column layout:

  csp, service, field_path, item_var_path, field_type, is_id,
  producing_op, op_kind, is_independent, root_op,
  chain_ops, chain_length, hop_distance, chain_ops_with_fields,
  operators, operators_no_value, python_call, http_path

Sources per CSP
---------------
Azure    : step1b_operation_registry.json  (step4 has namespace-collision bugs)
GCP      : step4_fields_produced_index.json + step3 chains
OCI      : step4_fields_produced_index.json + step2 read registry
IBM      : step4_fields_produced_index.json
AliCloud : step4_fields_produced_index.json
AWS      : step4_fields_produced_index.json + step3 chains

Usage
-----
    python3 .../generate_step4a_field_op_csv.py --csp azure
    python3 .../generate_step4a_field_op_csv.py --csp all
"""

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

CATALOG_ROOT = Path(__file__).resolve().parent.parent   # catalog/discovery_generator/

CSV_COLUMNS = [
    "csp", "service",
    "field_path", "item_var_path", "field_type", "is_id",
    "producing_op", "op_kind", "is_independent",
    "root_op", "chain_ops", "chain_length", "hop_distance", "chain_ops_with_fields",
    "operators", "operators_no_value",
    "python_call", "http_path",
]

READ_KINDS = {"read_list", "read_get", "read_describe", "read_search",
              "read_query", "read", "list", "get", "describe"}

# Params supplied by the scanner at scan time — ops needing only these are
# effectively independent (depth = 0)
SCAN_TIME_PARAMS: Set[str] = {
    "compartmentId", "compartment_id", "tenancyId", "tenancy_id",
    "subscriptionId", "subscription_id",
    "project", "projectId", "project_id", "organization", "folder",
    "region", "namespace", "location",
    "resourceGroupName", "resource_group_name", "resource_group",
}

# Operators per field type
_TYPE_OPERATORS: Dict[str, tuple] = {
    "string":  ("contains, equals, exists, in, not_equals", "exists"),
    "boolean": ("equals, not_equals", ""),
    "integer": ("equals, greater_than, greater_than_or_equal, less_than, less_than_or_equal, not_equals", ""),
    "number":  ("equals, greater_than, greater_than_or_equal, less_than, less_than_or_equal, not_equals", ""),
    "float":   ("equals, greater_than, greater_than_or_equal, less_than, less_than_or_equal, not_equals", ""),
    "array":   ("contains, equals, exists, in, not_equals", "exists"),
    "object":  ("equals, exists, not_equals", "exists"),
    "map":     ("contains, equals, exists, in, not_equals", "exists"),
}
_DEFAULT_OPS = ("contains, equals, exists, in, not_equals", "exists")


# ── helpers ──────────────────────────────────────────────────────────────────

def _load_json(path: Path) -> Optional[Any]:
    if not path.exists():
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def _is_read(kind: str) -> bool:
    k = (kind or "").lower()
    return any(r in k for r in READ_KINDS)


def _params_str(params: Any) -> str:
    if not params:
        return ""
    return ",".join(str(p) for p in (params if isinstance(params, list) else [params]))


def _operators(ftype: str) -> tuple:
    return _TYPE_OPERATORS.get((ftype or "").lower(), _DEFAULT_OPS)


def _is_effectively_independent(required_params: List[str]) -> bool:
    return all(p in SCAN_TIME_PARAMS for p in required_params)


def _item_var_path(field_path: str) -> str:
    """Convert raw field_path to check-rule variable path (item.xxx)."""
    # strip array notation prefix: value[].foo → item.foo; foo → item.foo
    stripped = field_path
    for prefix in ("value[].", "items[].", "results[].", "data[]."):
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):]
            break
    if stripped in ("value", "next_link", "items", "results", "data", ""):
        return ""
    return f"item.{stripped}"


def _is_id_field(field_name: str) -> str:
    """Heuristic: does the field name look like a resource identifier?"""
    fn = field_name.lower()
    if fn in ("id", "name", "arn", "ocid", "crn", "resource_id",
              "compartment_id", "tenant_id", "subscription_id"):
        return "Yes"
    if fn.endswith("_id") or fn.endswith("_arn") or fn.endswith("_name"):
        return "Yes"
    return "No"


# ── step3 chain loaders ───────────────────────────────────────────────────────

def _load_gcp_chains(svc_path: Path) -> Dict[str, Dict]:
    """GCP step3: op → {hop_distance, root_op, execution_steps}"""
    for name in [
        "step3_read_operation_dependency_chain_independent.json",
        "step3_read_operation_dependency_chain.json",
    ]:
        data = _load_json(svc_path / name)
        if not data:
            continue
        result = {}
        for op_id, cd in data.get("chains", {}).items():
            steps = cd.get("execution_steps", [])
            step_op_ids = [s["op"] for s in steps if "op" in s]
            root = step_op_ids[0] if step_op_ids else op_id
            result[op_id] = {
                "hop_distance": cd.get("hop_distance", 0),
                "root_op": root,
                "chain_ops": step_op_ids,
            }
        return result
    return {}


def _load_azure_chains(svc_path: Path, short_to_full: Dict[str, str]) -> Dict[str, Dict]:
    """Azure step3: entity_paths use 2-part names → map to full op_ids."""
    data = _load_json(svc_path / "step3_read_operation_dependency_chain.json")
    if not data:
        return {}
    result: Dict[str, Dict] = {}
    for paths in data.get("entity_paths", {}).values():
        if not isinstance(paths, list):
            continue
        for path_entry in paths:
            short_ops = path_entry.get("operations", [])
            if not short_ops:
                continue
            full_chain = [short_to_full.get(s, s) for s in short_ops]
            target_full = full_chain[-1]
            if target_full in result:
                continue
            result[target_full] = {
                "hop_distance": len(short_ops) - 1,
                "root_op": full_chain[0],
                "chain_ops": full_chain,
            }
    return result


def _load_aws_chains(svc_path: Path) -> Dict[str, Dict]:
    """AWS step3: roots list + entity_paths. Roots are hop_distance=0."""
    data = _load_json(svc_path / "step3_read_operation_dependency_chain.json")
    if not data:
        return {}
    root_ops: Set[str] = {r["op"] for r in data.get("roots", []) if "op" in r}
    result: Dict[str, Dict] = {}
    # Root ops are independent — depth 0, chain is just themselves
    for op in root_ops:
        result[op] = {"hop_distance": 0, "root_op": op, "chain_ops": [op]}
    # Dependent ops — resolve from entity_paths
    for paths in data.get("entity_paths", {}).values():
        if not isinstance(paths, list):
            continue
        for path_entry in paths:
            ops_in_path = path_entry.get("operations", [])
            if not ops_in_path:
                continue
            target = ops_in_path[-1]
            if target in result:
                continue
            # Find a root that feeds this chain
            root = ops_in_path[0] if ops_in_path[0] in root_ops else ops_in_path[0]
            result[target] = {
                "hop_distance": len(ops_in_path) - 1,
                "root_op": root,
                "chain_ops": ops_in_path,
            }
    return result


# ── per-op fields index ───────────────────────────────────────────────────────

def _op_fields_index(svc_path: Path, csp: str) -> Dict[str, List[tuple]]:
    """
    Return op_id → [(field_name, field_path, field_type, is_id), ...].
    Used to build chain_ops_with_fields.
    """
    index: Dict[str, List] = {}

    if csp == "azure":
        step1b = _load_json(svc_path / "step1b_operation_registry.json")
        if not step1b:
            return {}
        for op_id, op in step1b.get("operations", {}).items():
            for p in op.get("produces", []):
                path = p.get("path", "")
                fn = path.split("[].")[-1] if "[]." in path else path
                if fn in ("value", "next_link", ""):
                    continue
                index.setdefault(op_id, []).append((fn, path, "string", _is_id_field(fn)))
    else:
        step4 = _load_json(svc_path / "step4_fields_produced_index.json")
        if not step4:
            return {}
        for field_name, fdata in step4.get("fields", {}).items():
            for prod in fdata.get("producers", []):
                op_id = prod.get("op", "")
                ftype = prod.get("produces_type", "string")
                is_id = "Yes" if prod.get("is_id") else _is_id_field(field_name)
                fp = fdata.get("field_path", field_name)
                index.setdefault(op_id, []).append((field_name, fp, ftype, is_id))

    return index


def _chain_ops_with_fields(chain_op_ids: List[str],
                           op_fields: Dict[str, List]) -> str:
    """Render 'op1[f1|f2|...] -> op2[f1|f2|...]' string."""
    parts = []
    for op_id in chain_op_ids:
        fields = op_fields.get(op_id, [])
        field_str = "|".join(f[1] for f in fields[:20])  # use field_path
        parts.append(f"{op_id}[{field_str}]" if field_str else op_id)
    return " -> ".join(parts)


# ── Azure ─────────────────────────────────────────────────────────────────────

def process_azure_service(svc: str, svc_path: Path) -> List[Dict]:
    step1b = _load_json(svc_path / "step1b_operation_registry.json")
    if not step1b:
        return []

    # Build short (category.method) → full operation_id map for chain resolution
    short_to_full: Dict[str, str] = {}
    for full_id, op in step1b.get("operations", {}).items():
        cat = op.get("category", "")
        meth = op.get("operation", "")
        short = f"{cat}.{meth}" if cat else meth
        if short not in short_to_full:
            short_to_full[short] = full_id

    chains = _load_azure_chains(svc_path, short_to_full)
    op_fields = _op_fields_index(svc_path, "azure")
    rows = []

    for op_id, op in step1b.get("operations", {}).items():
        kind = op.get("kind", "")
        if not _is_read(kind):
            continue
        if op.get("class_name") == "Operations":   # skip metadata ops
            continue

        required = op.get("required_params", [])
        is_indep = _is_effectively_independent(required)
        class_name = op.get("class_name", "")
        category = op.get("category", "")
        method = op.get("python_method", op.get("operation", ""))

        # python_call: client.category.method(**params)
        call = f"client.{category}.{method}(**params)" if category else f"client.{method}(**params)"

        chain_info = chains.get(op_id, {})
        hop = chain_info.get("hop_distance", 0 if is_indep else 1)
        root = chain_info.get("root_op", op_id)
        chain_op_ids = chain_info.get("chain_ops", [op_id])

        cow = _chain_ops_with_fields(chain_op_ids, op_fields)
        chain_ops_str = " -> ".join(chain_op_ids)
        chain_len = len(chain_op_ids)

        for p in op.get("produces", []):
            path = p.get("path", "")
            fn = path.split("[].")[-1] if "[]." in path else path
            if fn in ("value", "next_link", ""):
                continue
            ivar = _item_var_path(path)
            if not ivar:
                continue
            ftype = "string"   # step1b doesn't expose field types; default
            ops_str, ops_nv = _operators(ftype)
            rows.append({
                "csp": "azure", "service": svc,
                "field_path": path, "item_var_path": ivar,
                "field_type": ftype, "is_id": _is_id_field(fn),
                "producing_op": op_id, "op_kind": kind,
                "is_independent": "Yes" if is_indep else "No",
                "root_op": root,
                "chain_ops": chain_ops_str,
                "chain_length": chain_len,
                "hop_distance": hop,
                "chain_ops_with_fields": cow,
                "operators": ops_str, "operators_no_value": ops_nv,
                "python_call": call, "http_path": "",
            })

    return rows


# ── GCP / OCI / IBM / AliCloud / AWS (step4-based) ───────────────────────────

def process_step4_service(csp: str, svc: str, svc_path: Path) -> List[Dict]:
    step4 = _load_json(svc_path / "step4_fields_produced_index.json")
    if not step4:
        return []
    fields: Dict[str, Any] = step4.get("fields", {})
    if not fields:
        return []

    # Load chain data
    chains = _load_gcp_chains(svc_path) if csp in ("gcp", "aws") else {}

    # Load step2 required_params for independence check
    step2 = _load_json(svc_path / "step2_read_operation_registry.json")
    op_req: Dict[str, List[str]] = {}
    if step2:
        ops2 = step2.get("operations", {})
        if isinstance(ops2, list):
            op_req = {o.get("operation_id", o.get("op", "")): o.get("required_params", [])
                      for o in ops2 if isinstance(o, dict)}
        elif isinstance(ops2, dict):
            op_req = {oid: o.get("required_params", []) for oid, o in ops2.items()}

    op_fields = _op_fields_index(svc_path, csp)
    seen: set = set()
    rows = []

    for field_name, fdata in fields.items():
        field_path = fdata.get("field_path", field_name)
        ivar = _item_var_path(field_path) or f"item.{field_name}"

        for prod in fdata.get("producers", []):
            op_id = prod.get("op", "")
            kind = prod.get("kind", "")
            if not op_id or not _is_read(kind):
                continue

            key = (op_id, field_name)
            if key in seen:
                continue
            seen.add(key)

            ftype = prod.get("produces_type", "string") or "string"
            is_id = "Yes" if prod.get("is_id") else _is_id_field(field_name)

            req = op_req.get(op_id, [])
            s4_indep = bool(prod.get("independent", False))
            is_indep = s4_indep or _is_effectively_independent(req)

            chain_info = chains.get(op_id, {})
            hop = chain_info.get("hop_distance", 0 if is_indep else 1)
            root = chain_info.get("root_op", op_id)
            chain_op_ids = chain_info.get("chain_ops", [op_id])

            # GCP step4 has http + python_call directly on producer
            http_path = prod.get("http", {}).get("path", "") if isinstance(prod.get("http"), dict) else ""
            py_call = prod.get("python_call", "")

            cow = _chain_ops_with_fields(chain_op_ids, op_fields)
            ops_str, ops_nv = _operators(ftype)

            rows.append({
                "csp": csp, "service": svc,
                "field_path": field_path, "item_var_path": ivar,
                "field_type": ftype, "is_id": is_id,
                "producing_op": op_id, "op_kind": kind,
                "is_independent": "Yes" if is_indep else "No",
                "root_op": root,
                "chain_ops": " -> ".join(chain_op_ids),
                "chain_length": len(chain_op_ids),
                "hop_distance": hop,
                "chain_ops_with_fields": cow,
                "operators": ops_str, "operators_no_value": ops_nv,
                "python_call": py_call, "http_path": http_path,
            })

    return rows


def process_aws_service(svc: str, svc_path: Path) -> List[Dict]:
    """AWS step4 uses field.operations list + field.type/operators directly."""
    step4 = _load_json(svc_path / "step4_fields_produced_index.json")
    if not step4:
        return []
    fields: Dict[str, Any] = step4.get("fields", {})
    if not fields:
        return []

    chains = _load_aws_chains(svc_path)
    op_fields = _op_fields_index(svc_path, "aws")
    seen: set = set()
    rows = []

    for field_name, fdata in fields.items():
        if not isinstance(fdata, dict):
            continue
        ops = fdata.get("operations", [])
        if not isinstance(ops, list):
            ops = [ops] if ops else []
        if not ops:
            continue

        field_path = fdata.get("field_path", field_name)
        ivar = _item_var_path(field_path) or f"item.{field_name}"
        ftype = fdata.get("type", "string") or "string"
        is_id = _is_id_field(field_name)

        # Use operators from step4 if present, else derive from type
        ops_list = fdata.get("operators", [])
        ops_str = ", ".join(ops_list) if ops_list else _operators(ftype)[0]
        # operators_no_value: operators that work without a value
        no_val_ops = [o for o in ops_list if o in ("exists", "not_exists", "is_null", "is_not_null")]
        ops_nv = ", ".join(no_val_ops) if no_val_ops else _operators(ftype)[1]

        for op_name in ops:
            key = (op_name, field_name)
            if key in seen:
                continue
            seen.add(key)

            chain_info = chains.get(op_name, {})
            hop = chain_info.get("hop_distance", 0)
            root = chain_info.get("root_op", op_name)
            chain_op_ids = chain_info.get("chain_ops", [op_name])
            is_indep = hop == 0

            cow = _chain_ops_with_fields(chain_op_ids, op_fields)

            rows.append({
                "csp": "aws", "service": svc,
                "field_path": field_path, "item_var_path": ivar,
                "field_type": ftype, "is_id": is_id,
                "producing_op": op_name, "op_kind": "read",
                "is_independent": "Yes" if is_indep else "No",
                "root_op": root,
                "chain_ops": " -> ".join(chain_op_ids),
                "chain_length": len(chain_op_ids),
                "hop_distance": hop,
                "chain_ops_with_fields": cow,
                "operators": ops_str, "operators_no_value": ops_nv,
                "python_call": "", "http_path": "",
            })

    return rows


# ── driver ────────────────────────────────────────────────────────────────────

CSP_CONFIG = {
    "azure":    {"handler": "azure",  "dir": "azure"},
    "gcp":      {"handler": "step4",  "dir": "gcp"},
    "oci":      {"handler": "step4",  "dir": "oci"},
    "ibm":      {"handler": "step4",  "dir": "ibm"},
    "alicloud": {"handler": "step4",  "dir": "alicloud"},
    "aws":      {"handler": "aws",    "dir": "aws"},
}

SKIP_NAMES = {".DS_Store", "__pycache__", "scripts", "all_services.json",
              "step4a_outputs"}


def process_csp(csp: str, output_dir: Path) -> None:
    cfg = CSP_CONFIG.get(csp)
    if not cfg:
        print(f"  [SKIP] unknown CSP: {csp}")
        return

    csp_path = CATALOG_ROOT / cfg["dir"]
    if not csp_path.exists():
        print(f"  [SKIP] {csp}: path not found")
        return

    all_rows: List[Dict] = []
    service_dirs = sorted(
        d for d in csp_path.iterdir()
        if d.is_dir() and d.name not in SKIP_NAMES and not d.name.startswith(".")
    )

    for svc_path in service_dirs:
        svc = svc_path.name
        if cfg["handler"] == "azure":
            rows = process_azure_service(svc, svc_path)
        elif cfg["handler"] == "aws":
            rows = process_aws_service(svc, svc_path)
        else:
            rows = process_step4_service(csp, svc, svc_path)
        all_rows.extend(rows)

    if not all_rows:
        print(f"  [WARN] {csp}: 0 rows generated")
        return

    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"step4a_{csp}_field_op_table.csv"

    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(all_rows)

    svcs   = len({r["service"] for r in all_rows})
    ops    = len({r["producing_op"] for r in all_rows})
    fields = len({(r["service"], r["field_path"]) for r in all_rows})
    indep  = sum(1 for r in all_rows if r["is_independent"] == "Yes")
    print(f"  {csp:12s}: {svcs:4d} svc  {ops:5d} ops  {fields:6d} (svc,field)  "
          f"{indep:6d} independent rows  →  {out_path.name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--csp", default="all",
                        choices=list(CSP_CONFIG) + ["all"])
    parser.add_argument("--output-dir",
                        default=str(CATALOG_ROOT / "step4a_outputs"))
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    targets = list(CSP_CONFIG) if args.csp == "all" else [args.csp]

    print(f"Generating step4a CSVs → {output_dir}")
    for csp in targets:
        process_csp(csp, output_dir)
    print("Done.")


if __name__ == "__main__":
    main()
