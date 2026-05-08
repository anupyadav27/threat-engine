#!/usr/bin/env python3
"""
Generate step1–step2r/w–step5–step6 for all IBM Cloud services.

Source files per service directory:
  ibm_dependencies_with_python_names_fully_enriched.json  → ops with python names
  resource_operations_prioritized.json                    → resource→ops mapping
  crn_identifier.json                                     → CRN stub

Output per service directory:
  step1_api_driven_registry.json
  step2_read_operation_registry.json
  step2_write_operation_registry.json
  step5_resource_catalog_inventory_enrich.json
  step6_{service}.discovery.yaml
"""

import json
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path

IBM_ROOT = Path(__file__).parent.parent / "ibm"
SKIP = {"temp_code", "__pycache__"}

READ_PREFIXES  = ("get", "list", "describe", "fetch", "search", "query")
WRITE_PREFIXES = ("create", "update", "delete", "add", "remove", "set",
                  "put", "post", "patch", "replace", "enable", "disable")

SKIP_FIELDS = {
    "next_url", "nextPage", "limit", "offset", "total_count", "total_pages",
    "next", "previous", "first", "last", "start", "total", "count",
    "page_size", "page_token", "pageToken", "next_token", "nextToken",
    "next_page", "nextPage", "opc_next_page", "opc_request_id",
}

# SDK helper methods that are not real IBM Cloud API inventory operations
SDK_HELPER_OPS = {
    "get_authenticator", "get_enable_gzip_compression", "get_http_client",
    "set_service_url", "set_default_headers", "set_enable_gzip_compression",
    "set_http_client", "configure_retries", "disable_retries",
}

# "kwargs" in required_params is Python **kwargs — not a real required param
def _real_required(params) -> list:
    if not isinstance(params, list):
        return []
    return [p for p in params if p != "kwargs"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_read(op_name: str) -> bool:
    low = op_name.lower().replace("-", "_").replace(" ", "_")
    return any(low.startswith(p) for p in READ_PREFIXES)


def _read_kind(op_name: str) -> str:
    low = op_name.lower()
    if low.startswith("list"):   return "read_list"
    if low.startswith("get"):    return "read_get"
    return "read_other"


def _write_kind(op_name: str) -> str:
    low = op_name.lower()
    if any(low.startswith(p) for p in ("create", "add", "post")): return "write_create"
    if any(low.startswith(p) for p in ("delete", "remove")):       return "write_delete"
    if any(low.startswith(p) for p in ("update", "patch", "put",
                                        "set", "replace")):         return "write_update"
    return "write_other"


# ── STEP 1 ────────────────────────────────────────────────────────────────────

def _parse_op_entry(op_name: str, op_data: dict) -> dict:
    """Normalise a single operation entry from ibm_dependencies format."""
    python_method = (op_data.get("python_method")
                     or op_data.get("python_name")
                     or op_name.lower().replace("-", "_"))
    yaml_action   = op_data.get("yaml_action", op_name)
    req_params    = _real_required(op_data.get("required_params", op_data.get("required", [])))
    opt_params    = op_data.get("optional_params", op_data.get("optional", []))
    return {
        "operation":        op_name,
        "python_method":    python_method,
        "yaml_action":      yaml_action,
        "kind":             _read_kind(op_name) if _is_read(op_name) else _write_kind(op_name),
        "required_params":  req_params,
        "optional_params":  opt_params if isinstance(opt_params, list) else [],
        "output_fields":    op_data.get("output_fields", {}),
        "item_fields":      op_data.get("item_fields", {}),
        "main_output_field": op_data.get("main_output_field"),
    }


def build_step1(svc_dir: Path) -> dict | None:
    dep_path = svc_dir / "ibm_dependencies_with_python_names_fully_enriched.json"
    rop_path = svc_dir / "resource_operations_prioritized.json"

    if not dep_path.exists() and not rop_path.exists():
        return None

    service     = svc_dir.name
    independent: list = []
    dependent:   list = []

    # ── Primary source: ibm_dependencies_with_python_names_fully_enriched.json ──
    # Format: { "service_name": { "service": "...", "csp": "ibm",
    #                             "independent": [{op_entry}, ...],
    #                             "dependent":   [{op_entry}, ...] } }
    if dep_path.exists():
        raw = json.loads(dep_path.read_text())
        # Unwrap one nesting level if top key is the service name
        content = raw
        if isinstance(raw, dict):
            for k, v in raw.items():
                if isinstance(v, dict) and ("independent" in v or "dependent" in v):
                    content = v
                    service = v.get("service", k)
                    break

        for op in content.get("independent", []):
            if not isinstance(op, dict):
                continue
            op_name = op.get("operation", "")
            if not op_name or op_name in SDK_HELPER_OPS:
                continue
            entry = _parse_op_entry(op_name, op)
            (dependent if entry["required_params"] else independent).append(entry)

        for op in content.get("dependent", []):
            if not isinstance(op, dict):
                continue
            op_name = op.get("operation", "")
            if not op_name or op_name in SDK_HELPER_OPS:
                continue
            entry = _parse_op_entry(op_name, op)
            (dependent if entry["required_params"] else independent).append(entry)

    # ── Fallback: resource_operations_prioritized.json ──
    if not independent and not dependent and rop_path.exists():
        raw = json.loads(rop_path.read_text())
        service = raw.get("service", service)
        for op_name in raw.get("root_operations", []):
            if op_name in SDK_HELPER_OPS:
                continue
            independent.append(_parse_op_entry(op_name, {"operation": op_name}))

    if not independent and not dependent:
        return None

    return {
        "service":           service,
        "csp":               "ibm",
        "generated_at":      _now(),
        "total_operations":  len(independent) + len(dependent),
        "independent_count": len(independent),
        "dependent_count":   len(dependent),
        "independent":       independent,
        "dependent":         dependent,
    }


# ── STEP 2 ────────────────────────────────────────────────────────────────────

def build_step2(step1: dict) -> tuple[dict, dict]:
    service = step1["service"]
    now     = _now()
    read_ops, write_ops = {}, {}

    for bucket in ("independent", "dependent"):
        for op in step1.get(bucket, []):
            name = op["operation"]
            kind = op.get("kind", "other")
            entry = {
                "operation":       name,
                "service":         service,
                "csp":             "ibm",
                "kind":            kind,
                "independent":     (bucket == "independent"),
                "python_method":   op["python_method"],
                "yaml_action":     op["yaml_action"],
                "required_params": op.get("required_params", []),
                "optional_params": op.get("optional_params", []),
                "output_fields":   op.get("output_fields", {}),
                "item_fields":     op.get("item_fields", {}),
                "main_output_field": op.get("main_output_field"),
            }
            if kind.startswith("read"):
                read_ops[name] = entry
            else:
                write_ops[name] = entry

    def _reg(ops):
        return {
            "service": service, "csp": "ibm", "generated_at": now,
            "total_operations":  len(ops),
            "independent_count": sum(1 for v in ops.values() if v["independent"]),
            "dependent_count":   sum(1 for v in ops.values() if not v["independent"]),
            "operations":        ops,
        }
    return _reg(read_ops), _reg(write_ops)


# ── STEP 5 ────────────────────────────────────────────────────────────────────

def build_step5(svc_dir: Path, step1: dict, read_reg: dict) -> dict:
    service  = step1["service"]
    read_ops = read_reg.get("operations", {})

    stub = {}
    for fname in ("crn_identifier.json",):
        p = svc_dir / fname
        if p.exists():
            stub = json.loads(p.read_text())
            break

    crn_pattern = (stub.get("pattern")
        or f"crn:v1:bluemix:public:{service}:${{Region}}:a/${{AccountId}}::::")

    # Group by resource type from op names
    resources_out: dict = {}
    for op_name, op_meta in read_ops.items():
        for prefix in ("list_", "get_", "describe_"):
            low = op_name.lower().replace("-", "_")
            if low.startswith(prefix):
                rtype = low[len(prefix):].rstrip("s")
                break
        else:
            rtype = op_name.lower().replace("-", "_")

        g = resources_out.setdefault(rtype, {
            "resource_type":      rtype,
            "classification":     "PRIMARY_RESOURCE",
            "has_identifier":     True,
            "identifier_type":    "crn",
            "identifier_pattern": crn_pattern,
            "identifier": {
                "primary_param":   stub.get("resource_identifiers", "crn"),
                "identifier_type": "crn",
            },
            "inventory":        {"ops": []},
            "inventory_enrich": {"ops": []},
        })
        op_entry = {"operation": op_name, "kind": op_meta["kind"],
                    "independent": op_meta["independent"],
                    "python_method": op_meta["python_method"]}
        if op_meta["independent"]:
            g["inventory"]["ops"].append(op_entry)
        else:
            g["inventory_enrich"]["ops"].append(op_entry)

    return {
        "service": service, "csp": "ibm", "generated_at": _now(),
        "total_resources": len(resources_out),
        "resources": resources_out,
    }


# ── STEP 6 ────────────────────────────────────────────────────────────────────

def build_step6(service: str, read_reg: dict) -> str:
    ops     = read_reg.get("operations", {})
    ind_ops = {k: v for k, v in ops.items() if v["independent"]}
    dep_ops = {k: v for k, v in ops.items() if not v["independent"]}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = textwrap.dedent(f"""\
        # Discovery YAML — {service} (IBM Cloud)
        # Generated: {now}
        version: '1.0'
        provider: ibm
        service: {service}
        services:
          client: {service}
          module: ibm_platform_services.{service}
        discovery:
        """)

    def _block(name, meta, dep=False):
        action    = meta.get("yaml_action", name)
        disc_id   = f"ibm.{service}.{action}"
        kind      = meta.get("kind", "read_get")
        label     = " [dependent]" if dep else ""

        # Per-item fields: prefer item_fields (explicit per-item schema),
        # fall back to output_fields filtered for CSPM-relevant content
        item_flds: dict = meta.get("item_fields") or {}
        if not item_flds:
            item_flds = {k: v for k, v in meta.get("output_fields", {}).items()
                         if k not in SKIP_FIELDS}

        # Collection field: what holds the list in the response
        main_out: str = meta.get("main_output_field") or "items"

        lines = [
            f"  # ── {name}{label} ──",
            f"  - discovery_id: {disc_id}",
            f"    calls:",
            f"      - action: {action}",
            f"        save_as: response",
            f"        on_error: continue",
            f"    emit:",
            f"      as: item",
        ]

        emit_fields = [f for f in sorted(item_flds.keys()) if f not in SKIP_FIELDS]

        if kind == "read_list":
            lines.append(f"      items_for: '{{{{ response.{main_out} }}}}'")
            if emit_fields:
                lines.append("      item:")
                for f in emit_fields:
                    lines.append(f"        {f}: '{{{{ item.{f} }}}}'")
        else:
            # get op — no items_for, emit fields reference response directly
            if emit_fields:
                lines.append("      item:")
                for f in emit_fields:
                    lines.append(f"        {f}: '{{{{ response.{f} }}}}'")

        return "\n".join(lines)

    blocks = [_block(k, v) for k, v in sorted(ind_ops.items())]
    if dep_ops:
        blocks += ["  # ── Dependent ops ──"] + [_block(k, v, True) for k, v in sorted(dep_ops.items())]
    return header + "\n".join(blocks) + "\n"


# ── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    svc_dirs = sorted(d for d in IBM_ROOT.iterdir()
                      if d.is_dir() and d.name not in SKIP)
    print(f"IBM: {len(svc_dirs)} service directories")
    ok = 0
    for svc_dir in svc_dirs:
        step1 = build_step1(svc_dir)
        if not step1:
            print(f"  {svc_dir.name}: SKIPPED (no source data)")
            continue
        read_reg, write_reg = build_step2(step1)
        step5 = build_step5(svc_dir, step1, read_reg)
        step6_yaml = build_step6(step1["service"], read_reg)
        (svc_dir / "step1_api_driven_registry.json").write_text(json.dumps(step1, indent=2))
        (svc_dir / "step2_read_operation_registry.json").write_text(json.dumps(read_reg, indent=2))
        (svc_dir / "step2_write_operation_registry.json").write_text(json.dumps(write_reg, indent=2))
        (svc_dir / "step5_resource_catalog_inventory_enrich.json").write_text(json.dumps(step5, indent=2))
        svc = step1["service"]
        (svc_dir / f"step6_{svc}.discovery.yaml").write_text(step6_yaml)
        r, w, res = read_reg["total_operations"], write_reg["total_operations"], step5["total_resources"]
        print(f"  {svc:<35} read={r:>3} write={w:>3} resources={res:>3}")
        ok += 1
    print(f"\nDone: {ok} IBM services processed")

if __name__ == "__main__":
    main()
