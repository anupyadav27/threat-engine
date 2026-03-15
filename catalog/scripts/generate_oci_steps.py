#!/usr/bin/env python3
"""
Generate step1–step2r/w–step5–step6 for all OCI services.

Source files per service directory:
  operation_registry.json   → kind, sdk.client/method, consumes[], produces[]
  ocid_identifier.json      → OCID stub
  minimal_operations_list.json

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

OCI_ROOT = Path(__file__).parent.parent / "oci"
SKIP = {"temp_code", "__pycache__"}

READ_KINDS  = {"read_get", "read_list", "read_describe", "read_query"}
WRITE_KINDS = {"write_create", "write_delete", "write_update", "write_apply", "write_other"}

SKIP_FIELDS = {"opc_next_page", "opcNextPage", "nextPage", "limit",
               "opc_request_id", "opcRequestId"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── STEP 1 ────────────────────────────────────────────────────────────────────

def build_step1(svc_dir: Path) -> dict | None:
    reg_path = svc_dir / "operation_registry.json"
    if not reg_path.exists():
        return None

    raw = json.loads(reg_path.read_text())
    service = raw.get("service", svc_dir.name)
    ops     = raw.get("operations", {})

    independent, dependent = [], []

    for op_name, op in ops.items():
        consumes = op.get("consumes", [])
        required = [c for c in consumes
                    if c.get("required", False)
                    and c.get("source", "") not in ("always_available", "context")]
        produces = op.get("produces", [])

        sdk    = op.get("sdk", {})
        method = sdk.get("method", op_name)

        entry = {
            "operation":     op_name,
            "python_method": method,
            "yaml_action":   method,
            "kind":          op.get("kind", "other"),
            "side_effect":   op.get("side_effect", False),
            "required_params": [c.get("param", c.get("entity", "").split(".")[-1]) for c in required],
            "optional_params": [c.get("param", c.get("entity", "").split(".")[-1])
                                 for c in consumes if not c.get("required", False)],
            "output_fields": {
                p.get("entity", p.get("path", "")).split(".")[-1]: {
                    "type": "string",
                    "path": p.get("path", ""),
                    "entity": p.get("entity", "")
                }
                for p in produces
                if p.get("entity") or p.get("path")
            },
        }
        if required:
            dependent.append(entry)
        else:
            independent.append(entry)

    return {
        "service":           service,
        "csp":               "oci",
        "generated_at":      _now(),
        "total_operations":  len(ops),
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
                "operation":     name,
                "service":       service,
                "csp":           "oci",
                "kind":          kind,
                "independent":   (bucket == "independent"),
                "python_method": op["python_method"],
                "yaml_action":   op["yaml_action"],
                "required_params": op.get("required_params", []),
                "optional_params": op.get("optional_params", []),
                "output_fields":   op.get("output_fields", {}),
            }
            if kind in READ_KINDS:
                read_ops[name] = entry
            else:
                write_ops[name] = entry

    def _reg(ops):
        return {
            "service": service, "csp": "oci", "generated_at": now,
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
    p = svc_dir / "ocid_identifier.json"
    if p.exists():
        stub = json.loads(p.read_text())

    ocid_pattern = (stub.get("pattern")
        or f"ocid1.{service}.oc1.${{Realm}}.${{UniqueId}}")

    resources_out: dict = {}
    for op_name, op_meta in read_ops.items():
        # Derive resource type from OCI op names: list_governance_instances → governance_instance
        low = op_name.lower()
        for prefix in ("list_", "get_", "describe_"):
            if low.startswith(prefix):
                rtype = low[len(prefix):].rstrip("s")
                break
        else:
            rtype = low

        g = resources_out.setdefault(rtype, {
            "resource_type":      rtype,
            "classification":     "PRIMARY_RESOURCE",
            "has_identifier":     True,
            "identifier_type":    "ocid",
            "identifier_pattern": ocid_pattern.replace(service, rtype.replace("_", ".")),
            "identifier": {
                "primary_param":   stub.get("resource_identifiers", f"{rtype.capitalize()}Id"),
                "identifier_type": "ocid",
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
        "service": service, "csp": "oci", "generated_at": _now(),
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
        # Discovery YAML — {service} (OCI)
        # Generated: {now}
        version: '1.0'
        provider: oci
        service: {service}
        services:
          client: {service}
          module: oci.{service}
        discovery:
        """)

    def _block(name, meta, dep=False):
        action  = meta.get("yaml_action", name)
        disc_id = f"oci.{service}.{action}"
        out_flds = meta.get("output_fields", {})
        list_field = next((k for k in out_flds if k not in SKIP_FIELDS), None)
        label = " [dependent]" if dep else ""
        lines = [f"  # ── {name}{label} ──",
                 f"  - discovery_id: {disc_id}",
                 f"    calls:",
                 f"      - action: {action}",
                 f"        save_as: response",
                 f"        on_error: continue",
                 f"    emit:",
                 f"      as: item"]
        if list_field:
            lines.append(f"      items_for: '{{{{ response.{list_field} }}}}'")
            sub = [k for k in out_flds if k not in SKIP_FIELDS and k != list_field]
            if sub:
                lines.append("      item:")
                for f in sub[:15]:
                    lines.append(f"        {f}: '{{{{ item.{f} }}}}'")
        else:
            lines.append("      items_for: '{{ response }}'")
        return "\n".join(lines)

    blocks = [_block(k, v) for k, v in sorted(ind_ops.items())]
    if dep_ops:
        blocks += ["  # ── Dependent ops ──"] + [_block(k, v, True) for k, v in sorted(dep_ops.items())]
    return header + "\n".join(blocks) + "\n"


# ── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    svc_dirs = sorted(d for d in OCI_ROOT.iterdir()
                      if d.is_dir() and d.name not in SKIP
                      and (d / "operation_registry.json").exists())
    print(f"OCI: {len(svc_dirs)} services with operation_registry.json")
    ok = 0
    for svc_dir in svc_dirs:
        step1 = build_step1(svc_dir)
        if not step1:
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
        print(f"  {svc:<40} read={r:>3} write={w:>3} resources={res:>3}")
        ok += 1
    print(f"\nDone: {ok} OCI services processed")

if __name__ == "__main__":
    main()
