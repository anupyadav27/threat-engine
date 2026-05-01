#!/usr/bin/env python3
"""
Generate step1–step2r/w–step5–step6 for all AliCloud services.

Source files per service directory:
  operation_registry.json   → kind, sdk.client/method, consumes[], produces[]
  arn_identifier.json       → single-resource identifier stub (optional)
  minimal_operations_list.json → independent ops list

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

ALICLOUD_ROOT = Path(__file__).parent.parent / "alicloud"
SKIP = {"temp_code", "__pycache__"}

READ_KINDS  = {"read_get", "read_list", "read_describe", "read_query", "read_other"}
WRITE_KINDS = {"write_create", "write_delete", "write_update", "write_apply",
               "write_other", "other"}

SKIP_FIELDS = {"nextToken", "NextToken", "Marker", "RequestId", "pageToken",
               "totalCount", "pageSize", "pageNumber", "maxResults"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── STEP 1 ────────────────────────────────────────────────────────────────────

def build_step1(svc_dir: Path) -> dict | None:
    reg_path = svc_dir / "operation_registry.json"
    if not reg_path.exists():
        return None

    raw = json.loads(reg_path.read_text())
    service = raw.get("service", svc_dir.name)
    ops = raw.get("operations", {})

    independent = []
    dependent   = []

    for op_name, op in ops.items():
        consumes = op.get("consumes", [])
        required = [c for c in consumes if c.get("required", False)
                    and c.get("source", "") != "always_available"]
        produces = op.get("produces", [])

        sdk = op.get("sdk", {})
        python_method = sdk.get("method", op_name)
        yaml_action   = python_method

        entry = {
            "operation":     op_name,
            "python_method": python_method,
            "yaml_action":   yaml_action,
            "kind":          op.get("kind", "other"),
            "side_effect":   op.get("side_effect", False),
            "required_params": [c.get("param", c.get("entity", "")) for c in required],
            "optional_params": [c.get("param", c.get("entity", ""))
                                 for c in consumes if not c.get("required", False)],
            "output_fields": {
                p.get("entity", p.get("path", "")).split(".")[-1]: {
                    "type": "string", "path": p.get("path", ""),
                    "entity": p.get("entity", "")
                }
                for p in produces if p.get("entity") or p.get("path")
            },
        }

        if required:
            dependent.append(entry)
        else:
            independent.append(entry)

    return {
        "service":          service,
        "csp":              "alicloud",
        "generated_at":     _now(),
        "total_operations": len(ops),
        "independent_count": len(independent),
        "dependent_count":   len(dependent),
        "independent":      independent,
        "dependent":        dependent,
    }


# ── STEP 2 ────────────────────────────────────────────────────────────────────

def build_step2(step1: dict) -> tuple[dict, dict]:
    service = step1["service"]
    now     = _now()

    read_ops  = {}
    write_ops = {}

    for bucket in ("independent", "dependent"):
        for op in step1.get(bucket, []):
            name = op["operation"]
            kind = op.get("kind", "other")
            is_ind = (bucket == "independent")
            entry = {
                "operation":     name,
                "service":       service,
                "csp":           "alicloud",
                "kind":          kind,
                "independent":   is_ind,
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

    def _reg(ops, label):
        return {
            "service":           service,
            "csp":               "alicloud",
            "generated_at":      now,
            "total_operations":  len(ops),
            "independent_count": sum(1 for v in ops.values() if v["independent"]),
            "dependent_count":   sum(1 for v in ops.values() if not v["independent"]),
            "operations":        ops,
        }

    return _reg(read_ops, "read"), _reg(write_ops, "write")


# ── STEP 5 ────────────────────────────────────────────────────────────────────

def build_step5(svc_dir: Path, step1: dict, read_reg: dict) -> dict:
    service   = step1["service"]
    read_ops  = read_reg.get("operations", {})

    stub = {}
    stub_path = svc_dir / "arn_identifier.json"
    if stub_path.exists():
        stub = json.loads(stub_path.read_text())

    # Load minimal_operations_list for independent ops
    min_path = svc_dir / "minimal_operations_list.json"
    min_ops  = []
    if min_path.exists():
        min_data = json.loads(min_path.read_text())
        for op in min_data.get("minimal_operations", {}).get("selected_operations", []):
            min_ops.append(op["operation"])

    # Group read ops by broad resource type
    # AliCloud operation names: DescribeFoos, ListFoos, GetFoo, QueryFoo
    resource_groups: dict = {}
    for op_name, op_meta in read_ops.items():
        # Derive resource slug from op name
        for prefix in ("Describe", "List", "Get", "Query", "Fetch"):
            if op_name.startswith(prefix):
                resource_slug = op_name[len(prefix):]
                # normalise plural → singular-ish
                rtype = re.sub(r"s$", "", resource_slug).lower().replace(" ", "_")
                break
        else:
            rtype = op_name.lower()

        g = resource_groups.setdefault(rtype, {"inventory": [], "enrich": []})
        if op_meta["independent"]:
            g["inventory"].append(op_meta)
        else:
            g["enrich"].append(op_meta)

    resources_out = {}
    for rtype, g in resource_groups.items():
        arn_pattern = (
            stub.get("pattern")
            or f"acs:{service}:${{Region}}:${{AccountId}}:{rtype.upper()}/${{{rtype.capitalize()}Id}}"
        )
        resources_out[rtype] = {
            "resource_type":           rtype,
            "classification":          "PRIMARY_RESOURCE",
            "has_identifier":          True,
            "identifier_type":         "arn",
            "identifier_pattern":      arn_pattern,
            "identifier": {
                "primary_param":   stub.get("resource_identifiers", f"{rtype.capitalize()}Id"),
                "identifier_type": "arn",
            },
            "inventory":        {"ops": [{"operation": o["operation"], "kind": o["kind"],
                                           "independent": o["independent"],
                                           "python_method": o["python_method"]}
                                          for o in g["inventory"]]},
            "inventory_enrich": {"ops": [{"operation": o["operation"], "kind": o["kind"],
                                           "independent": o["independent"],
                                           "python_method": o["python_method"]}
                                          for o in g["enrich"]]},
        }

    return {
        "service":         service,
        "csp":             "alicloud",
        "generated_at":    _now(),
        "total_resources": len(resources_out),
        "resources":       resources_out,
    }


# ── STEP 6 ────────────────────────────────────────────────────────────────────

def build_step6(service: str, read_reg: dict) -> str:
    ops = read_reg.get("operations", {})
    ind_ops = {k: v for k, v in ops.items() if v["independent"]}
    dep_ops = {k: v for k, v in ops.items() if not v["independent"]}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = textwrap.dedent(f"""\
        # ============================================================
        # Discovery YAML — {service} (AliCloud)
        # Generated: {now}
        # ============================================================
        version: '1.0'
        provider: alicloud
        service: {service}
        services:
          client: {service}
          module: alibabacloud_python_sdk.{service}
        discovery:
        """)

    def _block(op_name: str, op_meta: dict, dependent: bool = False) -> str:
        action  = op_meta.get("yaml_action", op_meta.get("python_method", op_name))
        disc_id = f"alicloud.{service}.{action}"
        out_flds = op_meta.get("output_fields", {})

        # Pick first non-skip key as items_for
        list_field = next((k for k in out_flds if k not in SKIP_FIELDS), None)

        lines = []
        label = " [dependent]" if dependent else ""
        lines.append(f"  # ── {op_name}{label} ──")
        lines.append(f"  - discovery_id: {disc_id}")
        lines.append(f"    calls:")
        lines.append(f"      - action: {action}")
        lines.append(f"        save_as: response")
        lines.append(f"        on_error: continue")
        lines.append(f"    emit:")
        lines.append(f"      as: item")
        if list_field:
            lines.append(f"      items_for: '{{{{ response.{list_field} }}}}'")
            item_flds = [k for k in out_flds if k not in SKIP_FIELDS and k != list_field]
            if item_flds:
                lines.append(f"      item:")
                for f in item_flds[:15]:
                    lines.append(f"        {f}: '{{{{ item.{f} }}}}'")
        else:
            lines.append(f"      items_for: '{{{{ response }}}}'")
        return "\n".join(lines)

    blocks = [_block(k, v) for k, v in sorted(ind_ops.items())]
    if dep_ops:
        blocks.append("  # ── Dependent ops ──")
        blocks.extend(_block(k, v, True) for k, v in sorted(dep_ops.items()))

    return header + "\n".join(blocks) + "\n"


# ── MAIN ─────────────────────────────────────────────────────────────────────

def main():
    svc_dirs = sorted(
        d for d in ALICLOUD_ROOT.iterdir()
        if d.is_dir() and d.name not in SKIP
        and (d / "operation_registry.json").exists()
    )
    print(f"AliCloud: {len(svc_dirs)} services with operation_registry.json")

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

        svc_name = step1["service"]
        yaml_path = svc_dir / f"step6_{svc_name}.discovery.yaml"
        yaml_path.write_text(step6_yaml)

        r = read_reg["total_operations"]
        w = write_reg["total_operations"]
        res = step5["total_resources"]
        print(f"  {svc_name:<35} read={r:>3} write={w:>3} resources={res:>3}")
        ok += 1

    print(f"\nDone: {ok} services processed")


if __name__ == "__main__":
    main()
