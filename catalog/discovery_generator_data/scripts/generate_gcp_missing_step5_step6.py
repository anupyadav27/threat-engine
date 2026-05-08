#!/usr/bin/env python3
"""
Generate step5_resource_catalog_inventory_enrich.json and step6_*.discovery.yaml
for the ~18 GCP services that are currently missing them.

INPUT per service directory (must exist):
  step2_read_operation_registry.json
  step2_write_operation_registry.json  (optional)
  step3_read_operation_dependency_chain_independent.json  (optional)

OUTPUT per service directory (only written if missing):
  step5_resource_catalog_inventory_enrich.json
  step6_{service}.discovery.yaml
"""

import json
import re
import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

GCP_ROOT = Path(__file__).parent.parent / "gcp"

SKIP_FIELDS = {
    "nextPageToken", "nextToken", "pageToken", "etag",
    "kind", "unreachable", "warning", "id", "selfLink",
}

NON_READ_VERBS = {"POST", "PUT", "DELETE", "PATCH"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─── STEP 5 BUILDER ────────────────────────────────────────────────────────

def _resource_from_op_key(op_key: str) -> str:
    """gcp.compute.addresses.list → addresses"""
    parts = op_key.split(".")
    return parts[2] if len(parts) >= 4 else parts[-2] if len(parts) >= 2 else op_key


def _verb_kind(op: dict) -> str:
    kind = op.get("kind", "")
    if kind:
        return kind
    http_verb = op.get("http", {}).get("verb", "GET")
    if http_verb == "GET":
        op_name = op.get("op", "").split(".")[-1].lower()
        if "list" in op_name or "aggregatedlist" in op_name:
            return "read_list"
        return "read_get"
    return "write_other"


def _is_read_op(op: dict) -> bool:
    kind = _verb_kind(op)
    return kind.startswith("read") or kind == "other"


def _pattern_type(op: dict) -> str:
    path = op.get("http", {}).get("path", "")
    if "/zones/" in path:
        return "ZONAL"
    if "/regions/" in path:
        return "REGIONAL"
    if "/locations/" in path:
        return "LOCATION"
    if "/global/" in path:
        return "PROJECT_GLOBAL"
    return "PROJECT_GLOBAL"


def _build_gcp_identifier(resource_type: str, inv_op: Optional[dict], enrich_op: Optional[dict]) -> dict:
    """Build a minimal identifier block for a GCP resource."""
    parts = []
    part_sources = {}

    # Always need project
    parts.append("project")
    part_sources["project"] = {"op": "service_anchor", "field_path": "project_id", "transform": None}

    if inv_op:
        path = inv_op.get("http", {}).get("path", "")
        if "/zones/" in path or "{zone}" in path:
            parts.append("zone")
            part_sources["zone"] = {"op": "service_anchor", "field_path": "zone", "transform": None}
        if "/regions/" in path or "{region}" in path:
            parts.append("region")
            part_sources["region"] = {"op": "service_anchor", "field_path": "region", "transform": None}
        if "/locations/" in path or "{location}" in path:
            parts.append("location")
            part_sources["location"] = {"op": "service_anchor", "field_path": "location", "transform": None}

    # Resource name part
    parts.append(resource_type)
    inv_op_key = inv_op.get("op", "") if inv_op else ""
    part_sources[resource_type] = {
        "op": inv_op_key,
        "field_path": f"items[].name",
        "transform": None,
    }

    template_parts = [f"{{{p}}}" for p in parts]
    template = "/".join(template_parts)

    return {
        "kind": "full_name",
        "full_identifier": {
            "template": template,
            "built_from_parts": parts,
            "notes": "Full resource name; anchor parts are user-provided.",
        },
        "parts": parts,
        "part_sources": part_sources,
        "transforms": [],
    }


def _produces_map(op: dict) -> dict:
    """Simple produces map from op inputs outputs."""
    result = {}
    outputs = op.get("outputs", op.get("produces", {}))
    if isinstance(outputs, dict):
        for k, v in outputs.items():
            if k not in SKIP_FIELDS:
                result[k] = v if isinstance(v, str) else f"items[].{k}"
    return result


def build_gcp_step5(svc_dir: Path) -> Optional[dict]:
    read2_path   = svc_dir / "step2_read_operation_registry.json"
    write2_path  = svc_dir / "step2_write_operation_registry.json"
    chains_path  = svc_dir / "step3_read_operation_dependency_chain_independent.json"

    if not read2_path.exists():
        return None

    s2r = json.loads(read2_path.read_text())
    ops_read: dict = s2r.get("operations", {})
    service = s2r.get("service", svc_dir.name)
    version = s2r.get("version", "v1")

    ops_write: dict = {}
    if write2_path.exists():
        ops_write = json.loads(write2_path.read_text()).get("operations", {})

    chains: dict = {}
    if chains_path.exists():
        chains = json.loads(chains_path.read_text()).get("chains", {})

    # Group read ops by resource_type
    groups: dict = {}  # resource_type → {list_ops, get_ops, other_ops}
    for op_key, op in ops_read.items():
        rtype = _resource_from_op_key(op_key)
        g = groups.setdefault(rtype, {"list_ops": [], "get_ops": [], "other_ops": []})
        kind = _verb_kind(op)
        if kind == "read_list":
            g["list_ops"].append(op)
        elif kind == "read_get":
            g["get_ops"].append(op)
        else:
            g["other_ops"].append(op)

    resources_out: dict = {}
    for rtype, g in groups.items():
        list_ops = g["list_ops"]
        get_ops  = g["get_ops"]

        inv_op    = list_ops[0] if list_ops else (g["other_ops"][0] if g["other_ops"] else None)
        enrich_op = get_ops[0]  if get_ops  else None

        identifier = _build_gcp_identifier(rtype, inv_op, enrich_op)
        pattern_t  = _pattern_type(inv_op) if inv_op else "PROJECT_GLOBAL"

        inv_ops_list = []
        for op in list_ops or g["other_ops"][:1]:
            inv_ops_list.append({
                "op":           op.get("op", ""),
                "kind":         _verb_kind(op),
                "independent":  op.get("independent", True),
                "python_call":  op.get("python_call", ""),
                "produces":     _produces_map(op),
                "chain_to_independent": None,
            })

        enrich_ops_list = []
        for op in get_ops:
            req_params = {}
            for inp in op.get("inputs", {}).get("required", []):
                pname = inp.get("param", "")
                if pname in identifier.get("parts", []):
                    req_params[pname] = {"from_identifier": pname}
                else:
                    req_params[pname] = {"from_identifier": pname}
            enrich_ops_list.append({
                "op":              op.get("op", ""),
                "kind":            _verb_kind(op),
                "independent":     False,
                "python_call":     op.get("python_call", ""),
                "required_params": req_params,
                "chain_to_independent": chains.get(op.get("op", ""), None),
            })

        confidence = 0.0
        if inv_ops_list:   confidence += 0.40
        if enrich_ops_list: confidence += 0.30
        if identifier.get("full_identifier", {}).get("template"): confidence += 0.20
        if identifier.get("part_sources"):                         confidence += 0.10

        resources_out[rtype] = {
            "resource_type":    rtype,
            "pattern_type":     pattern_t,
            "identifier":       identifier,
            "inventory":        {"ops": inv_ops_list},
            "inventory_enrich": {"ops": enrich_ops_list},
            "confidence":       round(min(confidence, 1.0), 2),
            "notes":            "",
        }

    if not resources_out:
        return None

    return {
        "csp":          "gcp",
        "generated_at": _now_iso(),
        "anchors": {
            "fixed": ["project_id", "org_id", "folder_id", "location", "zone", "region"]
        },
        "services": {
            service: {
                "version":   version,
                "resources": resources_out,
            }
        },
    }


# ─── STEP 6 BUILDER ────────────────────────────────────────────────────────

def _gcp_action(op_key: str) -> str:
    """gcp.compute.addresses.list → addresses.list"""
    parts = op_key.split(".", 2)
    return parts[2] if len(parts) >= 3 else op_key


def _gcp_items_for(op: dict, list_field: Optional[str] = None) -> Optional[str]:
    if list_field:
        return f"{{{{ {list_field}.items }}}}"
    path = op.get("http", {}).get("path", "")
    return "{{ response.items }}"


def _gcp_item_fields(op: dict) -> list[str]:
    outputs = op.get("outputs", {})
    if isinstance(outputs, dict):
        return [k for k in outputs if k not in SKIP_FIELDS]
    inputs_req = op.get("inputs", {}).get("required", [])
    return [inp.get("param", "") for inp in inputs_req if inp.get("param")]


def build_gcp_step6(svc_dir: Path) -> Optional[str]:
    read2_path = svc_dir / "step2_read_operation_registry.json"
    if not read2_path.exists():
        return None

    s2r     = json.loads(read2_path.read_text())
    service = s2r.get("service", svc_dir.name)
    version = s2r.get("version", "v1")
    ops     = s2r.get("operations", {})

    if not ops:
        return None

    # Only independent read ops (list/get that are independent)
    ind_ops = {k: v for k, v in ops.items() if v.get("independent", False)}
    dep_ops = {k: v for k, v in ops.items() if not v.get("independent", False)}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = textwrap.dedent(f"""\
        # ============================================================
        # Discovery YAML — {service} ({version})
        # Generated: {now}
        # ============================================================
        version: '1.0'
        provider: gcp
        service: {service}

        services:
          client: {service}
          module: "googleapiclient.discovery.build('{service}', '{version}')"

        anchors:
          project_id: null
          org_id: null
          folder_id: null
          location: null
          zone: null
          region: null

        checks: []

        discovery:
        """)

    blocks = []

    def _render_block(op_key: str, op: dict, dependent: bool = False) -> str:
        action     = _gcp_action(op_key)
        disc_id    = op_key
        rtype      = _resource_from_op_key(op_key)
        save_as    = f"{rtype}_response"
        item_alias = f"{rtype}_item"
        item_flds  = _gcp_item_fields(op)

        lines = []
        dep_label = " [dependent]" if dependent else ""
        lines.append(f"  # ── {op_key}{dep_label} ──")
        lines.append(f"  - discovery_id: {disc_id}")
        lines.append(f"    calls:")
        lines.append(f"      - action: {action}")
        lines.append(f"        params: {{}}")
        lines.append(f"        save_as: {save_as}")
        lines.append(f"        on_error: continue")
        lines.append(f"    emit:")
        lines.append(f"      as: {item_alias}")
        lines.append(f"      items_for: \"{{{{ {save_as}.items }}}}\"")
        if item_flds:
            lines.append(f"      item:")
            for fname in item_flds[:20]:  # cap at 20 fields
                lines.append(f"        {fname}: \"{{{{ item.{fname} }}}}\"")
        return "\n".join(lines)

    for op_key in sorted(ind_ops):
        blocks.append(_render_block(op_key, ind_ops[op_key], dependent=False))

    if dep_ops:
        blocks.append("")
        blocks.append("  # ── Dependent operations ──")
        for op_key in sorted(dep_ops):
            blocks.append(_render_block(op_key, dep_ops[op_key], dependent=True))

    return header + "\n".join(blocks) + "\n"


# ─── MAIN ────────────────────────────────────────────────────────────────────

def main():
    REAL_SKIP = {"temp_code", "tools", "__pycache__"}

    svc_dirs = sorted(
        d for d in GCP_ROOT.iterdir()
        if d.is_dir() and d.name not in REAL_SKIP
    )

    missing5 = [d for d in svc_dirs if not (d / "step5_resource_catalog_inventory_enrich.json").exists()]
    missing6 = [d for d in svc_dirs if not list(d.glob("step6_*.discovery.yaml"))]

    # Union of services needing either file
    need_work = sorted(set(missing5 + missing6), key=lambda d: d.name)

    print(f"GCP services needing step5: {len(missing5)}")
    print(f"GCP services needing step6: {len(missing6)}")
    print(f"Total to process: {len(need_work)}")
    print()

    for svc_dir in need_work:
        svc = svc_dir.name

        # step5
        step5_path = svc_dir / "step5_resource_catalog_inventory_enrich.json"
        if not step5_path.exists():
            catalog = build_gcp_step5(svc_dir)
            if catalog:
                step5_path.write_text(json.dumps(catalog, indent=2))
                n = sum(len(v["resources"]) for v in catalog["services"].values())
                print(f"  {svc:<40}  step5 written ({n} resources)")
            else:
                print(f"  {svc:<40}  step5 SKIPPED (no read ops)")

        # step6
        if not list(svc_dir.glob("step6_*.discovery.yaml")):
            content = build_gcp_step6(svc_dir)
            if content:
                out = svc_dir / f"step6_{svc}.discovery.yaml"
                out.write_text(content)
                lines = content.count("\n")
                print(f"  {svc:<40}  step6 written ({lines} lines)")
            else:
                print(f"  {svc:<40}  step6 SKIPPED (no ops)")

    print()
    print("Done.")


if __name__ == "__main__":
    main()
