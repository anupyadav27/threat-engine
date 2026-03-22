#!/usr/bin/env python3
"""
Regenerate step6_{service}.discovery.yaml for ALL GCP services.

Sources (in priority order):
  step2_read_operation_registry.json          — ALL read ops (read_list + read_get),
        independent flag set, inputs.required for params
  step3_read_operation_dependency_chain_*.json — dependency chains: for_each parent,
        param_sources telling which field from parent item fills which param
  step5_resource_catalog_inventory_enrich.json — per-op produces dict (primary field source)
  step4_fields_produced_index.json             — inverted field index (fallback field source)

Architecture (as designed):
  step2  → ONLY read methods (read_list + read_get); write ops filtered out
  step3  → dependency chain: which parent op feeds each dependent op, and via which field
  step4  → ALL fields produced by those read methods; decides what to emit
  step6  → YAML of ALL step2 ops:
           - for_each + params from step3 (for dependent ops)
           - CSPM-relevant fields from step4/step5 under emit.item

Engine execution model (from service_scanner.py):
  - Independent ops (no for_each) → executed in parallel
  - Dependent ops (with for_each) → engine iterates parent results, injects 'item' variable
  - list ops: emit.items_for extracts collection; item fields use {{ item.field }}
  - get ops:  no items_for; emit.item fields use {{ response.field }}
  - save_as: response is standard (engine uses saved_data['response'])

Output: step6_{service}.discovery.yaml (overwritten for all services)

Usage:
    python3 data_pythonsdk/scripts/generate_gcp_step6_from_step5.py
    python3 data_pythonsdk/scripts/generate_gcp_step6_from_step5.py --dry-run
    python3 data_pythonsdk/scripts/generate_gcp_step6_from_step5.py --service compute
"""

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

GCP_ROOT = Path(__file__).parent.parent / "gcp"

# Only read ops go in the discovery YAML
READ_KINDS = {"read_list", "read_get"}

# Fields to always skip — pagination, API metadata, not CSPM-relevant
SKIP_FIELDS = {
    "nextPageToken", "nextToken", "pageToken", "etag",
    "kind", "unreachable", "warning", "nextLink",
    "selfLink",  # GCP response-level URL, not per-item CSPM data
}


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Key derivation helpers ────────────────────────────────────────────────────

def _action(op_key: str, service: str) -> str:
    """
    gcp.compute.securityPolicies.list → securityPolicies.list
    gcp.accessapproval.organizations.approvalRequests.list
      → organizations.approvalRequests.list
    """
    prefix = f"gcp.{service}."
    if op_key.startswith(prefix):
        return op_key[len(prefix):]
    parts = op_key.split(".", 2)
    return parts[2] if len(parts) >= 3 else op_key


def _resource_name(op_key: str) -> str:
    """
    Extract the primary resource name (collection) from the op key.
    gcp.accessapproval.organizations.approvalRequests.list → approvalRequests
    gcp.compute.securityPolicies.list                     → securityPolicies
    gcp.compute.securityPolicies.aggregatedList           → securityPolicies
    """
    parts = op_key.split(".")
    verb = parts[-1].lower()
    if verb in ("list", "get", "aggregatedlist") and len(parts) >= 2:
        return parts[-2]
    return parts[-2] if len(parts) >= 3 else parts[-1]


def _items_collection(op_key: str, kind: str) -> str:
    """
    For list ops: the response field holding the item array.
      gcp.compute.addresses.list         → addresses  (response.addresses[])
      gcp.compute.addresses.aggregatedList → items     (response.items{})
    For get ops: empty (response IS the single item).
    """
    if kind != "read_list":
        return ""
    verb = op_key.split(".")[-1].lower()
    if verb == "aggregatedlist":
        return "items"
    return _resource_name(op_key)


def _required_params(op: dict) -> list[str]:
    """Extract required param names from step2 inputs.required."""
    return [p["param"] for p in op.get("inputs", {}).get("required", [])]


# ── Data loaders ──────────────────────────────────────────────────────────────

def _load_step3_chains(svc_dir: Path) -> dict:
    """
    Returns {op_key: chain_info} from step3 dependency chains.
    chain_info keys: independent, hop_distance, unresolved_params, execution_steps
    """
    step3_path = svc_dir / "step3_read_operation_dependency_chain_independent.json"
    if not step3_path.exists():
        return {}
    try:
        with open(step3_path) as f:
            return json.load(f).get("chains", {})
    except Exception:
        return {}


def _load_step5_produces(svc_dir: Path) -> dict:
    """
    Returns {op_key: {field_name: response_path}} from step5 inventory ops.
    e.g. {"gcp.accessapproval.organizations.approvalRequests.list":
              {"name": "approvalRequests[].name", ...}}
    """
    step5_path = svc_dir / "step5_resource_catalog_inventory_enrich.json"
    if not step5_path.exists():
        return {}
    try:
        with open(step5_path) as f:
            s5 = json.load(f)
    except Exception:
        return {}
    result = {}
    for svc_name, svc_data in s5.get("services", {}).items():
        for rt, rt_data in svc_data.get("resources", {}).items():
            for bucket in ("inventory", "inventory_enrich"):
                for op in rt_data.get(bucket, {}).get("ops", []):
                    key = op.get("op", "")
                    produces = op.get("produces", {})
                    if key and produces:
                        result[key] = produces
    return result


def _load_step4_op_fields(svc_dir: Path) -> dict:
    """
    Returns {op_key: [field_path, ...]} from step4 (inverted field index).
    Field paths: "approvalRequests[].name" (list items) or "name" (get response).
    """
    step4_path = svc_dir / "step4_fields_produced_index.json"
    if not step4_path.exists():
        return {}
    try:
        with open(step4_path) as f:
            s4 = json.load(f)
    except Exception:
        return {}
    result: dict[str, list[str]] = {}
    for field_path, field_data in s4.get("fields", {}).items():
        for producer in field_data.get("producers", []):
            op_key = producer.get("op", "")
            if op_key:
                result.setdefault(op_key, []).append(field_path)
    return result


# ── Field resolution ──────────────────────────────────────────────────────────

def _get_item_fields(
    op_key: str,
    kind: str,
    step5_produces: dict,
    step4_op_fields: dict,
) -> list[str]:
    """
    Return sorted list of CSPM-relevant field names to emit.

    Priority: step5 produces → step4 inverted index.

    For list ops (read_list):
      - step5: include only fields where response_path contains "[]." (per-item)
      - step4: include paths with "[].", extract field name after last "[]."

    For get ops (read_get):
      - step5: include all non-skipped fields (response IS the item)
      - step4: include flat field names (no "[]." in path)
    """
    fields: set[str] = set()

    if op_key in step5_produces:
        for field_name, path in step5_produces[op_key].items():
            if field_name in SKIP_FIELDS:
                continue
            if kind == "read_list" and "[]." not in path:
                continue  # Response-level field, not per-item
            fields.add(field_name)

    elif op_key in step4_op_fields:
        for raw_path in step4_op_fields[op_key]:
            if "[]." in raw_path:
                field_name = raw_path.split("[].")[-1]
                if kind != "read_list":
                    continue
            else:
                field_name = raw_path
                if kind == "read_list":
                    continue  # Skip response-level fields for list ops
            if field_name and field_name not in SKIP_FIELDS:
                fields.add(field_name)

    return sorted(fields)


# ── Dependency chain resolution ───────────────────────────────────────────────

def _get_dep_info(
    op_key: str,
    chains: dict,
) -> tuple[str | None, dict[str, str]]:
    """
    Returns (parent_discovery_id, params_dict) for a dependent op.

    parent_discovery_id: the for_each target (immediate parent op)
    params_dict: {param_name: "{{ item.field }}"} derived from step3 param_sources

    Returns (None, {}) for independent ops or when chain has unresolved params.
    """
    chain = chains.get(op_key)
    if not chain or chain.get("independent", True):
        return None, {}

    # Skip if any params cannot be resolved
    if chain.get("unresolved_params"):
        return None, {}

    steps = chain.get("execution_steps", [])
    if len(steps) < 2:
        return None, {}

    target_step = steps[-1]
    parent_step = steps[-2]
    parent_op   = parent_step["op"]

    param_sources = target_step.get("param_sources", {})
    params: dict[str, str] = {}

    for param_name, source in param_sources.items():
        if source == "always_available":
            continue  # Injected from anchors by engine
        if not isinstance(source, dict):
            continue

        # Two formats in step3:
        # Format A (direct):  {from_step: N, from_op: "...", field: "..."}
        # Format B (nested):  {intermediate_var: {from_step: N, from_op: "...", field: "..."}}
        if "from_step" in source:
            # Format A
            field = source.get("field")
            if field:
                params[param_name] = f"{{{{ item.{field} }}}}"
        else:
            # Format B — iterate to find the nested source
            for _var_name, src_info in source.items():
                if isinstance(src_info, dict):
                    field = src_info.get("field")
                    if field:
                        params[param_name] = f"{{{{ item.{field} }}}}"
                    break

    return parent_op, params


# ── YAML block renderer ───────────────────────────────────────────────────────

def _render_block(
    op_key: str,
    op: dict,
    service: str,
    dependent: bool,
    item_fields: list[str] | None = None,
    for_each_parent: str | None = None,
    dep_params: dict[str, str] | None = None,
) -> str:
    """
    Render one discovery YAML block.

    list ops:
        emit.items_for: '{{ response.{collection} }}'
        emit.item fields: '{{ item.field }}'

    get ops:
        no items_for (response IS the item)
        emit.item fields: '{{ response.field }}'

    dependent ops:
        for_each: {parent_discovery_id}
        calls.params: {param_name: '{{ item.field }}'}
    """
    action      = _action(op_key, service)
    disc_id     = op_key
    kind        = op.get("kind", "read_list")
    python_call = op.get("python_call", "")
    description = op.get("description", "")
    req_params  = _required_params(op)
    collection  = _items_collection(op_key, kind)

    dep_label = " [dependent]" if dependent else ""

    lines: list[str] = []

    # Comment: description + op key
    if description:
        lines.append(f"  # {description[:100]}")
    lines.append(f"  # ── {op_key}{dep_label} ──")

    # discovery_id
    lines.append(f"  - discovery_id: {disc_id}")

    # for_each (dependent ops only) — immediately after discovery_id
    if for_each_parent:
        lines.append(f"    for_each: {for_each_parent}")

    # python call comment
    if python_call:
        lines.append(f"    # python: {python_call}")

    # calls section
    lines.append(f"    calls:")
    lines.append(f"      - action: {action}")

    # params — only non-empty for dependent ops with resolved params
    if dep_params:
        lines.append(f"        params:")
        for p_name, p_val in sorted(dep_params.items()):
            lines.append(f"          {p_name}: '{p_val}'")
    else:
        lines.append(f"        params: {{}}")

    lines.append(f"        save_as: response")
    lines.append(f"        on_error: continue")

    # emit section
    lines.append(f"    emit:")
    lines.append(f"      as: item")

    if kind == "read_list" and collection:
        # List op: iterate over collection in response
        lines.append(f"      items_for: '{{{{ response.{collection} }}}}'")
        if item_fields:
            lines.append(f"      item:")
            for field in item_fields:
                lines.append(f"        {field}: '{{{{ item.{field} }}}}'")
    else:
        # Get op: response IS the single item
        if item_fields:
            lines.append(f"      item:")
            for field in item_fields:
                lines.append(f"        {field}: '{{{{ response.{field} }}}}'")

    # Required params comment (for dependent ops without resolved params)
    if dependent and req_params:
        lines.append(f"    # required_params: {req_params}")

    return "\n".join(lines)


# ── YAML builder ──────────────────────────────────────────────────────────────

def build_step6_yaml(svc_dir: Path) -> str:
    """
    Build full step6 YAML combining:
      step2 → op list (read ops only)
      step3 → for_each parent + params for dependent ops
      step5 → field emission (primary)
      step4 → field emission (fallback)
    """
    step2_path = svc_dir / "step2_read_operation_registry.json"
    if not step2_path.exists():
        return ""

    with open(step2_path) as f:
        s2 = json.load(f)

    service = s2.get("service", svc_dir.name)
    version = s2.get("version", "v1")
    ops     = s2.get("operations", {})

    if not ops:
        return ""

    # Filter to read ops only (write ops classified as kind=other are excluded)
    ops = {k: v for k, v in ops.items() if v.get("kind", "") in READ_KINDS}
    if not ops:
        return ""

    # Load all data sources
    step3_chains    = _load_step3_chains(svc_dir)
    step5_produces  = _load_step5_produces(svc_dir)
    step4_op_fields = _load_step4_op_fields(svc_dir)

    # Split by independent flag (set in step2)
    ind_ops = {k: v for k, v in ops.items() if v.get("independent", False)}
    dep_ops = {k: v for k, v in ops.items() if not v.get("independent", False)}

    # Count ops that will have field emission
    ops_with_fields = sum(
        1 for k in ops
        if _get_item_fields(k, ops[k].get("kind", "read_list"),
                            step5_produces, step4_op_fields)
    )
    # Count dependent ops with resolved for_each linkage
    ops_with_chain = sum(
        1 for k in dep_ops
        if _get_dep_info(k, step3_chains)[0] is not None
    )

    header = "\n".join([
        f"# ============================================================",
        f"# Discovery YAML — {service} ({version})",
        f"# Generated: {_now()}",
        f"# Sources: step2 (ops) | step3 (dep chain) | step4/step5 (fields)",
        f"# read ops: {len(ops)} | independent: {len(ind_ops)} | dependent: {len(dep_ops)}",
        f"# ops with fields: {ops_with_fields}/{len(ops)} | dep ops with chain: {ops_with_chain}/{len(dep_ops)}",
        f"# ============================================================",
        f"version: '1.0'",
        f"provider: gcp",
        f"service: {service}",
        f"",
        f"services:",
        f"  client: {service}",
        f"  module: \"googleapiclient.discovery.build('{service}', '{version}')\"",
        f"",
        f"# Anchors: fixed service-level parameters (caller provides values)",
        f"anchors:",
        f"  project_id: null",
        f"  org_id: null",
        f"  folder_id: null",
        f"  location: null",
        f"  zone: null",
        f"  region: null",
        f"",
        f"checks: []",
        f"",
        f"discovery:",
        f"",
    ])

    blocks = [header]

    if ind_ops:
        blocks.append("  # ════ INDEPENDENT (root) operations ════")
        for op_key in sorted(ind_ops):
            op   = ind_ops[op_key]
            kind = op.get("kind", "read_list")
            item_fields = _get_item_fields(op_key, kind, step5_produces, step4_op_fields)
            blocks.append(_render_block(
                op_key, op, service, dependent=False,
                item_fields=item_fields,
            ))

    if dep_ops:
        blocks.append("")
        blocks.append("  # ════ DEPENDENT (enrich) operations ════")
        for op_key in sorted(dep_ops):
            op   = dep_ops[op_key]
            kind = op.get("kind", "read_list")
            item_fields  = _get_item_fields(op_key, kind, step5_produces, step4_op_fields)
            parent_op, dep_params = _get_dep_info(op_key, step3_chains)
            blocks.append(_render_block(
                op_key, op, service, dependent=True,
                item_fields=item_fields,
                for_each_parent=parent_op,
                dep_params=dep_params if dep_params else None,
            ))

    return "\n".join(blocks) + "\n"


# ── CLI ───────────────────────────────────────────────────────────────────────

def process_service(svc_dir: Path, dry_run: bool) -> tuple[int, int, bool]:
    """Returns (ind_count, dep_count, skipped)."""
    content = build_step6_yaml(svc_dir)
    if not content:
        return 0, 0, True

    lines = content.splitlines()
    dep_count = sum(1 for l in lines if "[dependent]" in l)
    total     = sum(1 for l in lines if l.strip().startswith("- discovery_id:"))
    ind_count = total - dep_count

    out_path = svc_dir / f"step6_{svc_dir.name}.discovery.yaml"
    if not dry_run:
        out_path.write_text(content)

    return ind_count, dep_count, False


def main():
    parser = argparse.ArgumentParser(
        description="Generate GCP step6 discovery YAMLs (step2+step3+step4+step5)"
    )
    parser.add_argument("--dry-run", action="store_true",
                        help="Report without writing files")
    parser.add_argument("--service", default=None,
                        help="Only process one service directory name")
    args = parser.parse_args()

    SKIP = {"tools", "__pycache__", "temp_code"}

    if args.service:
        svc_dirs = [GCP_ROOT / args.service]
    else:
        svc_dirs = sorted(d for d in GCP_ROOT.iterdir()
                          if d.is_dir() and d.name not in SKIP)

    mode = "DRY RUN" if args.dry_run else "WRITING"
    print(f"GCP step6 generation ({mode}): {len(svc_dirs)} service(s)")
    print(f"Sources: step2 (read ops) | step3 (dep chain) | step5 (fields, primary) | step4 (fields, fallback)")
    print()

    total_ind = total_dep = total_skip = 0
    for svc_dir in svc_dirs:
        ind, dep, skipped = process_service(svc_dir, args.dry_run)
        if skipped:
            total_skip += 1
            print(f"  {svc_dir.name:<45} SKIPPED (no step2)")
        else:
            total_ind += ind
            total_dep += dep
            action = "Would write" if args.dry_run else "Written   "
            print(f"  {svc_dir.name:<45} {action}: {ind} independent, {dep} dependent")

    print()
    print(f"Done: {total_ind} independent + {total_dep} dependent ops "
          f"across {len(svc_dirs)-total_skip} services "
          f"({total_skip} skipped — no step2)")


if __name__ == "__main__":
    main()
