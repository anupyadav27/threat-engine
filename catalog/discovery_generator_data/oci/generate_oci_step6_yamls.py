#!/usr/bin/env python3
"""
Generate OCI step6 discovery YAMLs for all services.

Sources:
  - step2_read_operation_registry.json  → ops, required_params, output_fields
  - adjacency.json                       → op_consumes for parent resolution
  - oci_master_field_catalog.csv         → dependency chains (root_op per op)
  - catalog/rule/oci_rule_check/         → services that have check rules (priority)

Output format matches:
  catalog/discovery_generator/aws/access-analyzer/step6_access-analyzer.discovery.yaml

For each op:
  - Independent (list_*): no for_each, items_for: '{{ response.data }}'
  - Dependent (get_*):   for_each: oci.{service}.{parent_list_op}
                          params: {id_param: '{{ item.ocid }}'}
"""

from __future__ import annotations
import csv, json, re
from collections import defaultdict
from pathlib import Path
from datetime import datetime, timezone

BASE_OCI    = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/oci")
MASTER_CSV  = BASE_OCI / "oci_master_field_catalog.csv"
RULES_BASE  = Path("/Users/apple/Desktop/threat-engine/catalog/rule/oci_rule_check")

# ── Root params that are always available (skip in params block) ────────────
ROOT_PARAMS = {
    "compartmentId", "CompartmentId", "compartment_id",
    "tenancyId", "TenancyId", "tenancy_id",
    "regionId", "RegionId", "region_id",
    "namespaceName", "NamespaceName", "Namespace", "namespace",
}


# ── Helpers ──────────────────────────────────────────────────────────────────

def pascal_to_snake(name: str) -> str:
    """AutonomousDatabaseId → autonomous_database_id"""
    s1 = re.sub(r"(.)([A-Z][a-z]+)", r"\1_\2", name)
    return re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s1).lower()


def param_value(param_pascal: str, snake: str) -> str:
    """Determine the template value for a required param."""
    low = param_pascal.lower()
    # Any *Name param → item.name
    if low.endswith("name") and "namespace" not in low:
        return "{{ item.name }}"
    # NamespaceName → item.namespace_name (object_storage special)
    if "namespace" in low:
        return "{{ item.namespace_name }}"
    # Any *Id param → item.ocid (OCI uses OCID as universal identifier)
    return "{{ item.ocid }}"


# ── Load master CSV: op → root_op mapping ───────────────────────────────────

def load_chain_map(csv_path: Path) -> dict[str, dict[str, str]]:
    """
    Returns: service → {producing_op_bare → root_op_bare}
    e.g. {'database': {'get_autonomous_database': 'list_autonomous_databases'}}
    """
    chains: dict[str, dict[str, str]] = defaultdict(dict)
    for row in csv.DictReader(open(csv_path)):
        svc     = row["service"]
        prod    = row["producing_op"].split(".")[-1]   # bare op name
        root    = row["root_op"].split(".")[-1] if row.get("root_op") else prod
        is_indep = row.get("is_independent", "No").strip() == "Yes"

        if prod not in chains[svc]:
            chains[svc][prod] = root
        # If op is independent, root == self (no need for for_each)
        if is_indep and prod not in chains[svc]:
            chains[svc][prod] = prod

    return chains


# ── Load master CSV: op → list of field names ────────────────────────────────

def load_op_fields(csv_path: Path) -> dict[str, dict[str, list[str]]]:
    """
    Returns: service → {op_bare → [field_leaf, ...]}
    field_leaf is the last segment of field_path, e.g. 'kms_key_id'
    """
    result: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for row in csv.DictReader(open(csv_path)):
        svc  = row["service"]
        prod = row["producing_op"].split(".")[-1]
        fp   = row["field_path"]
        # Leaf field (last segment after the last '.')
        leaf = fp.split(".")[-1] if "." in fp else fp
        if leaf not in result[svc][prod]:
            result[svc][prod].append(leaf)
    return result


# ── Load step2 for a service ─────────────────────────────────────────────────

def load_step2(svc_dir: Path) -> dict:
    p = svc_dir / "step2_read_operation_registry.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text()).get("operations", {})


# ── Load adjacency for a service ─────────────────────────────────────────────

def load_adjacency(svc_dir: Path) -> dict:
    p = svc_dir / "adjacency.json"
    if not p.exists():
        return {}
    return json.loads(p.read_text())


# ── Services with check rules ────────────────────────────────────────────────

def services_with_checks() -> set[str]:
    if not RULES_BASE.exists():
        return set()
    return {d.name for d in RULES_BASE.iterdir() if d.is_dir()}


# ── Determine independence from master CSV ──────────────────────────────────

def load_independence_map(csv_path: Path) -> dict[str, dict[str, bool]]:
    """Returns: service → {op_bare → is_independent}"""
    result: dict[str, dict[str, bool]] = defaultdict(dict)
    for row in csv.DictReader(open(csv_path)):
        svc  = row["service"]
        prod = row["producing_op"].split(".")[-1]
        indep = row.get("is_independent", "No").strip() == "Yes"
        if prod not in result[svc]:
            result[svc][prod] = indep
    return result


# ── YAML emitter (manual, no pyyaml to control exact whitespace) ─────────────

class YAMLWriter:
    def __init__(self):
        self.lines: list[str] = []

    def w(self, line: str = "") -> None:
        self.lines.append(line)

    def text(self) -> str:
        return "\n".join(self.lines) + "\n"


# ── Build a single discovery entry ───────────────────────────────────────────

def build_entry(
    service: str,
    op: str,
    is_independent: bool,
    required_params: list[str],
    output_fields: list[str],
    parent_op: str | None,      # None if independent
) -> dict:
    """
    Returns a structured dict representing one discovery entry.
    """
    non_root_params = [p for p in required_params if p not in ROOT_PARAMS]

    return {
        "op":            op,
        "service":       service,
        "is_independent": is_independent,
        "parent_op":     parent_op,
        "params":        {pascal_to_snake(p): param_value(p, pascal_to_snake(p))
                          for p in non_root_params},
        "output_fields": output_fields or ["ocid", "compartment_id", "name",
                                            "status", "time_created",
                                            "freeform_tags", "defined_tags"],
    }


# ── Generate YAML text for one service ───────────────────────────────────────

def generate_service_yaml(
    svc_dir: Path,
    chain_map: dict[str, str],       # op_bare → root_op_bare
    indep_map: dict[str, bool],      # op_bare → is_independent
    op_fields_map: dict[str, list],  # op_bare → [field_leaf]
) -> str:
    service  = svc_dir.name
    ops_meta = load_step2(svc_dir)

    if not ops_meta:
        return ""

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Build entries
    entries: list[dict] = []
    for op, meta in ops_meta.items():
        kind    = meta.get("kind", "read_get")
        req_p   = meta.get("required_params", [])
        out_f   = meta.get("output_fields", [])
        if isinstance(out_f, dict):
            out_f = list(out_f.keys())

        # Merge fields from master CSV (enriched fields)
        csv_fields = op_fields_map.get(op, [])
        all_fields = list(dict.fromkeys(out_f + csv_fields))   # preserve order, dedup

        # Determine independence
        non_root = [p for p in req_p if p not in ROOT_PARAMS]
        is_indep = (len(non_root) == 0)
        # Override from CSV if available (more accurate)
        if op in indep_map:
            is_indep = indep_map[op]

        # Determine parent op for for_each
        parent_op: str | None = None
        if not is_indep:
            root = chain_map.get(op)
            if root and root != op:
                parent_op = root

        entries.append(build_entry(service, op, is_indep, req_p, all_fields, parent_op))

    # Sort: list_ (independent) first, then get_ (dependent)
    entries.sort(key=lambda e: (0 if e["is_independent"] else 1, e["op"]))

    # ── Write YAML ────────────────────────────────────────────────────────────
    w = YAMLWriter()
    w.w(f"# ============================================================")
    w.w(f"# Discovery YAML — {service} (OCI)")
    w.w(f"# Generated: {now}")
    w.w(f"# Actions use OCI Python SDK method names (snake_case)")
    w.w(f"# ============================================================")
    w.w(f"version: '1.0'")
    w.w(f"provider: oci")
    w.w(f"service: {service}")
    w.w(f"services:")
    w.w(f"  client: {service}")
    w.w(f"  module: oci.{service}")
    w.w(f"discovery:")

    for e in entries:
        op        = e["op"]
        indep     = e["is_independent"]
        parent    = e["parent_op"]
        params    = e["params"]
        fields    = e["output_fields"]
        kind_tag  = "independent" if indep else f"dependent → {parent}" if parent else "dependent"

        w.w(f"  # ── {op} [{kind_tag}] ──")
        w.w(f"  - discovery_id: oci.{service}.{op}")

        if parent:
            w.w(f"    for_each: oci.{service}.{parent}")

        w.w(f"    calls:")
        w.w(f"      - action: {op}")

        if params:
            w.w(f"        params:")
            for k, v in params.items():
                w.w(f"          {k}: '{v}'")

        w.w(f"        save_as: response")
        w.w(f"        on_error: continue")
        w.w(f"    emit:")
        w.w(f"      as: item")

        if indep:
            # List op → iterate over response.data
            w.w(f"      items_for: '{{{{ response.data }}}}'")
            w.w(f"      item:")
            for f in fields:
                w.w(f"        {f}: '{{{{ item.{f} }}}}'")
        else:
            # Get op → single response object
            w.w(f"      item:")
            for f in fields:
                w.w(f"        {f}: '{{{{ response.data.{f} }}}}'")

    return w.text()


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("Loading master CSV chains...")
    chain_map  = load_chain_map(MASTER_CSV)
    indep_map  = load_independence_map(MASTER_CSV)
    op_fields  = load_op_fields(MASTER_CSV)

    checked_svcs = services_with_checks()
    print(f"  Services with check rules: {len(checked_svcs)}")

    svc_dirs = sorted(d for d in BASE_OCI.iterdir() if d.is_dir())
    print(f"  Total OCI service dirs: {len(svc_dirs)}\n")

    generated = 0
    skipped   = 0
    has_checks_count = 0

    for svc_dir in svc_dirs:
        service = svc_dir.name
        out_path = svc_dir / f"step6_{service}.discovery.yaml"

        # Build per-service maps
        svc_chains = chain_map.get(service, {})
        svc_indep  = indep_map.get(service, {})
        svc_fields = op_fields.get(service, {})

        yaml_text = generate_service_yaml(
            svc_dir, svc_chains, svc_indep, svc_fields
        )

        if not yaml_text:
            skipped += 1
            continue

        out_path.write_text(yaml_text)
        generated += 1

        has_check = service in checked_svcs
        if has_check:
            has_checks_count += 1

        # Count for_each entries
        fe_count = yaml_text.count("for_each:")
        op_count = yaml_text.count("discovery_id:")
        check_marker = " [CHECK]" if has_check else ""
        print(f"  [{service}]{check_marker}  ops={op_count}  with_for_each={fe_count}")

    print(f"\n{'='*65}")
    print(f"DONE")
    print(f"  Generated : {generated}")
    print(f"  Skipped   : {skipped} (no step2 registry)")
    print(f"  With checks: {has_checks_count}")
    print(f"{'='*65}")


if __name__ == "__main__":
    main()
