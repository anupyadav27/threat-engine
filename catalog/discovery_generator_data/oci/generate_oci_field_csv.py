#!/usr/bin/env python3
"""
Generate enhanced field_operator_value_table.csv for every OCI service.

For every field in direct_vars.json this script adds:
  producing_op       — the OCI SDK operation that directly emits the field
  op_kind            — read_list | read_get | read_describe
  is_independent     — True if op runs with compartment_id only (no prior list needed)
  dependency_chain   — ordered ops needed to reach the field
                       e.g.  list_compartments → list_instances → get_instance
  required_ids       — ID entities the producing op consumes (pipe-separated)

Source files used per service (catalog/discovery_generator/oci/{service}/):
  adjacency.json                 — op_consumes, op_produces, independent_ops
  direct_vars.json               — fields with type + operators
  step2_read_operation_registry  — op kind + required_params
  step4_fields_produced_index    — field → preferred_op (fallback)
"""

from __future__ import annotations
import csv, json, re
from collections import defaultdict, deque
from pathlib import Path

BASE = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/oci")
CSV_COLUMNS = [
    "service",
    "field_name",
    "field_type",
    "is_enum",
    "operators",
    "operators_no_value",
    "operators_select_list",
    "operators_manual_input",
    "value_requirement_type",
    "possible_values",
    "values_source",
    "num_possible_values",
    # ── New columns ───────────────────────────────────────────────────────────
    "producing_op",
    "op_kind",
    "is_independent",
    "dependency_chain",
    "required_ids",
]

# Operator sets for field types
_OPS_BOOL    = "equals, not_equals"
_OPS_STR     = "contains, equals, in, not_equals"
_OPS_OBJ     = "contains, equals, in, not_equals"
_OPS_ARR     = "contains, equals, in, not_empty, not_equals"
_OPS_EXIST   = "equals, exists, not_equals"
_OPS_TAG     = "exists, not_empty"

# Which operators need no value
_NO_VAL_BOOL   = ""
_NO_VAL_EXIST  = "exists"
_NO_VAL_TAG    = "exists, not_empty"
_NO_VAL_NOTEMPTY = "not_empty"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _entity_to_field(entity: str, service: str) -> str | None:
    """
    Convert adjacency entity name → direct_vars field name.
    'oci.compute.app_catalog_listing.status'  →  'app_catalog_listing.status'
    'oci.ocid'                                →  'ocid'
    'oci.compute.appcataloglisting_id'        →  None  (ID entity, not a field)
    """
    if entity == "oci.ocid":
        return "ocid"
    prefix = f"oci.{service}."
    if not entity.startswith(prefix):
        return None
    rest = entity[len(prefix):]
    # ID entities end in _id (no dot) — skip them
    if "_id" in rest and "." not in rest:
        return None
    return rest


def _field_to_entity(field_name: str, service: str) -> str:
    """Reverse of _entity_to_field (best-effort)."""
    if field_name in ("ocid", "compartment_id", "defined_tags",
                      "freeform_tags", "name", "status", "time_created"):
        return f"oci.{service}.{field_name}"
    return f"oci.{service}.{field_name}"


def _is_compartment_only(consumes: list[str]) -> bool:
    """True if op only needs compartment_id (always available root input)."""
    return all(
        c in ("oci.compartment_id", "oci.tenancy_id", "oci.region")
        for c in consumes
    )


# ── Dependency chain builder ────────────────────────────────────────────────────

class DependencyGraph:
    """
    Builds a dependency graph from adjacency.json and resolves chains.
    """

    def __init__(self, service: str, adj: dict, step2: dict):
        self.service = service
        # op → list of entities it produces
        self.op_produces: dict[str, list[str]] = adj.get("op_produces", {})
        # op → list of entity IDs it consumes
        self.op_consumes: dict[str, list[str]] = adj.get("op_consumes", {})
        # ops that are truly independent (only need compartment_id)
        adj_indep = set(adj.get("independent_ops", []))

        # Build set of independent ops from step2 required_params + adjacency
        ops_meta = step2.get("operations", {})
        self.op_kind: dict[str, str] = {}
        self.is_independent: dict[str, bool] = {}
        for op, meta in ops_meta.items():
            kind = meta.get("kind", "read_get")
            self.op_kind[op] = kind
            rp = meta.get("required_params", [])
            # Independent: no required_params beyond compartmentId
            comp_like = {"CompartmentId", "TenancyId", "RegionId", "Namespace"}
            non_comp = [p for p in rp if p not in comp_like]
            self.is_independent[op] = len(non_comp) == 0

        # For ops not in step2, derive from adjacency
        for op in self.op_produces:
            if op not in self.op_kind:
                if op.startswith("list_"):
                    self.op_kind[op] = "read_list"
                elif op.startswith("get_") or op.startswith("describe_"):
                    self.op_kind[op] = "read_get"
                else:
                    self.op_kind[op] = "read_get"
            if op not in self.is_independent:
                consumes = self.op_consumes.get(op, [])
                self.is_independent[op] = (
                    op in adj_indep or _is_compartment_only(consumes)
                )

        # entity → ops that produce it  (reversed index)
        self.entity_producers: dict[str, list[str]] = defaultdict(list)
        for op, entities in self.op_produces.items():
            for e in entities:
                self.entity_producers[e].append(op)

    def producing_ops_for_field(self, field_name: str) -> list[str]:
        """
        Return ops that produce the given field_name.
        Tries entity lookup in adjacency first, then prefix-match heuristic.
        """
        entity = _field_to_entity(field_name, self.service)
        candidates = self.entity_producers.get(entity, [])
        if candidates:
            return candidates

        # Heuristic: match by field suffix in any entity key
        suffix = field_name.split(".")[-1] if "." in field_name else field_name
        resource = field_name.split(".")[0] if "." in field_name else ""
        matches = []
        for ent, ops in self.entity_producers.items():
            ent_suffix = ent.split(".")[-1]
            ent_resource = ent.replace(f"oci.{self.service}.", "").split(".")[0]
            if ent_suffix == suffix and (not resource or ent_resource == resource):
                matches.extend(ops)
        return list(dict.fromkeys(matches))  # deduplicate preserving order

    def best_producing_op(self, field_name: str) -> str:
        """Pick the single best producing op for a field."""
        ops = self.producing_ops_for_field(field_name)
        if not ops:
            # Guess from field name: resource.field → list_{resource}s
            resource = field_name.split(".")[0] if "." in field_name else ""
            return f"list_{resource}s" if resource else "unknown"

        # Prefer list_ > get_ for independence; prefer ops that match resource
        resource = field_name.split(".")[0] if "." in field_name else ""

        def score(op: str) -> int:
            s = 0
            if op.startswith("list_"):
                s += 10
            if resource and resource.replace("_", "") in op.replace("_", ""):
                s += 5
            if self.is_independent.get(op, False):
                s += 3
            return s

        return max(ops, key=score)

    def chain_for_op(self, op: str, max_depth: int = 5) -> list[str]:
        """
        BFS to find the shortest chain of ops from an independent root → op.
        Returns list like ['list_instances', 'get_instance'].
        If op is already independent, returns [op].
        """
        if self.is_independent.get(op, False):
            return [op]

        # BFS: find shortest path from any independent op to this op
        # State: current op, path taken so far
        queue: deque[tuple[str, list[str]]] = deque()

        # Find ops that produce the IDs consumed by 'op'
        consumed_ids = self.op_consumes.get(op, [])
        for id_entity in consumed_ids:
            for parent_op in self.entity_producers.get(id_entity, []):
                queue.append((parent_op, [parent_op, op]))

        if not queue:
            return [op]  # can't resolve, return just the op

        visited = set()
        best: list[str] = []

        while queue:
            current_op, path = queue.popleft()
            if current_op in visited or len(path) > max_depth:
                continue
            visited.add(current_op)

            if self.is_independent.get(current_op, False):
                if not best or len(path) < len(best):
                    best = path
                continue  # found a root

            # Go further up
            parent_consumed = self.op_consumes.get(current_op, [])
            for id_entity in parent_consumed:
                for parent_op in self.entity_producers.get(id_entity, []):
                    if parent_op not in visited:
                        queue.append((parent_op, [parent_op] + path))

        return best if best else [op]


# ── Field row builder ────────────────────────────────────────────────────────────

def _operators_for_type(ftype: str, possible_values: list | None,
                         field_name: str) -> tuple:
    """
    Returns (operators, no_value_ops, select_ops, manual_ops,
             value_req_type, pv_str, src, npv)
    """
    is_enum = bool(possible_values)
    npv = len(possible_values) if possible_values else 0
    pv_str = ", ".join(possible_values) if possible_values else ""

    # Tag-style fields
    if "tags" in field_name.lower():
        return (
            _OPS_TAG, _NO_VAL_TAG, "", "",
            "No value required", pv_str,
            "oci_deps" if is_enum else "", npv
        )

    # OCID / ID fields
    if field_name in ("ocid", "compartment_id") or field_name.endswith("_id"):
        return (
            _OPS_EXIST, _NO_VAL_EXIST, "", "equals, not_equals",
            "No value or manual input", pv_str,
            "oci_deps" if is_enum else "", npv
        )

    if ftype == "boolean":
        return (
            _OPS_BOOL, "", "", _OPS_BOOL,
            "Manual input only", pv_str,
            "oci_deps" if is_enum else "", npv
        )

    if ftype == "array":
        base_ops = _OPS_ARR
        return (
            base_ops, _NO_VAL_NOTEMPTY, "", "contains, equals, in, not_equals",
            "No value or manual input", pv_str,
            "oci_deps" if is_enum else "", npv
        )

    if ftype == "object":
        return (
            _OPS_OBJ, "", "", _OPS_OBJ,
            "Manual input only", pv_str,
            "oci_deps" if is_enum else "", npv
        )

    # string / integer / default
    if is_enum:
        return (
            "equals, in, not_equals", "", "equals, in, not_equals", "",
            "Select from list only", pv_str,
            "oci_deps", npv
        )

    if "time" in field_name or "date" in field_name:
        return (
            "contains, equals, exists, in, not_equals", "exists",
            "", "contains, equals, in, not_equals",
            "No value or manual input", pv_str, "", npv
        )

    return (
        _OPS_STR, "", "", _OPS_STR,
        "Manual input only", pv_str, "", npv
    )


def build_rows(service: str, graph: DependencyGraph,
               direct_vars: dict) -> list[dict]:
    fields = direct_vars.get("fields", {})
    rows = []

    for field_name, finfo in fields.items():
        ftype     = finfo.get("type", "string")
        pv        = finfo.get("possible_values") or []
        is_enum   = bool(pv)

        (ops, no_val, sel, manual,
         val_req, pv_str, src, npv) = _operators_for_type(ftype, pv, field_name)

        # ── Dependency chain ─────────────────────────────────────────────────
        best_op   = graph.best_producing_op(field_name)
        op_kind   = graph.op_kind.get(best_op, "read_get")
        is_indep  = graph.is_independent.get(best_op, False)
        chain     = graph.chain_for_op(best_op)
        chain_str = " → ".join(chain)

        consumed  = graph.op_consumes.get(best_op, [])
        req_ids   = " | ".join(
            c for c in consumed
            if not _is_compartment_only([c])
        )

        rows.append({
            "service":               service,
            "field_name":            field_name,
            "field_type":            ftype,
            "is_enum":               "Yes" if is_enum else "No",
            "operators":             ops,
            "operators_no_value":    no_val,
            "operators_select_list": sel,
            "operators_manual_input": manual,
            "value_requirement_type": val_req,
            "possible_values":       pv_str,
            "values_source":         src,
            "num_possible_values":   npv,
            # ── new ──────────────────────────────────────────────────────────
            "producing_op":          best_op,
            "op_kind":               op_kind,
            "is_independent":        "Yes" if is_indep else "No",
            "dependency_chain":      chain_str,
            "required_ids":          req_ids,
        })

    return rows


# ── Main ──────────────────────────────────────────────────────────────────────

def process_service(svc_dir: Path) -> list[dict]:
    service = svc_dir.name

    dv_path   = svc_dir / "direct_vars.json"
    adj_path  = svc_dir / "adjacency.json"
    step2_path = svc_dir / "step2_read_operation_registry.json"

    if not dv_path.exists():
        return []

    direct_vars = json.loads(dv_path.read_text())
    adj         = json.loads(adj_path.read_text()) if adj_path.exists() else {}
    step2       = json.loads(step2_path.read_text()) if step2_path.exists() else {}

    graph = DependencyGraph(service, adj, step2)
    return build_rows(service, graph, direct_vars)


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    services = sorted(p for p in BASE.iterdir() if p.is_dir())
    print(f"Processing {len(services)} OCI services...\n")

    grand_total = 0
    for svc_dir in services:
        rows = process_service(svc_dir)
        if not rows:
            continue
        out_path = svc_dir / "field_operator_value_table.csv"
        write_csv(out_path, rows)
        grand_total += len(rows)
        # show dependency chain sample for first row with a non-trivial chain
        sample = next(
            (r for r in rows if " → " in r["dependency_chain"]), None
        ) or rows[0]
        print(
            f"  [{svc_dir.name}] {len(rows)} fields  "
            f"sample chain: {sample['field_name']} → "
            f"{sample['dependency_chain']}"
        )

    print(f"\n{'='*70}")
    print(f"DONE — {grand_total} field rows written across {len(services)} services")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()
