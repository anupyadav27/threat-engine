#!/usr/bin/env python3
"""
Generate OCI field catalog matching the GCP master format.

Outputs:
  catalog/discovery_generator/oci/{service}/field_operator_value_table.csv  (per-service, GCP format)
  catalog/discovery_generator/oci/oci_master_field_catalog.csv              (combined)

GCP format columns:
  csp, service, field_path, item_var_path, field_type, is_id,
  producing_op, op_kind, is_independent, root_op,
  chain_ops, chain_length, hop_distance, chain_ops_with_fields,
  operators, operators_no_value, python_call, http_path

Sources per service (catalog/discovery_generator/oci/{service}/):
  step2_read_operation_registry.json  — ops, python_method, output_fields, required_params
  adjacency.json                      — op_consumes, op_produces, independent_ops
  direct_vars.json                    — fields with type, operators, possible_values
"""

from __future__ import annotations
import csv, json, re
from collections import defaultdict, deque
from pathlib import Path

BASE     = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/oci")
MASTER   = BASE / "oci_master_field_catalog.csv"

GCP_COLS = [
    "csp", "service", "field_path", "item_var_path",
    "field_type", "is_id",
    "producing_op", "op_kind", "is_independent",
    "root_op", "chain_ops", "chain_length", "hop_distance",
    "chain_ops_with_fields",
    "operators", "operators_no_value",
    "python_call", "http_path",
]

# Params that are always available (don't create a real dependency)
# OCI step2 files use both camelCase and PascalCase for the same params
ROOT_PARAMS = {
    "compartmentId", "compartment_id", "CompartmentId",
    "tenancyId",     "tenancy_id",     "TenancyId",
    "regionId",      "region",         "RegionId",
    "namespaceName", "namespace_name", "NamespaceName",
    "Namespace",
}

# ── Operator logic (same as before) ───────────────────────────────────────────
def _operators(ftype: str, field: str, pv: list | None) -> tuple[str, str]:
    is_enum = bool(pv)
    if "tags" in field.lower():
        return "exists, not_empty", "exists, not_empty"
    if field in ("ocid", "compartment_id") or field.endswith("_id"):
        return "equals, exists, not_equals", "exists"
    if ftype == "boolean":
        return "equals, not_equals", ""
    if ftype == "array":
        return "contains, equals, in, not_empty, not_equals", "not_empty"
    if ftype == "object":
        return "contains, equals, in, not_equals", ""
    if is_enum:
        return "equals, in, not_equals", ""
    if "time" in field or "date" in field:
        return "contains, equals, exists, in, not_equals", "exists"
    return "contains, equals, in, not_equals", ""


# ── OCI Python SDK client name from service ───────────────────────────────────
def _client_name(service: str) -> str:
    """DatabaseClient, IdentityClient, ObjectStorageClient, etc."""
    # Special cases
    _overrides = {
        "virtual_network": "VirtualNetworkClient",
        "object_storage":  "ObjectStorageClient",
        "key_management":  "KmsVaultClient",
        "block_storage":   "BlockstorageClient",
        "container_engine": "ContainerEngineClient",
        "data_science":    "DataScienceClient",
        "cloud_guard":     "CloudGuardClient",
        "data_catalog":    "DataCatalogClient",
        "data_flow":       "DataFlowClient",
        "data_safe":       "DataSafeClient",
        "data_integration": "DataIntegrationClient",
    }
    if service in _overrides:
        return _overrides[service]
    return "".join(w.title() for w in service.split("_")) + "Client"


def _python_call(service: str, op: str, required_params: list[str]) -> str:
    """
    Build the OCI Python SDK call string.
    e.g. DatabaseClient().list_autonomous_databases(compartment_id=compartment_id).data
    """
    client = _client_name(service)
    params = []
    for p in required_params:
        snake = re.sub(r'(?<!^)(?=[A-Z])', '_', p).lower()
        params.append(f"{snake}={snake}")
    # Always include compartment_id for list ops if not already there
    if not params or all("compartment" not in p for p in params):
        params = ["compartment_id=compartment_id"] + params
    param_str = ", ".join(params)
    return f"{client}().{op}({param_str}).data"


def _http_path(service: str, op: str) -> str:
    """
    Approximate OCI REST path from op name.
    list_autonomous_databases → /20160918/autonomousDatabases
    get_autonomous_database   → /20160918/autonomousDatabases/{autonomousDatabaseId}
    """
    # OCI API version dates by service (approximate)
    _versions = {
        "database":         "20160918",
        "identity":         "20160918",
        "compute":          "20160918",
        "virtual_network":  "20160918",
        "object_storage":   "20160918",
        "block_storage":    "20160918",
        "key_management":   "20180608",
        "container_engine": "20180222",
        "functions":        "20181201",
        "events":           "20181201",
        "streaming":        "20180418",
        "monitoring":       "20180401",
        "logging":          "20200531",
        "analytics":        "20190331",
        "dns":              "20180115",
        "load_balancer":    "20170115",
        "mysql":            "20190415",
        "nosql":            "20190828",
        "data_science":     "20190101",
        "data_flow":        "20200129",
        "data_catalog":     "20190325",
        "data_safe":        "20181201",
        "network_firewall": "20211001",
        "cloud_guard":      "20200131",
        "devops":           "20210630",
        "artifacts":        "20160918",
        "bds":              "20190101",
        "redis":            "20220315",
        "queue":            "20210201",
        "waf":              "20210930",
    }
    ver = _versions.get(service, "20160918")

    # Strip action prefix
    parts = op.split("_", 1)
    action  = parts[0] if parts else "list"
    rest    = parts[1] if len(parts) > 1 else ""

    # Convert snake_case → camelCase resource name
    words   = rest.split("_")
    camel   = words[0] + "".join(w.title() for w in words[1:]) if words else rest
    # Pluralize for list, singularize for get
    if action == "list":
        resource = camel + "s" if not camel.endswith("s") else camel
        return f"/{ver}/{resource}"
    elif action in ("get", "describe"):
        resource = camel + "s" if not camel.endswith("s") else camel
        id_param = "".join(w.title() for w in words) + "Id"
        return f"/{ver}/{resource}/{{{id_param}}}"
    return f"/{ver}/{camel}"


# ── Dependency graph ───────────────────────────────────────────────────────────

class DepGraph:
    def __init__(self, service: str, adj: dict, step2: dict):
        self.service = service
        self.op_produces: dict[str, list[str]] = adj.get("op_produces", {})
        self.op_consumes: dict[str, list[str]] = adj.get("op_consumes",  {})

        self.op_kind:        dict[str, str]  = {}
        self.is_independent: dict[str, bool] = {}
        self.required_params: dict[str, list[str]] = {}
        self.python_method:  dict[str, str]  = {}
        self.output_fields:  dict[str, dict] = {}   # op → {field: {type,path,entity}}

        for op, meta in step2.get("operations", {}).items():
            self.op_kind[op]         = meta.get("kind", "read_get")
            self.python_method[op]   = meta.get("python_method", op)
            self.output_fields[op]   = meta.get("output_fields", {})
            rp = meta.get("required_params", [])
            self.required_params[op] = rp
            # Independence = only compartment/tenancy/region-level params required
            non_root = [p for p in rp if p not in ROOT_PARAMS]
            self.is_independent[op]  = (len(non_root) == 0)

        # Fill in ops seen in adjacency but not step2
        for op in list(self.op_produces) + list(self.op_consumes):
            if op not in self.op_kind:
                self.op_kind[op]         = "read_list" if op.startswith("list_") else "read_get"
                self.required_params[op] = []
                consumes = self.op_consumes.get(op, [])
                self.is_independent[op]  = _is_root_only(consumes)

        # entity → ops that produce it (from adjacency)
        self.entity_producers: dict[str, list[str]] = defaultdict(list)
        for op, entities in self.op_produces.items():
            for e in entities:
                self.entity_producers[e].append(op)

        # ── Infer ID production from list ops ────────────────────────────────
        # Derive resource name directly from op name (avoids entity-name typos).
        # list_autonomous_databases → autonomous_database → oci.db.autonomous_database_id
        # list_users  → user → oci.identity.user_id
        # list_policies → policy → oci.identity.policy_id
        for op in list(self.op_produces) + list(self.op_consumes):
            if not op.startswith("list_"):
                continue
            resource = _singularize(op[len("list_"):])
            id_entity = f"oci.{service}.{resource}_id"
            if op not in self.entity_producers[id_entity]:
                self.entity_producers[id_entity].append(op)

        # Also infer from step2 required_params: UserId → oci.{service}.user_id
        # so get ops can be matched to their ID-producing list ops
        for op, rp in self.required_params.items():
            if op not in self.op_consumes and rp:
                # Build synthetic op_consumes entries from required_params
                non_root = [p for p in rp if p not in ROOT_PARAMS]
                if non_root and op not in self.op_consumes:
                    inferred = []
                    for p in non_root:
                        # UserId → user_id → oci.service.user_id
                        snake = re.sub(r'(?<!^)(?=[A-Z])', '_', p).lower()
                        inferred.append(f"oci.{service}.{snake}")
                    self.op_consumes[op] = inferred

    def _producers_for_entity(self, entity: str) -> list[str]:
        """
        Look up producers for an entity, with fuzzy normalization fallback.
        Adjacency may store 'governanceinstance_id' but we infer 'governance_instance_id'.
        Normalize by stripping underscores for comparison.
        """
        # Exact match first
        hits = self.entity_producers.get(entity, [])
        if hits:
            return hits
        # Normalized match: strip underscores from the final segment
        norm = entity.replace("_", "")
        for key, ops_list in self.entity_producers.items():
            if key.replace("_", "") == norm:
                return ops_list
        return []

    def chain_for_op(self, target_op: str, max_depth: int = 6) -> list[str]:
        """BFS: shortest path from an independent root op → target_op."""
        if self.is_independent.get(target_op, True):
            return [target_op]

        # Find ops that produce what target_op consumes
        consumed = self.op_consumes.get(target_op, [])
        queue: deque[tuple[str, list[str]]] = deque()
        for entity in consumed:
            for parent in self._producers_for_entity(entity):
                queue.append((parent, [parent, target_op]))

        if not queue:
            return [target_op]

        visited: set[str] = set()
        best: list[str] = []

        while queue:
            cur, path = queue.popleft()
            key = (cur, tuple(path))
            if key in visited or len(path) > max_depth:
                continue
            visited.add(key)

            if self.is_independent.get(cur, True):
                if not best or len(path) < len(best):
                    best = path
                continue

            for entity in self.op_consumes.get(cur, []):
                for parent in self._producers_for_entity(entity):
                    if parent != cur:
                        queue.append((parent, [parent] + path))

        return best if best else [target_op]

    def fields_for_op(self, op: str) -> list[str]:
        """Return field names produced by op (from output_fields or entity names)."""
        # From step2 output_fields — handle both list and dict format
        of = self.output_fields.get(op, {})
        if of:
            if isinstance(of, list):
                return list(of)
            return list(of.keys())
        # From adjacency entities
        ents = self.op_produces.get(op, [])
        fields = []
        prefix = f"oci.{self.service}."
        for e in ents:
            if e.startswith(prefix):
                rest = e[len(prefix):]
                if "." in rest:          # resource.field form
                    fields.append(rest)
            elif e == "oci.ocid":
                fields.append("ocid")
        return fields


def _singularize(plural: str) -> str:
    """
    Convert a plural snake_case resource name to singular.
    autonomous_databases → autonomous_database
    users → user, policies → policy, db_homes → db_home
    """
    if plural.endswith("ies"):
        return plural[:-3] + "y"
    if plural.endswith("sses") or plural.endswith("xes") or plural.endswith("shes"):
        return plural[:-2]     # addresses → address
    if plural.endswith("ses"):
        return plural[:-1]     # databases → database
    if plural.endswith("s") and not plural.endswith("ss"):
        return plural[:-1]
    return plural


def _is_root_only(consumes: list[str]) -> bool:
    return all(
        c in ("oci.compartment_id", "oci.tenancy_id", "oci.region",
              "oci.namespace_name")
        for c in consumes
    )


# ── Producing op for a field ───────────────────────────────────────────────────

def _best_producing_op(field_name: str, service: str, graph: DepGraph) -> str:
    """
    Find which op best produces this field.
    Checks: adjacency op_produces entity match, then step2 output_fields, then heuristic.
    """
    # 1. Match via adjacency entity
    entity_full = f"oci.{service}.{field_name}"
    candidates  = graph.entity_producers.get(entity_full, [])
    if not candidates and field_name == "ocid":
        candidates = [op for op in graph.op_produces if op.startswith("list_")][:1]

    # 2. Match via step2 output_fields (field name as key)
    if not candidates:
        bare_field = field_name.split(".")[-1] if "." in field_name else field_name
        resource   = field_name.split(".")[0]  if "." in field_name else ""
        for op, of in graph.output_fields.items():
            if bare_field in of:
                candidates.append(op)

    # 3. Heuristic: resource prefix → list_{resource}s
    if not candidates and "." in field_name:
        resource = field_name.split(".")[0]
        guesses  = [
            f"list_{resource}s",
            f"list_{resource}",
            f"get_{resource}",
        ]
        for g in guesses:
            if g in graph.op_kind:
                candidates.append(g)
                break

    if not candidates:
        return f"list_{field_name.split('.')[0]}s" if "." in field_name else "unknown"

    # Prefer list_ > get_ (more independent)
    def score(op: str) -> int:
        s = 0
        if op.startswith("list_"):
            s += 10
        if graph.is_independent.get(op, False):
            s += 5
        resource = field_name.split(".")[0] if "." in field_name else field_name
        if resource.replace("_", "") in op.replace("_", ""):
            s += 3
        return s

    return max(set(candidates), key=score)


# ── chain_ops_with_fields builder ─────────────────────────────────────────────

def _chain_with_fields(chain: list[str], service: str, graph: DepGraph) -> str:
    """
    Format: oci.svc.op1[f1|f2|f3] → oci.svc.op2[f4|f5]
    """
    parts = []
    for op in chain:
        fields = graph.fields_for_op(op)
        # Keep max 8 fields in the display to avoid massive strings
        shown  = fields[:8]
        fstr   = "|".join(shown)
        if len(fields) > 8:
            fstr += f"|... +{len(fields)-8}"
        parts.append(f"oci.{service}.{op}[{fstr}]")
    return " → ".join(parts)


# ── Main row builder ───────────────────────────────────────────────────────────

def build_rows(service: str, graph: DepGraph, direct_vars: dict) -> list[dict]:
    fields = direct_vars.get("fields", {})
    rows: list[dict] = []

    for field_name, finfo in fields.items():
        ftype = finfo.get("type", "string")
        pv    = finfo.get("possible_values") or []
        is_id = "Yes" if (
            field_name in ("ocid", "compartment_id") or
            (field_name.endswith("_id") and "." not in field_name)
        ) else "No"

        ops_str, no_val_str = _operators(ftype, field_name, pv)

        # ── Producing op & chain ─────────────────────────────────────────────
        prod_op   = _best_producing_op(field_name, service, graph)
        chain     = graph.chain_for_op(prod_op)
        root_op   = chain[0] if chain else prod_op

        chain_fq  = " → ".join(f"oci.{service}.{op}" for op in chain)
        root_fq   = f"oci.{service}.{root_op}"
        prod_fq   = f"oci.{service}.{prod_op}"
        chain_len = len(chain)
        hop_dist  = chain_len - 1

        chain_with_f = _chain_with_fields(chain, service, graph)

        op_kind   = graph.op_kind.get(prod_op, "read_get")
        is_indep  = "Yes" if graph.is_independent.get(prod_op, False) else "No"

        # ── Python call & HTTP path ──────────────────────────────────────────
        rp = graph.required_params.get(prod_op, [])
        py_call   = _python_call(service, prod_op, rp)
        http_path = _http_path(service, prod_op)

        rows.append({
            "csp":                 "oci",
            "service":             service,
            "field_path":          field_name,
            "item_var_path":       f"item.{field_name}",
            "field_type":          ftype,
            "is_id":               is_id,
            "producing_op":        prod_fq,
            "op_kind":             op_kind,
            "is_independent":      is_indep,
            "root_op":             root_fq,
            "chain_ops":           chain_fq,
            "chain_length":        chain_len,
            "hop_distance":        hop_dist,
            "chain_ops_with_fields": chain_with_f,
            "operators":           ops_str,
            "operators_no_value":  no_val_str,
            "python_call":         py_call,
            "http_path":           http_path,
        })

    return rows


# ── CSV I/O ───────────────────────────────────────────────────────────────────

def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=GCP_COLS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    services = sorted(p for p in BASE.iterdir() if p.is_dir())
    print(f"Processing {len(services)} OCI services...\n")

    all_rows: list[dict] = []
    total_fields = 0

    for svc_dir in services:
        service = svc_dir.name
        dv_path    = svc_dir / "direct_vars.json"
        adj_path   = svc_dir / "adjacency.json"
        step2_path = svc_dir / "step2_read_operation_registry.json"

        if not dv_path.exists():
            continue

        dv    = json.loads(dv_path.read_text())
        adj   = json.loads(adj_path.read_text())   if adj_path.exists()   else {}
        step2 = json.loads(step2_path.read_text()) if step2_path.exists() else {}

        graph = DepGraph(service, adj, step2)
        rows  = build_rows(service, graph, dv)

        if not rows:
            continue

        # Per-service CSV
        write_csv(svc_dir / "field_operator_value_table.csv", rows)
        all_rows.extend(rows)
        total_fields += len(rows)

        # Sample chain for display
        sample = next(
            (r for r in rows if r["chain_length"] > 1), rows[0]
        )
        print(
            f"  [{service}] {len(rows):4d} fields  "
            f"sample: {sample['field_path']} → {sample['chain_ops']}"
        )

    # Combined master catalog
    write_csv(MASTER, all_rows)

    print(f"\n{'='*72}")
    print(f"OCI MASTER FIELD CATALOG COMPLETE")
    print(f"{'='*72}")
    print(f"  Services processed   : {len(services)}")
    print(f"  Total field rows     : {total_fields}")
    print(f"  Master catalog       : {MASTER.relative_to(BASE.parent.parent)}")
    print(f"  Per-service CSVs     : updated in each service directory")

    # Stats
    indep  = sum(1 for r in all_rows if r["is_independent"] == "Yes")
    chains = {r["chain_length"] for r in all_rows}
    print(f"\n  Independent fields   : {indep:,} / {total_fields:,}")
    print(f"  Max chain length     : {max(chains)}")
    print(f"  Chain length dist    : "
          + ", ".join(f"len{k}={sum(1 for r in all_rows if r['chain_length']==k)}"
                      for k in sorted(chains)))


if __name__ == "__main__":
    main()
