#!/usr/bin/env python3
"""
Generate k8s_<service>_finalized_discovery_v1.yaml for every k8s service
that has active rule checks.

Each file merges two operation sources:
  1. Rule-check ops   — producing_op for every active rule's var field
  2. Identifier ops   — root_ops/enrich_ops from resource_inventory_identifier table
Duplicate operations are collapsed.

Output format mirrors:
  catalog/discovery_generator/aws/access-analyzer/step6_access-analyzer.discovery.yaml

Files written to:
  catalog/discovery_generator/k8s/<service>/k8s_<service>_finalized_discovery_v1.yaml
"""

import csv
import json
import os
import psycopg2
import yaml
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
K8S_DIR      = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/k8s")
CHECKS_ROOT  = Path("/Users/apple/Desktop/threat-engine/catalog/rule/k8s_rule_check")
CATALOG_CSV  = K8S_DIR / "k8s_master_field_catalog.csv"

# ── DB connection ─────────────────────────────────────────────────────────────
DB_CFG = dict(
    host="postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com",
    port=5432, dbname="threat_engine_inventory",
    user="postgres", password="jtv2BkJF8qoFtAKP", sslmode="require",
)

# ── api_version → (client_var, api_class, http_prefix) ───────────────────────
API_VERSION_META = {
    "v1":                                   ("core_v1_api",                  "CoreV1Api",                       "/api/v1"),
    "apps/v1":                              ("apps_v1_api",                  "AppsV1Api",                       "/apis/apps/v1"),
    "batch/v1":                             ("batch_v1_api",                 "BatchV1Api",                      "/apis/batch/v1"),
    "batch/v1beta1":                        ("batch_v1beta1_api",            "BatchV1beta1Api",                 "/apis/batch/v1beta1"),
    "rbac.authorization.k8s.io/v1":         ("rbac_authorization_v1_api",    "RbacAuthorizationV1Api",          "/apis/rbac.authorization.k8s.io/v1"),
    "networking.k8s.io/v1":                 ("networking_v1_api",            "NetworkingV1Api",                 "/apis/networking.k8s.io/v1"),
    "storage.k8s.io/v1":                    ("storage_v1_api",               "StorageV1Api",                    "/apis/storage.k8s.io/v1"),
    "autoscaling/v1":                       ("autoscaling_v1_api",           "AutoscalingV1Api",                "/apis/autoscaling/v1"),
    "autoscaling/v2":                       ("autoscaling_v2_api",           "AutoscalingV2Api",                "/apis/autoscaling/v2"),
    "policy/v1":                            ("policy_v1_api",                "PolicyV1Api",                     "/apis/policy/v1"),
    "policy/v1beta1":                       ("policy_v1beta1_api",           "PolicyV1beta1Api",                "/apis/policy/v1beta1"),
    "certificates.k8s.io/v1":              ("certificates_v1_api",          "CertificatesV1Api",               "/apis/certificates.k8s.io/v1"),
    "admissionregistration.k8s.io/v1":     ("admissionregistration_v1_api", "AdmissionregistrationV1Api",      "/apis/admissionregistration.k8s.io/v1"),
    "apiregistration.k8s.io/v1":           ("apiregistration_v1_api",       "ApiregistrationV1Api",            "/apis/apiregistration.k8s.io/v1"),
    "scheduling.k8s.io/v1":                ("scheduling_v1_api",            "SchedulingV1Api",                 "/apis/scheduling.k8s.io/v1"),
}

# Namespaced resources (affect method naming and params)
NAMESPACED = {
    "pod", "deployment", "daemonset", "statefulset", "replicaset",
    "replicationcontroller", "job", "cronjob", "configmap", "secret",
    "service", "serviceaccount", "persistentvolumeclaim", "ingress",
    "networkpolicy", "role", "rolebinding", "horizontalpodautoscaler",
    "poddisruptionbudget", "resourcequota", "limitrange", "podtemplate", "event",
}

# Resource plural map
RESOURCE_PLURAL = {
    "pod": "pods", "deployment": "deployments", "daemonset": "daemonsets",
    "statefulset": "statefulsets", "replicaset": "replicasets",
    "replicationcontroller": "replicationcontrollers",
    "job": "jobs", "cronjob": "cronjobs", "configmap": "configmaps",
    "secret": "secrets", "service": "services", "serviceaccount": "serviceaccounts",
    "namespace": "namespaces", "node": "nodes",
    "persistentvolume": "persistentvolumes",
    "persistentvolumeclaim": "persistentvolumeclaims",
    "storageclass": "storageclasses", "ingress": "ingresses",
    "networkpolicy": "networkpolicies", "role": "roles",
    "rolebinding": "rolebindings", "clusterrole": "clusterroles",
    "clusterrolebinding": "clusterrolebindings",
    "horizontalpodautoscaler": "horizontalpodautoscalers",
    "poddisruptionbudget": "poddisruptionbudgets",
    "priorityclass": "priorityclasses", "resourcequota": "resourcequotas",
    "limitrange": "limitranges", "podtemplate": "podtemplates",
    "event": "events",
}

# ── Helpers ───────────────────────────────────────────────────────────────────
def _load_json(path: Path) -> dict:
    if path.exists():
        with open(path) as f:
            return json.load(f)
    return {}


def _load_step1(svc_dir: Path) -> dict:
    return _load_json(svc_dir / "step1_api_driven_registry.json")


def _load_step2(svc_dir: Path) -> dict:
    return _load_json(svc_dir / "step2_read_operation_registry.json")


def _load_step3(svc_dir: Path) -> dict:
    return _load_json(svc_dir / "step3_read_operation_dependency_chain.json")


def _api_meta(api_version: str) -> tuple:
    return API_VERSION_META.get(api_version, ("core_v1_api", "CoreV1Api", "/api/v1"))


# ── K8s compound-name service → actual API method name fragment ───────────────
# For services whose name doesn't directly translate to a method name via
# simple concatenation (e.g. "clusterrole" → "cluster_role" in K8s client)
K8S_API_NAME = {
    "clusterrole":        "cluster_role",
    "clusterrolebinding": "cluster_role_binding",
    "storageclass":       "storage_class",
    "horizontalpodautoscaler": "horizontal_pod_autoscaler",
    "poddisruptionbudget": "pod_disruption_budget",
    "networkpolicy":      "network_policy",
    "serviceaccount":     "service_account",
    "persistentvolume":   "persistent_volume",
    "persistentvolumeclaim": "persistent_volume_claim",
    "replicaset":         "replica_set",
    "statefulset":        "stateful_set",
    "daemonset":          "daemon_set",
    "limitrange":         "limit_range",
    "resourcequota":      "resource_quota",
    "podtemplate":        "pod_template",
    # Additional compound names whose Python client form differs from the resource name
    "configmap":          "config_map",
    "cronjob":            "cron_job",
    "rolebinding":        "role_binding",
}


def _resolve_method_name(op_name: str, svc: str, step2_ops: dict) -> str:
    """
    Resolve a generic op_name (list / get / list_for_all_namespaces) to the
    actual Python client method name, using step2 data or K8s naming conventions.
    """
    # step2 has it directly
    step2_op = step2_ops.get(op_name, {})
    py = step2_op.get("python_method", "")
    if py and py not in ("list", "get"):
        return py

    # Use canonical K8s API name (handles compound service names)
    api_name  = K8S_API_NAME.get(svc, svc)
    namespaced = svc in NAMESPACED

    if op_name in ("list", "list_for_all_namespaces"):
        if namespaced:
            return f"list_{api_name}_for_all_namespaces"
        return f"list_{api_name}"
    if op_name == "get":
        if namespaced:
            return f"read_namespaced_{api_name}"
        return f"read_{api_name}"
    # Custom / already fully qualified
    return op_name


def _build_params(op_name: str, svc: str, step2_ops: dict, parent_op: str | None) -> dict:
    """Build params dict for the calls section."""
    namespaced = svc in NAMESPACED
    step2_op   = step2_ops.get(op_name, {})
    req_params = step2_op.get("required_params", [])

    params = {}
    if parent_op:
        # Dependent op: pull identifier from parent item
        params["name"] = "{{ item.metadata.name }}"
        if namespaced:
            params["namespace"] = "{{ item.metadata.namespace }}"
    elif req_params:
        for p in req_params:
            # req_params entries may be str or dict
            param_name = p if isinstance(p, str) else p.get("name", str(p))
            params[param_name] = f"{{{{ {param_name} }}}}"

    return params


def _emit_block(op_name: str, svc: str) -> dict:
    """Build the emit block."""
    is_list = "list" in op_name.lower() or op_name == "list"
    if is_list:
        return {"as": "item", "items_for": "{{ response.items }}"}
    else:
        # get op: emit as single item dict
        return {"as": "item", "item": {svc: "{{ response }}"}}


# ── Load catalog index ────────────────────────────────────────────────────────
def load_catalog_ops() -> dict[str, dict[str, str]]:
    """Returns {service: {op_name: {python_call, http_path, ...}}}."""
    ops: dict[str, dict] = {}
    with open(CATALOG_CSV) as f:
        for row in csv.DictReader(f):
            svc = row["service"]
            prod_op = row["producing_op"]              # k8s.svc.op_name
            op_name = prod_op.split(".")[-1]
            if svc not in ops:
                ops[svc] = {}
            if op_name not in ops[svc]:
                ops[svc][op_name] = {
                    "producing_op": prod_op,
                    "python_call":  row["python_call"],
                    "http_path":    row["http_path"],
                    "is_independent": row["is_independent"],
                    "root_op":        row["root_op"],
                    "chain_ops":      row["chain_ops"],
                }
    return ops


def load_identifier_ops_from_catalog() -> dict[str, list[dict]]:
    """
    For each service, return the ops that produce is_id=Yes fields.
    Each entry: {op_name, producing_op, is_independent, root_op, chain_ops, python_call, http_path}

    Rules:
     - independent (list) ops: include as-is
     - dependent (get) ops: include BOTH root_op (list) AND the get op (with parent link)
    This gives the full chain needed to produce resource identifiers.
    """
    # (svc, op_name) → row  — prefer list (independent) rows over get rows for same op_name
    seen: dict[tuple, dict] = {}
    with open(CATALOG_CSV) as f:
        for row in csv.DictReader(f):
            if row["is_id"] != "Yes":
                continue
            svc     = row["service"]
            op_name = row["producing_op"].split(".")[-1]
            key     = (svc, op_name)
            existing = seen.get(key)
            if existing is None:
                seen[key] = row
            elif row["is_independent"] == "Yes" and existing["is_independent"] == "No":
                seen[key] = row   # prefer list over get

    # Build per-service result, expanding dependent ops into (root + dep) pairs
    result: dict[str, list[dict]] = {}
    for (svc, op_name), row in seen.items():
        is_indep   = row["is_independent"]
        prod_op    = row["producing_op"]
        root_op_str = row["root_op"]

        entry = {
            "op_name":       op_name,
            "producing_op":  prod_op,
            "is_independent": is_indep == "Yes",
            "python_call":   row["python_call"],
            "http_path":     row["http_path"],
            "parent_op":     None,
        }

        entries = result.setdefault(svc, [])

        if is_indep == "No":
            # For dependent ops: first ensure the root (list) op is present
            root_op_name = root_op_str.split(".")[-1]
            already_root = any(e["op_name"] == root_op_name and e["is_independent"] for e in entries)
            if not already_root:
                # Look up root op row from catalog for python_call/http_path
                root_row = seen.get((svc, root_op_name))
                if root_row:
                    entries.append({
                        "op_name":        root_op_name,
                        "producing_op":   root_row["producing_op"],
                        "is_independent": True,
                        "python_call":    root_row["python_call"],
                        "http_path":      root_row["http_path"],
                        "parent_op":      None,
                    })
            # Add the dependent get op, linked to the root list op
            entry["parent_op"]     = root_op_name
            entry["is_independent"] = False
            entries.append(entry)
        else:
            entries.append(entry)

    return result


# ── Collect active services + their needed ops ───────────────────────────────
def collect_rule_ops() -> dict[str, set[str]]:
    """
    Walk all active check YAMLs. For each active rule, collect
    the for_each op_name.
    Returns {service: {op_name, ...}}.
    """
    svc_ops: dict[str, set[str]] = {}
    for cf in sorted(CHECKS_ROOT.glob("*/*.checks.yaml")):
        if cf.name.startswith("1_"):
            continue
        with open(cf) as f:
            doc = yaml.safe_load(f)
        svc = doc.get("service", cf.parent.name)
        for check in doc.get("checks", []):
            fe = check.get("for_each", "")
            if not fe:
                continue
            # fe = k8s.<svc>.<op_name>
            parts = fe.split(".")
            if len(parts) >= 3:
                op_name = ".".join(parts[2:])   # handle multi-part like list_component_status
                svc_ops.setdefault(svc, set()).add(op_name)
    return svc_ops


def collect_identifier_ops(conn) -> dict[str, list[dict]]:
    """
    Query resource_inventory_identifier for k8s root_ops + enrich_ops.
    Returns {service: [op_dict, ...]}.
    """
    cur = conn.cursor()
    cur.execute(
        "SELECT service, root_ops, enrich_ops FROM resource_inventory_identifier "
        "WHERE csp='k8s' ORDER BY service"
    )
    result: dict[str, list[dict]] = {}
    for svc, root_ops, enrich_ops in cur.fetchall():
        ops = []
        for o in (root_ops or []):
            ops.append({
                "operation":    o.get("operation", ""),
                "python_method": o.get("python_method", ""),
                "independent":  o.get("independent", True),
                "kind":         o.get("kind", "read_list"),
                "source":       "identifier",
            })
        for o in (enrich_ops or []):
            ops.append({
                "operation":    o.get("operation", ""),
                "python_method": o.get("python_method", ""),
                "independent":  o.get("independent", False),
                "kind":         o.get("kind", "read_get"),
                "source":       "identifier_enrich",
            })
        if ops:
            result[svc] = ops
    return result


# ── Build discovery entries ───────────────────────────────────────────────────
def build_discovery_entries(
    svc: str,
    rule_ops: set[str],
    id_ops: list[dict],
    catalog_id_ops: list[dict],
    step2: dict,
    step3: dict,
    catalog_ops: dict,
) -> list[dict]:
    """
    Merge rule ops + DB identifier ops + catalog identifier-field ops
    → deduplicated list of discovery entries.

    Sources (priority order, lowest wins on dedup):
      1. rule_check  — for_each ops from active rule checks
      2. catalog_id  — ops producing is_id=Yes fields from master catalog
                       (includes full list→get chains for dependent ops)
      3. db_id       — root_ops/enrich_ops from resource_inventory_identifier DB
    """
    step2_ops = step2.get("operations", {})

    # Collect all ops: {op_name: metadata}
    all_ops: dict[str, dict] = {}

    def resolved_method(op_name: str) -> str:
        """Return the actual Python client method name for an op.
        For list/get ops we always use _resolve_method_name which applies
        K8S_API_NAME to correctly handle compound resource names (clusterrole,
        serviceaccount, etc.) and for_all_namespaces for namespaced resources.
        """
        pm = step2_ops.get(op_name, {}).get("python_method", op_name)
        # If step2 only has an abstract name, or just the op itself, use our resolver
        if pm in ("list", "get", op_name):
            pm = _resolve_method_name(op_name, svc, step2_ops)
        return pm or op_name

    # ── 1. Rule ops (from for_each values) ───────────────────────────────────
    for op_name in rule_ops:
        if op_name not in all_ops:
            s2 = step2_ops.get(op_name, {})
            all_ops[op_name] = {
                "independent":   s2.get("independent", True),
                "python_method": s2.get("python_method", op_name),
                "kind":          "read_list" if "list" in op_name else "read_get",
                "source":        "rule_check",
                "parent_op":     None,
            }

    # Build resolved-method → op_name dedup index
    method_to_op: dict[str, str] = {}
    for op_name in all_ops:
        pm = resolved_method(op_name)
        if pm:
            method_to_op[pm] = op_name

    # ── 2. Catalog identifier-field ops (from is_id=Yes rows in CSV) ─────────
    # These are the ops that produce resource identifier fields.
    # For dependent (get) ops: catalog_id_ops already contains BOTH the root list op
    # and the dependent op with parent_op set — add both in order.
    for cat_op in (catalog_id_ops or []):
        op_name  = cat_op["op_name"]
        py_call  = cat_op["python_call"]
        is_indep = cat_op["is_independent"]
        parent   = cat_op.get("parent_op")

        # Resolve via _resolve_method_name — the catalog python_call field has
        # a bug where the service name is appended as a suffix (e.g.
        # list_daemon_set_for_all_namespaces_workload). Never parse py_call directly.
        py_method = _resolve_method_name(op_name, svc, step2_ops)

        if py_method in method_to_op:
            continue   # already covered

        if op_name in all_ops:
            continue   # same op_name already present

        all_ops[op_name] = {
            "independent":   is_indep,
            "python_method": py_method,
            "kind":          "read_list" if is_indep else "read_get",
            "source":        "catalog_id",
            "parent_op":     parent,
        }
        method_to_op[py_method] = op_name

    # ── 3. DB identifier ops (root_ops/enrich_ops from inventory DB) ──────────
    for id_op in (id_ops or []):
        raw_op = id_op["operation"]
        if not raw_op:
            continue
        if raw_op.startswith(f"k8s.{svc}."):
            op_name = raw_op[len(f"k8s.{svc}."):]
        else:
            op_name = raw_op

        py_method = id_op.get("python_method", op_name)
        # Skip synthetic non-K8s operations (e.g. workload_resources, admission_resources)
        if py_method.endswith("_resources"):
            continue
        if py_method in method_to_op:
            continue
        if op_name in all_ops:
            continue

        all_ops[op_name] = {
            "independent":   id_op.get("independent", True),
            "python_method": py_method,
            "kind":          id_op.get("kind", "read_list"),
            "source":        "db_id",
            "parent_op":     None,
        }
        if py_method and py_method not in ("list", "get"):
            method_to_op[py_method] = op_name

    # 3. Resolve dependent ops from step3
    dep_parents: dict[str, str] = {}   # op_name → parent op_name
    for root in step3.get("roots", []):
        root_op = root["op"].split(".")[-1]
        for dep in root.get("dependents", []):
            dep_op = dep.get("op", "").split(".")[-1]
            if dep_op:
                dep_parents[dep_op] = root_op

    # Ensure dependent ops know their parent
    for op_name, meta in all_ops.items():
        if op_name in dep_parents:
            meta["independent"] = False
            meta["parent_op"]   = dep_parents[op_name]
            # Also add parent if not already present
            parent = dep_parents[op_name]
            if parent not in all_ops:
                s2 = step2_ops.get(parent, {})
                all_ops[parent] = {
                    "independent":   True,
                    "python_method": s2.get("python_method", parent),
                    "kind":          "read_list",
                    "source":        "dep_parent",
                    "parent_op":     None,
                }

    # 4. Build YAML entries — independent first, then dependents
    entries = []

    def make_entry(op_name: str, meta: dict) -> dict:
        discovery_id = f"k8s.{svc}.{op_name}"
        method       = meta["python_method"] if meta["python_method"] not in ("list", "get") else \
                       _resolve_method_name(op_name, svc, step2_ops)
        parent_op    = meta.get("parent_op")
        params       = _build_params(op_name, svc, step2_ops, parent_op)
        emit         = _emit_block(op_name, svc)
        is_list      = "list" in op_name.lower()

        call = {"action": method, "save_as": "response", "on_error": "continue"}
        if params:
            call["params"] = params

        entry: dict = {
            "discovery_id": discovery_id,
            "calls":        [call],
            "emit":         emit,
        }
        if parent_op:
            entry = {"discovery_id": discovery_id,
                     "for_each": f"k8s.{svc}.{parent_op}",
                     "calls": [call],
                     "emit": emit}
        return entry

    # Sort: independent list ops first, then independent get ops, then dependents
    independent = [(n, m) for n, m in all_ops.items() if m.get("independent", True)]
    dependent   = [(n, m) for n, m in all_ops.items() if not m.get("independent", True)]

    list_ops = [(n, m) for n, m in independent if "list" in n.lower()]
    get_ops  = [(n, m) for n, m in independent if "list" not in n.lower()]

    for op_name, meta in sorted(list_ops) + sorted(get_ops) + sorted(dependent):
        # Skip orphan dependent ops that have no resolved parent — they would
        # produce a get entry without for_each and without params, which is invalid.
        if not meta.get("independent", True) and meta.get("parent_op") is None:
            continue
        entries.append(make_entry(op_name, meta))

    return entries


# ── Build comment header ──────────────────────────────────────────────────────
def build_header(svc: str, n_rule_ops: int, n_id_ops: int, n_entries: int, n_catid_ops: int = 0) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (
        f"# ============================================================\n"
        f"# K8s Finalized Discovery — {svc}\n"
        f"# Generated: {ts}\n"
        f"# Sources:\n"
        f"#   rule_check ops      : {n_rule_ops} unique operations from active rule checks\n"
        f"#   catalog id ops      : {n_catid_ops} ops producing is_id=Yes fields (with chains)\n"
        f"#   db identifier ops   : {n_id_ops} operations from resource_inventory_identifier\n"
        f"#   total entries       : {n_entries} (after deduplication)\n"
        f"# ============================================================\n"
    )


# ── Per-service api_version ───────────────────────────────────────────────────
def get_api_version(svc: str, svc_dir: Path) -> str:
    step1 = _load_step1(svc_dir)
    svc_data = step1.get(svc, {})
    api_ver = svc_data.get("api_version", "")
    if not api_ver:
        for ind in svc_data.get("independent", []):
            grp = ind.get("api_group", "")
            ver = ind.get("api_version_in_url", "")
            if grp and ver:
                api_ver = f"{grp}/{ver}" if grp != "core" else ver
            elif ver:
                api_ver = ver
            if api_ver:
                break
    return api_ver or "v1"


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    print("Loading master catalog ops index...")
    catalog_ops = load_catalog_ops()

    print("Loading catalog identifier-field ops (is_id=Yes)...")
    catalog_id_ops_by_svc = load_identifier_ops_from_catalog()
    id_svcs_in_catalog = len(catalog_id_ops_by_svc)
    total_cat_id_ops = sum(len(v) for v in catalog_id_ops_by_svc.values())
    print(f"  {total_cat_id_ops} identifier ops across {id_svcs_in_catalog} services")

    print("Collecting rule-check ops...")
    rule_ops_by_svc = collect_rule_ops()
    print(f"  {len(rule_ops_by_svc)} services with active rules")

    print("Fetching identifier ops from DB...")
    # Try local cache first (fetched via kubectl exec), fall back to direct DB
    local_cache = Path("/tmp/k8s_identifier_ops.json")
    if local_cache.exists():
        import json as _json
        raw_rows = _json.loads(local_cache.read_text())
        id_ops_by_svc: dict[str, list[dict]] = {}
        for row in raw_rows:
            svc_key = row["service"]
            ops = []
            for o in (row.get("root_ops") or []):
                if isinstance(o, dict):
                    ops.append({"operation": o.get("operation",""), "python_method": o.get("python_method",""),
                                "independent": o.get("independent", True), "kind": o.get("kind","read_list"), "source": "identifier"})
            for o in (row.get("enrich_ops") or []):
                if isinstance(o, dict):
                    ops.append({"operation": o.get("operation",""), "python_method": o.get("python_method",""),
                                "independent": o.get("independent", False), "kind": o.get("kind","read_get"), "source": "identifier_enrich"})
            if ops:
                id_ops_by_svc[svc_key] = ops
        print(f"  {len(id_ops_by_svc)} services (loaded from local cache)")
    else:
        conn = psycopg2.connect(**DB_CFG)
        id_ops_by_svc = collect_identifier_ops(conn)
        conn.close()
    print(f"  {len(id_ops_by_svc)} services in resource_inventory_identifier")

    # Only generate for services that have rule checks
    all_svcs = sorted(rule_ops_by_svc.keys())
    print(f"\nGenerating discovery files for {len(all_svcs)} services (rule-check services only)...")

    generated = 0
    for svc in all_svcs:
        svc_dir = K8S_DIR / svc
        if not svc_dir.exists():
            svc_dir.mkdir(parents=True, exist_ok=True)

        rule_ops    = rule_ops_by_svc.get(svc, set())
        id_ops      = id_ops_by_svc.get(svc, [])
        cat_id_ops  = catalog_id_ops_by_svc.get(svc, [])

        step2 = _load_step2(svc_dir)
        step3 = _load_step3(svc_dir)
        api_ver = get_api_version(svc, svc_dir)
        client_var, api_class, http_prefix = _api_meta(api_ver)

        entries = build_discovery_entries(svc, rule_ops, id_ops, cat_id_ops, step2, step3, catalog_ops)

        if not entries:
            print(f"  SKIP {svc}: no ops resolved")
            continue

        doc = {
            "version":  "1.0",
            "provider": "k8s",
            "service":  svc,
            "services": {
                "client":    client_var,
                "module":    "kubernetes.client",
                "api_class": api_class,
            },
            "discovery": entries,
        }

        n_rule  = len(rule_ops)
        n_catid = len(cat_id_ops)
        n_dbid  = len(id_ops)
        header  = build_header(svc, n_rule, n_dbid, len(entries), n_catid)
        out_path = svc_dir / f"k8s_{svc}_finalized_discovery_v1.yaml"
        out_path.write_text(
            header + "\n" +
            yaml.dump(doc, default_flow_style=False, sort_keys=False, allow_unicode=True)
        )
        print(f"  {svc:<35} rule={n_rule}  cat_id={n_catid}  db_id={n_dbid}  → {len(entries)} ops")
        generated += 1

    print(f"\nDone: {generated} discovery files written.")


if __name__ == "__main__":
    main()
