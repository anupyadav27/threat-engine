#!/usr/bin/env python3
"""
Generate k8s_master_field_catalog.csv — same 18-column schema as gcp_master_field_catalog.csv.

Columns (matching GCP schema exactly):
  csp, service, field_path, item_var_path, field_type, is_id, producing_op, op_kind,
  is_independent, root_op, chain_ops, chain_length, hop_distance, chain_ops_with_fields,
  operators, operators_no_value, python_call, http_path
"""

import csv
import json
from pathlib import Path

K8S_DIR = Path("/Users/apple/Desktop/threat-engine/catalog/discovery_generator/k8s")
OUT_CSV  = K8S_DIR / "k8s_master_field_catalog.csv"

COLUMNS = [
    "csp", "service", "field_path", "item_var_path", "field_type", "is_id",
    "producing_op", "op_kind", "is_independent", "root_op", "chain_ops",
    "chain_length", "hop_distance", "chain_ops_with_fields",
    "operators", "operators_no_value", "python_call", "http_path",
]

# ── ID fields ─────────────────────────────────────────────────────────────────
ID_FIELDS = {"metadata.name", "metadata.uid", "metadata.namespace",
             "metadata.selfLink", "metadata.resourceVersion"}

# ── K8s API version → Python client + http base ────────────────────────────
#   key = api_version as found in step1
API_META = {
    "v1": {
        "client": "core_v1_api",
        "http_base": "/api/v1",
    },
    "apps/v1": {
        "client": "apps_v1_api",
        "http_base": "/apis/apps/v1",
    },
    "batch/v1": {
        "client": "batch_v1_api",
        "http_base": "/apis/batch/v1",
    },
    "batch/v1beta1": {
        "client": "batch_v1beta1_api",
        "http_base": "/apis/batch/v1beta1",
    },
    "rbac.authorization.k8s.io/v1": {
        "client": "rbac_authorization_v1_api",
        "http_base": "/apis/rbac.authorization.k8s.io/v1",
    },
    "networking.k8s.io/v1": {
        "client": "networking_v1_api",
        "http_base": "/apis/networking.k8s.io/v1",
    },
    "storage.k8s.io/v1": {
        "client": "storage_v1_api",
        "http_base": "/apis/storage.k8s.io/v1",
    },
    "autoscaling/v1": {
        "client": "autoscaling_v1_api",
        "http_base": "/apis/autoscaling/v1",
    },
    "autoscaling/v2": {
        "client": "autoscaling_v2_api",
        "http_base": "/apis/autoscaling/v2",
    },
    "autoscaling/v2beta2": {
        "client": "autoscaling_v2beta2_api",
        "http_base": "/apis/autoscaling/v2beta2",
    },
    "policy/v1": {
        "client": "policy_v1_api",
        "http_base": "/apis/policy/v1",
    },
    "policy/v1beta1": {
        "client": "policy_v1beta1_api",
        "http_base": "/apis/policy/v1beta1",
    },
    "apiregistration.k8s.io/v1": {
        "client": "apiregistration_v1_api",
        "http_base": "/apis/apiregistration.k8s.io/v1",
    },
    "admissionregistration.k8s.io/v1": {
        "client": "admissionregistration_v1_api",
        "http_base": "/apis/admissionregistration.k8s.io/v1",
    },
    "certificates.k8s.io/v1": {
        "client": "certificates_v1_api",
        "http_base": "/apis/certificates.k8s.io/v1",
    },
    "auditregistration.k8s.io/v1alpha1": {
        "client": "auditregistration_v1alpha1_api",
        "http_base": "/apis/auditregistration.k8s.io/v1alpha1",
    },
    "scheduling.k8s.io/v1": {
        "client": "scheduling_v1_api",
        "http_base": "/apis/scheduling.k8s.io/v1",
    },
}

# ── Resource plural forms (for http_path) ────────────────────────────────────
RESOURCE_PLURAL = {
    "pod": "pods",
    "deployment": "deployments",
    "daemonset": "daemonsets",
    "statefulset": "statefulsets",
    "replicaset": "replicasets",
    "replicationcontroller": "replicationcontrollers",
    "job": "jobs",
    "cronjob": "cronjobs",
    "configmap": "configmaps",
    "secret": "secrets",
    "service": "services",
    "serviceaccount": "serviceaccounts",
    "namespace": "namespaces",
    "node": "nodes",
    "persistentvolume": "persistentvolumes",
    "persistentvolumeclaim": "persistentvolumeclaims",
    "storageclass": "storageclasses",
    "ingress": "ingresses",
    "networkpolicy": "networkpolicies",
    "role": "roles",
    "rolebinding": "rolebindings",
    "clusterrole": "clusterroles",
    "clusterrolebinding": "clusterrolebindings",
    "horizontalpodautoscaler": "horizontalpodautoscalers",
    "poddisruptionbudget": "poddisruptionbudgets",
    "priorityclass": "priorityclasses",
    "resourcequota": "resourcequotas",
    "limitrange": "limitranges",
    "podtemplate": "podtemplates",
    "event": "events",
    "endpoints": "endpoints",
    "certificate": "certificatesigningrequests",
    "node": "nodes",
    "apiserver": "apiservices",
    "admission": "validatingwebhookconfigurations",
    "audit": "auditsinks",
}

# ── Namespaced resources (for http_path) ────────────────────────────────────
NAMESPACED = {
    "pod", "deployment", "daemonset", "statefulset", "replicaset",
    "replicationcontroller", "job", "cronjob", "configmap", "secret",
    "service", "serviceaccount", "persistentvolumeclaim", "ingress",
    "networkpolicy", "role", "rolebinding", "horizontalpodautoscaler",
    "poddisruptionbudget", "resourcequota", "limitrange", "podtemplate",
    "event", "endpoints",
}


def _load_step1(svc_dir: Path) -> dict:
    p = svc_dir / "step1_api_driven_registry.json"
    if p.exists():
        with open(p) as f:
            return json.load(f)
    return {}


def _load_step4(svc_dir: Path) -> dict:
    p = svc_dir / "step4_fields_produced_index.json"
    if p.exists():
        with open(p) as f:
            return json.load(f)
    return {}


def _load_step4a(svc_dir: Path) -> dict:
    """Returns dict keyed by field_name → row dict."""
    p = svc_dir / "step4a_field_operator_value_table.csv"
    if not p.exists():
        return {}
    with open(p) as f:
        reader = csv.DictReader(f)
        return {row["field_name"]: row for row in reader}


def _load_step2_read(svc_dir: Path) -> dict:
    p = svc_dir / "step2_read_operation_registry.json"
    if p.exists():
        with open(p) as f:
            return json.load(f)
    return {}


def _get_api_version(step1: dict, svc: str) -> str:
    """Extract api_version from step1 data."""
    svc_data = step1.get(svc, {})
    api_ver = svc_data.get("api_version", "")
    if not api_ver:
        # Try first operation's api_group
        for op in svc_data.get("independent", []):
            grp = op.get("api_group", "")
            ver = op.get("api_version_in_url", "")
            if grp and ver:
                api_ver = f"{grp}/{ver}" if grp != "core" else ver
            elif ver:
                api_ver = ver
            if api_ver:
                break
    return api_ver or "v1"


def _python_call(client: str, op: str, svc: str, namespaced: bool) -> str:
    """Build a representative python_call string."""
    plural = RESOURCE_PLURAL.get(svc, f"{svc}s")
    if op == "list":
        if namespaced:
            method = f"list_namespaced_{svc}"
        else:
            method = f"list_{svc}"
    elif op == "get":
        if namespaced:
            method = f"read_namespaced_{svc}"
        else:
            method = f"read_{svc}"
    else:
        method = f"{op}_{svc}"
    return f"{client}.{method}(**params)"


def _http_path(http_base: str, svc: str, op: str, namespaced: bool) -> str:
    plural = RESOURCE_PLURAL.get(svc, f"{svc}s")
    if namespaced:
        path = f"{http_base}/namespaces/{{namespace}}/{plural}"
    else:
        path = f"{http_base}/{plural}"
    if op == "get":
        path += "/{name}"
    return path


def _op_kind(op: str) -> str:
    if op in ("list", "list_for_all_namespaces", "list_all_namespaces"):
        return "read_list"
    if op in ("get", "read"):
        return "read_get"
    return "read_list"


def _is_id_field(field_short: str) -> str:
    return "Yes" if field_short in ID_FIELDS else "No"


# ── Workload controllers that wrap a Pod spec under spec.template.spec. ──────
WORKLOAD_CONTROLLERS = {
    "deployment", "daemonset", "statefulset", "replicaset", "job", "cronjob",
}

# Containers sub-fields from pod step4 that should be propagated to workload controllers
# pod field_short → workload field_short (prepend spec.template.spec. prefix)
def _pod_container_fields(pod_step4: dict) -> list[dict]:
    """Return pod container sub-fields (spec.containers[].* etc.) for injection."""
    fields = pod_step4.get("fields", {})
    result = []
    for full_key, finfo in sorted(fields.items()):
        short = finfo.get("field_short", "")
        if not short:
            continue
        # Only container array sub-fields: spec.containers[].*, spec.initContainers[].*
        if not (short.startswith("spec.containers[].") or
                short.startswith("spec.initContainers[].") or
                short.startswith("spec.ephemeralContainers[].")):
            continue
        result.append((short, finfo))
    return result


def build_catalog() -> list[dict]:
    rows = []

    svc_dirs = sorted([
        d for d in K8S_DIR.iterdir()
        if d.is_dir() and (d / "step4_fields_produced_index.json").exists()
    ])

    # Pre-load pod step4 for cross-propagation to workload controllers
    pod_dir = K8S_DIR / "pod"
    pod_step4 = _load_step4(pod_dir) if pod_dir.exists() else {}
    pod_step4a = _load_step4a(pod_dir) if pod_dir.exists() else {}
    pod_container_fields = _pod_container_fields(pod_step4)

    for svc_dir in svc_dirs:
        svc = svc_dir.name

        step1   = _load_step1(svc_dir)
        step4   = _load_step4(svc_dir)
        step4a  = _load_step4a(svc_dir)
        step2   = _load_step2_read(svc_dir)

        if not step4:
            print(f"  SKIP {svc}: no step4")
            continue

        # Determine api_version
        api_ver = _get_api_version(step1, svc)
        if not api_ver:
            # Fallback: look at step4 metadata
            api_ver = step4.get("api_version", "v1")

        meta     = API_META.get(api_ver, API_META["v1"])
        client   = meta["client"]
        http_base = meta["http_base"]
        namespaced = svc in NAMESPACED

        # step2 ops info
        step2_ops = step2.get("operations", {})

        fields = step4.get("fields", {})
        if not fields:
            print(f"  SKIP {svc}: no fields in step4")
            continue

        # Build set of fields per producing op for chain_ops_with_fields
        op_fields: dict[str, list[str]] = {}
        for full_key, finfo in fields.items():
            short = finfo.get("field_short", full_key.split(".", 2)[-1] if "." in full_key else full_key)
            for prod_op in finfo.get("produced_by", []):
                op_fields.setdefault(prod_op, []).append(short)

        # ── Identify the primary list op and get op for this service ──────────
        list_op_name = next(
            (o for o in step2_ops if "list" in o.lower()),
            None
        )
        get_op_name = "get" if "get" in step2_ops else None
        primary_list_op = f"k8s.{svc}.{list_op_name}" if list_op_name else None
        primary_get_op  = f"k8s.{svc}.{get_op_name}"  if get_op_name  else None

        for full_key, finfo in sorted(fields.items()):
            short = finfo.get("field_short",
                              full_key.split(".", 2)[-1] if "." in full_key else full_key)
            ftype = finfo.get("type", "string")

            produced_by = finfo.get("produced_by", [])
            if not produced_by:
                continue

            # Operators from step4a (shared by both list and get rows)
            step4a_row = step4a.get(short, {})
            operators          = step4a_row.get("operators", "contains, equals, exists, in, not_equals, not_in")
            operators_no_value = step4a_row.get("operators_no_value", "exists")

            # ── Emit one row per producing op (list AND get) ──────────────
            list_prod_ops = [o for o in produced_by if "list" in o.split(".")[-1]]
            get_prod_ops  = [o for o in produced_by if o.split(".")[-1] == "get"]
            other_ops     = [o for o in produced_by
                             if o not in list_prod_ops and o not in get_prod_ops]

            # All ops to emit rows for: list first, then get, then others
            all_prod = list_prod_ops + get_prod_ops + other_ops

            for producing_op in all_prod:
                op_name = producing_op.split(".")[-1]
                is_list_op = "list" in op_name.lower()
                is_get_op  = op_name == "get"

                op_k    = _op_kind(op_name)
                py_call = _python_call(client, op_name, svc, namespaced)
                h_path  = _http_path(http_base, svc, op_name, namespaced)

                if is_get_op and primary_list_op:
                    # ── DEPENDENT get row (mirrors GCP pattern) ──────────
                    root_op      = primary_list_op
                    chain_ops    = f"{primary_list_op} -> {producing_op}"
                    chain_length = 2
                    hop_distance = 1
                    is_independent = "No"

                    # chain_ops_with_fields: list[fields] -> get[fields]
                    list_fields = "|".join(sorted(op_fields.get(primary_list_op, [])))
                    get_fields  = "|".join(sorted(op_fields.get(producing_op, [short])))
                    chain_ops_with_fields = (
                        f"{primary_list_op}[{list_fields}] -> {producing_op}[{get_fields}]"
                    )
                else:
                    # ── INDEPENDENT list (or other) row ──────────────────
                    root_op      = producing_op
                    chain_ops    = producing_op
                    chain_length = 1
                    hop_distance = 0
                    is_independent = "Yes"

                    op_field_list = "|".join(sorted(op_fields.get(producing_op, [short])))
                    chain_ops_with_fields = f"{producing_op}[{op_field_list}]"

                rows.append({
                    "csp":                   "k8s",
                    "service":               svc,
                    "field_path":            short,
                    "item_var_path":         f"item.{short}",
                    "field_type":            ftype,
                    "is_id":                 _is_id_field(short),
                    "producing_op":          producing_op,
                    "op_kind":               op_k,
                    "is_independent":        is_independent,
                    "root_op":               root_op,
                    "chain_ops":             chain_ops,
                    "chain_length":          chain_length,
                    "hop_distance":          hop_distance,
                    "chain_ops_with_fields": chain_ops_with_fields,
                    "operators":             operators,
                    "operators_no_value":    operators_no_value,
                    "python_call":           py_call,
                    "http_path":             h_path,
                })

        # ── Propagate pod container sub-fields to workload controllers ────────
        if svc in WORKLOAD_CONTROLLERS and pod_container_fields:
            # The pod's spec.containers[].X maps to spec.template.spec.containers[].X
            existing_paths = {r["field_path"] for r in rows if r["service"] == svc}
            for pod_short, pod_finfo in pod_container_fields:
                # Adapt path: spec.containers[].X → spec.template.spec.containers[].X
                if pod_short.startswith("spec."):
                    workload_short = "spec.template." + pod_short
                else:
                    workload_short = pod_short

                if workload_short in existing_paths:
                    continue  # already in catalog from this service's own step4

                ftype  = pod_finfo.get("type", "string")
                step4a_row = pod_step4a.get(pod_short.split(".")[-1], pod_step4a.get(pod_short, {}))
                operators = step4a_row.get("operators", "contains, equals, exists, in, not_equals, not_in")
                operators_no_value = step4a_row.get("operators_no_value", "exists")

                # Emit list row (independent)
                list_prod_op = f"k8s.{svc}.{list_op_name}" if list_op_name else f"k8s.{svc}.list"
                # List row (independent)
                rows.append({
                    "csp":                   "k8s",
                    "service":               svc,
                    "field_path":            workload_short,
                    "item_var_path":         f"item.{workload_short}",
                    "field_type":            ftype,
                    "is_id":                 "No",
                    "producing_op":          list_prod_op,
                    "op_kind":               "read_list",
                    "is_independent":        "Yes",
                    "root_op":               list_prod_op,
                    "chain_ops":             list_prod_op,
                    "chain_length":          1,
                    "hop_distance":          0,
                    "chain_ops_with_fields": f"{list_prod_op}[{workload_short}]",
                    "operators":             operators,
                    "operators_no_value":    operators_no_value,
                    "python_call":           _python_call(client, "list", svc, namespaced),
                    "http_path":             _http_path(http_base, svc, "list", namespaced),
                })
                # Get row (dependent) — only if this service has a get op
                if get_op_name and primary_list_op:
                    get_prod_op = f"k8s.{svc}.{get_op_name}"
                    rows.append({
                        "csp":                   "k8s",
                        "service":               svc,
                        "field_path":            workload_short,
                        "item_var_path":         f"item.{workload_short}",
                        "field_type":            ftype,
                        "is_id":                 "No",
                        "producing_op":          get_prod_op,
                        "op_kind":               "read_get",
                        "is_independent":        "No",
                        "root_op":               list_prod_op,
                        "chain_ops":             f"{list_prod_op} -> {get_prod_op}",
                        "chain_length":          2,
                        "hop_distance":          1,
                        "chain_ops_with_fields": f"{list_prod_op}[{workload_short}] -> {get_prod_op}[{workload_short}]",
                        "operators":             operators,
                        "operators_no_value":    operators_no_value,
                        "python_call":           _python_call(client, "get", svc, namespaced),
                        "http_path":             _http_path(http_base, svc, "get", namespaced),
                    })

    return rows


def main():
    print("Building k8s master field catalog...")
    rows = build_catalog()

    with open(OUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    # Summary
    services = len({r["service"] for r in rows})
    print(f"Done: {len(rows):,} rows, {services} services → {OUT_CSV.name}")

    # Per-service count
    from collections import Counter
    counts = Counter(r["service"] for r in rows)
    for svc, cnt in sorted(counts.items()):
        print(f"  {svc:<35} {cnt:>5} fields")


if __name__ == "__main__":
    main()
