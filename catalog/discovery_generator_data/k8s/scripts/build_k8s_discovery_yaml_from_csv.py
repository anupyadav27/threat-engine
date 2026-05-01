#!/usr/bin/env python3
"""
build_k8s_discovery_yaml_from_csv.py
======================================
Generates finalized K8s discovery YAMLs from k8s_field_rule_catalog.csv.

For each service in the CSV:
  - Collect unique producing_ops (list ops + get ops)
  - Resolve each op → API action method name
  - Emit discovery YAML identical in format to k8s_*_finalized_discovery_v1.yaml

Output:
    catalog/discovery_generator/k8s/{service}/k8s_{service}_finalized_discovery_v1.yaml

Usage:
    python catalog/discovery_generator/k8s/scripts/build_k8s_discovery_yaml_from_csv.py
    python ...  --services pod,deployment,rbac  # specific services only
    python ...  --dry-run                        # print, don't write
"""
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import yaml

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).resolve().parents[4]
K8S_DIR     = REPO_ROOT / "catalog/discovery_generator/k8s"
CATALOG_CSV = K8S_DIR / "k8s_field_rule_catalog.csv"

# ── K8s naming helpers (same as generate_k8s_finalized_discovery.py) ─────────
K8S_API_NAME: Dict[str, str] = {
    "clusterrole":             "cluster_role",
    "clusterrolebinding":      "cluster_role_binding",
    "storageclass":            "storage_class",
    "horizontalpodautoscaler": "horizontal_pod_autoscaler",
    "poddisruptionbudget":     "pod_disruption_budget",
    "networkpolicy":           "network_policy",
    "serviceaccount":          "service_account",
    "persistentvolume":        "persistent_volume",
    "persistentvolumeclaim":   "persistent_volume_claim",
    "replicaset":              "replica_set",
    "statefulset":             "stateful_set",
    "daemonset":               "daemon_set",
    "limitrange":              "limit_range",
    "resourcequota":           "resource_quota",
    "podtemplate":             "pod_template",
    "configmap":               "config_map",
    "cronjob":                 "cron_job",
    "rolebinding":             "role_binding",
}

NAMESPACED: Set[str] = {
    "pod", "deployment", "daemonset", "statefulset", "replicaset",
    "replicationcontroller", "job", "cronjob", "configmap", "secret",
    "service", "serviceaccount", "persistentvolumeclaim", "ingress",
    "networkpolicy", "role", "rolebinding", "horizontalpodautoscaler",
    "poddisruptionbudget", "resourcequota", "limitrange", "podtemplate", "event",
}

# api_class / client / module per service (from existing discovery YAMLs)
SVC_CLIENT: Dict[str, Dict[str, str]] = {
    "admission":              {"api_class": "AdmissionregistrationV1Api", "client": "admissionregistration_v1_api", "module": "kubernetes.client"},
    "apiserver":              {"api_class": "ApiregistrationV1Api",       "client": "apiregistration_v1_api",       "module": "kubernetes.client"},
    "audit":                  {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "autoscaling":            {"api_class": "AutoscalingV1Api",           "client": "autoscaling_v1_api",           "module": "kubernetes.client"},
    "certificate":            {"api_class": "CertificatesV1Api",          "client": "certificates_v1_api",          "module": "kubernetes.client"},
    "cluster":                {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "clusterrole":            {"api_class": "RbacAuthorizationV1Api",     "client": "rbac_authorization_v1_api",    "module": "kubernetes.client"},
    "clusterrolebinding":     {"api_class": "RbacAuthorizationV1Api",     "client": "rbac_authorization_v1_api",    "module": "kubernetes.client"},
    "configmap":              {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "controlplane":           {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "cronjob":                {"api_class": "BatchV1Api",                 "client": "batch_v1_api",                 "module": "kubernetes.client"},
    "daemonset":              {"api_class": "AppsV1Api",                  "client": "apps_v1_api",                  "module": "kubernetes.client"},
    "deployment":             {"api_class": "AppsV1Api",                  "client": "apps_v1_api",                  "module": "kubernetes.client"},
    "disaster_recovery":      {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "etcd":                   {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "event":                  {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "federation":             {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "general":                {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "horizontalpodautoscaler": {"api_class": "AutoscalingV1Api",          "client": "autoscaling_v1_api",           "module": "kubernetes.client"},
    "image":                  {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "ingress":                {"api_class": "NetworkingV1Api",            "client": "networking_v1_api",            "module": "kubernetes.client"},
    "inventory":              {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "job":                    {"api_class": "BatchV1Api",                 "client": "batch_v1_api",                 "module": "kubernetes.client"},
    "kubelet":                {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "limitrange":             {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "monitoring":             {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "namespace":              {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "network":                {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "networkpolicy":          {"api_class": "NetworkingV1Api",            "client": "networking_v1_api",            "module": "kubernetes.client"},
    "node":                   {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "persistentvolume":       {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "persistentvolumeclaim":  {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "pod":                    {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "pod_security":           {"api_class": "PolicyV1Api",                "client": "policy_v1_api",                "module": "kubernetes.client"},
    "podtemplate":            {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "policy":                 {"api_class": "PolicyV1Api",                "client": "policy_v1_api",                "module": "kubernetes.client"},
    "rbac":                   {"api_class": "RbacAuthorizationV1Api",     "client": "rbac_authorization_v1_api",    "module": "kubernetes.client"},
    "replicaset":             {"api_class": "AppsV1Api",                  "client": "apps_v1_api",                  "module": "kubernetes.client"},
    "resource":               {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "resourcequota":          {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "role":                   {"api_class": "RbacAuthorizationV1Api",     "client": "rbac_authorization_v1_api",    "module": "kubernetes.client"},
    "rolebinding":            {"api_class": "RbacAuthorizationV1Api",     "client": "rbac_authorization_v1_api",    "module": "kubernetes.client"},
    "scheduler":              {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "secret":                 {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "service":                {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "serviceaccount":         {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "software":               {"api_class": "CoreV1Api",                  "client": "core_v1_api",                  "module": "kubernetes.client"},
    "statefulset":            {"api_class": "AppsV1Api",                  "client": "apps_v1_api",                  "module": "kubernetes.client"},
    "storage":                {"api_class": "StorageV1Api",               "client": "storage_v1_api",               "module": "kubernetes.client"},
    "storageclass":           {"api_class": "StorageV1Api",               "client": "storage_v1_api",               "module": "kubernetes.client"},
    "workload":               {"api_class": "AppsV1Api",                  "client": "apps_v1_api",                  "module": "kubernetes.client"},
}


def _resolve_action(producing_op: str, svc: str) -> str:
    """
    Resolve a producing_op to the actual kubernetes-client method name.

    producing_op format: k8s.{service}.{suffix}
    suffix is either:
      - 'list' / 'get'  → expand with K8S_API_NAME + NAMESPACED
      - already full     → use as-is (e.g. list_node, list_cluster_role)
    """
    parts  = producing_op.split(".")       # ['k8s', svc, suffix...]
    suffix = ".".join(parts[2:]) if len(parts) > 2 else ""

    api_name   = K8S_API_NAME.get(svc, svc)
    namespaced = svc in NAMESPACED

    if suffix == "list":
        return f"list_{api_name}_for_all_namespaces" if namespaced else f"list_{api_name}"
    if suffix == "get":
        return f"read_namespaced_{api_name}" if namespaced else f"read_{api_name}"
    # Explicit method name in the op (e.g. list_node, list_cluster_role_binding)
    return suffix


def _make_entry(
    discovery_id: str,
    action: str,
    is_independent: bool,
    root_op: str,
    svc: str,
) -> Dict:
    """Build a single discovery entry dict."""
    entry: Dict = {"discovery_id": discovery_id}

    if not is_independent:
        entry["for_each"] = root_op

    call: Dict = {
        "action":   action,
        "save_as":  "response",
        "on_error": "continue",
    }

    # Get ops need name (and namespace for namespaced resources)
    if not is_independent:
        if svc in NAMESPACED or action.startswith("read_namespaced_"):
            call["params"] = {
                "name":      "{{ item.metadata.name }}",
                "namespace": "{{ item.metadata.namespace }}",
            }
        else:
            call["params"] = {"name": "{{ item.metadata.name }}"}

    entry["calls"] = [call]

    # Emit block
    if is_independent:
        entry["emit"] = {
            "as":        "item",
            "items_for": "{{ response.items }}",
        }
    else:
        # Resource key: strip read_namespaced_ / read_ prefix
        rkey = action.removeprefix("read_namespaced_").removeprefix("read_")
        entry["emit"] = {
            "as":   "item",
            "item": {rkey: "{{ response }}"},
        }

    return entry


def _load_csv_ops(csv_path: Path) -> Dict[str, List[Tuple]]:
    """
    Returns {service: [(discovery_id, action, is_independent, root_op), ...]}
    De-duplicated and sorted (list ops first, get ops after).
    """
    svc_ops: Dict[str, Dict[str, Tuple]] = defaultdict(dict)

    with open(csv_path) as f:
        for row in csv.DictReader(f):
            svc   = row["service"]
            op    = row["producing_op"]
            indep = row["is_independent"].strip().lower() in ("yes", "true", "1")
            root  = row["root_op"]

            if op in svc_ops[svc]:
                continue  # already seen

            action = _resolve_action(op, svc)

            # Skip synthetic DB ops (shouldn't be in CSV but guard anyway)
            if action.endswith("_resources"):
                continue

            svc_ops[svc][op] = (op, action, indep, root)

    # Sort: independent (list) ops first, then dependent (get) ops
    result: Dict[str, List[Tuple]] = {}
    for svc, ops in svc_ops.items():
        lst = sorted(ops.values(), key=lambda x: (0 if x[2] else 1, x[0]))
        result[svc] = lst

    return result


def _yaml_str(data: dict) -> str:
    """Dump YAML with consistent style: flow strings, 2-space indent."""
    return yaml.dump(
        data,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        indent=2,
        width=120,
    )


def build_discovery_yaml(svc: str, ops: List[Tuple], dry_run: bool = False) -> str:
    """Build and optionally write the finalized discovery YAML for one service."""
    client_meta = SVC_CLIENT.get(svc, {
        "api_class": "CoreV1Api",
        "client":    "core_v1_api",
        "module":    "kubernetes.client",
    })

    entries = []
    for (discovery_id, action, is_independent, root_op) in ops:
        # Skip dependent ops where root_op is unknown / same as self (shouldn't happen)
        if not is_independent and (not root_op or root_op == discovery_id):
            continue
        entries.append(_make_entry(discovery_id, action, is_independent, root_op, svc))

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    n_list = sum(1 for _, _, indep, _ in ops if indep)
    n_get  = sum(1 for _, _, indep, _ in ops if not indep)

    header = (
        f"# ============================================================\n"
        f"# K8s Finalized Discovery — {svc}\n"
        f"# Generated: {ts}\n"
        f"# Source: k8s_field_rule_catalog.csv\n"
        f"# Ops: {n_list} list  +  {n_get} get  =  {len(ops)} total\n"
        f"# ============================================================\n\n"
    )

    doc = {
        "version":  "1.0",
        "provider": "k8s",
        "service":  svc,
        "services": {
            "client":    client_meta["client"],
            "module":    client_meta["module"],
            "api_class": client_meta["api_class"],
        },
        "discovery": entries,
    }

    content = header + _yaml_str(doc)

    if not dry_run:
        out_dir  = K8S_DIR / svc
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"k8s_{svc}_finalized_discovery_v1.yaml"
        out_path.write_text(content)

    return content


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate K8s discovery YAMLs from k8s_field_rule_catalog.csv"
    )
    parser.add_argument("--services", help="Comma-separated services (default: all)")
    parser.add_argument("--dry-run",  action="store_true",
                        help="Print to stdout, do not write files")
    args = parser.parse_args()

    if not CATALOG_CSV.exists():
        print(f"ERROR: {CATALOG_CSV} not found. Run build_k8s_catalog_csv.py first.")
        return

    svc_ops = _load_csv_ops(CATALOG_CSV)

    if args.services:
        requested = {s.strip() for s in args.services.split(",")}
        svc_ops = {k: v for k, v in svc_ops.items() if k in requested}

    written = 0
    for svc in sorted(svc_ops):
        ops = svc_ops[svc]
        build_discovery_yaml(svc, ops, dry_run=args.dry_run)
        if args.dry_run:
            print(f"  [dry-run] {svc}  {len(ops)} ops")
        else:
            print(f"  ✓ {svc:<30}  {len(ops)} ops → k8s_{svc}_finalized_discovery_v1.yaml")
            written += 1

    if not args.dry_run:
        print(f"\nWrote {written} discovery YAMLs")


if __name__ == "__main__":
    main()
