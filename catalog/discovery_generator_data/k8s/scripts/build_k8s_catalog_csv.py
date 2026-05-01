#!/usr/bin/env python3
"""
build_k8s_catalog_csv.py
=========================
Creates k8s_field_rule_catalog.csv — the single source of truth for
K8s discovery operations, inventory normalisation, and check rules.

Column layout (35 columns, matching OCI oci_field_rule_catalog.csv):
  [18 from k8s_master_field_catalog.csv]
    csp, service, field_path, item_var_path, field_type, is_id,
    producing_op, op_kind, is_independent, root_op, chain_ops,
    chain_length, hop_distance, chain_ops_with_fields,
    operators, operators_no_value, python_call, http_path
  [3 inventory]
    resource_type, resource_id_field, resource_id_param
  [14 check rule]
    check_rule_id, check_for_each, check_var,
    check_condition_op, check_condition_value,
    check_condition, check_conditions_json,
    check_severity, check_frameworks, check_description,
    is_system_rule, is_active, needs_review, review_reason

Merge strategy:
  1. Load all 2,876 field rows from k8s_master_field_catalog.csv
  2. Fill resource_type / resource_id_field / resource_id_param per service
  3. Load severity + domain from 1_k8s_full_scope_assertions.yaml
  4. Load all 718 check rules from catalog/rule/k8s_rule_check/**/*.checks.yaml
  5. Match each rule to a field row:
       key = (service, producing_op == check_for_each, item_var_path == check_var)
     - First unassigned match  → populate check_* in-place
     - All matches taken       → duplicate first match row with new check_*
     - No field row match      → append synthetic row (field data derived from check_var)
  6. Write k8s_field_rule_catalog.csv

Usage:
    python catalog/discovery_generator/k8s/scripts/build_k8s_catalog_csv.py
"""
from __future__ import annotations

import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

import yaml

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT  = Path(__file__).resolve().parents[4]
K8S_DIR    = REPO_ROOT / "catalog/discovery_generator/k8s"
CHECKS_DIR = REPO_ROOT / "catalog/rule/k8s_rule_check"
MASTER_CSV = K8S_DIR / "k8s_master_field_catalog.csv"
OUT_CSV    = K8S_DIR / "k8s_field_rule_catalog.csv"
ASSERTIONS = CHECKS_DIR / "1_k8s_full_scope_assertions.yaml"

# ── Column definitions ────────────────────────────────────────────────────────
BASE_COLS = [
    "csp", "service", "field_path", "item_var_path", "field_type", "is_id",
    "producing_op", "op_kind", "is_independent", "root_op", "chain_ops",
    "chain_length", "hop_distance", "chain_ops_with_fields",
    "operators", "operators_no_value", "python_call", "http_path",
]
NEW_COLS = [
    "resource_type", "resource_id_field", "resource_id_param",
    "check_rule_id", "check_for_each", "check_var",
    "check_condition_op", "check_condition_value",
    "check_condition", "check_conditions_json",
    "check_severity", "check_frameworks", "check_description",
    "is_system_rule", "is_active", "needs_review", "review_reason",
]
ALL_COLS = BASE_COLS + NEW_COLS

# ── Service → K8s resource kind ───────────────────────────────────────────────
RESOURCE_TYPE: Dict[str, str] = {
    "admission":              "ValidatingWebhookConfiguration",
    "apiserver":              "APIService",
    "audit":                  "Event",
    "autoscaling":            "HorizontalPodAutoscaler",
    "certificate":            "CertificateSigningRequest",
    "cluster":                "Namespace",
    "clusterrole":            "ClusterRole",
    "clusterrolebinding":     "ClusterRoleBinding",
    "configmap":              "ConfigMap",
    "controlplane":           "ComponentStatus",
    "cronjob":                "CronJob",
    "daemonset":              "DaemonSet",
    "deployment":             "Deployment",
    "disaster_recovery":      "PersistentVolumeClaim",
    "etcd":                   "ComponentStatus",
    "event":                  "Event",
    "federation":             "Namespace",
    "general":                "Pod",
    "horizontalpodautoscaler": "HorizontalPodAutoscaler",
    "image":                  "Pod",
    "ingress":                "Ingress",
    "inventory":              "Deployment",
    "job":                    "Job",
    "kubelet":                "Node",
    "limitrange":             "LimitRange",
    "monitoring":             "ConfigMap",
    "namespace":              "Namespace",
    "network":                "Service",
    "networkpolicy":          "NetworkPolicy",
    "node":                   "Node",
    "persistentvolume":       "PersistentVolume",
    "persistentvolumeclaim":  "PersistentVolumeClaim",
    "pod":                    "Pod",
    "pod_security":           "PodSecurityPolicy",
    "podtemplate":            "PodTemplate",
    "policy":                 "PodDisruptionBudget",
    "rbac":                   "ClusterRole",
    "replicaset":             "ReplicaSet",
    "resource":               "ResourceQuota",
    "resourcequota":          "ResourceQuota",
    "role":                   "Role",
    "rolebinding":            "RoleBinding",
    "scheduler":              "ComponentStatus",
    "secret":                 "Secret",
    "service":                "Service",
    "serviceaccount":         "ServiceAccount",
    "software":               "Pod",
    "statefulset":            "StatefulSet",
    "storage":                "StorageClass",
    "storageclass":           "StorageClass",
    "workload":               "Deployment",
}


def _empty_check_cols() -> Dict[str, str]:
    return {c: "" for c in NEW_COLS}


def _load_severity_map() -> Dict[str, Dict[str, str]]:
    """rule_id → {severity, domain} from assertions YAML."""
    if not ASSERTIONS.exists():
        return {}
    with open(ASSERTIONS) as f:
        data = yaml.safe_load(f)
    sev_map: Dict[str, Dict[str, str]] = {}
    for svc_data in data.values():
        if not isinstance(svc_data, dict):
            continue
        for resource_rules in svc_data.values():
            if not isinstance(resource_rules, list):
                continue
            for entry in resource_rules:
                rule_id = entry.get("rule_id", "")
                if rule_id:
                    sev_map[rule_id] = {
                        "severity": entry.get("severity", "medium"),
                        "domain":   entry.get("domain", ""),
                    }
    return sev_map


def _load_check_rules() -> List[Dict]:
    """Load all check rules from *.checks.yaml files."""
    rules: List[Dict] = []
    for f in sorted(CHECKS_DIR.glob("*/*.checks.yaml")):
        with open(f) as fh:
            data = yaml.safe_load(fh)
        svc = data.get("service", f.parent.name)
        for chk in data.get("checks", []):
            cond = chk.get("conditions", {})
            if not isinstance(cond, dict):
                continue
            rules.append({
                "service":      svc,
                "rule_id":      chk.get("rule_id", ""),
                "for_each":     chk.get("for_each", ""),
                "var":          cond.get("var", ""),
                "op":           cond.get("op", ""),
                "value":        cond.get("value", ""),
            })
    return rules


def _make_condition_json(var: str, op: str, value) -> str:
    return json.dumps({"var": var, "op": op, "value": value}, ensure_ascii=False)


def _make_conditions_json(var: str, op: str, value) -> str:
    return json.dumps([{"var": var, "op": op, "value": value}], ensure_ascii=False)


def _synthetic_row(svc: str, rule: Dict, severity: str) -> Dict:
    """Build a minimal field row for a rule whose var has no entry in master CSV."""
    var = rule["var"]
    # Derive field_path from var (strip 'item.' prefix, collapse '[]')
    field_path = var.removeprefix("item.").replace("[]", "")
    return {
        "csp":                  "k8s",
        "service":              svc,
        "field_path":           field_path,
        "item_var_path":        var,
        "field_type":           "object",
        "is_id":                "No",
        "producing_op":         rule["for_each"],
        "op_kind":              "read_list",
        "is_independent":       "Yes",
        "root_op":              rule["for_each"],
        "chain_ops":            rule["for_each"],
        "chain_length":         "1",
        "hop_distance":         "0",
        "chain_ops_with_fields": "",
        "operators":            rule["op"],
        "operators_no_value":   rule["op"],
        "python_call":          "",
        "http_path":            "",
    }


def main() -> None:
    # ── 1. Load master field catalog ─────────────────────────────────────────
    with open(MASTER_CSV) as f:
        master_rows: List[Dict] = list(csv.DictReader(f))
    print(f"Loaded {len(master_rows)} rows from master CSV")

    # ── 2. Add new columns (empty) + fill inventory meta ─────────────────────
    rows: List[Dict] = []
    for r in master_rows:
        svc = r["service"]
        nr = dict(r)
        nr.update(_empty_check_cols())
        nr["resource_type"]      = RESOURCE_TYPE.get(svc, svc.capitalize())
        nr["resource_id_field"]  = "metadata.uid"
        nr["resource_id_param"]  = "name"
        rows.append(nr)
    print(f"Extended to {len(ALL_COLS)} columns")

    # ── 3. Load severity map ──────────────────────────────────────────────────
    sev_map = _load_severity_map()
    print(f"Loaded severity for {len(sev_map)} rules")

    # ── 4. Load check rules ───────────────────────────────────────────────────
    check_rules = _load_check_rules()
    print(f"Loaded {len(check_rules)} check rules")

    # ── 5. Build lookup: (service, producing_op, item_var_path) → [row_indices]
    # Tracks which master rows are available for assignment
    lookup: Dict[tuple, List[int]] = defaultdict(list)
    for i, r in enumerate(rows):
        key = (r["service"], r["producing_op"], r["item_var_path"])
        lookup[key].append(i)

    # Tracks which row indices have already been assigned a check rule
    assigned: set = set()
    extra_rows: List[Dict] = []

    matched = 0
    duplicated = 0
    synthetic = 0

    for rule in check_rules:
        svc       = rule["service"]
        for_each  = rule["for_each"]
        var       = rule["var"]
        rule_id   = rule["rule_id"]
        op        = rule["op"]
        value     = rule["value"]
        meta      = sev_map.get(rule_id, {})
        severity  = meta.get("severity", "medium")
        domain    = meta.get("domain", "")

        cond_json  = _make_condition_json(var, op, value)
        conds_json = _make_conditions_json(var, op, value)

        def fill_check(target: Dict) -> None:
            target["check_rule_id"]        = rule_id
            target["check_for_each"]       = for_each
            target["check_var"]            = var
            target["check_condition_op"]   = op
            target["check_condition_value"] = "" if value is None else str(value)
            target["check_condition"]      = cond_json
            target["check_conditions_json"] = conds_json
            target["check_severity"]       = severity
            target["check_frameworks"]     = domain
            target["check_description"]    = ""
            target["is_system_rule"]       = "true"
            target["is_active"]            = "true"
            target["needs_review"]         = "false"
            target["review_reason"]        = ""

        key = (svc, for_each, var)
        candidates = lookup.get(key, [])

        # Find first unassigned candidate
        free_idx: Optional[int] = None
        first_idx: Optional[int] = None
        for idx in candidates:
            if first_idx is None:
                first_idx = idx
            if idx not in assigned:
                free_idx = idx
                break

        if free_idx is not None:
            # Assign in-place
            fill_check(rows[free_idx])
            assigned.add(free_idx)
            matched += 1
        elif first_idx is not None:
            # All candidates taken → duplicate first matching row
            dup = dict(rows[first_idx])
            dup.update(_empty_check_cols())
            dup["resource_type"]     = rows[first_idx]["resource_type"]
            dup["resource_id_field"] = "metadata.uid"
            dup["resource_id_param"] = "name"
            fill_check(dup)
            extra_rows.append(dup)
            duplicated += 1
        else:
            # No field row exists → synthetic row
            syn = _synthetic_row(svc, rule, severity)
            syn.update(_empty_check_cols())
            syn["resource_type"]     = RESOURCE_TYPE.get(svc, svc.capitalize())
            syn["resource_id_field"] = "metadata.uid"
            syn["resource_id_param"] = "name"
            fill_check(syn)
            extra_rows.append(syn)
            synthetic += 1

    print(f"Rules matched in-place : {matched}")
    print(f"Rules duplicated rows  : {duplicated}")
    print(f"Rules synthetic rows   : {synthetic}")

    # ── 6. Write output CSV ───────────────────────────────────────────────────
    all_output_rows = rows + extra_rows
    with open(OUT_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=ALL_COLS)
        writer.writeheader()
        writer.writerows(all_output_rows)

    total_with_rules = sum(1 for r in all_output_rows if r.get("check_rule_id"))
    print(f"\nWrote {len(all_output_rows)} rows → {OUT_CSV}")
    print(f"Rows with check rule : {total_with_rules}")
    print(f"Rows without rule    : {len(all_output_rows) - total_with_rules}")


if __name__ == "__main__":
    main()
