#!/usr/bin/env python3
"""
K8s Discovery Generator — Full Step Pipeline

Generates step1 → step5 + step4a for every k8s resource so the directory
mirrors the AWS / Azure / GCP structure in catalog/discovery_generator/.

Source priority (per resource):
  1. lgtech data  (cspm-lgtech/…/data_pythonsdk/k8s/<svc>/)  — 17 core resources
  2. python_field_generator (catalog/python_field_generator/k8s/<svc>/) — 38 extras

Outputs per resource (catalog/discovery_generator/k8s/<svc>/):
  step1_api_driven_registry.json           — all operations (read + write)
  step2_read_operation_registry.json       — GET / read operations only
  step2_write_operation_registry.json      — mutating operations only
  step3_read_operation_dependency_chain.json — dependency chain for reads
  step4_fields_produced_index.json         — field → ops that produce it
  step4a_field_operator_value_table.csv    — CSV: field, type, operators …
  step5_resource_catalog_inventory_enrich.json — enriched catalog
  (step6 discovery YAML already exists — not touched)
"""

import csv
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

# ── paths ────────────────────────────────────────────────────────────────────
REPO          = Path("/Users/apple/Desktop/threat-engine")
DISC_GEN_K8S  = REPO / "catalog/discovery_generator/k8s"
LGTECH_K8S    = REPO / "cspm-lgtech/engine_input/engine_rule/input/data_pythonsdk/k8s"
PFG_K8S       = REPO / "catalog/python_field_generator/k8s"

NOW = datetime.now(timezone.utc).isoformat()

# ── operator helpers ─────────────────────────────────────────────────────────
TYPE_OPERATORS = {
    "string":  ["contains", "equals", "exists", "in", "not_equals", "not_in"],
    "boolean": ["equals", "exists", "not_equals"],
    "integer": ["equals", "exists", "greater_than", "less_than", "not_equals"],
    "number":  ["equals", "exists", "greater_than", "less_than", "not_equals"],
    "object":  ["equals", "exists", "not_equals"],
    "array":   ["contains", "equals", "exists", "not_equals"],
}
DEFAULT_OPS = ["equals", "exists", "not_equals"]

NO_VALUE_OPS  = {"exists"}
SELECT_OPS    = {"in", "not_in"}


def operators_for(field_info: dict) -> list:
    ftype  = field_info.get("type", "string").lower()
    is_enum = field_info.get("enum", False)
    pv     = field_info.get("possible_values") or []
    if is_enum and pv:
        return ["equals", "exists", "in", "not_equals", "not_in"]
    return TYPE_OPERATORS.get(ftype, DEFAULT_OPS)


def csv_row(svc: str, fname: str, finfo: dict) -> dict:
    ops      = operators_for(finfo)
    no_val   = sorted(o for o in ops if o in NO_VALUE_OPS)
    sel_ops  = sorted(o for o in ops if o in SELECT_OPS)
    man_ops  = sorted(o for o in ops if o not in NO_VALUE_OPS)
    pv       = finfo.get("possible_values") or []
    is_enum  = bool(finfo.get("enum", False) and pv)

    if pv:
        req_type = "Select from list"
        src      = "enum"
    elif no_val:
        req_type = "No value or manual input"
        src      = ""
    else:
        req_type = "Manual input only"
        src      = ""

    return {
        "service":                 svc,
        "field_name":              fname,
        "field_type":              finfo.get("type", "string"),
        "is_enum":                 "Yes" if is_enum else "No",
        "operators":               ", ".join(ops),
        "operators_no_value":      ", ".join(no_val),
        "operators_select_list":   ", ".join(sel_ops),
        "operators_manual_input":  ", ".join(man_ops),
        "value_requirement_type":  req_type,
        "possible_values":         ", ".join(str(v) for v in pv),
        "values_source":           src,
        "num_possible_values":     len(pv),
    }


CSV_COLS = [
    "service", "field_name", "field_type", "is_enum",
    "operators", "operators_no_value", "operators_select_list",
    "operators_manual_input", "value_requirement_type",
    "possible_values", "values_source", "num_possible_values",
]


# ── load source data ─────────────────────────────────────────────────────────

def load_step4_json(svc: str) -> dict | None:
    """Load k8s_dependencies_with_python_names_fully_enriched.json for a resource."""
    # Priority 1: lgtech (richer, security-annotated)
    lgtech_file = LGTECH_K8S / svc / "k8s_dependencies_with_python_names_fully_enriched.json"
    if lgtech_file.exists():
        d = json.loads(lgtech_file.read_text())
        return d.get(svc) or d.get(list(d.keys())[0])

    # Priority 2: python_field_generator (enriched for newer resources)
    pfg_file = PFG_K8S / svc / "k8s_dependencies_with_python_names_fully_enriched.json"
    if pfg_file.exists():
        d = json.loads(pfg_file.read_text())
        return d.get(svc) or d.get(list(d.keys())[0])

    # Priority 3: already in discovery_generator
    gen_file = DISC_GEN_K8S / svc / "k8s_dependencies_with_python_names_fully_enriched.json"
    if gen_file.exists():
        d = json.loads(gen_file.read_text())
        return d.get(svc) or d.get(list(d.keys())[0])

    return None


def load_dependency_index(svc: str) -> dict | None:
    for root in [LGTECH_K8S, DISC_GEN_K8S]:
        p = root / svc / "dependency_index.json"
        if p.exists():
            return json.loads(p.read_text())
    return None


def load_existing_csv(svc: str) -> list[dict] | None:
    """Load lgtech field_operator_value_table.csv if present."""
    p = LGTECH_K8S / svc / "field_operator_value_table.csv"
    if p.exists():
        with open(p) as f:
            return list(csv.DictReader(f))
    return None


# ── step generators ──────────────────────────────────────────────────────────

def make_step1(svc: str, entry: dict) -> dict:
    """step1_api_driven_registry.json — all operations."""
    ind  = entry.get("independent", [])
    dep  = entry.get("dependent", [])
    all_ops = ind + dep

    def enrich_op(op: dict, is_read: bool) -> dict:
        return {
            "operation":     op.get("operation", ""),
            "python_method": op.get("operation", "").replace("-", "_"),
            "yaml_action":   op.get("operation", ""),
            "http_method":   op.get("http_method", "GET" if is_read else "POST"),
            "description":   op.get("description", ""),
            "independent":   is_read,
            "required_params":  op.get("consumes", []),
            "optional_params":  [],
            "output_fields": list(op.get("item_fields", {}).keys()),
            "item_fields":   op.get("item_fields", {}),
        }

    return {
        svc: {
            "service":          svc,
            "csp":              "k8s",
            "api_version":      entry.get("api_version", "v1"),
            "kind":             entry.get("kind", svc.title()),
            "total_operations": len(all_ops),
            "independent":      [enrich_op(o, True)  for o in ind],
            "dependent":        [enrich_op(o, False) for o in dep],
        }
    }


def make_step2(svc: str, entry: dict) -> tuple[dict, dict]:
    """step2_read + step2_write operation registries."""
    ind_ops = entry.get("independent", [])
    dep_ops = entry.get("dependent", [])

    def build_registry(ops: list, label: str, independent: bool) -> dict:
        operations = {}
        for op in ops:
            name = op.get("operation", "")
            operations[name] = {
                "operation":    name,
                "service":      svc,
                "csp":          "k8s",
                "independent":  independent,
                "python_method": name.replace("-", "_"),
                "yaml_action":  name,
                "http_method":  op.get("http_method", "GET" if independent else "POST"),
                "required_params": op.get("consumes", []),
                "optional_params": [],
                "output_fields": list(op.get("item_fields", {}).keys()),
                "item_fields":  op.get("item_fields", {}),
            }
        return {
            "service":          svc,
            "csp":              "k8s",
            "generated_at":     NOW,
            "total_operations": len(ops),
            "independent_count": len(ops) if independent else 0,
            "dependent_count":   0 if independent else len(ops),
            "operations":       operations,
        }

    read_reg  = build_registry(ind_ops, "read",  True)
    write_reg = build_registry(dep_ops, "write", False)
    return read_reg, write_reg


def make_step3(svc: str, entry: dict, dep_index: dict | None) -> dict:
    """step3_read_operation_dependency_chain.json."""
    if dep_index:
        # Already have it — just standardise keys
        return {
            "service":   svc,
            "csp":       "k8s",
            "read_only": True,
            "generated_at": NOW,
            "roots":     dep_index.get("roots", []),
            "chains":    dep_index.get("chains", []),
        }

    # Build from independent ops
    roots = []
    for op in entry.get("independent", []):
        name   = op.get("operation", "")
        fields = [f"k8s.{svc}.{f}" for f in op.get("item_fields", {})]
        roots.append({
            "op":       f"k8s.{svc}.{name}",
            "produces": fields,
            "dependencies": [],
        })

    return {
        "service":      svc,
        "csp":          "k8s",
        "read_only":    True,
        "generated_at": NOW,
        "roots":        roots,
        "chains":       [],
    }


def make_step4(svc: str, entry: dict) -> dict:
    """step4_fields_produced_index.json — field → operations that produce it."""
    field_map: dict[str, dict] = {}

    for op in entry.get("independent", []):
        op_id = f"k8s.{svc}.{op.get('operation', '')}"
        for fname, finfo in op.get("item_fields", {}).items():
            key = f"k8s.{svc}.{fname}"
            if key not in field_map:
                field_map[key] = {
                    "field":         key,
                    "field_short":   fname,
                    "type":          finfo.get("type", "string"),
                    "description":   finfo.get("description", ""),
                    "compliance_category": finfo.get("compliance_category", "general"),
                    "security_impact":    finfo.get("security_impact"),
                    "enum":          finfo.get("enum", False),
                    "possible_values": finfo.get("possible_values"),
                    "produced_by":   [],
                }
            field_map[key]["produced_by"].append(op_id)

    return {
        "service":      svc,
        "csp":          "k8s",
        "generated_at": NOW,
        "total_fields": len(field_map),
        "fields":       field_map,
    }


def make_step4a_csv(svc: str, entry: dict, existing_csv: list | None) -> list[dict]:
    """step4a_field_operator_value_table.csv rows."""
    if existing_csv:
        # Lgtech CSV already correct format — just return it
        return existing_csv

    rows = []
    seen = set()
    for op in entry.get("independent", []):
        for fname, finfo in op.get("item_fields", {}).items():
            if fname not in seen:
                rows.append(csv_row(svc, fname, finfo))
                seen.add(fname)
    return rows


def make_step5(svc: str, entry: dict, step4: dict) -> dict:
    """step5_resource_catalog_inventory_enrich.json — enriched catalog."""
    ind_ops = entry.get("independent", [])
    key_op  = ind_ops[0] if ind_ops else {}

    # Security-relevant fields = those with security_impact or known security subcategories
    sec_fields = {
        k: v for k, v in step4["fields"].items()
        if v.get("security_impact") or v.get("compliance_category") in
           ("security", "identity", "network", "encryption")
    }

    return {
        "service":      svc,
        "csp":          "k8s",
        "api_version":  entry.get("api_version", "v1"),
        "kind":         entry.get("kind", svc.title()),
        "generated_at": NOW,
        "primary_operation": f"k8s.{svc}.{key_op.get('operation', 'list')}",
        "total_fields": step4["total_fields"],
        "security_relevant_fields": len(sec_fields),
        "field_summary": {
            k: {
                "type":             v["type"],
                "compliance_category": v["compliance_category"],
                "security_impact":  v["security_impact"],
                "produced_by":      v["produced_by"],
            }
            for k, v in step4["fields"].items()
        },
        "security_fields": {k: v for k, v in step4["fields"].items() if v.get("security_impact")},
    }


# ── per-resource runner ───────────────────────────────────────────────────────

def process_resource(svc: str):
    out_dir = DISC_GEN_K8S / svc
    out_dir.mkdir(parents=True, exist_ok=True)

    entry = load_step4_json(svc)
    if not entry:
        print(f"  [SKIP] {svc} — no step4 source found")
        return

    dep_index   = load_dependency_index(svc)
    existing_csv = load_existing_csv(svc)

    # ── step1 ──────────────────────────────────────────────────────────────
    step1 = make_step1(svc, entry)
    (out_dir / "step1_api_driven_registry.json").write_text(
        json.dumps(step1, indent=2))

    # ── step2 ──────────────────────────────────────────────────────────────
    step2_read, step2_write = make_step2(svc, entry)
    (out_dir / "step2_read_operation_registry.json").write_text(
        json.dumps(step2_read, indent=2))
    (out_dir / "step2_write_operation_registry.json").write_text(
        json.dumps(step2_write, indent=2))

    # ── step3 ──────────────────────────────────────────────────────────────
    step3 = make_step3(svc, entry, dep_index)
    (out_dir / "step3_read_operation_dependency_chain.json").write_text(
        json.dumps(step3, indent=2))

    # ── step4 ──────────────────────────────────────────────────────────────
    step4 = make_step4(svc, entry)
    (out_dir / "step4_fields_produced_index.json").write_text(
        json.dumps(step4, indent=2))

    # ── step4a CSV ──────────────────────────────────────────────────────────
    rows = make_step4a_csv(svc, entry, existing_csv)
    csv_path = out_dir / "step4a_field_operator_value_table.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLS)
        writer.writeheader()
        writer.writerows(rows)

    # ── step5 ──────────────────────────────────────────────────────────────
    step5 = make_step5(svc, entry, step4)
    (out_dir / "step5_resource_catalog_inventory_enrich.json").write_text(
        json.dumps(step5, indent=2))

    # ── copy source files if not already in out_dir ──────────────────────
    src_dep = dep_index  # already loaded
    # Copy dependency_index, direct_vars, minimal_operations_list from lgtech
    for fname in ["dependency_index.json", "direct_vars.json",
                  "minimal_operations_list.json", "resource_operations_prioritized.json"]:
        src = LGTECH_K8S / svc / fname
        dst = out_dir / fname
        if src.exists() and not dst.exists():
            shutil.copy2(src, dst)

    n_fields = step4["total_fields"]
    n_ops    = len(entry.get("independent", [])) + len(entry.get("dependent", []))
    print(f"  {svc:<35} ops={n_ops:<4} fields={n_fields:<4} csv={len(rows)}")


# ── K8s action → fields knowledge base ───────────────────────────────────────
# Used when a resource only has a step6 YAML (no step4 JSON source).
# Fields cover what the kubernetes.client returns for each list action.

def _sf(t="string", desc="", cat="general", sec=None, enum=False, vals=None):
    return {"type": t, "description": desc, "compliance_category": cat,
            "security_impact": sec, "enum": enum, "possible_values": vals}

K8S_ACTION_FIELDS: dict[str, dict] = {
    # ── Node ─────────────────────────────────────────────────────────────────
    "list_node": {
        "metadata.name":               _sf("string", "Node name", "identity"),
        "metadata.labels":             _sf("object", "Node labels", "identity"),
        "metadata.annotations":        _sf("object", "Node annotations", "identity"),
        "spec.podCIDR":                _sf("string", "Pod CIDR range", "network"),
        "spec.unschedulable":          _sf("boolean", "Whether node is unschedulable", "security"),
        "spec.taints":                 _sf("array", "Node taints", "security"),
        "status.conditions":           _sf("array", "Node health conditions", "security",
                                          sec="Conditions expose node readiness and disk/memory pressure"),
        "status.capacity.cpu":         _sf("string", "CPU capacity", "general"),
        "status.capacity.memory":      _sf("string", "Memory capacity", "general"),
        "status.nodeInfo.kubeletVersion":   _sf("string", "Kubelet version", "security",
                                              sec="Outdated kubelet versions may have known CVEs"),
        "status.nodeInfo.osImage":          _sf("string", "Node OS image", "security"),
        "status.nodeInfo.containerRuntimeVersion": _sf("string", "Container runtime version", "security",
                                                       sec="Outdated runtimes expose container escape vulnerabilities"),
    },
    # ── Admission webhooks ───────────────────────────────────────────────────
    "list_validating_webhook_configuration": {
        "metadata.name":               _sf("string", "Webhook configuration name", "identity"),
        "webhooks":                    _sf("array", "List of webhook definitions", "security",
                                          sec="Webhooks with failurePolicy=Ignore skip enforcement on errors"),
        "webhooks[].name":             _sf("string", "Webhook name", "identity"),
        "webhooks[].failurePolicy":    _sf("string", "Failure policy (Fail/Ignore)", "security",
                                          sec="Ignore allows requests through when webhook fails",
                                          enum=True, vals=["Fail", "Ignore"]),
        "webhooks[].rules":            _sf("array", "API operations matched by webhook", "security"),
        "webhooks[].namespaceSelector": _sf("object", "Namespace label selector", "security"),
        "webhooks[].sideEffects":      _sf("string", "Whether webhook has side effects", "security",
                                          enum=True, vals=["None", "NoneOnDryRun", "Some", "Unknown"]),
        "webhooks[].timeoutSeconds":   _sf("integer", "Webhook timeout (1-30s)", "security"),
    },
    "list_mutating_webhook_configuration": {
        "metadata.name":               _sf("string", "Webhook configuration name", "identity"),
        "webhooks":                    _sf("array", "List of mutating webhook definitions", "security",
                                          sec="Mutating webhooks can modify request objects — misconfiguration risks"),
        "webhooks[].name":             _sf("string", "Webhook name", "identity"),
        "webhooks[].failurePolicy":    _sf("string", "Failure policy", "security",
                                          enum=True, vals=["Fail", "Ignore"]),
        "webhooks[].rules":            _sf("array", "Matched API operations", "security"),
        "webhooks[].reinvocationPolicy": _sf("string", "Reinvocation policy", "security",
                                            enum=True, vals=["Never", "IfNeeded"]),
        "webhooks[].sideEffects":      _sf("string", "Side effects declaration", "security",
                                          enum=True, vals=["None", "NoneOnDryRun"]),
    },
    # ── API Server / Component Status ────────────────────────────────────────
    "list_component_status": {
        "metadata.name":               _sf("string", "Component name", "identity"),
        "conditions":                  _sf("array", "Component health conditions", "security",
                                          sec="Unhealthy components indicate cluster control-plane degradation"),
        "conditions[].type":           _sf("string", "Condition type", "security",
                                          enum=True, vals=["Healthy"]),
        "conditions[].status":         _sf("string", "Condition status", "security",
                                          enum=True, vals=["True", "False", "Unknown"]),
        "conditions[].message":        _sf("string", "Condition message", "general"),
    },
    "list_api_service": {
        "metadata.name":               _sf("string", "APIService name", "identity"),
        "spec.service":                _sf("object", "Service reference", "network"),
        "spec.insecureSkipTLSVerify":  _sf("boolean", "Skip TLS verification", "security",
                                          sec="Skipping TLS verification allows MITM attacks on API aggregation"),
        "spec.groupPriorityMinimum":   _sf("integer", "Group priority minimum", "general"),
        "spec.versionPriority":        _sf("integer", "Version priority", "general"),
        "status.conditions":           _sf("array", "APIService availability conditions", "security"),
    },
    # ── Audit ────────────────────────────────────────────────────────────────
    "list_audit_sink": {
        "metadata.name":               _sf("string", "AuditSink name", "identity"),
        "spec.policy.level":           _sf("string", "Audit level (None/Metadata/Request/RequestResponse)", "security",
                                          sec="Low audit levels miss security-relevant events",
                                          enum=True, vals=["None", "Metadata", "Request", "RequestResponse"]),
        "spec.policy.stages":          _sf("array", "Audit stages captured", "security"),
        "spec.webhook.clientConfig":   _sf("object", "Webhook destination config", "security"),
        "spec.webhook.throttle":       _sf("object", "Throttle configuration", "security"),
    },
    "list_event_for_all_namespaces": {
        "metadata.name":               _sf("string", "Event name", "identity"),
        "metadata.namespace":          _sf("string", "Namespace", "identity"),
        "reason":                      _sf("string", "Event reason", "security"),
        "message":                     _sf("string", "Event message", "security"),
        "type":                        _sf("string", "Event type", "security",
                                          enum=True, vals=["Normal", "Warning"]),
        "involvedObject.kind":         _sf("string", "Object kind", "identity"),
        "involvedObject.name":         _sf("string", "Object name", "identity"),
        "count":                       _sf("integer", "Number of occurrences", "general"),
    },
    # ── Certificates ─────────────────────────────────────────────────────────
    "list_certificate_signing_request": {
        "metadata.name":               _sf("string", "CSR name", "identity"),
        "metadata.annotations":        _sf("object", "CSR annotations", "identity"),
        "spec.signerName":             _sf("string", "Signer name", "security",
                                          sec="Custom signers may bypass certificate validation controls"),
        "spec.usages":                 _sf("array", "Certificate usages", "security"),
        "spec.expirationSeconds":      _sf("integer", "Requested expiration seconds", "security",
                                          sec="Long-lived certificates increase exposure window"),
        "status.conditions":           _sf("array", "Approval conditions", "security"),
        "status.certificate":          _sf("string", "Issued certificate (base64)", "security"),
    },
    # ── Horizontal Pod Autoscaler ────────────────────────────────────────────
    "list_horizontal_pod_autoscaler_for_all_namespaces": {
        "metadata.name":               _sf("string", "HPA name", "identity"),
        "metadata.namespace":          _sf("string", "Namespace", "identity"),
        "spec.minReplicas":            _sf("integer", "Minimum replicas", "security"),
        "spec.maxReplicas":            _sf("integer", "Maximum replicas", "security",
                                          sec="Unbounded maxReplicas can cause resource exhaustion"),
        "spec.scaleTargetRef":         _sf("object", "Target workload reference", "general"),
        "spec.metrics":                _sf("array", "Scaling metrics", "general"),
        "status.currentReplicas":      _sf("integer", "Current replica count", "general"),
    },
    # ── PodSecurityPolicy (deprecated) ───────────────────────────────────────
    "list_pod_security_policy": {
        "metadata.name":               _sf("string", "PSP name", "identity"),
        "spec.privileged":             _sf("boolean", "Allow privileged containers", "security",
                                          sec="Allowing privileged containers bypasses container isolation"),
        "spec.hostNetwork":            _sf("boolean", "Allow host network", "security"),
        "spec.hostPID":                _sf("boolean", "Allow host PID", "security"),
        "spec.hostIPC":                _sf("boolean", "Allow host IPC", "security"),
        "spec.readOnlyRootFilesystem": _sf("boolean", "Require read-only root filesystem", "security"),
        "spec.runAsUser.rule":         _sf("string", "Run-as-user rule", "security",
                                          enum=True, vals=["MustRunAsNonRoot", "MustRunAs", "RunAsAny"]),
        "spec.volumes":                _sf("array", "Allowed volume types", "security"),
        "spec.allowedCapabilities":    _sf("array", "Allowed Linux capabilities", "security",
                                          sec="Allowed capabilities expand container privilege scope"),
        "spec.requiredDropCapabilities": _sf("array", "Required capabilities to drop", "security"),
        "spec.seLinux.rule":           _sf("string", "SELinux rule", "security"),
        "spec.supplementalGroups.rule": _sf("string", "Supplemental groups rule", "security"),
    },
    # ── PodDisruptionBudget ──────────────────────────────────────────────────
    "list_pod_disruption_budget_for_all_namespaces": {
        "metadata.name":               _sf("string", "PDB name", "identity"),
        "metadata.namespace":          _sf("string", "Namespace", "identity"),
        "spec.minAvailable":           _sf("string", "Min available pods", "security"),
        "spec.maxUnavailable":         _sf("string", "Max unavailable pods", "security"),
        "spec.selector":               _sf("object", "Pod selector", "general"),
        "status.currentHealthy":       _sf("integer", "Currently healthy pods", "general"),
        "status.desiredHealthy":       _sf("integer", "Desired healthy pods", "general"),
        "status.disruptionsAllowed":   _sf("integer", "Disruptions allowed now", "general"),
    },
}

# Actions that map to existing resource step4 data (reuse their fields)
ACTION_TO_RESOURCE: dict[str, str] = {
    "list_pod_for_all_namespaces":                  "pod",
    "list_deployment_for_all_namespaces":            "deployment",
    "list_stateful_set_for_all_namespaces":          "statefulset",
    "list_daemon_set_for_all_namespaces":            "daemonset",
    "list_service_for_all_namespaces":               "service",
    "list_config_map_for_all_namespaces":            "configmap",
    "list_namespace":                                "namespace",
    "list_persistent_volume":                        "persistentvolume",
    "list_persistent_volume_claim_for_all_namespaces": "persistentvolumeclaim",
    "list_cluster_role":                             "clusterrole",
    "list_cluster_role_binding":                     "clusterrolebinding",
    "list_role_for_all_namespaces":                  "role",
    "list_role_binding_for_all_namespaces":          "rolebinding",
    "list_network_policy_for_all_namespaces":        "networkpolicy",
    "list_ingress_for_all_namespaces":               "ingress",
    "list_replica_set_for_all_namespaces":           "replicaset",
    "list_cron_job_for_all_namespaces":              "cronjob",
    "list_job_for_all_namespaces":                   "job",
    "list_limit_range_for_all_namespaces":           "limitrange",
    "list_resource_quota_for_all_namespaces":        "resourcequota",
    "list_storage_class":                            "storageclass",
    "list_horizontal_pod_autoscaler_for_all_namespaces": None,  # use knowledge base
    "list_pod_disruption_budget_for_all_namespaces": None,
}

_RESOURCE_FIELD_CACHE: dict[str, dict] = {}

def get_fields_for_action(action: str) -> dict:
    """Return item_fields for a k8s client action."""
    # 1. Direct knowledge base
    if action in K8S_ACTION_FIELDS:
        return K8S_ACTION_FIELDS[action]

    # 2. Delegate to existing resource step4
    resource = ACTION_TO_RESOURCE.get(action)
    if resource:
        if resource not in _RESOURCE_FIELD_CACHE:
            entry = load_step4_json(resource)
            if entry:
                for op in entry.get("independent", []):
                    if op.get("operation") == "list":
                        _RESOURCE_FIELD_CACHE[resource] = op.get("item_fields", {})
                        break
        return _RESOURCE_FIELD_CACHE.get(resource, {})

    return {}


def build_step4_from_step6(svc: str, step6_path: Path) -> dict | None:
    """Build a synthetic step4-compatible entry from a step6 discovery YAML."""
    import yaml as _yaml
    with open(step6_path) as f:
        doc = _yaml.safe_load(f)

    discoveries = doc.get("discovery", [])
    if not discoveries:
        return None

    # Collect all unique fields across all discovery operations
    all_fields: dict[str, dict] = {}
    independent_ops = []

    for disc in discoveries:
        action = ""
        for call in disc.get("calls", []):
            action = call.get("action", "")
            break
        if not action:
            continue

        fields = get_fields_for_action(action)
        all_fields.update(fields)
        independent_ops.append({
            "operation":    action,
            "http_method":  "GET",
            "description":  f"List {svc} resources via {action}",
            "item_fields":  fields,
        })

    if not independent_ops:
        return None

    return {
        "resource":    svc,
        "api_version": "v1",
        "kind":        svc.title(),
        "description": f"{svc} security view — aggregated from k8s API",
        "independent": independent_ops,
        "dependent":   [],
    }


def process_step6_only_resource(svc: str):
    """Process a resource that has only a step6 YAML — no step4 source."""
    out_dir   = DISC_GEN_K8S / svc
    step6_path = out_dir / f"step6_{svc}.discovery.yaml"
    if not step6_path.exists():
        print(f"  [SKIP] {svc} — no step6 YAML")
        return

    entry = build_step4_from_step6(svc, step6_path)
    if not entry:
        print(f"  [SKIP] {svc} — could not build step4 from step6")
        return

    # Write the synthetic step4 source so main pipeline can use it
    synth_path = out_dir / "k8s_dependencies_with_python_names_fully_enriched.json"
    synth_path.write_text(json.dumps({svc: entry}, indent=2))

    # Now run the standard pipeline
    dep_index    = None
    existing_csv = None

    step1 = make_step1(svc, entry)
    (out_dir / "step1_api_driven_registry.json").write_text(json.dumps(step1, indent=2))

    step2_read, step2_write = make_step2(svc, entry)
    (out_dir / "step2_read_operation_registry.json").write_text(json.dumps(step2_read, indent=2))
    (out_dir / "step2_write_operation_registry.json").write_text(json.dumps(step2_write, indent=2))

    step3 = make_step3(svc, entry, dep_index)
    (out_dir / "step3_read_operation_dependency_chain.json").write_text(json.dumps(step3, indent=2))

    step4 = make_step4(svc, entry)
    (out_dir / "step4_fields_produced_index.json").write_text(json.dumps(step4, indent=2))

    rows = make_step4a_csv(svc, entry, existing_csv)
    csv_path = out_dir / "step4a_field_operator_value_table.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLS)
        writer.writeheader()
        writer.writerows(rows)

    step5 = make_step5(svc, entry, step4)
    (out_dir / "step5_resource_catalog_inventory_enrich.json").write_text(json.dumps(step5, indent=2))

    n_fields = step4["total_fields"]
    n_ops    = len(entry.get("independent", []))
    print(f"  {svc:<35} ops={n_ops:<4} fields={n_fields:<4} csv={len(rows)}  [from step6]")


# ── main ──────────────────────────────────────────────────────────────────────

def main():
    # Collect all resource dirs from discovery_generator/k8s/
    existing = sorted([
        d.name for d in DISC_GEN_K8S.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    ])
    print(f"Found {len(existing)} resource dirs in discovery_generator/k8s/\n")
    print("Generating step1–step5 + step4a CSV...\n")

    done = step6_done = skipped = 0
    for svc in existing:
        if svc == "scripts":
            continue
        entry = load_step4_json(svc)
        if entry:
            process_resource(svc)
            done += 1
        else:
            # Try step6-only path
            step6 = DISC_GEN_K8S / svc / f"step6_{svc}.discovery.yaml"
            if step6.exists():
                process_step6_only_resource(svc)
                step6_done += 1
            else:
                print(f"  [SKIP] {svc} — no source data")
                skipped += 1

    print(f"\nDone: {done} from step4, {step6_done} from step6, {skipped} skipped")
    print(f"Output: {DISC_GEN_K8S}")


if __name__ == "__main__":
    main()
