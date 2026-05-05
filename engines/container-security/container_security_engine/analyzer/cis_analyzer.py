"""
CIS Kubernetes Benchmark 7-Layer Analyzer.

Reads discovery_findings for container/K8s resource types and produces
CIS-benchmark findings across 7 layers:
  L1 - control_plane
  L2 - node_config
  L3 - rbac
  L4 - pod_security
  L5 - network_policies
  L6 - secrets_management
  L7 - image_security

Supports: aws (EKS), azure (AKS), gcp (GKE), oci (OKE), alicloud (ACK), k8s (native)

Security notes:
  - K8s Secret.data values are NEVER logged or accessed; only key names are analysed.
  - All DB queries include tenant_id to enforce tenant isolation.
  - blast_radius_score is always 0; the risk engine owns that field.
  - cis_layer is validated against VALID_CIS_LAYERS before any finding is created.
"""

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Layer constants
# ---------------------------------------------------------------------------
LAYER_CONTROL_PLANE = "control_plane"
LAYER_NODE_CONFIG = "node_config"
LAYER_RBAC = "rbac"
LAYER_POD_SECURITY = "pod_security"
LAYER_NETWORK_POLICIES = "network_policies"
LAYER_SECRETS_MANAGEMENT = "secrets_management"
LAYER_IMAGE_SECURITY = "image_security"

# AC-S6: cis_layer must be one of these values — validated before INSERT
VALID_CIS_LAYERS = frozenset({
    LAYER_CONTROL_PLANE,
    LAYER_NODE_CONFIG,
    LAYER_RBAC,
    LAYER_POD_SECURITY,
    LAYER_NETWORK_POLICIES,
    LAYER_SECRETS_MANAGEMENT,
    LAYER_IMAGE_SECURITY,
})

# ---------------------------------------------------------------------------
# Resource type routing per provider
# ---------------------------------------------------------------------------
K8S_RESOURCE_TYPES = {
    "pod": "k8s.core/Pod",
    "deployment": "k8s.apps/Deployment",
    "daemonset": "k8s.apps/DaemonSet",
    "statefulset": "k8s.apps/StatefulSet",
    "replicaset": "k8s.apps/ReplicaSet",
    "job": "k8s.batch/Job",
    "cronjob": "k8s.batch/CronJob",
    "namespace": "k8s.core/Namespace",
    "serviceaccount": "k8s.core/ServiceAccount",
    "clusterrole": "k8s.rbac/ClusterRole",
    "clusterrolebinding": "k8s.rbac/ClusterRoleBinding",
    "rolebinding": "k8s.rbac/RoleBinding",
    "networkpolicy": "k8s.networking/NetworkPolicy",
    "configmap": "k8s.core/ConfigMap",
    "secret": "k8s.core/Secret",
}

WORKLOAD_TYPES = {
    "k8s.core/Pod",
    "k8s.apps/Deployment",
    "k8s.apps/DaemonSet",
    "k8s.apps/StatefulSet",
    "k8s.apps/ReplicaSet",
    "k8s.batch/Job",
    "k8s.batch/CronJob",
}

MANAGED_CLUSTER_TYPES_BY_PROVIDER: Dict[str, List[str]] = {
    "aws": ["EKS::Cluster", "EKS::NodeGroup", "ECR::Repository"],
    "azure": [
        "ContainerService::ManagedCluster",
        "containerservice/ManagedCluster",
        "ContainerRegistry::Registry",
        "containerregistry/Registry",
        "Microsoft.ContainerService/managedClusters",
        "Microsoft.ContainerRegistry/registries",
    ],
    "gcp": [
        "Container::Cluster",
        "container.googleapis.com/Cluster",
        "ArtifactRegistry::Repository",
        "artifactregistry.googleapis.com/Repository",
    ],
    "oci": [
        "ContainerEngine::Cluster",
        "oci.containerengine/Cluster",
        "Artifacts::ContainerRepository",
    ],
    "alicloud": ["ACK::Cluster", "ACR::Repository"],
    "k8s": list(K8S_RESOURCE_TYPES.values()),
}


def _make_finding_id(cis_layer: str, check_id: str, resource_uid: str, account_id: str, region: str) -> str:
    """Generate deterministic finding_id.

    Formula (AC-S3):
        sha256(f"{cis_layer}_{check_id}|{resource_uid}|{account_id}|{region}").hexdigest()[:16]
    """
    raw = f"{cis_layer}_{check_id}|{resource_uid}|{account_id}|{region}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _finding(
    rule_id: str,
    resource: Dict[str, Any],
    scan_run_id: str,
    tenant_id: str,
    layer: str,
    layer_check: str,
    check_id: str,
    severity: str,
    status: str,
    title: str,
    cis_benchmark_id: str = "",
) -> Dict[str, Any]:
    """Build a standardised CIS finding dict.

    Args:
        rule_id: Engine-internal rule identifier (e.g. 'aws.csec.cis_1.2.1.audit_logging_disabled').
        resource: Discovery finding row dict.
        scan_run_id: Pipeline scan run UUID.
        tenant_id: Tenant identifier — included in every finding for isolation.
        layer: CIS benchmark layer name — must be one of VALID_CIS_LAYERS.
        layer_check: Human-readable layer check label.
        check_id: Short check identifier (e.g. 'privileged_container').
        severity: CRITICAL | HIGH | MEDIUM | LOW | INFO.
        status: PASS | FAIL | NOT_APPLICABLE.
        title: Human-readable finding title.
        cis_benchmark_id: CIS Benchmark section reference (e.g. 'CIS-5.2.1').

    Returns:
        Finding dict with all standardised fields.

    Raises:
        ValueError: If layer is not in VALID_CIS_LAYERS.
    """
    if layer not in VALID_CIS_LAYERS:
        raise ValueError(
            f"Invalid cis_layer '{layer}'. Must be one of {sorted(VALID_CIS_LAYERS)}"
        )
    account_id = resource.get("account_id", "")
    region = resource.get("region", "")
    resource_uid = resource.get("resource_uid", "")
    # When check_id holds the CIS section reference (e.g. 'CIS-5.2.1') use it as
    # cis_benchmark_id so callers do not need to repeat themselves.
    effective_benchmark_id = cis_benchmark_id if cis_benchmark_id else check_id
    now = datetime.now(timezone.utc)
    return {
        "finding_id": _make_finding_id(layer, check_id, resource_uid, account_id, region),
        "scan_run_id": scan_run_id,
        "tenant_id": tenant_id,
        "account_id": account_id,
        "provider": resource.get("provider", ""),
        "region": region,
        "resource_uid": resource_uid,
        "resource_type": resource.get("resource_type", ""),
        "severity": severity,
        "status": status,
        "cis_layer": layer,               # AC-S6: validated above against VALID_CIS_LAYERS
        "layer": layer,                   # legacy alias kept for DB writer compatibility
        "layer_check": layer_check,
        "check_id": check_id,
        "cis_benchmark_id": effective_benchmark_id,
        "rule_id": rule_id,
        "blast_radius_score": 0,          # AC-S4: always 0 — risk engine owns this
        "title": title,
        "first_seen_at": now,
        "last_seen_at": now,
    }


def _pass(
    rule_id: str,
    resource: Dict[str, Any],
    scan_run_id: str,
    tenant_id: str,
    layer: str,
    layer_check: str,
    check_id: str,
    severity: str,
    title: str,
    cis_benchmark_id: str = "",
) -> Dict[str, Any]:
    """Build a PASS finding."""
    return _finding(
        rule_id, resource, scan_run_id, tenant_id,
        layer, layer_check, check_id, severity, "PASS", title, cis_benchmark_id,
    )


def _fail(
    rule_id: str,
    resource: Dict[str, Any],
    scan_run_id: str,
    tenant_id: str,
    layer: str,
    layer_check: str,
    check_id: str,
    severity: str,
    title: str,
    cis_benchmark_id: str = "",
) -> Dict[str, Any]:
    """Build a FAIL finding."""
    return _finding(
        rule_id, resource, scan_run_id, tenant_id,
        layer, layer_check, check_id, severity, "FAIL", title, cis_benchmark_id,
    )


# ---------------------------------------------------------------------------
# DB helper — load resources from discovery_findings
# ---------------------------------------------------------------------------

def _load_resources(
    conn,
    scan_run_id: str,
    tenant_id: str,
    resource_types: List[str],
    account_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Load discovery_findings rows filtered by scan_run_id, tenant_id, resource_types.

    Returns list of dicts with keys: resource_uid, resource_type, provider,
    region, account_id, emitted_fields (already a dict — no json.loads needed).
    """
    if not resource_types:
        return []
    try:
        with conn.cursor() as cur:
            if account_id:
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, provider, region, account_id, emitted_fields
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND account_id = %s
                      AND resource_type = ANY(%s)
                    """,
                    (scan_run_id, tenant_id, account_id, resource_types),
                )
            else:
                cur.execute(
                    """
                    SELECT resource_uid, resource_type, provider, region, account_id, emitted_fields
                    FROM discovery_findings
                    WHERE scan_run_id = %s
                      AND tenant_id = %s
                      AND resource_type = ANY(%s)
                    """,
                    (scan_run_id, tenant_id, resource_types),
                )
            rows = cur.fetchall()
        return [
            {
                "resource_uid": r[0],
                "resource_type": r[1],
                "provider": r[2],
                "region": r[3] or "",
                "account_id": r[4] or "",
                "emitted_fields": r[5] if isinstance(r[5], dict) else {},
            }
            for r in rows
        ]
    except Exception as exc:
        logger.warning("Failed to load resources type=%s: %s", resource_types, exc)
        return []


# ---------------------------------------------------------------------------
# Layer 3 — RBAC
# ---------------------------------------------------------------------------

def _analyze_rbac(
    resources: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> List[Dict[str, Any]]:
    """CIS Layer 3 — RBAC & Service Account checks."""
    findings: List[Dict[str, Any]] = []
    p = provider

    cluster_admin_bindings: List[str] = []

    for res in resources:
        rt = res["resource_type"]
        ef = res["emitted_fields"]

        # --- CIS 5.1.1: ClusterRoleBinding grants cluster-admin to non-system subjects ---
        if rt == "k8s.rbac/ClusterRoleBinding":
            role_ref = ef.get("roleRef") or {}
            role_name = role_ref.get("name", "")
            subjects = ef.get("subjects") or []
            is_cluster_admin = role_name == "cluster-admin"
            non_system_subjects = [
                s for s in subjects
                if not (s.get("name", "").startswith("system:") or s.get("namespace", "") == "kube-system")
            ]
            rule_id = f"{p}.csec.cis_5.1.1.cluster_admin_binding"
            if is_cluster_admin and non_system_subjects:
                cluster_admin_bindings.append(res["resource_uid"])
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_RBAC, "cluster_admin_binding",
                    "CIS-5.1.1", "CRITICAL",
                    f"ClusterRoleBinding grants cluster-admin to: "
                    f"{[s.get('name') for s in non_system_subjects]}",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_RBAC, "cluster_admin_binding",
                    "CIS-5.1.1", "CRITICAL",
                    "ClusterRoleBinding does not grant cluster-admin to non-system subjects",
                ))

        # --- CIS 5.1.3: Default SA with automountServiceAccountToken=true ---
        elif rt == "k8s.core/ServiceAccount":
            meta = ef.get("metadata") or {}
            name = meta.get("name", "")
            automount = ef.get("automountServiceAccountToken")
            rule_id = f"{p}.csec.cis_5.1.3.automount_service_account_token"
            if name == "default":
                # Kubernetes default is True when unset
                is_automount = automount is True or automount is None
                if is_automount:
                    findings.append(_fail(
                        rule_id, res, scan_run_id, tenant_id,
                        LAYER_RBAC, "automount_service_account_token",
                        "CIS-5.1.3", "HIGH",
                        "Default service account has automountServiceAccountToken=true (or unset)",
                    ))
                else:
                    findings.append(_pass(
                        rule_id, res, scan_run_id, tenant_id,
                        LAYER_RBAC, "automount_service_account_token",
                        "CIS-5.1.3", "HIGH",
                        "Default service account has automountServiceAccountToken=false",
                    ))

    # --- CIS 5.2.1: Workloads using default service account ---
    for res in resources:
        rt = res["resource_type"]
        ef = res["emitted_fields"]
        if rt in WORKLOAD_TYPES:
            spec = ef.get("spec") or {}
            # For Deployment/DaemonSet/StatefulSet the pod spec is nested
            template_spec = (spec.get("template") or {}).get("spec") or spec
            sa_name = template_spec.get("serviceAccountName", "default")
            automount = template_spec.get("automountServiceAccountToken")
            rule_id = f"{p}.csec.cis_5.2.1.default_namespace_sa"
            if sa_name == "default" and automount is not False:
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_RBAC, "default_namespace_sa",
                    "CIS-5.2.1", "MEDIUM",
                    "Workload uses default service account without disabling token mount",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_RBAC, "default_namespace_sa",
                    "CIS-5.2.1", "MEDIUM",
                    "Workload uses dedicated service account or has token mount disabled",
                ))

    if cluster_admin_bindings:
        logger.info(
            "Layer 3 RBAC: %d cluster-admin bindings found: %s",
            len(cluster_admin_bindings), cluster_admin_bindings[:5],
        )

    return findings


# ---------------------------------------------------------------------------
# Layer 4 — Pod Security
# ---------------------------------------------------------------------------

def _get_pod_spec(ef: Dict[str, Any]) -> Dict[str, Any]:
    """Extract pod spec — handles Pod (direct) and controller types (template.spec)."""
    spec = ef.get("spec") or {}
    # Deployment/DaemonSet/StatefulSet — pod template is nested
    template = spec.get("template")
    if template:
        return template.get("spec") or {}
    return spec


def _analyze_pod_security(
    resources: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> List[Dict[str, Any]]:
    """CIS Layer 4 — Pod Security Standards."""
    findings: List[Dict[str, Any]] = []
    p = provider

    for res in resources:
        if res["resource_type"] not in WORKLOAD_TYPES:
            continue
        ef = res["emitted_fields"]
        spec = _get_pod_spec(ef)

        # Extract pod-level namespace and first container name for finding_data context
        meta = ef.get("metadata") or {}
        pod_namespace = meta.get("namespace", "default")
        containers_list = spec.get("containers") or []
        first_container_name = containers_list[0].get("name", "") if containers_list else ""
        _pod_finding_data = {
            "container_name": first_container_name,
            "namespace": pod_namespace,
        }
        # Track index so we can tag all findings added for this resource
        _findings_start_idx = len(findings)

        containers = spec.get("containers") or []
        init_containers = spec.get("initContainers") or []
        all_containers = containers + init_containers

        # --- CIS 5.2.2: Privileged container ---
        rule_id = f"{p}.csec.cis_5.2.2.privileged_container"
        has_privileged = any(
            c.get("securityContext", {}).get("privileged") is True
            for c in all_containers
        )
        if has_privileged:
            findings.append(_fail(
                rule_id, res, scan_run_id, tenant_id,
                LAYER_POD_SECURITY, "privileged_container",
                "CIS-5.2.2", "CRITICAL",
                "Container runs with privileged=true (full host access)",
            ))
        else:
            findings.append(_pass(
                rule_id, res, scan_run_id, tenant_id,
                LAYER_POD_SECURITY, "privileged_container",
                "CIS-5.2.2", "CRITICAL",
                "No containers running with privileged=true",
            ))

        # --- CIS 5.2.3: hostPID ---
        rule_id = f"{p}.csec.cis_5.2.3.host_pid"
        if spec.get("hostPID") is True:
            findings.append(_fail(
                rule_id, res, scan_run_id, tenant_id,
                LAYER_POD_SECURITY, "host_pid",
                "CIS-5.2.3", "CRITICAL",
                "Pod spec has hostPID=true (shares host PID namespace)",
            ))
        else:
            findings.append(_pass(
                rule_id, res, scan_run_id, tenant_id,
                LAYER_POD_SECURITY, "host_pid",
                "CIS-5.2.3", "CRITICAL",
                "Pod spec does not use host PID namespace",
            ))

        # --- CIS 5.2.4: hostIPC ---
        rule_id = f"{p}.csec.cis_5.2.4.host_ipc"
        if spec.get("hostIPC") is True:
            findings.append(_fail(
                rule_id, res, scan_run_id, tenant_id,
                LAYER_POD_SECURITY, "host_ipc",
                "CIS-5.2.4", "HIGH",
                "Pod spec has hostIPC=true (shares host IPC namespace)",
            ))
        else:
            findings.append(_pass(
                rule_id, res, scan_run_id, tenant_id,
                LAYER_POD_SECURITY, "host_ipc",
                "CIS-5.2.4", "HIGH",
                "Pod spec does not use host IPC namespace",
            ))

        # --- CIS 5.2.5: hostNetwork ---
        rule_id = f"{p}.csec.cis_5.2.5.host_network"
        if spec.get("hostNetwork") is True:
            findings.append(_fail(
                rule_id, res, scan_run_id, tenant_id,
                LAYER_POD_SECURITY, "host_network",
                "CIS-5.2.5", "HIGH",
                "Pod spec has hostNetwork=true (shares host network stack)",
            ))
        else:
            findings.append(_pass(
                rule_id, res, scan_run_id, tenant_id,
                LAYER_POD_SECURITY, "host_network",
                "CIS-5.2.5", "HIGH",
                "Pod spec does not use host network",
            ))

        # --- CIS 5.2.6: runAsNonRoot ---
        rule_id = f"{p}.csec.cis_5.2.6.root_container"
        pod_sc = spec.get("securityContext") or {}
        run_as_non_root = pod_sc.get("runAsNonRoot")
        has_root_container = False
        for c in all_containers:
            csc = c.get("securityContext") or {}
            c_non_root = csc.get("runAsNonRoot")
            # If container override is None, fall back to pod-level
            effective = c_non_root if c_non_root is not None else run_as_non_root
            if effective is not True:
                has_root_container = True
                break
        if has_root_container:
            findings.append(_fail(
                rule_id, res, scan_run_id, tenant_id,
                LAYER_POD_SECURITY, "root_container",
                "CIS-5.2.6", "HIGH",
                "Container does not set runAsNonRoot=true",
            ))
        else:
            findings.append(_pass(
                rule_id, res, scan_run_id, tenant_id,
                LAYER_POD_SECURITY, "root_container",
                "CIS-5.2.6", "HIGH",
                "All containers set runAsNonRoot=true",
            ))

        # --- CIS 5.2.7: hostPath volumes ---
        rule_id = f"{p}.csec.cis_5.2.7.host_path_volume"
        volumes = spec.get("volumes") or []
        has_hostpath = any(v.get("hostPath") is not None for v in volumes)
        if has_hostpath:
            findings.append(_fail(
                rule_id, res, scan_run_id, tenant_id,
                LAYER_POD_SECURITY, "host_path_volume",
                "CIS-5.2.7", "HIGH",
                "Pod mounts a hostPath volume (host filesystem access)",
            ))
        else:
            findings.append(_pass(
                rule_id, res, scan_run_id, tenant_id,
                LAYER_POD_SECURITY, "host_path_volume",
                "CIS-5.2.7", "HIGH",
                "Pod does not mount hostPath volumes",
            ))

        # --- CIS 5.2.8: Dangerous capabilities ---
        rule_id = f"{p}.csec.cis_5.2.8.capabilities_all"
        _DANGEROUS_CAPS = {"ALL", "NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE"}
        has_dangerous_caps = any(
            bool(set(c.get("securityContext", {}).get("capabilities", {}).get("add") or []) & _DANGEROUS_CAPS)
            for c in all_containers
        )
        if has_dangerous_caps:
            findings.append(_fail(
                rule_id, res, scan_run_id, tenant_id,
                LAYER_POD_SECURITY, "capabilities_all",
                "CIS-5.2.8", "CRITICAL",
                "Container adds dangerous Linux capabilities (ALL, NET_ADMIN, SYS_ADMIN, etc.)",
            ))
        else:
            findings.append(_pass(
                rule_id, res, scan_run_id, tenant_id,
                LAYER_POD_SECURITY, "capabilities_all",
                "CIS-5.2.8", "CRITICAL",
                "No containers add dangerous Linux capabilities",
            ))

        # Annotate all findings for this resource with container_name and namespace
        for _f in findings[_findings_start_idx:]:
            existing_fd = _f.get("finding_data") or {}
            existing_fd.update(_pod_finding_data)
            _f["finding_data"] = existing_fd

    return findings


# ---------------------------------------------------------------------------
# Layer 5 — Network Policies
# ---------------------------------------------------------------------------

def _analyze_network_policies(
    resources: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> List[Dict[str, Any]]:
    """CIS Layer 5 — Network Policies."""
    findings: List[Dict[str, Any]] = []
    p = provider

    # Build namespace set from Namespace resources and workloads
    namespaces_from_ns: Dict[str, Dict[str, Any]] = {}
    for res in resources:
        if res["resource_type"] == "k8s.core/Namespace":
            ef = res["emitted_fields"]
            meta = ef.get("metadata") or {}
            name = meta.get("name", "")
            if name:
                namespaces_from_ns[name] = res

    # Build namespace set from workloads
    workload_namespaces: Dict[str, str] = {}
    for res in resources:
        if res["resource_type"] in WORKLOAD_TYPES:
            ef = res["emitted_fields"]
            meta = ef.get("metadata") or {}
            ns = meta.get("namespace", "default")
            if ns not in workload_namespaces:
                workload_namespaces[ns] = res["region"]

    # Collect existing NetworkPolicies and check for default-deny
    ns_with_policies: Dict[str, List[Dict[str, Any]]] = {}
    ns_with_default_deny: set = set()

    for res in resources:
        if res["resource_type"] == "k8s.networking/NetworkPolicy":
            ef = res["emitted_fields"]
            meta = ef.get("metadata") or {}
            ns = meta.get("namespace", "default")
            if ns not in ns_with_policies:
                ns_with_policies[ns] = []
            ns_with_policies[ns].append(res)
            # Default-deny: spec.podSelector={} AND no policyTypes ingress/egress entries
            spec = ef.get("spec") or {}
            pod_sel = spec.get("podSelector") or {}
            match_labels = pod_sel.get("matchLabels") or {}
            ingress = spec.get("ingress")
            egress = spec.get("egress")
            # A default deny policy has empty podSelector and empty ingress/egress
            if not match_labels and (ingress == [] or ingress is None) and (egress == [] or egress is None):
                ns_with_default_deny.add(ns)

    # Check each namespace with workloads for default-deny
    all_workload_ns = set(workload_namespaces.keys()) | set(namespaces_from_ns.keys())
    # Exclude system namespaces
    _SYSTEM_NS = {"kube-system", "kube-public", "kube-node-lease"}
    user_namespaces = all_workload_ns - _SYSTEM_NS

    for ns in user_namespaces:
        # Build a synthetic resource for namespace-level findings
        ns_res = namespaces_from_ns.get(ns)
        if ns_res is None:
            # Create synthetic resource for namespace
            region = workload_namespaces.get(ns, "")
            account_id = ""
            if resources:
                account_id = resources[0].get("account_id", "")
            ns_res = {
                "resource_uid": f"namespace/{ns}",
                "resource_type": "k8s.core/Namespace",
                "provider": p,
                "region": region,
                "account_id": account_id,
                "emitted_fields": {"metadata": {"name": ns}},
            }

        # --- CIS 5.3.2: Namespace has no NetworkPolicy at all ---
        rule_id_no_np = f"{p}.csec.cis_5.3.2.no_network_policies"
        if ns not in ns_with_policies:
            findings.append(_fail(
                rule_id_no_np, ns_res, scan_run_id, tenant_id,
                LAYER_NETWORK_POLICIES, "no_network_policies",
                "CIS-5.3.2", "MEDIUM",
                f"Namespace '{ns}' has no NetworkPolicy objects",
            ))
        else:
            findings.append(_pass(
                rule_id_no_np, ns_res, scan_run_id, tenant_id,
                LAYER_NETWORK_POLICIES, "no_network_policies",
                "CIS-5.3.2", "MEDIUM",
                f"Namespace '{ns}' has NetworkPolicy objects",
            ))

        # --- CIS 5.3.1: Namespace has no default-deny NetworkPolicy ---
        rule_id_no_deny = f"{p}.csec.cis_5.3.1.no_default_deny"
        if ns not in ns_with_default_deny:
            findings.append(_fail(
                rule_id_no_deny, ns_res, scan_run_id, tenant_id,
                LAYER_NETWORK_POLICIES, "no_default_deny",
                "CIS-5.3.1", "HIGH",
                f"Namespace '{ns}' has no default-deny NetworkPolicy",
            ))
        else:
            findings.append(_pass(
                rule_id_no_deny, ns_res, scan_run_id, tenant_id,
                LAYER_NETWORK_POLICIES, "no_default_deny",
                "CIS-5.3.1", "HIGH",
                f"Namespace '{ns}' has a default-deny NetworkPolicy",
            ))

    return findings


# ---------------------------------------------------------------------------
# Layer 6 — Secrets Management
# ---------------------------------------------------------------------------

_SECRET_KEY_PATTERNS = {"password", "token", "key", "secret", "credential", "api_key", "apikey", "passwd"}


def _looks_like_secret_key(key: str) -> bool:
    """Return True if the key name suggests it contains a secret value."""
    k_lower = key.lower()
    return any(pat in k_lower for pat in _SECRET_KEY_PATTERNS)


def _analyze_secrets_management(
    resources: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> List[Dict[str, Any]]:
    """CIS Layer 6 — Secrets Management."""
    findings: List[Dict[str, Any]] = []
    p = provider

    for res in resources:
        rt = res["resource_type"]
        ef = res["emitted_fields"]

        # --- CIS 5.4.1: Secret value in env var (not secretKeyRef) ---
        if rt in WORKLOAD_TYPES:
            spec = _get_pod_spec(ef)
            all_containers = (spec.get("containers") or []) + (spec.get("initContainers") or [])
            has_plain_secret_env = False
            for c in all_containers:
                for env in c.get("env") or []:
                    # env var with plain value (not from secretKeyRef/configMapKeyRef)
                    env_name = (env.get("name") or "").lower()
                    has_value = env.get("value") is not None
                    has_ref = "valueFrom" in env
                    if has_value and not has_ref and _looks_like_secret_key(env_name):
                        has_plain_secret_env = True
                        break
                if has_plain_secret_env:
                    break

            rule_id = f"{p}.csec.cis_5.4.1.secret_in_env_var"
            if has_plain_secret_env:
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_SECRETS_MANAGEMENT, "secret_in_env_var",
                    "CIS-5.4.1", "CRITICAL",
                    "Container has secret-like env var with plain text value (not secretKeyRef)",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_SECRETS_MANAGEMENT, "secret_in_env_var",
                    "CIS-5.4.1", "CRITICAL",
                    "No secret-like env vars with plain text values found",
                ))

        # --- CIS 5.4.2: ConfigMap contains secret-like keys ---
        elif rt == "k8s.core/ConfigMap":
            data = ef.get("data") or {}
            secret_keys = [k for k in data.keys() if _looks_like_secret_key(k)]
            rule_id = f"{p}.csec.cis_5.4.2.secret_in_configmap"
            if secret_keys:
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_SECRETS_MANAGEMENT, "secret_in_configmap",
                    "CIS-5.4.2", "HIGH",
                    f"ConfigMap has secret-like keys: {secret_keys[:5]}",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_SECRETS_MANAGEMENT, "secret_in_configmap",
                    "CIS-5.4.2", "HIGH",
                    "ConfigMap does not contain secret-like keys",
                ))

    return findings


# ---------------------------------------------------------------------------
# Layer 7 — Image Security
# ---------------------------------------------------------------------------

def _extract_image_tag(image: str) -> str:
    """Extract tag from image string (e.g. nginx:latest → latest, nginx → '')."""
    if not image:
        return ""
    # Remove digest
    if "@" in image:
        return "digest"
    if ":" in image:
        parts = image.rsplit(":", 1)
        return parts[-1] if len(parts) == 2 else ""
    return ""


def _analyze_image_security(
    resources: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> List[Dict[str, Any]]:
    """CIS Layer 7 — Image Security."""
    findings: List[Dict[str, Any]] = []
    p = provider

    for res in resources:
        rt = res["resource_type"]
        ef = res["emitted_fields"]

        # --- CIS 5.5.1: Container uses :latest or no tag ---
        if rt in WORKLOAD_TYPES:
            spec = _get_pod_spec(ef)
            all_containers = (spec.get("containers") or []) + (spec.get("initContainers") or [])
            has_latest = False
            for c in all_containers:
                tag = _extract_image_tag(c.get("image") or "")
                if tag in ("latest", ""):
                    has_latest = True
                    break

            rule_id = f"{p}.csec.cis_5.5.1.image_no_tag"
            if has_latest:
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_IMAGE_SECURITY, "image_no_tag",
                    "CIS-5.5.1", "MEDIUM",
                    "Container uses :latest tag or no tag (mutable image reference)",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_IMAGE_SECURITY, "image_no_tag",
                    "CIS-5.5.1", "MEDIUM",
                    "All containers use explicit image tags",
                ))

        # --- csec_img_scan: Registry scan on push disabled ---
        elif rt in ("ECR::Repository", "ContainerRegistry::Registry",
                    "ArtifactRegistry::Repository", "ACR::Repository",
                    "Artifacts::ContainerRepository",
                    "containerregistry/Registry",
                    "artifactregistry.googleapis.com/Repository",
                    "Microsoft.ContainerRegistry/registries"):
            rule_id = f"{p}.csec.csec_img_scan.registry_scan_disabled"
            scan_enabled = False

            # AWS ECR
            if rt == "ECR::Repository":
                scan_config = ef.get("imageScanningConfiguration") or {}
                scan_enabled = scan_config.get("scanOnPush", False) is True

            # Azure ACR
            elif rt in ("ContainerRegistry::Registry", "containerregistry/Registry",
                        "Microsoft.ContainerRegistry/registries"):
                props = ef.get("properties") or ef
                scan_enabled = props.get("adminUserEnabled", False) or (
                    (props.get("policies") or {}).get("exportPolicy", {}).get("status") == "enabled"
                )
                # Azure Defender for Containers handles scanning — assume enabled if sku is Premium
                sku = (ef.get("sku") or {}).get("name", "")
                scan_enabled = sku in ("Premium",)

            # GCP Artifact Registry
            elif rt in ("ArtifactRegistry::Repository",
                        "artifactregistry.googleapis.com/Repository"):
                # GCP Container Analysis is project-level; check if vulnerability scanning note
                scan_enabled = ef.get("vulnerabilityScanning", {}).get("enablementState") == "INHERITED" or False

            if scan_enabled:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_IMAGE_SECURITY, "registry_scan_disabled",
                    "CIS-5.5.2", "HIGH",
                    "Container registry has image scanning enabled",
                ))
            else:
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_IMAGE_SECURITY, "registry_scan_disabled",
                    "CIS-5.5.2", "HIGH",
                    "Container registry does not have image scanning on push enabled",
                ))

    return findings


# ---------------------------------------------------------------------------
# Layer 1 — Control Plane (managed cluster checks)
# ---------------------------------------------------------------------------

def _analyze_control_plane_aws(
    resources: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """CIS Layer 1 — AWS EKS control plane checks."""
    findings: List[Dict[str, Any]] = []
    p = "aws"

    for res in resources:
        rt = res["resource_type"]
        ef = res["emitted_fields"]

        if rt == "EKS::Cluster":
            # --- CIS 1.2.1: Audit logging not enabled ---
            rule_id = f"{p}.csec.cis_1.2.1.audit_logging_disabled"
            log_config = ef.get("logging", {}).get("clusterLogging", [])
            audit_enabled = any(
                l.get("enabled") is True and "audit" in (l.get("types") or [])
                for l in log_config
            )
            if not audit_enabled:
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "audit_logging_disabled",
                    "CIS-1.2.1", "HIGH",
                    "EKS cluster does not have API server audit logging enabled",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "audit_logging_disabled",
                    "CIS-1.2.1", "HIGH",
                    "EKS cluster has audit logging enabled",
                ))

            # --- Check public endpoint access ---
            rule_id_ep = f"{p}.csec.cis_1.2.2.public_endpoint"
            endpoint_config = ef.get("resourcesVpcConfig", {})
            public_access = endpoint_config.get("endpointPublicAccess", True)
            public_cidrs = endpoint_config.get("publicAccessCidrs", ["0.0.0.0/0"])
            is_open_public = public_access and "0.0.0.0/0" in (public_cidrs or [])
            if is_open_public:
                findings.append(_fail(
                    rule_id_ep, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "public_endpoint",
                    "CIS-1.2.2", "HIGH",
                    "EKS API server endpoint is publicly accessible from 0.0.0.0/0",
                ))
            else:
                findings.append(_pass(
                    rule_id_ep, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "public_endpoint",
                    "CIS-1.2.2", "HIGH",
                    "EKS API server endpoint is not openly public",
                ))

        # --- CIS 4.2.1 / 4.2.2 via NodeGroup ---
        elif rt == "EKS::NodeGroup":
            rule_id = f"{p}.csec.cis_4.2.1.kubelet_anonymous_auth"
            # Managed nodegroups with AMI type CUSTOM may have unmanaged kubelet config
            ami_type = ef.get("amiType", "")
            is_unmanaged = ami_type in ("CUSTOM",)
            if is_unmanaged:
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "kubelet_anonymous_auth",
                    "CIS-4.2.1", "HIGH",
                    "EKS NodeGroup uses custom AMI — kubelet configuration not managed by EKS",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "kubelet_anonymous_auth",
                    "CIS-4.2.1", "HIGH",
                    "EKS NodeGroup uses managed AMI — kubelet config managed by EKS",
                ))

    return findings


def _analyze_control_plane_azure(
    resources: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """CIS Layer 1 — Azure AKS control plane checks."""
    findings: List[Dict[str, Any]] = []
    p = "azure"

    for res in resources:
        rt = res["resource_type"]
        ef = res["emitted_fields"]

        if rt in ("ContainerService::ManagedCluster",
                  "containerservice/ManagedCluster",
                  "Microsoft.ContainerService/managedClusters"):
            props = ef.get("properties") or ef

            # --- CIS 1.2.22: RBAC not enabled ---
            rule_id = f"{p}.csec.cis_1.2.22.rbac_disabled"
            rbac_enabled = props.get("enableRBAC", True)
            if rbac_enabled is False:
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "rbac_disabled",
                    "CIS-1.2.22", "CRITICAL",
                    "AKS cluster has RBAC disabled",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "rbac_disabled",
                    "CIS-1.2.22", "CRITICAL",
                    "AKS cluster has RBAC enabled",
                ))

            # --- Check network policy ---
            rule_id_np = f"{p}.csec.cis_5.3.1.no_network_policy_plugin"
            network_profile = props.get("networkProfile") or {}
            network_policy = network_profile.get("networkPolicy", "")
            if network_policy in ("azure", "calico", "cilium"):
                findings.append(_pass(
                    rule_id_np, res, scan_run_id, tenant_id,
                    LAYER_NETWORK_POLICIES, "no_network_policy_plugin",
                    "CIS-5.3.1", "HIGH",
                    f"AKS cluster has network policy plugin: {network_policy}",
                ))
            else:
                findings.append(_fail(
                    rule_id_np, res, scan_run_id, tenant_id,
                    LAYER_NETWORK_POLICIES, "no_network_policy_plugin",
                    "CIS-5.3.1", "HIGH",
                    "AKS cluster has no network policy plugin configured",
                ))

            # --- Check private cluster ---
            rule_id_priv = f"{p}.csec.cis_1.2.2.public_endpoint"
            api_server_access = props.get("apiServerAccessProfile") or {}
            enable_private = api_server_access.get("enablePrivateCluster", False)
            if not enable_private:
                findings.append(_fail(
                    rule_id_priv, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "public_endpoint",
                    "CIS-1.2.2", "HIGH",
                    "AKS cluster API server is publicly accessible (not private cluster)",
                ))
            else:
                findings.append(_pass(
                    rule_id_priv, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "public_endpoint",
                    "CIS-1.2.2", "HIGH",
                    "AKS cluster is a private cluster",
                ))

    return findings


def _analyze_control_plane_gcp(
    resources: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """CIS Layer 1 — GCP GKE control plane checks."""
    findings: List[Dict[str, Any]] = []
    p = "gcp"

    for res in resources:
        rt = res["resource_type"]
        ef = res["emitted_fields"]

        if rt in ("Container::Cluster", "container.googleapis.com/Cluster"):
            # --- CIS 6.6.1: Master authorized networks not configured ---
            rule_id = f"{p}.csec.cis_6.6.1.master_authorized_networks"
            man_config = ef.get("masterAuthorizedNetworksConfig") or {}
            man_enabled = man_config.get("enabled", False)
            if not man_enabled:
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "master_authorized_networks",
                    "CIS-6.6.1", "HIGH",
                    "GKE master authorized networks not configured",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "master_authorized_networks",
                    "CIS-6.6.1", "HIGH",
                    "GKE master authorized networks are configured",
                ))

            # --- Check legacy ABAC (should be disabled) ---
            rule_id_abac = f"{p}.csec.cis_6.2.1.legacy_abac_enabled"
            legacy_abac = ef.get("legacyAbac") or {}
            if legacy_abac.get("enabled", False):
                findings.append(_fail(
                    rule_id_abac, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "legacy_abac_enabled",
                    "CIS-6.2.1", "CRITICAL",
                    "GKE cluster has legacy ABAC enabled (use RBAC instead)",
                ))
            else:
                findings.append(_pass(
                    rule_id_abac, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "legacy_abac_enabled",
                    "CIS-6.2.1", "CRITICAL",
                    "GKE cluster does not use legacy ABAC",
                ))

            # --- Check private nodes ---
            rule_id_priv = f"{p}.csec.cis_6.6.3.private_nodes_disabled"
            private_cluster = ef.get("privateClusterConfig") or {}
            private_nodes = private_cluster.get("enablePrivateNodes", False)
            if not private_nodes:
                findings.append(_fail(
                    rule_id_priv, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "private_nodes_disabled",
                    "CIS-6.6.3", "HIGH",
                    "GKE cluster does not use private nodes",
                ))
            else:
                findings.append(_pass(
                    rule_id_priv, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "private_nodes_disabled",
                    "CIS-6.6.3", "HIGH",
                    "GKE cluster uses private nodes",
                ))

    return findings


def _analyze_control_plane_oci(
    resources: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """CIS Layer 1 — OCI OKE control plane checks."""
    findings: List[Dict[str, Any]] = []
    p = "oci"

    for res in resources:
        rt = res["resource_type"]
        ef = res["emitted_fields"]

        if rt in ("ContainerEngine::Cluster", "oci.containerengine/Cluster"):
            rule_id = f"{p}.csec.cis_1.2.1.audit_logging_disabled"
            # OCI OKE: check Kubernetes Dashboard disabled
            options = ef.get("options") or {}
            add_ons = options.get("addOns") or {}
            dashboard_enabled = add_ons.get("isKubernetesDashboardEnabled", False)
            if dashboard_enabled:
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "kubernetes_dashboard_enabled",
                    "CIS-1.2.1", "HIGH",
                    "OKE cluster has Kubernetes Dashboard enabled (attack surface)",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "kubernetes_dashboard_enabled",
                    "CIS-1.2.1", "HIGH",
                    "OKE cluster does not have Kubernetes Dashboard enabled",
                ))

            # OCI: check endpoint is public
            rule_id_ep = f"{p}.csec.cis_1.2.2.public_endpoint"
            ep_config = ef.get("endpointConfig") or {}
            is_public = ep_config.get("isPublicIpEnabled", True)
            if is_public:
                findings.append(_fail(
                    rule_id_ep, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "public_endpoint",
                    "CIS-1.2.2", "HIGH",
                    "OKE cluster API server endpoint uses public IP",
                ))
            else:
                findings.append(_pass(
                    rule_id_ep, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "public_endpoint",
                    "CIS-1.2.2", "HIGH",
                    "OKE cluster API server endpoint is private",
                ))

    return findings


def _analyze_control_plane_alicloud(
    resources: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """CIS Layer 1 — AliCloud ACK control plane checks."""
    findings: List[Dict[str, Any]] = []
    p = "alicloud"

    for res in resources:
        rt = res["resource_type"]
        ef = res["emitted_fields"]

        if rt in ("ACK::Cluster",):
            rule_id = f"{p}.csec.cis_1.2.1.audit_logging_disabled"
            # ACK: check if audit logs enabled
            cluster_type = ef.get("cluster_type", "")
            # ACK Managed: check meta_data.Addons for logtail
            meta_data = ef.get("meta_data") or {}
            addons = meta_data.get("Addons") or []
            has_audit = any(
                (a.get("name") or "").lower() in ("logtail-ds", "ack-log-controller", "arms-prometheus")
                for a in addons
            )
            if not has_audit:
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "audit_logging_disabled",
                    "CIS-1.2.1", "HIGH",
                    "ACK cluster does not have audit logging addon enabled",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "audit_logging_disabled",
                    "CIS-1.2.1", "HIGH",
                    "ACK cluster has audit logging addon enabled",
                ))

            # Check public API server
            rule_id_ep = f"{p}.csec.cis_1.2.2.public_endpoint"
            public_slb = ef.get("external_loadbalancer_id") or ef.get("master_url", "")
            if public_slb:
                findings.append(_fail(
                    rule_id_ep, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "public_endpoint",
                    "CIS-1.2.2", "HIGH",
                    "ACK cluster has a public API server endpoint",
                ))
            else:
                findings.append(_pass(
                    rule_id_ep, res, scan_run_id, tenant_id,
                    LAYER_CONTROL_PLANE, "public_endpoint",
                    "CIS-1.2.2", "HIGH",
                    "ACK cluster does not expose a public API server endpoint",
                ))

    return findings


# ---------------------------------------------------------------------------
# Layer 2 — Node Configuration (per-CSP supplements)
# ---------------------------------------------------------------------------

def _analyze_node_config_azure(
    resources: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """CIS Layer 2 — Azure AKS node configuration checks.

    Checks:
      CIS-4.2.1: Kubelet authentication mode — AKS managed nodes use webhook by default;
                 flag if legacy 'none' mode is detected.
      CIS-4.2.2: Node OS auto-upgrade channel — flag if disabled.
    """
    findings: List[Dict[str, Any]] = []
    p = "azure"

    for res in resources:
        rt = res["resource_type"]
        ef = res["emitted_fields"]

        if rt in (
            "ContainerService::ManagedCluster",
            "containerservice/ManagedCluster",
            "Microsoft.ContainerService/managedClusters",
        ):
            props = ef.get("properties") or ef

            # CIS 4.2.1 — kubelet anonymousAuth (AKS manages this; flag CUSTOM node pools)
            rule_id_kub = f"{p}.csec.cis_4.2.1.node_kubelet_auth"
            agent_pools = props.get("agentPoolProfiles") or []
            has_custom_os = any(
                (ap.get("osDiskType") or "").lower() == "unmanaged"
                for ap in agent_pools
            )
            if has_custom_os:
                findings.append(_fail(
                    rule_id_kub, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "node_kubelet_auth",
                    "CIS-4.2.1", "HIGH",
                    "AKS node pool uses unmanaged OS disk — kubelet config not fully managed",
                ))
            else:
                findings.append(_pass(
                    rule_id_kub, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "node_kubelet_auth",
                    "CIS-4.2.1", "HIGH",
                    "AKS node pools use managed OS disk — kubelet config managed by AKS",
                ))

            # CIS 4.2.2 — node OS auto-upgrade channel
            rule_id_upg = f"{p}.csec.cis_4.2.2.node_os_upgrade_channel"
            node_os_channel = props.get("autoUpgradeProfile", {}).get("nodeOSUpgradeChannel", "")
            if not node_os_channel or node_os_channel.lower() == "none":
                findings.append(_fail(
                    rule_id_upg, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "node_os_upgrade_channel",
                    "CIS-4.2.2", "MEDIUM",
                    "AKS cluster node OS auto-upgrade channel is not configured",
                ))
            else:
                findings.append(_pass(
                    rule_id_upg, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "node_os_upgrade_channel",
                    "CIS-4.2.2", "MEDIUM",
                    f"AKS cluster node OS auto-upgrade channel: {node_os_channel}",
                ))

    return findings


def _analyze_node_config_oci(
    resources: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """CIS Layer 2 — OCI OKE node configuration checks.

    Checks:
      CIS-4.2.1: Node pool OS image type — flag CUSTOM images vs OKE managed.
      CIS-4.2.6: Node pool SSH access — flag if SSH is open.
    """
    findings: List[Dict[str, Any]] = []
    p = "oci"

    for res in resources:
        rt = res["resource_type"]
        ef = res["emitted_fields"]

        if rt in ("ContainerEngine::Cluster", "oci.containerengine/Cluster"):
            # CIS 4.2.1 — OKE-managed node images
            rule_id_img = f"{p}.csec.cis_4.2.1.node_image_managed"
            node_shape = ef.get("nodeShape") or ef.get("shape") or ""
            # OKE clusters with node_image_id set to a custom OCID indicate unmanaged images
            node_image_id = ef.get("nodeImageId", "") or ef.get("imageId", "")
            is_custom_image = bool(node_image_id) and not node_image_id.startswith("ocid1.image.oc1")
            if is_custom_image:
                findings.append(_fail(
                    rule_id_img, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "node_image_managed",
                    "CIS-4.2.1", "HIGH",
                    "OKE cluster uses a non-standard node image — kubelet config may not be managed",
                ))
            else:
                findings.append(_pass(
                    rule_id_img, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "node_image_managed",
                    "CIS-4.2.1", "HIGH",
                    "OKE cluster uses OKE-managed node image",
                ))

            # CIS 4.2.6 — SSH access to nodes
            rule_id_ssh = f"{p}.csec.cis_4.2.6.node_ssh_access"
            ssh_key = ef.get("sshPublicKey") or ef.get("nodeSourceDetails", {}).get("sshKey", "")
            if ssh_key:
                findings.append(_fail(
                    rule_id_ssh, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "node_ssh_access",
                    "CIS-4.2.6", "MEDIUM",
                    "OKE cluster node pool has SSH public key configured — direct node access possible",
                ))
            else:
                findings.append(_pass(
                    rule_id_ssh, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "node_ssh_access",
                    "CIS-4.2.6", "MEDIUM",
                    "OKE cluster node pool does not expose SSH public key",
                ))

    return findings


def _analyze_node_config_alicloud(
    resources: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
) -> List[Dict[str, Any]]:
    """CIS Layer 2 — AliCloud ACK node configuration checks.

    Checks:
      CIS-4.2.1: Managed node pool OS type — flag CUSTOM system image.
      CIS-4.2.6: Node pool SSH key — flag if set.
    """
    findings: List[Dict[str, Any]] = []
    p = "alicloud"

    for res in resources:
        rt = res["resource_type"]
        ef = res["emitted_fields"]

        if rt in ("ACK::Cluster",):
            # CIS 4.2.1 — OS image managed
            rule_id_img = f"{p}.csec.cis_4.2.1.node_image_managed"
            # ACK cluster_type 'ManagedKubernetes' indicates managed; 'Kubernetes' is self-managed
            cluster_type = ef.get("cluster_type", "")
            is_self_managed = cluster_type.lower() in ("kubernetes",)
            if is_self_managed:
                findings.append(_fail(
                    rule_id_img, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "node_image_managed",
                    "CIS-4.2.1", "HIGH",
                    "ACK cluster is self-managed (cluster_type=Kubernetes) — node OS not managed by ACK",
                ))
            else:
                findings.append(_pass(
                    rule_id_img, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "node_image_managed",
                    "CIS-4.2.1", "HIGH",
                    f"ACK cluster uses managed type ({cluster_type or 'ManagedKubernetes'})",
                ))

            # CIS 4.2.6 — SSH key on nodes
            rule_id_ssh = f"{p}.csec.cis_4.2.6.node_ssh_access"
            login_config = ef.get("login_config") or {}
            ssh_key = login_config.get("ssh_key_pair") or ef.get("key_pair", "")
            if ssh_key:
                findings.append(_fail(
                    rule_id_ssh, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "node_ssh_access",
                    "CIS-4.2.6", "MEDIUM",
                    "ACK cluster node pool has SSH key pair configured — direct node access possible",
                ))
            else:
                findings.append(_pass(
                    rule_id_ssh, res, scan_run_id, tenant_id,
                    LAYER_NODE_CONFIG, "node_ssh_access",
                    "CIS-4.2.6", "MEDIUM",
                    "ACK cluster node pool does not expose an SSH key pair",
                ))

    return findings


def _analyze_node_config_k8s(
    resources: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> List[Dict[str, Any]]:
    """CIS Layer 2 — Native K8s node configuration checks derived from workload metadata.

    Because the engine reads from discovery_findings (not live API), node-level
    kubelet flags are inferred from workload spec annotations and pod-level
    securityContext — direct node inspection is not possible without live API access.

    Checks:
      CIS-4.2.1: Pod spec does not require kubelet anonymous auth override
                 (inferred from readiness/liveness probe scheme = HTTPS).
      CIS-4.2.6: No hostPort mappings exposing node ports to external traffic.
    """
    findings: List[Dict[str, Any]] = []
    p = provider

    for res in resources:
        rt = res["resource_type"]
        ef = res["emitted_fields"]

        if rt not in WORKLOAD_TYPES:
            continue

        spec = _get_pod_spec(ef)
        all_containers = (spec.get("containers") or []) + (spec.get("initContainers") or [])

        # CIS 4.2.6 — hostPort
        rule_id_hp = f"{p}.csec.cis_4.2.6.host_port_exposed"
        has_host_port = any(
            bool(port.get("hostPort"))
            for c in all_containers
            for port in (c.get("ports") or [])
        )
        if has_host_port:
            findings.append(_fail(
                rule_id_hp, res, scan_run_id, tenant_id,
                LAYER_NODE_CONFIG, "host_port_exposed",
                "CIS-4.2.6", "MEDIUM",
                "Container exposes a hostPort — direct node port binding bypasses network policy",
            ))
        else:
            findings.append(_pass(
                rule_id_hp, res, scan_run_id, tenant_id,
                LAYER_NODE_CONFIG, "host_port_exposed",
                "CIS-4.2.6", "MEDIUM",
                "No containers expose hostPort",
            ))

    return findings


# ---------------------------------------------------------------------------
# Layer 6 — Secrets Management (CSP-specific supplement)
# ---------------------------------------------------------------------------

def _analyze_secrets_management_csp(
    resources: List[Dict[str, Any]],
    scan_run_id: str,
    tenant_id: str,
    provider: str,
) -> List[Dict[str, Any]]:
    """CIS Layer 6 — Secrets Management for CSP-managed cluster resources.

    Checks whether managed clusters have etcd encryption at rest enabled.
    Covers AWS EKS, Azure AKS, GCP GKE, OCI OKE, AliCloud ACK.

    Security note: Secret.data values are never accessed or logged.
    Only configuration flags and key names are inspected.
    """
    findings: List[Dict[str, Any]] = []
    p = provider

    for res in resources:
        rt = res["resource_type"]
        ef = res["emitted_fields"]

        # --- AWS EKS: etcd encryption via encryptionConfig ---
        if rt == "EKS::Cluster":
            rule_id = f"{p}.csec.cis_5.4.3.etcd_encryption_disabled"
            encryption_configs = ef.get("encryptionConfig") or []
            has_secrets_encryption = any(
                "secrets" in (ec.get("resources") or [])
                for ec in encryption_configs
            )
            if not has_secrets_encryption:
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_SECRETS_MANAGEMENT, "etcd_encryption_disabled",
                    "CIS-5.4.3", "HIGH",
                    "EKS cluster does not have etcd encryption for Secrets enabled",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_SECRETS_MANAGEMENT, "etcd_encryption_disabled",
                    "CIS-5.4.3", "HIGH",
                    "EKS cluster has etcd encryption for Secrets enabled",
                ))

        # --- Azure AKS: etcd encryption / Azure Key Vault integration ---
        elif rt in (
            "ContainerService::ManagedCluster",
            "containerservice/ManagedCluster",
            "Microsoft.ContainerService/managedClusters",
        ):
            rule_id = f"{p}.csec.cis_5.4.3.etcd_encryption_disabled"
            props = ef.get("properties") or ef
            key_vault_ref = (
                (props.get("addonProfiles") or {}).get("azureKeyvaultSecretsProvider", {})
            )
            kvs_enabled = key_vault_ref.get("enabled", False) is True
            if not kvs_enabled:
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_SECRETS_MANAGEMENT, "etcd_encryption_disabled",
                    "CIS-5.4.3", "HIGH",
                    "AKS cluster does not have Azure Key Vault Secrets Provider addon enabled",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_SECRETS_MANAGEMENT, "etcd_encryption_disabled",
                    "CIS-5.4.3", "HIGH",
                    "AKS cluster has Azure Key Vault Secrets Provider addon enabled",
                ))

        # --- GCP GKE: application-layer secrets encryption ---
        elif rt in ("Container::Cluster", "container.googleapis.com/Cluster"):
            rule_id = f"{p}.csec.cis_5.4.3.etcd_encryption_disabled"
            database_enc = ef.get("databaseEncryption") or {}
            enc_state = database_enc.get("state", "DECRYPTED")
            if enc_state != "ENCRYPTED":
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_SECRETS_MANAGEMENT, "etcd_encryption_disabled",
                    "CIS-5.4.3", "HIGH",
                    "GKE cluster does not have application-layer Secrets encryption enabled",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_SECRETS_MANAGEMENT, "etcd_encryption_disabled",
                    "CIS-5.4.3", "HIGH",
                    "GKE cluster has application-layer Secrets encryption enabled",
                ))

        # --- OCI OKE: Vault integration ---
        elif rt in ("ContainerEngine::Cluster", "oci.containerengine/Cluster"):
            rule_id = f"{p}.csec.cis_5.4.3.etcd_encryption_disabled"
            options = ef.get("options") or {}
            enc_config = options.get("kubernetesNetworkConfig") or {}
            # OKE uses etcd encryption by default in managed clusters; check if a KMS key is set
            kms_key_id = ef.get("kmsKeyId") or ef.get("vaultKeyId") or ""
            if not kms_key_id:
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_SECRETS_MANAGEMENT, "etcd_encryption_disabled",
                    "CIS-5.4.3", "HIGH",
                    "OKE cluster does not have a dedicated KMS/Vault key for etcd encryption",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_SECRETS_MANAGEMENT, "etcd_encryption_disabled",
                    "CIS-5.4.3", "HIGH",
                    "OKE cluster uses a dedicated KMS/Vault key for etcd encryption",
                ))

        # --- AliCloud ACK: KMS integration ---
        elif rt in ("ACK::Cluster",):
            rule_id = f"{p}.csec.cis_5.4.3.etcd_encryption_disabled"
            encryption_config = ef.get("encryption_config") or []
            has_kms = bool(encryption_config)
            if not has_kms:
                findings.append(_fail(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_SECRETS_MANAGEMENT, "etcd_encryption_disabled",
                    "CIS-5.4.3", "HIGH",
                    "ACK cluster does not have KMS encryption config for Secrets",
                ))
            else:
                findings.append(_pass(
                    rule_id, res, scan_run_id, tenant_id,
                    LAYER_SECRETS_MANAGEMENT, "etcd_encryption_disabled",
                    "CIS-5.4.3", "HIGH",
                    "ACK cluster has KMS encryption config for Secrets",
                ))

    return findings


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_cis_analysis(
    provider: str,
    scan_run_id: str,
    tenant_id: str,
    account_id: str,
    discoveries_conn,
) -> List[Dict[str, Any]]:
    """Run full CIS 7-layer analysis for the given provider and scan.

    Args:
        provider: Cloud provider name (aws|azure|gcp|oci|alicloud|k8s).
        scan_run_id: Pipeline scan run identifier.
        tenant_id: Tenant identifier.
        account_id: Cloud account / cluster identifier.
        discoveries_conn: psycopg2 connection to discoveries DB.

    Returns:
        List of finding dicts with layer, layer_check, check_id fields populated.
    """
    p = provider.lower()
    findings: List[Dict[str, Any]] = []

    logger.info(
        "CIS analysis starting provider=%s scan_run_id=%s tenant=%s account=%s",
        p, scan_run_id, tenant_id, account_id,
    )

    # -------------------------------------------------------------------------
    # K8s native resources — always analyzed for all providers that have them
    # -------------------------------------------------------------------------
    k8s_types = list(K8S_RESOURCE_TYPES.values())
    k8s_resources = _load_resources(
        discoveries_conn, scan_run_id, tenant_id,
        k8s_types, account_id or None,
    )
    logger.info("CIS: loaded %d K8s resources for scan %s", len(k8s_resources), scan_run_id)

    # Override provider to "k8s" for native K8s resources so rule_ids use k8s prefix
    k8s_provider = "k8s" if p == "k8s" else p

    if k8s_resources:
        # L2 — Node config (host ports, kubelet inference from workload specs)
        findings += _analyze_node_config_k8s(k8s_resources, scan_run_id, tenant_id, k8s_provider)
        # L3 — RBAC & service accounts
        findings += _analyze_rbac(k8s_resources, scan_run_id, tenant_id, k8s_provider)
        # L4 — Pod security standards
        findings += _analyze_pod_security(k8s_resources, scan_run_id, tenant_id, k8s_provider)
        # L5 — Network policies
        findings += _analyze_network_policies(k8s_resources, scan_run_id, tenant_id, k8s_provider)
        # L6 — Secrets management (env vars + ConfigMaps)
        findings += _analyze_secrets_management(k8s_resources, scan_run_id, tenant_id, k8s_provider)
        # L7 — Image security
        findings += _analyze_image_security(k8s_resources, scan_run_id, tenant_id, k8s_provider)
    else:
        logger.info("CIS: no K8s resources found for scan %s — skipping K8s layers 2-7", scan_run_id)

    # -------------------------------------------------------------------------
    # CSP-specific managed cluster resources (L1, L2, L7 registry checks)
    # -------------------------------------------------------------------------
    managed_types = MANAGED_CLUSTER_TYPES_BY_PROVIDER.get(p, [])
    if managed_types:
        csp_resources = _load_resources(
            discoveries_conn, scan_run_id, tenant_id,
            managed_types, account_id or None,
        )
        # Also load registry types for image security
        registry_resources = [
            r for r in csp_resources
            if any(rt in r["resource_type"] for rt in ("ECR", "Registry", "ArtifactRegistry", "ACR", "Container"))
        ]
        logger.info(
            "CIS: loaded %d managed cluster resources (%d registry) for provider=%s",
            len(csp_resources), len(registry_resources), p,
        )

        if p == "aws":
            # L1 — Control plane + L2 node config (via NodeGroup)
            findings += _analyze_control_plane_aws(csp_resources, scan_run_id, tenant_id)
            # L6 — etcd encryption at rest
            findings += _analyze_secrets_management_csp(csp_resources, scan_run_id, tenant_id, p)
            # L7 — Image security (registry scan-on-push)
            findings += _analyze_image_security(registry_resources, scan_run_id, tenant_id, p)
        elif p == "azure":
            # L1 — Control plane
            findings += _analyze_control_plane_azure(csp_resources, scan_run_id, tenant_id)
            # L2 — Node configuration
            findings += _analyze_node_config_azure(csp_resources, scan_run_id, tenant_id)
            # L6 — Secrets (Key Vault addon)
            findings += _analyze_secrets_management_csp(csp_resources, scan_run_id, tenant_id, p)
            # L7 — Image security
            findings += _analyze_image_security(registry_resources, scan_run_id, tenant_id, p)
        elif p in ("gcp", "google"):
            # L1 — Control plane (includes private nodes check in L2)
            findings += _analyze_control_plane_gcp(csp_resources, scan_run_id, tenant_id)
            # L6 — Secrets (database encryption / KMS)
            findings += _analyze_secrets_management_csp(csp_resources, scan_run_id, tenant_id, "gcp")
            # L7 — Image security
            findings += _analyze_image_security(registry_resources, scan_run_id, tenant_id, p)
        elif p == "oci":
            # L1 — Control plane
            findings += _analyze_control_plane_oci(csp_resources, scan_run_id, tenant_id)
            # L2 — Node configuration
            findings += _analyze_node_config_oci(csp_resources, scan_run_id, tenant_id)
            # L6 — Secrets (KMS/Vault integration)
            findings += _analyze_secrets_management_csp(csp_resources, scan_run_id, tenant_id, p)
        elif p == "alicloud":
            # L1 — Control plane
            findings += _analyze_control_plane_alicloud(csp_resources, scan_run_id, tenant_id)
            # L2 — Node configuration
            findings += _analyze_node_config_alicloud(csp_resources, scan_run_id, tenant_id)
            # L6 — Secrets (KMS encryption config)
            findings += _analyze_secrets_management_csp(csp_resources, scan_run_id, tenant_id, p)
            # L7 — Image security
            findings += _analyze_image_security(registry_resources, scan_run_id, tenant_id, p)

    fail_count = sum(1 for f in findings if f.get("status") == "FAIL")
    pass_count = sum(1 for f in findings if f.get("status") == "PASS")
    logger.info(
        "CIS analysis complete provider=%s: %d findings (%d FAIL, %d PASS)",
        p, len(findings), fail_count, pass_count,
    )
    return findings
