import os
import re
import yaml
from typing import Dict, List, Any, Optional

# Source (reference) checks root
REF_ROOT = os.path.join(
    os.path.dirname(__file__),
    "..", "..", "kubernetes_checks"
)

# Destination YAML rules root
DEST_ROOT = os.path.join(
    os.path.dirname(__file__),
    "..", "rules"
)

# Standard discovery fields per component
DISCOVERY_FIELDS: Dict[str, List[Dict[str, str]]] = {
    "apiserver": [
        {"path": "arguments.authorization-mode", "var": "authorization_mode"},
        {"path": "arguments.audit-log-path", "var": "audit_log_path"},
        {"path": "arguments.audit-log-maxage", "var": "audit_log_max_age"},
        {"path": "arguments.audit-log-maxbackup", "var": "audit_log_max_backup"},
        {"path": "arguments.audit-log-maxsize", "var": "audit_log_max_size"},
        {"path": "arguments.encryption-provider-config", "var": "encryption_provider_config"},
        {"path": "arguments.tls-cert-file", "var": "tls_cert_file"},
        {"path": "arguments.tls-private-key-file", "var": "tls_private_key_file"},
        {"path": "arguments.client-ca-file", "var": "client_ca_file"},
        {"path": "arguments.enable-admission-plugins", "var": "enable_admission_plugins"},
        {"path": "pod_name", "var": "pod_name"},
    ],
    "scheduler": [
        {"path": "arguments.bind-address", "var": "bind_address"},
        {"path": "arguments.profiling", "var": "profiling"},
        {"path": "arguments.tls-cert-file", "var": "tls_cert_file"},
        {"path": "arguments.tls-private-key-file", "var": "tls_private_key_file"},
        {"path": "arguments.client-ca-file", "var": "client_ca_file"},
        {"path": "pod_name", "var": "pod_name"},
    ],
    "controllermanager": [
        {"path": "arguments.bind-address", "var": "bind_address"},
        {"path": "arguments.profiling", "var": "profiling"},
        {"path": "arguments.use-service-account-credentials", "var": "use_service_account_credentials"},
        {"path": "arguments.service-account-private-key-file", "var": "service_account_private_key_file"},
        {"path": "arguments.root-ca-file", "var": "root_ca_file"},
        {"path": "arguments.rotate-kubelet-server-cert", "var": "rotate_kubelet_server_cert"},
        {"path": "arguments.terminated-pod-gc-threshold", "var": "terminated_pod_gc_threshold"},
        {"path": "arguments.tls-cert-file", "var": "tls_cert_file"},
        {"path": "arguments.tls-private-key-file", "var": "tls_private_key_file"},
        {"path": "pod_name", "var": "pod_name"},
    ],
    "etcd": [
        {"path": "arguments.cert-file", "var": "cert_file"},
        {"path": "arguments.key-file", "var": "key_file"},
        {"path": "arguments.client-cert-auth", "var": "client_cert_auth"},
        {"path": "arguments.trusted-ca-file", "var": "trusted_ca_file"},
        {"path": "arguments.peer-cert-file", "var": "peer_cert_file"},
        {"path": "arguments.peer-key-file", "var": "peer_key_file"},
        {"path": "arguments.peer-client-cert-auth", "var": "peer_client_cert_auth"},
        {"path": "arguments.peer-trusted-ca-file", "var": "peer_trusted_ca_file"},
        {"path": "arguments.auto-tls", "var": "auto_tls"},
        {"path": "arguments.peer-auto-tls", "var": "peer_auto_tls"},
        {"path": "pod_name", "var": "pod_name"},
    ],
    "kubelet": [
        # Placeholder; kubelet discovery via get_component_config might be empty in some clusters
        {"path": "pod_name", "var": "pod_name"},
    ],
    "rbac": [
        # RBAC will use dedicated discovery below (list roles, bindings, cluster roles)
        {"path": "pod_name", "var": "pod_name"},
    ],
    "core": [
        # core checks will use list_pods discovery
        {"path": "pod_name", "var": "pod_name"},
    ],
}

# Mappings per component
APISERVER_CHECK_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "apiserver_always_pull_images_plugin": {"field": "enable_admission_plugins", "operator": "contains", "expected": "AlwaysPullImages", "severity": "MEDIUM"},
    "apiserver_auth_mode_not_always_allow": {"field": "authorization_mode", "operator": "not_equals", "expected": "AlwaysAllow", "severity": "HIGH"},
    "apiserver_auth_mode_include_rbac": {"field": "authorization_mode", "operator": "contains", "expected": "RBAC", "severity": "HIGH"},
    "apiserver_auth_mode_include_node": {"field": "authorization_mode", "operator": "contains", "expected": "Node", "severity": "HIGH"},
    "apiserver_audit_log_path_set": {"field": "audit_log_path", "operator": "exists", "expected": True, "severity": "MEDIUM"},
    "apiserver_audit_log_maxsize_set": {"field": "audit_log_max_size", "operator": "gte", "expected": 100, "severity": "MEDIUM"},
    "apiserver_audit_log_maxbackup_set": {"field": "audit_log_max_backup", "operator": "exists", "expected": True, "severity": "MEDIUM"},
    "apiserver_audit_log_maxage_set": {"field": "audit_log_max_age", "operator": "exists", "expected": True, "severity": "MEDIUM"},
    "apiserver_encryption_provider_config_set": {"field": "encryption_provider_config", "operator": "exists", "expected": True, "severity": "CRITICAL"},
}

SCHEDULER_CHECK_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "scheduler_bind_address": {"field": "bind_address", "operator": "equals", "expected": "127.0.0.1", "severity": "MEDIUM"},
    "scheduler_profiling": {"field": "profiling", "operator": "equals", "expected": "false", "severity": "MEDIUM"},
}

CONTROLLER_CHECK_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "controllermanager_bind_address": {"field": "bind_address", "operator": "equals", "expected": "127.0.0.1", "severity": "MEDIUM"},
    "controllermanager_disable_profiling": {"field": "profiling", "operator": "equals", "expected": "false", "severity": "MEDIUM"},
    "controllermanager_service_account_credentials": {"field": "use_service_account_credentials", "operator": "equals", "expected": "true", "severity": "HIGH"},
    "controllermanager_service_account_private_key_file": {"field": "service_account_private_key_file", "operator": "exists", "expected": True, "severity": "HIGH"},
    "controllermanager_root_ca_file_set": {"field": "root_ca_file", "operator": "exists", "expected": True, "severity": "HIGH"},
    "controllermanager_rotate_kubelet_server_cert": {"field": "rotate_kubelet_server_cert", "operator": "equals", "expected": "true", "severity": "MEDIUM"},
    "controllermanager_garbage_collection": {"field": "terminated_pod_gc_threshold", "operator": "gte", "expected": 1, "severity": "LOW"},
}

ETCD_CHECK_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "etcd_tls_encryption": {"multi": [
        {"field": "cert_file", "operator": "exists", "expected": True},
        {"field": "key_file", "operator": "exists", "expected": True},
        {"field": "client_cert_auth", "operator": "equals", "expected": "true"},
    ], "severity": "CRITICAL"},
    "etcd_client_cert_auth": {"field": "client_cert_auth", "operator": "equals", "expected": "true", "severity": "CRITICAL"},
    "etcd_peer_tls_config": {"multi": [
        {"field": "peer_cert_file", "operator": "exists", "expected": True},
        {"field": "peer_key_file", "operator": "exists", "expected": True},
        {"field": "peer_client_cert_auth", "operator": "equals", "expected": "true"},
    ], "severity": "HIGH"},
    "etcd_peer_client_cert_auth": {"field": "peer_client_cert_auth", "operator": "equals", "expected": "true", "severity": "HIGH"},
    "etcd_no_auto_tls": {"field": "auto_tls", "operator": "not_equals", "expected": "true", "severity": "MEDIUM"},
    "etcd_no_peer_auto_tls": {"field": "peer_auto_tls", "operator": "not_equals", "expected": "true", "severity": "MEDIUM"},
    "etcd_unique_ca": {"multi": [
        {"field": "trusted_ca_file", "operator": "exists", "expected": True},
        {"field": "peer_trusted_ca_file", "operator": "exists", "expected": True},
    ], "severity": "MEDIUM"},
}

# RBAC mappings (identity checks; detailed resource/verb checks require domain policy definitions)
RBAC_CHECK_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "rbac_minimize_wildcard_use_roles": {"field": "rules", "operator": "not_regex", "expected": ".*\\*.*", "severity": "HIGH"},
    "rbac_minimize_secret_access": {"field": "rules", "operator": "not_regex", "expected": ".*secrets.*(get|list|watch).*", "severity": "HIGH"},
    "rbac_minimize_pod_creation_access": {"field": "rules", "operator": "not_regex", "expected": ".*pods.*create.*", "severity": "HIGH"},
    "rbac_minimize_pv_creation_access": {"field": "rules", "operator": "not_regex", "expected": ".*persistentvolumes.*create.*", "severity": "MEDIUM"},
    "rbac_minimize_webhook_config_access": {"field": "rules", "operator": "not_regex", "expected": ".*admissionregistration.k8s.io.*(mutatingwebhookconfigurations|validatingwebhookconfigurations).*", "severity": "MEDIUM"},
    "rbac_minimize_service_account_token_creation": {"field": "rules", "operator": "not_regex", "expected": ".*serviceaccounts.*token.*create.*", "severity": "MEDIUM"},
    "rbac_minimize_node_proxy_subresource_access": {"field": "rules", "operator": "not_regex", "expected": ".*nodes/proxy.*", "severity": "MEDIUM"},
    "rbac_minimize_csr_approval_access": {"field": "rules", "operator": "not_regex", "expected": ".*certificates.k8s.io.*certificatesigningrequests.*(approve|update|patch).*", "severity": "MEDIUM"},
    # cluster-admin usage often managed by policy; placeholder to identify existence
    "rbac_cluster_admin_usage": {"field": "name", "operator": "regex", "expected": "^cluster-admin$", "severity": "LOW"},
}

# CORE mappings (pod-level security)
CORE_CHECK_MAPPINGS: Dict[str, Dict[str, Any]] = {
    "core_minimize_privileged_containers": {"field": "containers.0.securityContext.privileged", "operator": "not_equals", "expected": True, "severity": "HIGH"},
    "core_minimize_root_containers_admission": {"field": "containers.0.securityContext.run_as_user", "operator": "not_equals", "expected": 0, "severity": "HIGH"},
    "core_minimize_allowPrivilegeEscalation_containers": {"field": "containers.0.securityContext.allow_privilege_escalation", "operator": "not_equals", "expected": True, "severity": "HIGH"},
    "core_minimize_containers_capabilities_assigned": {"field": "containers.0.securityContext.capabilities.add", "operator": "not_exists", "expected": True, "severity": "MEDIUM"},
    "core_minimize_containers_added_capabilities": {"field": "containers.0.securityContext.capabilities.add.0", "operator": "not_exists", "expected": True, "severity": "MEDIUM"},
    "core_minimize_hostNetwork_containers": {"field": "hostNetwork", "operator": "equals", "expected": False, "severity": "MEDIUM"},
    "core_minimize_hostPID_containers": {"field": "hostPID", "operator": "equals", "expected": False, "severity": "MEDIUM"},
    "core_minimize_hostIPC_containers": {"field": "hostIPC", "operator": "equals", "expected": False, "severity": "MEDIUM"},
    "core_minimize_net_raw_capability_admission": {"field": "containers.0.securityContext.capabilities.drop", "operator": "contains", "expected": "NET_RAW", "severity": "LOW"},
    "core_seccomp_profile_docker_default": {"field": "containers.0.securityContext.seccomp_profile.type", "operator": "equals", "expected": "RuntimeDefault", "severity": "MEDIUM"},
    "core_no_secrets_envs": {"field": "containers.0.env.0.value", "operator": "not_regex", "expected": ".*(AKIA|SECRET|PASSWORD|TOKEN|KEY).*", "severity": "LOW"},
    "core_minimize_admission_hostport_containers": {"field": "containers.0.ports.0.containerPort", "operator": "not_equals", "expected": 0, "severity": "LOW"},
    "core_minimize_admission_windows_hostprocess_containers": {"field": "containers.0.securityContext.windows_options.host_process", "operator": "not_equals", "expected": True, "severity": "LOW"},
}


def title_from_check_id(check_id: str) -> str:
    return check_id.replace('_', ' ').strip().title()


def build_yaml_definition(component: str, check_id: str) -> Dict[str, Any]:
    # Default definition scaffold
    definition: Dict[str, Any] = {
        "component": component,
        "component_type": "control_plane" if component in {"apiserver", "controllermanager", "scheduler", "etcd"} else "workload",
        "discovery": [],
        "checks": [],
    }

    # Discovery: control plane components via get_component_config
    if component in {"apiserver", "controllermanager", "scheduler", "etcd"}:
        definition["discovery"].append({
            "discovery_id": f"get_{component}_config",
            "calls": [{
                "action": "get_component_config",
                "params": {"component": f"kube-{component}" if component != "etcd" else "etcd"},
                "fields": DISCOVERY_FIELDS.get(component, []),
            }],
        })
    elif component == "rbac":
        # RBAC discovery
        definition["discovery"].append({
            "discovery_id": "list_cluster_roles",
            "calls": [{"action": "list_cluster_roles", "fields": [
                {"path": "name", "var": "name"},
                {"path": "rules", "var": "rules"},
            ]}]})
        definition["discovery"].append({
            "discovery_id": "list_roles",
            "calls": [{"action": "list_roles", "fields": [
                {"path": "name", "var": "name"},
                {"path": "namespace", "var": "namespace"},
                {"path": "rules", "var": "rules"},
            ]}]})
    elif component == "core":
        # Core pod discovery (all namespaces)
        definition["discovery"].append({
            "discovery_id": "list_pods",
            "calls": [{"action": "list_pods", "fields": [
                {"path": "name", "var": "pod_name"},
                {"path": "namespace", "var": "namespace"},
                {"path": "hostNetwork", "var": "hostNetwork"},
                {"path": "hostPID", "var": "hostPID"},
                {"path": "hostIPC", "var": "hostIPC"},
                {"path": "containers", "var": "containers"},
            ]}]})
    else:
        # Fallback minimal discovery
        definition["discovery"].append({
            "discovery_id": f"get_{component}_config",
            "calls": [{
                "action": "get_component_config",
                "params": {"component": f"kube-{component}"},
                "fields": DISCOVERY_FIELDS.get(component, []),
            }],
        })

    # Resolve mapping
    mapping: Optional[Dict[str, Any]] = None
    if component == "apiserver":
        mapping = APISERVER_CHECK_MAPPINGS.get(check_id)
    elif component == "scheduler":
        mapping = SCHEDULER_CHECK_MAPPINGS.get(check_id)
    elif component == "controllermanager":
        mapping = CONTROLLER_CHECK_MAPPINGS.get(check_id)
    elif component == "etcd":
        mapping = ETCD_CHECK_MAPPINGS.get(check_id)
    elif component == "rbac":
        mapping = RBAC_CHECK_MAPPINGS.get(check_id)
    elif component == "core":
        mapping = CORE_CHECK_MAPPINGS.get(check_id)

    # Build check block
    fields: List[Dict[str, Any]]
    severity = "MEDIUM"
    if mapping and "multi" in mapping:
        fields = [{"path": m["field"], "operator": m["operator"], "expected": m["expected"]} for m in mapping["multi"]]
        severity = mapping.get("severity", "MEDIUM")
    elif mapping:
        fields = [{"path": mapping["field"], "operator": mapping["operator"], "expected": mapping["expected"]}]
        severity = mapping.get("severity", "MEDIUM")
    else:
        fields = [{"path": "pod_name", "operator": "exists", "expected": True}]
        severity = "MEDIUM"

    # For identity actions (rbac/core), prefix paths with 'item.'
    if component in {"rbac", "core"}:
        for f in fields:
            f["path"] = f"item.{f['path']}"

    # Select discovery id for_each per component
    if component in {"apiserver", "controllermanager", "scheduler", "etcd"}:
        for_each = f"get_{component}_config"
        param_name = "config"
        action_name = "get_component_config"
        action_params = {"component": f"kube-{component}" if component != "etcd" else "etcd"}
    elif component == "rbac":
        for_each = "list_roles"
        param_name = "item"
        action_name = "identity"
        action_params = {}
    elif component == "core":
        for_each = "list_pods"
        param_name = "item"
        action_name = "identity"
        action_params = {}
    else:
        for_each = f"get_{component}_config"
        param_name = "config"
        action_name = "get_component_config"
        action_params = {"component": f"kube-{component}"}

    check_block = {
        "check_id": check_id,
        "name": title_from_check_id(check_id),
        "severity": severity,
        "for_each": for_each,
        "param": param_name,
        "calls": [{
            "action": action_name,
            "params": action_params,
            "fields": fields,
        }],
        "logic": "AND",
        "errors_as_fail": [],
    }

    definition["checks"].append(check_block)
    return definition


def write_yaml(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        yaml.safe_dump(data, fh, sort_keys=False)


def find_check_dirs(component_path: str) -> List[str]:
    dirs: List[str] = []
    for entry in os.listdir(component_path):
        full = os.path.join(component_path, entry)
        if os.path.isdir(full) and not entry.startswith("__"):
            dirs.append(full)
    return sorted(dirs)


def main(target_components: Optional[List[str]] = None) -> None:
    overwrite = os.environ.get("OVERWRITE", "0") in ("1", "true", "TRUE")
    components = [d for d in os.listdir(REF_ROOT) if os.path.isdir(os.path.join(REF_ROOT, d)) and not d.startswith("__")]
    if target_components:
        components = [c for c in components if c in target_components]

    for comp in components:
        comp_src = os.path.join(REF_ROOT, comp)
        comp_dst = os.path.join(DEST_ROOT, comp)
        check_dirs = find_check_dirs(comp_src)
        for chk_dir in check_dirs:
            check_id = os.path.basename(chk_dir)
            dest_file = os.path.join(comp_dst, f"{check_id}.yaml")
            if os.path.exists(dest_file) and not overwrite:
                continue
            definition = build_yaml_definition(comp, check_id)
            write_yaml(dest_file, definition)
            print(("Overwrote" if overwrite else "Created") + f" {dest_file}")


if __name__ == "__main__":
    # Generate for all components by default
    main(target_components=None) 