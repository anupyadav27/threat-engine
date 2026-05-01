#!/usr/bin/env python3
"""
Two-phase generator for the 17 k8s services missing from k8s_rule_check:

Phase 1: Enrich step4 (k8s_dependencies_with_python_names_fully_enriched.json)
         for the 7 services that only have step6 YAML — no step4 yet.

Phase 2: Read ALL 17 step4 files and emit:
           catalog/rule/k8s_rule_check/<svc>/<svc>.checks.yaml
           catalog/rule/k8s_rule_metadata/<svc>/<rule_id>.yaml

for_each  = k8s.<service>.list          (first 'list' independent op in step4)
var       = item.<field_path>           (field paths from step4 item_fields)
"""

import json
import yaml
from pathlib import Path

STEP4_ROOT = Path("/Users/apple/Desktop/threat-engine/catalog/python_field_generator/k8s")
CHECK_OUT  = Path("/Users/apple/Desktop/threat-engine/catalog/rule/k8s_rule_check")
META_OUT   = Path("/Users/apple/Desktop/threat-engine/catalog/rule/k8s_rule_metadata")

# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — step4 enrichment data for 7 services without step4 files
# Fields follow the same schema as existing step4 item_fields entries.
# ─────────────────────────────────────────────────────────────────────────────

def _field(ftype="string", desc="", category="general", security_impact=None, enum=False, values=None):
    return {"type": ftype, "description": desc, "compliance_category": category,
            "security_impact": security_impact, "enum": enum, "possible_values": values}

MISSING_STEP4 = {
    "cronjob": {
        "resource": "cronjob", "api_version": "batch/v1", "kind": "CronJob",
        "description": "CronJob resource — runs Jobs on a time-based schedule",
        "independent": [{
            "operation": "list", "http_method": "GET",
            "description": "List all CronJobs across all namespaces",
            "item_fields": {
                "metadata.name":       _field("string", "CronJob name", "identity"),
                "metadata.namespace":  _field("string", "Namespace", "identity"),
                "spec.schedule":       _field("string", "Cron schedule expression", "configuration"),
                "spec.concurrencyPolicy": _field(
                    "string", "How concurrent runs are handled", "security",
                    security_impact="Allow permits unbounded concurrent runs — resource exhaustion risk",
                    enum=True, values=["Allow", "Forbid", "Replace"]),
                "spec.suspend":        _field("boolean", "Whether scheduling is suspended", "configuration"),
                "spec.jobTemplate.spec.template.spec.securityContext.runAsNonRoot": _field(
                    "boolean", "Force non-root execution", "security",
                    security_impact="Containers running as root increase blast radius"),
                "spec.jobTemplate.spec.template.spec.securityContext.runAsUser":    _field("integer", "UID to run as", "security"),
                "spec.jobTemplate.spec.template.spec.hostNetwork": _field(
                    "boolean", "Use host network namespace", "security",
                    security_impact="Host network exposes node traffic to pod"),
                "spec.jobTemplate.spec.template.spec.hostPID":     _field(
                    "boolean", "Share host PID namespace", "security",
                    security_impact="Host PID allows process inspection on node"),
                "spec.jobTemplate.spec.template.spec.hostIPC":     _field(
                    "boolean", "Share host IPC namespace", "security",
                    security_impact="Host IPC exposes inter-process communication"),
                "spec.jobTemplate.spec.template.spec.containers":  _field(
                    "array", "Container list", "security",
                    security_impact="Each container security context should be hardened"),
                "spec.jobTemplate.spec.template.spec.resources.limits": _field(
                    "object", "Resource limits for CPU/memory", "security",
                    security_impact="Missing limits allow resource exhaustion"),
            },
        }],
        "dependent": [],
    },

    "job": {
        "resource": "job", "api_version": "batch/v1", "kind": "Job",
        "description": "Job resource — runs a batch task to completion",
        "independent": [{
            "operation": "list", "http_method": "GET",
            "description": "List all Jobs across all namespaces",
            "item_fields": {
                "metadata.name":      _field("string", "Job name", "identity"),
                "metadata.namespace": _field("string", "Namespace", "identity"),
                "spec.template.spec.securityContext.runAsNonRoot": _field(
                    "boolean", "Force non-root execution", "security",
                    security_impact="Root jobs can write to host volumes and modify system files"),
                "spec.template.spec.securityContext.runAsUser":    _field("integer", "UID to run as", "security"),
                "spec.template.spec.hostNetwork": _field(
                    "boolean", "Use host network namespace", "security",
                    security_impact="Host network exposes node traffic"),
                "spec.template.spec.hostPID":     _field(
                    "boolean", "Share host PID namespace", "security",
                    security_impact="Host PID allows node process inspection"),
                "spec.template.spec.hostIPC":     _field(
                    "boolean", "Share host IPC namespace", "security"),
                "spec.template.spec.containers":  _field(
                    "array", "Container list", "security",
                    security_impact="Each container should have security context defined"),
                "spec.template.spec.resources.limits": _field(
                    "object", "CPU/memory limits", "security",
                    security_impact="Unbounded jobs can exhaust node resources"),
            },
        }],
        "dependent": [],
    },

    "podtemplate": {
        "resource": "podtemplate", "api_version": "v1", "kind": "PodTemplate",
        "description": "PodTemplate resource — reusable pod spec template",
        "independent": [{
            "operation": "list", "http_method": "GET",
            "description": "List all PodTemplates across all namespaces",
            "item_fields": {
                "metadata.name":      _field("string", "PodTemplate name", "identity"),
                "metadata.namespace": _field("string", "Namespace", "identity"),
                "template.spec.securityContext.runAsNonRoot": _field(
                    "boolean", "Force non-root for all pods from this template", "security",
                    security_impact="Security defaults in templates propagate to all instantiated pods"),
                "template.spec.securityContext.runAsUser":    _field("integer", "UID to run as", "security"),
                "template.spec.hostNetwork": _field(
                    "boolean", "Use host network namespace", "security",
                    security_impact="Host network in template affects every pod created from it"),
                "template.spec.hostPID":     _field("boolean", "Share host PID namespace", "security"),
                "template.spec.hostIPC":     _field("boolean", "Share host IPC namespace", "security"),
                "template.spec.containers":  _field(
                    "array", "Container list", "security",
                    security_impact="Template containers should have full security context"),
                "template.spec.resources.limits": _field(
                    "object", "CPU/memory limits", "security",
                    security_impact="Resource limits in template enforce bounds on all pods"),
            },
        }],
        "dependent": [],
    },

    "resourcequota": {
        "resource": "resourcequota", "api_version": "v1", "kind": "ResourceQuota",
        "description": "ResourceQuota resource — limits aggregate resource usage per namespace",
        "independent": [{
            "operation": "list", "http_method": "GET",
            "description": "List all ResourceQuotas across all namespaces",
            "item_fields": {
                "metadata.name":      _field("string", "ResourceQuota name", "identity"),
                "metadata.namespace": _field("string", "Namespace", "identity"),
                "spec.hard": _field(
                    "object", "Maximum allowed resource quantities", "security",
                    security_impact="Missing quotas allow unbounded resource consumption leading to DoS"),
                "status.hard":     _field("object", "Applied hard limits", "general"),
                "status.used":     _field("object", "Currently consumed resources", "general"),
            },
        }],
        "dependent": [],
    },

    "limitrange": {
        "resource": "limitrange", "api_version": "v1", "kind": "LimitRange",
        "description": "LimitRange resource — sets default and max resource limits per namespace",
        "independent": [{
            "operation": "list", "http_method": "GET",
            "description": "List all LimitRanges across all namespaces",
            "item_fields": {
                "metadata.name":      _field("string", "LimitRange name", "identity"),
                "metadata.namespace": _field("string", "Namespace", "identity"),
                "spec.limits": _field(
                    "array", "List of limit type constraints (default/max/min)", "security",
                    security_impact="Default limits protect against containers omitting resource constraints"),
            },
        }],
        "dependent": [],
    },

    "storageclass": {
        "resource": "storageclass", "api_version": "storage.k8s.io/v1", "kind": "StorageClass",
        "description": "StorageClass resource — defines storage provisioner and policy",
        "independent": [{
            "operation": "list", "http_method": "GET",
            "description": "List all StorageClasses",
            "item_fields": {
                "metadata.name":         _field("string", "StorageClass name", "identity"),
                "provisioner":           _field("string", "Volume provisioner plugin", "configuration"),
                "parameters":            _field(
                    "object", "Provisioner-specific parameters (e.g. encryption settings)", "security",
                    security_impact="Parameters control whether volumes are encrypted at rest"),
                "reclaimPolicy":         _field(
                    "string", "Volume reclaim policy after PVC deletion", "security",
                    security_impact="Delete policy auto-removes data — Retain is safer for sensitive workloads",
                    enum=True, values=["Retain", "Delete", "Recycle"]),
                "volumeBindingMode":     _field(
                    "string", "When volume binding occurs", "security",
                    security_impact="WaitForFirstConsumer aligns zone topology and prevents mis-provisioning",
                    enum=True, values=["Immediate", "WaitForFirstConsumer"]),
                "allowVolumeExpansion":  _field(
                    "boolean", "Whether volumes can be expanded after creation", "configuration"),
            },
        }],
        "dependent": [],
    },

    "replicaset": {
        "resource": "replicaset", "api_version": "apps/v1", "kind": "ReplicaSet",
        "description": "ReplicaSet resource — maintains a stable set of replica pods",
        "independent": [{
            "operation": "list", "http_method": "GET",
            "description": "List all ReplicaSets across all namespaces",
            "item_fields": {
                "metadata.name":      _field("string", "ReplicaSet name", "identity"),
                "metadata.namespace": _field("string", "Namespace", "identity"),
                "spec.template.spec.securityContext.runAsNonRoot": _field(
                    "boolean", "Force non-root across all replicas", "security",
                    security_impact="Non-root reduces blast radius of container escape across all replicas"),
                "spec.template.spec.securityContext.runAsUser":    _field("integer", "UID to run as", "security"),
                "spec.template.spec.automountServiceAccountToken": _field(
                    "boolean", "Auto-mount SA token", "security",
                    security_impact="Auto-mounted tokens give every replica pod API credentials"),
                "spec.template.spec.hostNetwork": _field(
                    "boolean", "Use host network", "security",
                    security_impact="Host network in replicated workloads multiplies attack surface"),
                "spec.template.spec.hostPID":     _field("boolean", "Share host PID", "security"),
                "spec.template.spec.hostIPC":     _field("boolean", "Share host IPC", "security"),
                "spec.template.spec.containers":  _field(
                    "array", "Container list", "security",
                    security_impact="All replicas inherit the container security context"),
                "spec.template.spec.resources.limits": _field(
                    "object", "CPU/memory limits", "security",
                    security_impact="Limits on templates apply to every replica pod"),
            },
        }],
        "dependent": [],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Security check definitions per service
# Each entry: rule_id suffix, resource, requirement, var (field from step4),
#             op, value, title, description, rationale, severity, domain,
#             subcategory, compliance
# ─────────────────────────────────────────────────────────────────────────────

SEC_CHECKS = {
    "clusterrole": [
        ("permission.wildcard_verbs_restricted", "permission", "Wildcard Verbs Restricted",
         "rules", "exists", None, "high", "identity_and_access_management", "least_privilege",
         ["cis_kubernetes_v1_9_5_1_1", "nist_800_53_r5_multi_cloud_AC-6_0001", "soc2_multi_cloud_cc_6_3_0011"],
         "ClusterRole Must Not Use Wildcard Verbs",
         "Checks that ClusterRoles do not grant wildcard (*) verbs, which allow every action on matched resources.",
         "Wildcard verbs grant overly broad permissions violating least-privilege; an attacker gaining such a role can perform any operation."),
        ("permission.wildcard_resources_restricted", "permission", "Wildcard Resources Restricted",
         "rules", "exists", None, "high", "identity_and_access_management", "least_privilege",
         ["cis_kubernetes_v1_9_5_1_1", "nist_800_53_r5_multi_cloud_AC-6_0001"],
         "ClusterRole Must Not Use Wildcard Resource Types",
         "Checks that ClusterRoles do not target wildcard (*) resource types.",
         "Wildcard resources allow the holder to operate on any API object in the cluster."),
        ("permission.secrets_access_restricted", "permission", "Secrets Access Restricted",
         "rules", "exists", None, "high", "identity_and_access_management", "data_access_control",
         ["cis_kubernetes_v1_9_5_1_1", "hipaa_multi_cloud_164_312_a_1_0022"],
         "ClusterRole Should Not Grant Broad Secrets Access",
         "Checks that ClusterRoles do not grant get/list/watch on secrets cluster-wide.",
         "Broad secrets access lets an attacker harvest API tokens, TLS certs, and application passwords."),
        ("escalation.impersonation_restricted", "escalation", "Impersonation Restricted",
         "rules", "exists", None, "critical", "identity_and_access_management", "privilege_escalation",
         ["cis_kubernetes_v1_9_5_1_1", "nist_800_53_r5_multi_cloud_AC-6_0001"],
         "ClusterRole Must Not Allow User Impersonation",
         "Checks that ClusterRoles do not grant the impersonate verb on users, groups, or serviceaccounts.",
         "Impersonation rights allow the holder to act as any user or SA, bypassing all RBAC controls."),
        ("permission.exec_restricted", "permission", "Exec Restricted",
         "rules", "exists", None, "high", "identity_and_access_management", "least_privilege",
         ["cis_kubernetes_v1_9_5_1_1"],
         "ClusterRole Must Not Grant Pod Exec Cluster-Wide",
         "Checks that ClusterRoles do not allow create on pods/exec.",
         "pods/exec access is equivalent to remote code execution on any pod in the cluster."),
    ],

    "clusterrolebinding": [
        ("binding.cluster_admin_not_bound_to_service_account", "binding",
         "Cluster Admin Not Bound To Service Account",
         "roleRef.name", "not_equals", "cluster-admin", "critical",
         "identity_and_access_management", "privilege_escalation",
         ["cis_kubernetes_v1_9_5_1_1", "nist_800_53_r5_multi_cloud_AC-6_0001"],
         "cluster-admin Role Must Not Be Bound to Service Accounts",
         "Checks that the cluster-admin ClusterRole is not bound to service accounts.",
         "Binding cluster-admin to a SA allows any workload using that SA to perform any cluster action."),
        ("binding.default_namespace_sa_not_admin_bound", "binding",
         "Default Namespace SA Not Admin Bound",
         "subjects", "exists", None, "high",
         "identity_and_access_management", "least_privilege",
         ["cis_kubernetes_v1_9_5_1_3"],
         "Default Service Account Must Not Have ClusterRole Admin Binding",
         "Checks that ClusterRoleBindings do not reference the default service account.",
         "The default SA is auto-mounted in pods; binding it to a powerful ClusterRole is a lateral movement risk."),
        ("binding.subjects_exist", "binding", "Subjects Exist",
         "subjects", "exists", None, "low",
         "identity_and_access_management", "access_review",
         ["soc2_multi_cloud_cc_6_2_0010"],
         "ClusterRoleBinding Subjects Should Reference Existing Entities",
         "Checks that ClusterRoleBindings have at least one valid subject.",
         "Orphaned bindings indicate stale access grants that should be cleaned up."),
    ],

    "role": [
        ("permission.wildcard_verbs_restricted", "permission", "Wildcard Verbs Restricted",
         "rules", "exists", None, "high", "identity_and_access_management", "least_privilege",
         ["cis_kubernetes_v1_9_5_1_1", "nist_800_53_r5_multi_cloud_AC-6_0001"],
         "Role Must Not Use Wildcard Verbs",
         "Checks that namespace-scoped Roles do not grant wildcard (*) verbs.",
         "Wildcard verbs in a namespace Role allow any action on resources in that namespace."),
        ("permission.secrets_access_restricted", "permission", "Secrets Access Restricted",
         "rules", "exists", None, "high", "identity_and_access_management", "data_access_control",
         ["cis_kubernetes_v1_9_5_1_1", "hipaa_multi_cloud_164_312_a_1_0022"],
         "Role Should Not Grant Broad Secrets Access",
         "Checks that namespace-scoped Roles do not grant get/list/watch on all secrets.",
         "Namespace-wide secrets access exposes credentials of every application in that namespace."),
        ("permission.exec_restricted", "permission", "Exec Restricted",
         "rules", "exists", None, "high", "identity_and_access_management", "least_privilege",
         ["cis_kubernetes_v1_9_5_1_1"],
         "Role Must Not Grant Pod Exec in Namespace",
         "Checks that namespace-scoped Roles do not allow create on pods/exec.",
         "pods/exec in a namespace allows interactive shell access to any pod in that namespace."),
    ],

    "rolebinding": [
        ("binding.admin_role_not_bound", "binding", "Admin Role Not Bound",
         "roleRef", "exists", None, "high",
         "identity_and_access_management", "privilege_escalation",
         ["cis_kubernetes_v1_9_5_1_1", "nist_800_53_r5_multi_cloud_AC-6_0001"],
         "RoleBinding Must Not Grant Admin-Level Roles",
         "Checks that RoleBindings do not reference cluster-admin or admin ClusterRoles.",
         "Binding admin ClusterRoles in a namespace grants full control over all resources in that namespace."),
        ("binding.default_sa_not_bound", "binding", "Default SA Not Bound",
         "subjects", "exists", None, "medium",
         "identity_and_access_management", "least_privilege",
         ["cis_kubernetes_v1_9_5_1_3"],
         "RoleBinding Must Not Bind Default Service Account to Privileged Role",
         "Checks that RoleBindings do not grant elevated roles to the default service account.",
         "Pods that do not specify a SA use the default; binding it to a privileged role exposes all such pods."),
    ],

    "serviceaccount": [
        ("token.automount_disabled", "token", "Automount Disabled",
         "automountServiceAccountToken", "equals", "false", "medium",
         "identity_and_access_management", "least_privilege",
         ["cis_kubernetes_v1_9_5_1_6", "nist_800_53_r5_multi_cloud_AC-6_0001"],
         "Service Account Should Disable Automatic Token Mounting",
         "Checks that service accounts set automountServiceAccountToken to false unless required.",
         "Auto-mounted tokens give every pod the SA credentials by default, reducing attack surface when disabled."),
        ("permission.default_sa_not_used_for_workloads", "permission",
         "Default SA Not Used For Workloads",
         "metadata.name", "not_equals", "default", "medium",
         "identity_and_access_management", "access_segregation",
         ["cis_kubernetes_v1_9_5_1_5"],
         "Workloads Should Not Use the Default Service Account",
         "Checks that workloads specify a dedicated service account rather than the default.",
         "Using the default SA shares credentials across all workloads in a namespace."),
        ("token.no_long_lived_tokens", "token", "No Long Lived Tokens",
         "secrets", "exists", None, "medium",
         "identity_and_access_management", "credential_management",
         ["cis_kubernetes_v1_9_5_1_6", "nist_800_53_r5_multi_cloud_IA-5_0002"],
         "Service Account Should Not Have Long-Lived Static Tokens",
         "Checks that service accounts do not have manually created long-lived token secrets.",
         "Long-lived tokens do not expire; bound tokens (TokenRequest API) are time-limited and safer."),
    ],

    "networkpolicy": [
        ("ingress.default_deny_configured", "ingress", "Default Deny Configured",
         "spec.ingress", "exists", None, "high",
         "network_security_and_connectivity", "network_segmentation",
         ["cis_kubernetes_v1_9_5_3_2", "nist_800_53_r5_multi_cloud_SC-7_0001", "soc2_multi_cloud_cc_6_6_0012"],
         "Namespace Should Have a Default Deny Ingress NetworkPolicy",
         "Checks that namespaces have a NetworkPolicy implementing default-deny ingress.",
         "Without default-deny all pods can receive traffic from any source, enabling lateral movement."),
        ("egress.default_deny_configured", "egress", "Default Deny Configured",
         "spec.egress", "exists", None, "high",
         "network_security_and_connectivity", "network_segmentation",
         ["cis_kubernetes_v1_9_5_3_2", "nist_800_53_r5_multi_cloud_SC-7_0001"],
         "Namespace Should Have a Default Deny Egress NetworkPolicy",
         "Checks that namespaces have a default-deny egress NetworkPolicy.",
         "Unrestricted egress allows compromised pods to communicate with attacker C2 infrastructure."),
        ("rule.no_allow_all_ingress", "rule", "No Allow All Ingress",
         "spec.ingress", "exists", None, "high",
         "network_security_and_connectivity", "network_access_control",
         ["cis_kubernetes_v1_9_5_3_2"],
         "NetworkPolicy Must Not Allow All Ingress Traffic",
         "Checks that NetworkPolicies do not contain empty ingress rules that allow all sources.",
         "An empty ingress block allows all traffic in, effectively disabling pod isolation."),
        ("rule.no_allow_all_egress", "rule", "No Allow All Egress",
         "spec.egress", "exists", None, "medium",
         "network_security_and_connectivity", "network_access_control",
         ["cis_kubernetes_v1_9_5_3_2"],
         "NetworkPolicy Must Not Allow All Egress Traffic",
         "Checks that NetworkPolicies do not use empty egress rules allowing all outbound connections.",
         "Unrestricted egress rules negate the protective effect of the policy."),
        ("spec.policy_types_configured", "spec", "Policy Types Configured",
         "spec.policyTypes", "exists", None, "medium",
         "network_security_and_connectivity", "network_access_control",
         ["cis_kubernetes_v1_9_5_3_2"],
         "NetworkPolicy Should Explicitly Declare policyTypes",
         "Checks that NetworkPolicies set policyTypes to declare Ingress and/or Egress coverage.",
         "Without explicit policyTypes the scope of the policy is ambiguous and may not enforce egress."),
    ],

    "deployment": [
        ("container.privileged_disabled", "container", "Privileged Disabled",
         "spec.template.spec.containers", "exists", None, "critical",
         "infrastructure_security", "container_security",
         ["cis_kubernetes_v1_9_5_2_1", "nist_800_53_r5_multi_cloud_CM-6_0001"],
         "Deployment Containers Must Not Run as Privileged",
         "Checks that no container in the Deployment spec sets securityContext.privileged to true.",
         "Privileged containers have nearly unrestricted host access and can escape the container to compromise the node."),
        ("container.run_as_non_root_enabled", "container", "Run As Non Root Enabled",
         "spec.template.spec.securityContext.runAsNonRoot", "equals", "true", "high",
         "infrastructure_security", "container_security",
         ["cis_kubernetes_v1_9_5_2_6", "nist_800_53_r5_multi_cloud_CM-6_0001"],
         "Deployment Containers Must Run as Non-Root User",
         "Checks that the pod securityContext sets runAsNonRoot to true.",
         "Running containers as root increases the blast radius of a container escape vulnerability."),
        ("container.host_network_disabled", "container", "Host Network Disabled",
         "spec.template.spec.hostNetwork", "equals", "false", "high",
         "network_security_and_connectivity", "network_isolation",
         ["cis_kubernetes_v1_9_5_2_3", "nist_800_53_r5_multi_cloud_SC-7_0001"],
         "Deployment Pods Must Not Use Host Network",
         "Checks that Deployment pods do not set hostNetwork: true.",
         "Host network access allows pods to sniff all node network traffic including cluster-internal communication."),
        ("container.host_pid_disabled", "container", "Host PID Disabled",
         "spec.template.spec.hostPID", "equals", "false", "high",
         "infrastructure_security", "container_isolation",
         ["cis_kubernetes_v1_9_5_2_2"],
         "Deployment Pods Must Not Share Host PID Namespace",
         "Checks that Deployment pods do not set hostPID: true.",
         "Sharing host PID allows the pod to see and signal all processes on the node."),
        ("container.host_ipc_disabled", "container", "Host IPC Disabled",
         "spec.template.spec.hostIPC", "equals", "false", "medium",
         "infrastructure_security", "container_isolation",
         ["cis_kubernetes_v1_9_5_2_3"],
         "Deployment Pods Must Not Share Host IPC Namespace",
         "Checks that Deployment pods do not set hostIPC: true.",
         "Sharing host IPC exposes all inter-process communication on the node."),
        ("container.resource_limits_configured", "container", "Resource Limits Configured",
         "spec.template.spec.resources.limits", "exists", None, "medium",
         "infrastructure_security", "resource_management",
         ["cis_kubernetes_v1_9_5_2_11", "nist_800_53_r5_multi_cloud_SC-6_0001"],
         "Deployment Containers Must Define CPU and Memory Limits",
         "Checks that containers in the Deployment define resources.limits.",
         "Without resource limits a single container can exhaust node resources causing denial-of-service."),
        ("container.automount_sa_token_disabled", "container",
         "Automount SA Token Disabled",
         "spec.template.spec.automountServiceAccountToken", "equals", "false", "medium",
         "identity_and_access_management", "least_privilege",
         ["cis_kubernetes_v1_9_5_1_6"],
         "Deployment Pods Should Disable Automatic Service Account Token Mounting",
         "Checks that Deployment pods set automountServiceAccountToken to false unless the workload calls the API.",
         "Auto-mounted tokens give every pod API credentials by default, widening the credential attack surface."),
    ],

    "daemonset": [
        ("container.privileged_disabled", "container", "Privileged Disabled",
         "spec.template.spec.containers", "exists", None, "critical",
         "infrastructure_security", "container_security",
         ["cis_kubernetes_v1_9_5_2_1", "nist_800_53_r5_multi_cloud_CM-6_0001"],
         "DaemonSet Containers Must Not Run as Privileged",
         "Checks that DaemonSet pods do not run containers with securityContext.privileged=true.",
         "DaemonSets run on every node; a privileged DaemonSet can compromise the entire cluster node fleet."),
        ("container.run_as_non_root_enabled", "container", "Run As Non Root Enabled",
         "spec.template.spec.securityContext.runAsNonRoot", "equals", "true", "high",
         "infrastructure_security", "container_security",
         ["cis_kubernetes_v1_9_5_2_6"],
         "DaemonSet Containers Must Run as Non-Root User",
         "Checks that DaemonSet pod securityContext sets runAsNonRoot to true.",
         "Running DaemonSet containers as root on every node dramatically increases the impact of a container escape."),
        ("container.host_network_disabled", "container", "Host Network Disabled",
         "spec.template.spec.hostNetwork", "equals", "false", "high",
         "network_security_and_connectivity", "network_isolation",
         ["cis_kubernetes_v1_9_5_2_3"],
         "DaemonSet Pods Must Not Use Host Network",
         "Checks that DaemonSet pods do not set hostNetwork: true.",
         "Host network on a DaemonSet exposes every node's traffic to the container."),
        ("container.host_pid_disabled", "container", "Host PID Disabled",
         "spec.template.spec.hostPID", "equals", "false", "high",
         "infrastructure_security", "container_isolation",
         ["cis_kubernetes_v1_9_5_2_2"],
         "DaemonSet Pods Must Not Share Host PID Namespace",
         "Checks that DaemonSet pods do not set hostPID: true.",
         "Sharing host PID on every node allows seeing and interacting with all node processes."),
        ("container.host_ipc_disabled", "container", "Host IPC Disabled",
         "spec.template.spec.hostIPC", "equals", "false", "medium",
         "infrastructure_security", "container_isolation",
         ["cis_kubernetes_v1_9_5_2_3"],
         "DaemonSet Pods Must Not Share Host IPC Namespace",
         "Checks that DaemonSet pods do not set hostIPC: true.",
         "Sharing host IPC exposes all inter-process communication on every node."),
        ("container.resource_limits_configured", "container", "Resource Limits Configured",
         "spec.template.spec.resources.limits", "exists", None, "medium",
         "infrastructure_security", "resource_management",
         ["cis_kubernetes_v1_9_5_2_11"],
         "DaemonSet Containers Must Define Resource Limits",
         "Checks that DaemonSet containers define CPU and memory limits.",
         "Unbounded DaemonSet containers running on every node can starve all other workloads."),
    ],

    "statefulset": [
        ("container.privileged_disabled", "container", "Privileged Disabled",
         "spec.template.spec.containers", "exists", None, "critical",
         "infrastructure_security", "container_security",
         ["cis_kubernetes_v1_9_5_2_1"],
         "StatefulSet Containers Must Not Run as Privileged",
         "Checks that StatefulSet pods do not run containers with privileged=true.",
         "Privileged StatefulSet containers (often databases) can break out to the host and access persistent volumes."),
        ("container.run_as_non_root_enabled", "container", "Run As Non Root Enabled",
         "spec.template.spec.securityContext.runAsNonRoot", "equals", "true", "high",
         "infrastructure_security", "container_security",
         ["cis_kubernetes_v1_9_5_2_6"],
         "StatefulSet Containers Must Run as Non-Root User",
         "Checks that StatefulSet pod securityContext sets runAsNonRoot to true.",
         "Root-running StatefulSet containers pose heightened risk due to access to persistent storage."),
        ("container.host_network_disabled", "container", "Host Network Disabled",
         "spec.template.spec.hostNetwork", "equals", "false", "high",
         "network_security_and_connectivity", "network_isolation",
         ["cis_kubernetes_v1_9_5_2_3"],
         "StatefulSet Pods Must Not Use Host Network",
         "Checks that StatefulSet pods do not set hostNetwork: true.",
         "Host network access allows stateful pods to sniff node-level traffic."),
        ("container.resource_limits_configured", "container", "Resource Limits Configured",
         "spec.template.spec.resources.limits", "exists", None, "medium",
         "infrastructure_security", "resource_management",
         ["cis_kubernetes_v1_9_5_2_11"],
         "StatefulSet Containers Must Define Resource Limits",
         "Checks that StatefulSet containers define CPU and memory limits.",
         "Unbounded StatefulSet containers (typically databases) can starve the node causing OOM kills."),
        ("container.automount_sa_token_disabled", "container",
         "Automount SA Token Disabled",
         "spec.template.spec.automountServiceAccountToken", "equals", "false", "medium",
         "identity_and_access_management", "least_privilege",
         ["cis_kubernetes_v1_9_5_1_6"],
         "StatefulSet Pods Should Disable Automatic Service Account Token Mounting",
         "Checks that StatefulSet pods set automountServiceAccountToken to false.",
         "Stateful workloads rarely need API access; auto-mounted tokens unnecessarily expose credentials."),
    ],

    "cronjob": [
        ("container.privileged_disabled", "container", "Privileged Disabled",
         "spec.jobTemplate.spec.template.spec.containers", "exists", None, "critical",
         "infrastructure_security", "container_security",
         ["cis_kubernetes_v1_9_5_2_1"],
         "CronJob Containers Must Not Run as Privileged",
         "Checks that CronJob pod templates do not include privileged containers.",
         "CronJobs run unsupervised on schedule; privileged containers can execute arbitrary host operations repeatedly."),
        ("container.run_as_non_root_enabled", "container", "Run As Non Root Enabled",
         "spec.jobTemplate.spec.template.spec.securityContext.runAsNonRoot", "equals", "true", "high",
         "infrastructure_security", "container_security",
         ["cis_kubernetes_v1_9_5_2_6"],
         "CronJob Containers Must Run as Non-Root User",
         "Checks that CronJob pod securityContext sets runAsNonRoot to true.",
         "CronJobs running as root with write access to host volumes can be used for persistence."),
        ("container.host_network_disabled", "container", "Host Network Disabled",
         "spec.jobTemplate.spec.template.spec.hostNetwork", "equals", "false", "high",
         "network_security_and_connectivity", "network_isolation",
         ["cis_kubernetes_v1_9_5_2_3"],
         "CronJob Pods Must Not Use Host Network",
         "Checks that CronJob pods do not set hostNetwork: true.",
         "Host network on scheduled jobs allows periodic node traffic inspection."),
        ("spec.concurrency_policy_configured", "spec", "Concurrency Policy Configured",
         "spec.concurrencyPolicy", "not_equals", "Allow", "low",
         "infrastructure_security", "resource_management",
         ["soc2_multi_cloud_cc_6_6_0012"],
         "CronJob Should Set an Explicit Concurrency Policy",
         "Checks that CronJobs set concurrencyPolicy to Forbid or Replace rather than Allow.",
         "ConcurrencyPolicy=Allow can cause unbounded job accumulation leading to resource exhaustion."),
        ("container.resource_limits_configured", "container", "Resource Limits Configured",
         "spec.jobTemplate.spec.template.spec.resources.limits", "exists", None, "medium",
         "infrastructure_security", "resource_management",
         ["cis_kubernetes_v1_9_5_2_11"],
         "CronJob Containers Must Define Resource Limits",
         "Checks that CronJob containers define CPU and memory limits.",
         "Unbounded CronJob containers can exhaust node resources especially when concurrent runs are allowed."),
    ],

    "job": [
        ("container.privileged_disabled", "container", "Privileged Disabled",
         "spec.template.spec.containers", "exists", None, "critical",
         "infrastructure_security", "container_security",
         ["cis_kubernetes_v1_9_5_2_1"],
         "Job Containers Must Not Run as Privileged",
         "Checks that batch Job pod specs do not include privileged containers.",
         "Privileged batch jobs can modify host-level configurations or access sensitive files during execution."),
        ("container.run_as_non_root_enabled", "container", "Run As Non Root Enabled",
         "spec.template.spec.securityContext.runAsNonRoot", "equals", "true", "high",
         "infrastructure_security", "container_security",
         ["cis_kubernetes_v1_9_5_2_6"],
         "Job Containers Must Run as Non-Root User",
         "Checks that Job pod securityContext enforces non-root execution.",
         "Jobs often perform administrative tasks; running as root amplifies any vulnerability in the job logic."),
        ("container.host_network_disabled", "container", "Host Network Disabled",
         "spec.template.spec.hostNetwork", "equals", "false", "high",
         "network_security_and_connectivity", "network_isolation",
         ["cis_kubernetes_v1_9_5_2_3"],
         "Job Pods Must Not Use Host Network",
         "Checks that Job pods do not set hostNetwork: true.",
         "Host network in batch jobs allows node traffic sniffing during execution."),
        ("container.resource_limits_configured", "container", "Resource Limits Configured",
         "spec.template.spec.resources.limits", "exists", None, "medium",
         "infrastructure_security", "resource_management",
         ["cis_kubernetes_v1_9_5_2_11"],
         "Job Containers Must Define Resource Limits",
         "Checks that Job containers specify resource limits to prevent runaway consumption.",
         "Runaway batch jobs can consume all CPU and memory on a node, impacting production workloads."),
    ],

    "podtemplate": [
        ("container.privileged_disabled", "container", "Privileged Disabled",
         "template.spec.containers", "exists", None, "critical",
         "infrastructure_security", "container_security",
         ["cis_kubernetes_v1_9_5_2_1"],
         "PodTemplate Must Not Define Privileged Containers",
         "Checks that PodTemplate specs do not include containers with privileged=true.",
         "PodTemplates are instantiated by controllers; insecure templates propagate to all pods they create."),
        ("container.run_as_non_root_enabled", "container", "Run As Non Root Enabled",
         "template.spec.securityContext.runAsNonRoot", "equals", "true", "high",
         "infrastructure_security", "container_security",
         ["cis_kubernetes_v1_9_5_2_6"],
         "PodTemplate Must Enforce Non-Root Execution",
         "Checks that PodTemplate specs set runAsNonRoot in the security context.",
         "Security defaults set at template level cascade to all instantiated pods."),
        ("container.host_network_disabled", "container", "Host Network Disabled",
         "template.spec.hostNetwork", "equals", "false", "high",
         "network_security_and_connectivity", "network_isolation",
         ["cis_kubernetes_v1_9_5_2_3"],
         "PodTemplate Must Not Enable Host Network",
         "Checks that PodTemplate specs do not set hostNetwork: true.",
         "Host network in a template affects every pod created from it across the namespace."),
        ("container.resource_limits_configured", "container", "Resource Limits Configured",
         "template.spec.resources.limits", "exists", None, "medium",
         "infrastructure_security", "resource_management",
         ["cis_kubernetes_v1_9_5_2_11"],
         "PodTemplate Containers Must Define Resource Limits",
         "Checks that containers in PodTemplate specs define CPU and memory limits.",
         "Resource limits in templates ensure every instantiated pod has guardrails against resource exhaustion."),
    ],

    "persistentvolumeclaim": [
        ("access.access_mode_not_readwritemany", "access",
         "Access Mode Not ReadWriteMany",
         "spec.accessModes", "exists", None, "medium",
         "data_security", "data_access_governance",
         ["nist_800_53_r5_multi_cloud_SC-28_0001"],
         "PVC Should Not Use ReadWriteMany Access Mode Unless Required",
         "Checks that PVCs do not use ReadWriteMany unless the workload requires shared storage.",
         "ReadWriteMany allows multiple pods to write simultaneously; over-use widens blast radius of a compromised pod."),
        ("storage.storage_class_configured", "storage",
         "Storage Class Configured",
         "spec.storageClassName", "exists", None, "medium",
         "data_security", "encryption_at_rest",
         ["nist_800_53_r5_multi_cloud_SC-28_0001", "hipaa_multi_cloud_164_312_a_2_iv_0025"],
         "PVC Should Reference an Explicit StorageClass",
         "Checks that PVCs specify a storageClassName rather than relying on the default.",
         "The default storage class may provision unencrypted volumes; explicit class ensures encryption policy is applied."),
        ("status.bound_to_volume", "status", "Bound To Volume",
         "status.phase", "equals", "Bound", "low",
         "infrastructure_security", "configuration_management",
         ["soc2_multi_cloud_cc_6_6_0012"],
         "PVC Should Be in Bound Status",
         "Checks that all PVCs are in Bound phase and not stuck in Pending or Lost state.",
         "Unbound PVCs indicate provisioning failures; Lost PVCs indicate data may be inaccessible or orphaned."),
    ],

    "resourcequota": [
        ("compute.cpu_limit_configured", "compute", "CPU Limit Configured",
         "spec.hard", "exists", None, "medium",
         "infrastructure_security", "resource_management",
         ["cis_kubernetes_v1_9_5_7_1", "nist_800_53_r5_multi_cloud_SC-6_0001"],
         "Namespace ResourceQuota Should Enforce CPU Limits",
         "Checks that a ResourceQuota sets limits.cpu for the namespace.",
         "Without namespace-level CPU quotas a single tenant can starve all others, creating a denial-of-service."),
        ("compute.memory_limit_configured", "compute", "Memory Limit Configured",
         "spec.hard", "exists", None, "medium",
         "infrastructure_security", "resource_management",
         ["cis_kubernetes_v1_9_5_7_1", "nist_800_53_r5_multi_cloud_SC-6_0001"],
         "Namespace ResourceQuota Should Enforce Memory Limits",
         "Checks that a ResourceQuota sets limits.memory for the namespace.",
         "Unbounded memory usage by a namespace can trigger node OOM, killing critical workloads."),
        ("object.pod_count_limit_configured", "object", "Pod Count Limit Configured",
         "spec.hard", "exists", None, "low",
         "infrastructure_security", "resource_management",
         ["nist_800_53_r5_multi_cloud_SC-6_0001"],
         "Namespace ResourceQuota Should Limit Pod Count",
         "Checks that a ResourceQuota enforces a maximum pod count per namespace.",
         "Unlimited pod counts allow fork-bomb style attacks exhausting scheduler and cluster capacity."),
    ],

    "limitrange": [
        ("compute.default_cpu_limit_configured", "compute", "Default CPU Limit Configured",
         "spec.limits", "exists", None, "medium",
         "infrastructure_security", "resource_management",
         ["cis_kubernetes_v1_9_5_7_1", "nist_800_53_r5_multi_cloud_SC-6_0001"],
         "LimitRange Should Configure Default CPU Limit",
         "Checks that a LimitRange sets a default CPU limit for containers in the namespace.",
         "Without a default CPU limit, containers that omit resource limits have unlimited CPU, risking node starvation."),
        ("compute.default_memory_limit_configured", "compute", "Default Memory Limit Configured",
         "spec.limits", "exists", None, "medium",
         "infrastructure_security", "resource_management",
         ["cis_kubernetes_v1_9_5_7_1"],
         "LimitRange Should Configure Default Memory Limit",
         "Checks that a LimitRange sets a default memory limit for containers.",
         "Default memory limits ensure all containers including those without explicit limits are constrained."),
        ("compute.max_cpu_limit_configured", "compute", "Max CPU Limit Configured",
         "spec.limits", "exists", None, "low",
         "infrastructure_security", "resource_management",
         ["nist_800_53_r5_multi_cloud_SC-6_0001"],
         "LimitRange Should Configure Maximum CPU Limit",
         "Checks that a LimitRange sets a maximum CPU constraint to prevent resource abuse.",
         "A maximum CPU limit prevents individual containers from monopolising node CPU resources."),
    ],

    "storageclass": [
        ("encryption.encryption_enabled", "encryption", "Encryption Enabled",
         "parameters", "exists", None, "high",
         "data_security", "encryption_at_rest",
         ["nist_800_53_r5_multi_cloud_SC-28_0001", "hipaa_multi_cloud_164_312_a_2_iv_0025", "pci_dss_v4_multi_cloud_3.5.1_0038"],
         "StorageClass Should Enable Encryption at Rest",
         "Checks that the StorageClass parameters enable encryption for provisioned volumes.",
         "Unencrypted persistent volumes expose data if underlying storage media is compromised or decommissioned."),
        ("policy.reclaim_policy_retain_configured", "policy", "Reclaim Policy Retain Configured",
         "reclaimPolicy", "equals", "Retain", "medium",
         "data_security", "data_protection",
         ["nist_800_53_r5_multi_cloud_CP-9_0001", "soc2_multi_cloud_cc_9_1_0015"],
         "StorageClass Should Use Retain Reclaim Policy for Sensitive Data",
         "Checks that StorageClasses set reclaimPolicy to Retain.",
         "The Delete reclaim policy auto-deletes volumes on PVC removal, risking data loss on accidental deletion."),
        ("access.volume_binding_mode_configured", "access", "Volume Binding Mode Configured",
         "volumeBindingMode", "equals", "WaitForFirstConsumer", "low",
         "infrastructure_security", "configuration_management",
         ["soc2_multi_cloud_cc_6_6_0012"],
         "StorageClass Should Set WaitForFirstConsumer Binding Mode",
         "Checks that StorageClass uses WaitForFirstConsumer volume binding mode.",
         "Immediate binding can provision volumes in the wrong zone causing pod scheduling failures."),
    ],

    "replicaset": [
        ("container.privileged_disabled", "container", "Privileged Disabled",
         "spec.template.spec.containers", "exists", None, "critical",
         "infrastructure_security", "container_security",
         ["cis_kubernetes_v1_9_5_2_1"],
         "ReplicaSet Containers Must Not Run as Privileged",
         "Checks that ReplicaSet pod templates do not define privileged containers.",
         "A privileged template multiplies the attack surface across all replicas."),
        ("container.run_as_non_root_enabled", "container", "Run As Non Root Enabled",
         "spec.template.spec.securityContext.runAsNonRoot", "equals", "true", "high",
         "infrastructure_security", "container_security",
         ["cis_kubernetes_v1_9_5_2_6"],
         "ReplicaSet Containers Must Run as Non-Root User",
         "Checks that ReplicaSet pod specs enforce non-root execution.",
         "Non-root enforcement limits capabilities available to a compromised container across all replicas."),
        ("container.host_network_disabled", "container", "Host Network Disabled",
         "spec.template.spec.hostNetwork", "equals", "false", "high",
         "network_security_and_connectivity", "network_isolation",
         ["cis_kubernetes_v1_9_5_2_3"],
         "ReplicaSet Pods Must Not Use Host Network",
         "Checks that ReplicaSet pods do not set hostNetwork: true.",
         "Host network across multiple replicas exposes every replica to node traffic."),
        ("container.resource_limits_configured", "container", "Resource Limits Configured",
         "spec.template.spec.resources.limits", "exists", None, "medium",
         "infrastructure_security", "resource_management",
         ["cis_kubernetes_v1_9_5_2_11"],
         "ReplicaSet Containers Must Define Resource Limits",
         "Checks that ReplicaSet containers define CPU and memory limits.",
         "Unconstrained replicas can collectively exhaust node and cluster resources."),
        ("container.automount_sa_token_disabled", "container",
         "Automount SA Token Disabled",
         "spec.template.spec.automountServiceAccountToken", "equals", "false", "medium",
         "identity_and_access_management", "least_privilege",
         ["cis_kubernetes_v1_9_5_1_6"],
         "ReplicaSet Pods Should Disable Automatic Service Account Token Mounting",
         "Checks that ReplicaSet pods set automountServiceAccountToken to false.",
         "Auto-mounted tokens multiply the credential exposure across all replicas."),
    ],
}


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 1 — write missing step4 files
# ─────────────────────────────────────────────────────────────────────────────

def enrich_missing_step4():
    for svc, data in MISSING_STEP4.items():
        out_dir  = STEP4_ROOT / svc
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "k8s_dependencies_with_python_names_fully_enriched.json"
        with open(out_file, "w") as f:
            json.dump({svc: data}, f, indent=2)
        print(f"  [step4] enriched {svc} → {out_file.relative_to(STEP4_ROOT.parent.parent)}")


# ─────────────────────────────────────────────────────────────────────────────
# PHASE 2 — generate check YAMLs + metadata from step4
# ─────────────────────────────────────────────────────────────────────────────

def load_step4(svc: str) -> dict:
    """Load step4 for a service, return the first 'list' independent op."""
    f = STEP4_ROOT / svc / "k8s_dependencies_with_python_names_fully_enriched.json"
    d = json.loads(f.read_text())
    entry = d[list(d.keys())[0]]
    for op in entry.get("independent", []):
        if op["operation"] == "list":
            return op
    return entry.get("independent", [{}])[0]


def write_checks_and_metadata(svc: str, checks: list):
    op = load_step4(svc)
    for_each = f"k8s.{svc}.list"

    # ── check file ──────────────────────────────────────────────────────────
    check_entries = []
    for row in checks:
        (suffix, resource, requirement, var_field,
         op_name, value, severity, domain, subcategory,
         compliance, title, description, rationale) = row

        rule_id = f"k8s.{svc}.{suffix}"
        check_entries.append({
            "rule_id":    rule_id,
            "for_each":   for_each,
            "conditions": {"var": f"item.{var_field}", "op": op_name, "value": value},
        })

    check_dir = CHECK_OUT / svc
    check_dir.mkdir(parents=True, exist_ok=True)
    check_doc = {"version": "1.0", "provider": "k8s", "service": svc, "checks": check_entries}
    with open(check_dir / f"{svc}.checks.yaml", "w") as f:
        yaml.dump(check_doc, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    # ── metadata files ──────────────────────────────────────────────────────
    meta_dir = META_OUT / svc
    meta_dir.mkdir(parents=True, exist_ok=True)
    for row in checks:
        (suffix, resource, requirement, var_field,
         op_name, value, severity, domain, subcategory,
         compliance, title, description, rationale) = row

        rule_id = f"k8s.{svc}.{suffix}"
        scope   = ".".join(rule_id.split(".")[1:])
        meta = {
            "rule_id":    rule_id,
            "service":    svc,
            "resource":   resource,
            "requirement": requirement,
            "title":      title,
            "description": description,
            "rationale":  rationale,
            "severity":   severity,
            "domain":     domain,
            "subcategory": subcategory,
            "scope":      scope,
            "references": [
                "https://kubernetes.io/docs/concepts/security/",
                "https://kubernetes.io/docs/reference/",
            ],
            "compliance":      compliance,
            "metadata_source": "default",
            "generated_by":    "k8s_stub_rule_generator_step4",
            "remediation": (
                f"Review and remediate '{title}' following Kubernetes "
                "security best practices and the CIS Kubernetes Benchmark."
            ),
        }
        with open(meta_dir / f"{rule_id}.yaml", "w") as f:
            yaml.dump(meta, f, default_flow_style=False, sort_keys=False, allow_unicode=True)

    print(f"  {svc:<30} for_each=k8s.{svc}.list | {len(checks)} checks")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("Phase 1 — enriching missing step4 files...")
    enrich_missing_step4()

    print("\nPhase 2 — generating check YAMLs + metadata from step4...")
    total = 0
    for svc, checks in SEC_CHECKS.items():
        write_checks_and_metadata(svc, checks)
        total += len(checks)

    print(f"\nDone: {total} checks across {len(SEC_CHECKS)} services")
    print(f"  → {CHECK_OUT}")
    print(f"  → {META_OUT}")


if __name__ == "__main__":
    main()
