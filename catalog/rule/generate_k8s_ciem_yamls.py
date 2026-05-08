#!/usr/bin/env python3
"""
generate_k8s_ciem_yamls.py

Generates fully-enriched K8s CIEM log-detection rule YAMLs under:
  catalog/rule/k8s_rule_ciem/<service>/k8s.<service>.<log_type>.<operation>.yaml

Source: Kubernetes API server audit logs (k8s_audit)
Applies to: GKE, EKS, AKS, OpenShift, self-managed clusters

Usage:
    python3 generate_k8s_ciem_yamls.py
    python3 generate_k8s_ciem_yamls.py --dry-run
"""

import argparse
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parent.parent.parent
OUT  = ROOT / "catalog" / "rule" / "k8s_rule_ciem"

# ─────────────────────────────────────────────────────────────────────────────
# Lookup tables
# ─────────────────────────────────────────────────────────────────────────────

DOMAIN_BY_CAT = {
    "privilege_escalation":    "container_and_kubernetes_security",
    "persistence":             "container_and_kubernetes_security",
    "credential_access":       "identity_and_access_management",
    "lateral_movement":        "network_security_and_connectivity",
    "defense_evasion":         "logging_monitoring_and_alerting",
    "data_exfiltration":       "data_protection_and_privacy",
    "impact":                  "compute_and_workload_security",
    "execution":               "compute_and_workload_security",
    "collection":              "data_protection_and_privacy",
    "supply_chain_compromise": "configuration_and_change_management",
    "identity_manipulation":   "identity_and_access_management",
}

ACTION_BY_CAT = {
    "privilege_escalation":    "privilege_escalation",
    "persistence":             "create",
    "credential_access":       "read",
    "lateral_movement":        "modify",
    "defense_evasion":         "delete",
    "data_exfiltration":       "read",
    "impact":                  "delete",
    "execution":               "create",
    "collection":              "read",
    "supply_chain_compromise": "create",
    "identity_manipulation":   "modify",
}

POSTURE_BY_CAT = {
    "privilege_escalation":    "iam_posture",
    "persistence":             "iam_posture",
    "credential_access":       "iam_posture",
    "lateral_movement":        "threat_posture",
    "defense_evasion":         "security_posture",
    "data_exfiltration":       "threat_posture",
    "impact":                  "threat_posture",
    "execution":               "threat_posture",
    "collection":              "threat_posture",
    "supply_chain_compromise": "security_posture",
    "identity_manipulation":   "iam_posture",
}

IAM_CATS  = {"privilege_escalation", "persistence", "credential_access", "identity_manipulation"}
DATA_CATS = {"data_exfiltration", "collection", "impact"}

COMPLIANCE = {
    "privilege_escalation": {
        "cis_k8s_v1":      ["5.1.1", "5.1.2", "5.1.3", "5.1.5"],
        "nist_800_53_r5":  ["AC-2", "AC-3", "AC-6", "IA-2"],
        "pci_dss_v4":      ["7.1", "7.2", "8.2"],
        "iso_27001_2022":  ["A.5.18", "A.8.2", "A.8.3"],
    },
    "persistence": {
        "cis_k8s_v1":      ["5.1.1", "5.1.4", "5.4.1"],
        "nist_800_53_r5":  ["AC-2", "AC-6", "CM-7"],
        "pci_dss_v4":      ["7.1", "8.2", "6.4"],
        "iso_27001_2022":  ["A.5.18", "A.8.19"],
    },
    "credential_access": {
        "cis_k8s_v1":      ["5.1.6", "5.4.1", "5.4.2"],
        "nist_800_53_r5":  ["IA-5", "IA-8", "SC-28"],
        "pci_dss_v4":      ["3.1", "8.3", "8.6"],
        "iso_27001_2022":  ["A.8.5", "A.8.6", "A.5.17"],
    },
    "lateral_movement": {
        "cis_k8s_v1":      ["5.2.5", "5.2.7", "5.7.1"],
        "nist_800_53_r5":  ["AC-4", "SC-7", "SI-4"],
        "pci_dss_v4":      ["1.3", "7.2"],
        "iso_27001_2022":  ["A.8.20", "A.8.22"],
    },
    "defense_evasion": {
        "cis_k8s_v1":      ["3.2.1", "3.2.2", "4.2.1"],
        "nist_800_53_r5":  ["AU-2", "AU-6", "AU-12", "SI-4"],
        "pci_dss_v4":      ["10.1", "10.2", "10.3"],
        "iso_27001_2022":  ["A.8.15", "A.8.16", "A.5.28"],
    },
    "data_exfiltration": {
        "cis_k8s_v1":      ["5.4.1", "5.4.2", "5.7.4"],
        "nist_800_53_r5":  ["AC-4", "SC-28", "SI-4"],
        "pci_dss_v4":      ["3.1", "4.1", "7.1"],
        "iso_27001_2022":  ["A.8.12", "A.5.12", "A.8.10"],
    },
    "impact": {
        "cis_k8s_v1":      ["3.2.1", "5.7.4"],
        "nist_800_53_r5":  ["CP-9", "CP-10", "SI-7"],
        "pci_dss_v4":      ["12.3", "10.2"],
        "iso_27001_2022":  ["A.8.13", "A.8.14"],
    },
    "execution": {
        "cis_k8s_v1":      ["5.2.1", "5.2.2", "5.2.3"],
        "nist_800_53_r5":  ["CM-7", "SI-3", "SI-4"],
        "pci_dss_v4":      ["6.3", "6.4"],
        "iso_27001_2022":  ["A.8.19", "A.8.20"],
    },
    "collection": {
        "cis_k8s_v1":      ["5.4.1", "5.4.2"],
        "nist_800_53_r5":  ["AC-4", "SC-28"],
        "pci_dss_v4":      ["3.1", "7.1"],
        "iso_27001_2022":  ["A.8.12", "A.5.12"],
    },
    "supply_chain_compromise": {
        "cis_k8s_v1":      ["5.2.1", "5.5.1", "5.6.4"],
        "nist_800_53_r5":  ["SA-12", "SI-3", "CM-7"],
        "pci_dss_v4":      ["6.3", "12.8"],
        "iso_27001_2022":  ["A.5.19", "A.5.20", "A.8.30"],
    },
    "identity_manipulation": {
        "cis_k8s_v1":      ["5.1.1", "5.1.2", "5.1.3"],
        "nist_800_53_r5":  ["AC-2", "AC-3", "IA-4"],
        "pci_dss_v4":      ["7.1", "8.2"],
        "iso_27001_2022":  ["A.5.18", "A.8.2"],
    },
}

RATIONALE = {
    "T1098.006": (
        "Adversaries create Kubernetes ClusterRoleBindings or RoleBindings to grant cluster-wide "
        "or namespace-scoped permissions to attacker-controlled identities. Binding to cluster-admin "
        "or privileged ClusterRoles provides unrestricted access to all cluster resources. "
        "Detected via K8s audit logs for clusterrolebindings/create and rolebindings/create verbs "
        "by non-CI/CD service accounts, especially outside deployment windows."
    ),
    "T1611": (
        "Adversaries escape Kubernetes container isolation by launching pods with privileged "
        "security contexts, hostPath mounts to node paths, or hostPID/hostNetwork/hostIPC enabled. "
        "These configurations break container isolation, allowing access to the underlying node, "
        "its kubelet credentials, and cloud instance metadata. Detected via K8s audit logs for "
        "pod creation with securityContext.privileged=true or sensitive hostPath volume mounts."
    ),
    "T1609": (
        "Adversaries execute commands inside running Kubernetes pods via the kubectl exec API — "
        "achieving interactive shell access without SSH or network access to the pod. "
        "Pod exec by non-CI/CD users or service accounts, especially in production namespaces, "
        "indicates unauthorized access or post-exploitation activity. Detected via K8s audit logs "
        "for pods/exec subresource with create verb."
    ),
    "T1552.001": (
        "Adversaries access Kubernetes Secrets containing credentials, API keys, TLS certificates, "
        "or cloud provider access tokens. K8s Secrets are base64-encoded and accessible to any "
        "principal with get/list permissions on secrets. Bulk Secret access or reads outside normal "
        "application runtime indicates credential harvesting. Detected via K8s Data Access audit logs."
    ),
    "T1543": (
        "Adversaries create or modify DaemonSets to run malicious containers on every node in a "
        "cluster, achieving persistent code execution across the entire cluster infrastructure. "
        "DaemonSet creation in kube-system or with privileged containers is a strong persistence "
        "indicator. Detected via K8s audit logs for daemonsets/create in sensitive namespaces."
    ),
    "T1053": (
        "Adversaries create Kubernetes CronJobs to schedule recurring malicious workloads — "
        "cryptomining, data exfiltration, or C2 callbacks — that survive pod restarts and "
        "operator intervention. CronJob creation outside normal CI/CD pipelines or with unusual "
        "schedules indicates adversary use. Detected via K8s audit logs for cronjobs/create."
    ),
    "T1610": (
        "Adversaries deploy containers via Kubernetes API outside normal deployment pipelines "
        "to host malicious workloads within trusted cluster infrastructure. Pods created with "
        "images from unregistered registries, latest tags, or in privileged namespaces indicate "
        "adversary container deployment. Detected via K8s audit logs for pod creation events."
    ),
    "T1562.008": (
        "Adversaries disable or modify Kubernetes audit logging by deleting audit policy resources, "
        "removing audit webhook backends, or modifying the API server audit configuration — "
        "blinding defenders to all subsequent cluster activity. Detected via K8s audit logs for "
        "audit policy deletions and webhook configuration modifications."
    ),
    "T1562.001": (
        "Adversaries disable Kubernetes security controls — removing admission webhooks (OPA/Gatekeeper, "
        "Kyverno), deleting network policies, or disabling PSA enforcement — to allow execution of "
        "otherwise blocked workloads. Admission webhook deletion enables deployment of privileged or "
        "non-compliant pods. Detected via K8s audit logs for webhook config deletion events."
    ),
    "T1548": (
        "Adversaries use Kubernetes user impersonation (--as flag or Impersonate-User header) "
        "to act as a higher-privileged user or service account without obtaining their credentials. "
        "Impersonation requests appear in K8s audit logs with impersonation user info and are a "
        "strong indicator of privilege escalation attempts by lower-privileged principals."
    ),
    "T1572": (
        "Adversaries use kubectl port-forward to establish encrypted tunnels to pods running "
        "internal services — exposing cluster-internal databases, APIs, or management interfaces "
        "to attacker-controlled endpoints. Port-forward activity by non-operator users outside "
        "maintenance windows indicates unauthorized access. Detected via K8s audit logs."
    ),
    "T1205": (
        "Adversaries modify Kubernetes Service objects to add external load balancer IPs or "
        "NodePort configurations, exposing internal cluster services to the internet. This creates "
        "unauthorized ingress points for C2 traffic or data exfiltration. Detected via K8s audit "
        "logs for service patch/update operations adding externalIPs or changing type to NodePort/LoadBalancer."
    ),
    "T1136.003": (
        "Adversaries create Kubernetes ServiceAccounts or Namespaces to establish persistent "
        "identities within a cluster. New service accounts can be bound to ClusterRoles and used "
        "for persistent cluster access. Namespace creation by non-admin users may indicate "
        "attempts to establish isolated execution environments. Detected via K8s audit logs."
    ),
    "T1485": (
        "Adversaries delete Kubernetes nodes, namespaces, or persistent volumes to disrupt "
        "cluster workloads or destroy forensic evidence. Node deletion causes workload eviction "
        "and may disrupt cluster availability. PersistentVolume deletion with reclaim policy "
        "Delete destroys underlying storage permanently. Detected via K8s audit logs."
    ),
}

REMEDIATION = {
    "privilege_escalation": """\
1. Immediately delete the unauthorized ClusterRoleBinding or RoleBinding.
2. Audit all cluster-admin bindings: `kubectl get clusterrolebindings -o wide | grep cluster-admin`
3. Enable OPA Gatekeeper or Kyverno policy to prevent cluster-admin binding creation by non-admins.
4. Use just-in-time (JIT) access for privileged Kubernetes operations.
5. Configure Falco rules to alert on ClusterRoleBinding creation outside CI/CD service accounts.
""",
    "persistence": """\
1. Delete the unauthorized DaemonSet, CronJob, or ServiceAccount immediately.
2. Audit all resources in kube-system: `kubectl get all -n kube-system`
3. Enable admission control policies restricting resource creation to known CI/CD identities.
4. Use RBAC least-privilege: restrict create verbs on DaemonSets/CronJobs to dedicated service accounts.
5. Monitor for new ServiceAccount creation via Falco or audit log alerting.
""",
    "credential_access": """\
1. Rotate all secrets that were read by the unauthorized principal.
2. Enable K8s audit log alerting on secrets/get and secrets/list for non-application subjects.
3. Use external secret managers (Vault, AWS Secrets Manager) instead of K8s Secrets for sensitive data.
4. Apply RBAC to restrict secrets access to only the service accounts that need them.
5. Enable encryption at rest for etcd where K8s Secrets are stored.
""",
    "lateral_movement": """\
1. Terminate the unauthorized kubectl exec or port-forward session immediately.
2. Audit RBAC permissions: restrict pods/exec and pods/portforward to specific service accounts.
3. Apply NetworkPolicies to prevent unauthorized pod-to-pod communication.
4. Enable audit log alerting for exec/portforward operations by non-CI/CD users.
5. Use Falco rules to detect and alert on interactive exec sessions in production namespaces.
""",
    "defense_evasion": """\
1. Immediately restore the deleted webhook configuration or network policy.
2. Apply RBAC to restrict deletion of admission webhooks and audit policies to cluster-admin only.
3. Enable Falco rules to alert on webhook configuration deletion and network policy removal.
4. Use GitOps (ArgoCD/Flux) to detect and restore unauthorized configuration drift.
5. Configure out-of-band audit log export before admission webhook changes take effect.
""",
    "data_exfiltration": """\
1. Revoke RBAC access for the principal that performed the unauthorized Secret/ConfigMap read.
2. Rotate all secrets and credentials that may have been accessed.
3. Enable K8s audit log alerting on bulk secrets/list or configmaps/list operations.
4. Restrict data access using RBAC and namespace isolation for sensitive workloads.
5. Use Vault or external secret stores with dynamic short-lived credentials.
""",
    "impact": """\
1. Restore deleted resources from cluster backup or etcd snapshot.
2. Apply RBAC to restrict delete verbs on nodes, namespaces, and PersistentVolumes.
3. Enable Velero or equivalent backup solution for cluster state and PersistentVolumes.
4. Configure resource deletion protection policies via admission controllers.
5. Alert on node and namespace deletion via audit log monitoring or Falco.
""",
    "execution": """\
1. Audit the created pod or container for malicious images or startup commands.
2. Enforce Binary Authorization or Cosign image signing via admission webhooks.
3. Apply Pod Security Standards (Restricted profile) to prevent privileged execution.
4. Restrict pod creation to specific service accounts in production namespaces.
5. Enable runtime threat detection (Falco, Tetragon) for anomalous container behavior.
""",
    "collection": """\
1. Revoke the unauthorized RBAC access used for secret/configmap enumeration.
2. Rotate all secrets and credentials in the affected namespace.
3. Apply namespace isolation and RBAC least-privilege for secrets access.
4. Enable K8s audit alerting on secrets/list and configmaps/list from unexpected subjects.
5. Use external secret stores to prevent lateral secret access within the cluster.
""",
    "supply_chain_compromise": """\
1. Remove the unauthorized workload and quarantine the image for forensic analysis.
2. Enable Binary Authorization or Kyverno policy to allowlist approved registries.
3. Scan all cluster images with Trivy or Snyk for vulnerabilities and malicious code.
4. Restrict image pull sources to internal registries via OPA/Kyverno admission policies.
5. Enable Sigstore/Cosign image signing verification for all production deployments.
""",
    "identity_manipulation": """\
1. Remove the unauthorized ServiceAccount, Role, or binding immediately.
2. Audit all service accounts and their bound roles: `kubectl get sa,rolebindings -A`
3. Apply RBAC policies restricting ServiceAccount and Role creation to CI/CD pipelines.
4. Enable audit alerting on identity resource creation outside normal deployment windows.
5. Use Workload Identity (GKE, EKS, AKS) instead of legacy service account tokens.
""",
}

REFERENCES = {
    "T1098.006": [
        "https://attack.mitre.org/techniques/T1098/006/",
        "https://kubernetes.io/docs/reference/access-authn-authz/rbac/",
        "https://www.cisa.gov/sites/default/files/2022-03/kubernetes-hardening-guidance-1.2-508c.pdf",
    ],
    "T1611": [
        "https://attack.mitre.org/techniques/T1611/",
        "https://kubernetes.io/docs/concepts/security/pod-security-standards/",
        "https://www.cisa.gov/sites/default/files/2022-03/kubernetes-hardening-guidance-1.2-508c.pdf",
    ],
    "T1609": [
        "https://attack.mitre.org/techniques/T1609/",
        "https://kubernetes.io/docs/tasks/debug/debug-application/get-shell-running-container/",
    ],
    "T1552.001": [
        "https://attack.mitre.org/techniques/T1552/001/",
        "https://kubernetes.io/docs/concepts/configuration/secret/",
        "https://kubernetes.io/docs/concepts/security/secrets-good-practices/",
    ],
    "T1543": [
        "https://attack.mitre.org/techniques/T1543/",
        "https://kubernetes.io/docs/concepts/workloads/controllers/daemonset/",
    ],
    "T1053": [
        "https://attack.mitre.org/techniques/T1053/",
        "https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/",
    ],
    "T1610": [
        "https://attack.mitre.org/techniques/T1610/",
        "https://kubernetes.io/docs/concepts/security/pod-security-admission/",
    ],
    "T1562.008": [
        "https://attack.mitre.org/techniques/T1562/008/",
        "https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/",
    ],
    "T1562.001": [
        "https://attack.mitre.org/techniques/T1562/001/",
        "https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/",
    ],
    "T1548": [
        "https://attack.mitre.org/techniques/T1548/",
        "https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation",
    ],
    "T1572": [
        "https://attack.mitre.org/techniques/T1572/",
        "https://kubernetes.io/docs/tasks/access-application-cluster/port-forward-access-application-cluster/",
    ],
    "T1205": [
        "https://attack.mitre.org/techniques/T1205/",
        "https://kubernetes.io/docs/concepts/services-networking/service/",
    ],
    "T1136.003": [
        "https://attack.mitre.org/techniques/T1136/003/",
        "https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/",
    ],
    "T1485": [
        "https://attack.mitre.org/techniques/T1485/",
        "https://kubernetes.io/docs/concepts/storage/persistent-volumes/",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# Rule definitions
# ─────────────────────────────────────────────────────────────────────────────

RULES = [
    # ── RBAC / Cluster Role Bindings ─────────────────────────────────────────
    {
        "rule_id": "k8s.rbac.audit.cluster_admin_binding_create",
        "service": "rbac", "severity": "critical",
        "title": "RBAC: cluster-admin ClusterRoleBinding Created",
        "description": "ClusterRoleBinding to cluster-admin created — grants unrestricted access to all Kubernetes resources cluster-wide; highest-severity privilege escalation.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098.006"],
        "risk_score": 96,
        "resource": "k8s_cluster_role_binding",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals",   "value": "k8s_audit"},
            {"field": "resource",    "op": "equals",   "value": "clusterrolebindings"},
            {"field": "verb",        "op": "equals",   "value": "create"},
            {"field": "role_ref",    "op": "contains", "value": "cluster-admin"},
        ]}},
    },
    {
        "rule_id": "k8s.rbac.audit.cluster_role_binding_create",
        "service": "rbac", "severity": "high",
        "title": "RBAC: ClusterRoleBinding Created",
        "description": "New ClusterRoleBinding created — grants cluster-wide permissions to a subject outside normal deployment pipelines.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098.006"],
        "risk_score": 82,
        "resource": "k8s_cluster_role_binding",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "clusterrolebindings"},
            {"field": "verb",        "op": "equals", "value": "create"},
        ]}},
    },
    {
        "rule_id": "k8s.rbac.audit.role_binding_create",
        "service": "rbac", "severity": "medium",
        "title": "RBAC: RoleBinding Created",
        "description": "New namespace-scoped RoleBinding created — grants permissions within a namespace to an unexpected subject.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098.006"],
        "risk_score": 65,
        "resource": "k8s_role_binding",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "rolebindings"},
            {"field": "verb",        "op": "equals", "value": "create"},
        ]}},
    },
    {
        "rule_id": "k8s.rbac.audit.cluster_role_create",
        "service": "rbac", "severity": "medium",
        "title": "RBAC: ClusterRole Created with Broad Permissions",
        "description": "New ClusterRole created — may define wildcard verbs or resources (*) enabling broad cluster-wide permission grants.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098.006"],
        "risk_score": 68,
        "resource": "k8s_cluster_role",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "clusterroles"},
            {"field": "verb",        "op": "equals", "value": "create"},
        ]}},
    },
    {
        "rule_id": "k8s.rbac.audit.cluster_role_update",
        "service": "rbac", "severity": "high",
        "title": "RBAC: ClusterRole Updated",
        "description": "Existing ClusterRole modified — permissions may have been expanded to include sensitive verbs (create, delete) on critical resources (secrets, nodes, pods).",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098.006"],
        "risk_score": 75,
        "resource": "k8s_cluster_role",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "clusterroles"},
            {"field": "verb",        "op": "in", "value": ["update", "patch"]},
        ]}},
    },
    {
        "rule_id": "k8s.rbac.audit.impersonation_used",
        "service": "rbac", "severity": "high",
        "title": "RBAC: User Impersonation Detected",
        "description": "Kubernetes user impersonation (--as flag) used — a principal is acting as a different user or service account, bypassing their own permission boundary.",
        "threat_category": "identity_manipulation",
        "mitre_tactics": ["privilege_escalation", "lateral_movement"],
        "mitre_techniques": ["T1548"],
        "risk_score": 85,
        "resource": "k8s_user",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",         "op": "equals", "value": "k8s_audit"},
            {"field": "impersonated_user",   "op": "exists", "value": None},
        ]}},
    },
    # ── Service Accounts ──────────────────────────────────────────────────────
    {
        "rule_id": "k8s.serviceaccount.audit.create",
        "service": "serviceaccount", "severity": "medium",
        "title": "ServiceAccount: New ServiceAccount Created",
        "description": "New Kubernetes ServiceAccount created outside normal CI/CD — may be used to establish a persistent cluster identity for an attacker.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1136.003"],
        "risk_score": 60,
        "resource": "k8s_service_account",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "serviceaccounts"},
            {"field": "verb",        "op": "equals", "value": "create"},
        ]}},
    },
    {
        "rule_id": "k8s.serviceaccount.audit.token_create",
        "service": "serviceaccount", "severity": "high",
        "title": "ServiceAccount: Long-lived Token Created",
        "description": "ServiceAccount token created via tokenrequest or secret — long-lived bearer token issued for a service account, potentially enabling persistent cluster access.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552.001"],
        "risk_score": 78,
        "resource": "k8s_service_account",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals",   "value": "k8s_audit"},
            {"field": "resource",    "op": "equals",   "value": "serviceaccounts"},
            {"field": "subresource", "op": "equals",   "value": "token"},
            {"field": "verb",        "op": "equals",   "value": "create"},
        ]}},
    },
    # ── Pod / Container Security ───────────────────────────────────────────────
    {
        "rule_id": "k8s.pod.audit.privileged_container_create",
        "service": "pod", "severity": "critical",
        "title": "Pod: Privileged Container Created",
        "description": "Pod created with securityContext.privileged=true — container runs with full node capabilities, enabling container escape and access to host resources.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation", "execution"],
        "mitre_techniques": ["T1611"],
        "risk_score": 94,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",           "op": "equals", "value": "k8s_audit"},
            {"field": "resource",              "op": "equals", "value": "pods"},
            {"field": "verb",                  "op": "equals", "value": "create"},
            {"field": "privileged_container",  "op": "equals", "value": True},
        ]}},
    },
    {
        "rule_id": "k8s.pod.audit.hostpath_sensitive_mount",
        "service": "pod", "severity": "critical",
        "title": "Pod: Sensitive HostPath Volume Mounted",
        "description": "Pod created with hostPath volume mounting sensitive node paths (/, /etc, /proc, /var/run/docker.sock) — direct access to node filesystem, enabling container escape.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1611"],
        "risk_score": 93,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",       "op": "equals",  "value": "k8s_audit"},
            {"field": "resource",          "op": "equals",  "value": "pods"},
            {"field": "verb",              "op": "equals",  "value": "create"},
            {"field": "hostpath_volume",   "op": "exists",  "value": None},
        ]}},
    },
    {
        "rule_id": "k8s.pod.audit.hostpid_enabled",
        "service": "pod", "severity": "critical",
        "title": "Pod: Host PID Namespace Shared",
        "description": "Pod created with hostPID=true — shares the node's process namespace, enabling container processes to see and signal all host processes including kubelet.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation", "execution"],
        "mitre_techniques": ["T1611"],
        "risk_score": 90,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "pods"},
            {"field": "verb",        "op": "equals", "value": "create"},
            {"field": "host_pid",    "op": "equals", "value": True},
        ]}},
    },
    {
        "rule_id": "k8s.pod.audit.hostnetwork_enabled",
        "service": "pod", "severity": "high",
        "title": "Pod: Host Network Namespace Shared",
        "description": "Pod created with hostNetwork=true — container uses the node's network stack, bypassing network policies and allowing access to node-level network interfaces.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["lateral_movement", "defense_evasion"],
        "mitre_techniques": ["T1611"],
        "risk_score": 85,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",  "op": "equals", "value": "k8s_audit"},
            {"field": "resource",     "op": "equals", "value": "pods"},
            {"field": "verb",         "op": "equals", "value": "create"},
            {"field": "host_network", "op": "equals", "value": True},
        ]}},
    },
    {
        "rule_id": "k8s.pod.audit.hostipc_enabled",
        "service": "pod", "severity": "high",
        "title": "Pod: Host IPC Namespace Shared",
        "description": "Pod created with hostIPC=true — container can access host inter-process communication mechanisms, enabling shared memory inspection of node processes.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1611"],
        "risk_score": 82,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "pods"},
            {"field": "verb",        "op": "equals", "value": "create"},
            {"field": "host_ipc",    "op": "equals", "value": True},
        ]}},
    },
    {
        "rule_id": "k8s.pod.audit.capability_add_dangerous",
        "service": "pod", "severity": "high",
        "title": "Pod: Dangerous Linux Capability Added",
        "description": "Pod created with dangerous Linux capabilities (SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE) — enables container escape, network manipulation, or process injection.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation", "execution"],
        "mitre_techniques": ["T1611"],
        "risk_score": 87,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",       "op": "equals", "value": "k8s_audit"},
            {"field": "resource",          "op": "equals", "value": "pods"},
            {"field": "verb",              "op": "equals", "value": "create"},
            {"field": "capabilities_add",  "op": "exists", "value": None},
        ]}},
    },
    {
        "rule_id": "k8s.pod.audit.exec_command",
        "service": "pod", "severity": "high",
        "title": "Pod: Exec Command in Running Container",
        "description": "kubectl exec used to run commands in a running pod — interactive shell access by a non-CI/CD user, especially in production namespaces, indicates active intrusion.",
        "threat_category": "execution",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1609"],
        "risk_score": 82,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "pods"},
            {"field": "subresource", "op": "equals", "value": "exec"},
            {"field": "verb",        "op": "equals", "value": "create"},
        ]}},
    },
    {
        "rule_id": "k8s.pod.audit.port_forward",
        "service": "pod", "severity": "medium",
        "title": "Pod: Port Forwarding to Pod",
        "description": "kubectl port-forward used to tunnel traffic to a pod — may expose cluster-internal services to attacker-controlled endpoints or establish covert C2 channels.",
        "threat_category": "lateral_movement",
        "mitre_tactics": ["lateral_movement", "command_and_control"],
        "mitre_techniques": ["T1572"],
        "risk_score": 68,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "pods"},
            {"field": "subresource", "op": "equals", "value": "portforward"},
            {"field": "verb",        "op": "equals", "value": "create"},
        ]}},
    },
    {
        "rule_id": "k8s.pod.audit.ephemeral_container_add",
        "service": "pod", "severity": "high",
        "title": "Pod: Ephemeral Debug Container Added",
        "description": "Ephemeral container added to a running pod via kubectl debug — attacker may inject a privileged debug container into a running production workload.",
        "threat_category": "execution",
        "mitre_tactics": ["execution", "privilege_escalation"],
        "mitre_techniques": ["T1609"],
        "risk_score": 80,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "pods"},
            {"field": "subresource", "op": "equals", "value": "ephemeralcontainers"},
            {"field": "verb",        "op": "equals", "value": "update"},
        ]}},
    },
    {
        "rule_id": "k8s.pod.audit.unregistered_registry_image",
        "service": "pod", "severity": "high",
        "title": "Pod: Image from Unregistered Registry",
        "description": "Pod created with container image from an unregistered or untrusted registry — supply chain risk; malicious images may contain backdoors or cryptominers.",
        "threat_category": "supply_chain_compromise",
        "mitre_tactics": ["execution", "persistence"],
        "mitre_techniques": ["T1610"],
        "risk_score": 78,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals",     "value": "k8s_audit"},
            {"field": "resource",    "op": "equals",     "value": "pods"},
            {"field": "verb",        "op": "equals",     "value": "create"},
            {"field": "image",       "op": "not_starts", "value": "gcr.io"},
        ]}},
    },
    {
        "rule_id": "k8s.pod.audit.kube_system_pod_create",
        "service": "pod", "severity": "critical",
        "title": "Pod: Pod Created in kube-system Namespace",
        "description": "Pod created in the kube-system namespace by a non-cluster-admin — privileged namespace creation may inject malicious components into cluster management infrastructure.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence", "privilege_escalation"],
        "mitre_techniques": ["T1610"],
        "risk_score": 92,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "pods"},
            {"field": "verb",        "op": "equals", "value": "create"},
            {"field": "namespace",   "op": "equals", "value": "kube-system"},
        ]}},
    },
    # ── Workloads ─────────────────────────────────────────────────────────────
    {
        "rule_id": "k8s.daemonset.audit.create",
        "service": "daemonset", "severity": "high",
        "title": "DaemonSet: DaemonSet Created Outside CI/CD",
        "description": "DaemonSet created — runs a pod on every cluster node; malicious DaemonSets achieve cluster-wide code execution and persistence across all nodes.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence", "execution"],
        "mitre_techniques": ["T1543"],
        "risk_score": 82,
        "resource": "k8s_daemonset",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "daemonsets"},
            {"field": "verb",        "op": "equals", "value": "create"},
        ]}},
    },
    {
        "rule_id": "k8s.daemonset.audit.update",
        "service": "daemonset", "severity": "high",
        "title": "DaemonSet: DaemonSet Image or Config Updated",
        "description": "Existing DaemonSet modified — image or configuration change affects all nodes simultaneously; may inject malicious code into cluster-wide infrastructure.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence", "execution"],
        "mitre_techniques": ["T1543"],
        "risk_score": 78,
        "resource": "k8s_daemonset",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "daemonsets"},
            {"field": "verb",        "op": "in",     "value": ["update", "patch"]},
        ]}},
    },
    {
        "rule_id": "k8s.cronjob.audit.create",
        "service": "cronjob", "severity": "high",
        "title": "CronJob: CronJob Created",
        "description": "CronJob created outside normal CI/CD pipelines — scheduled recurring workloads used for persistent cryptomining, data exfiltration, or C2 callbacks.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence", "execution"],
        "mitre_techniques": ["T1053"],
        "risk_score": 75,
        "resource": "k8s_cronjob",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "cronjobs"},
            {"field": "verb",        "op": "equals", "value": "create"},
        ]}},
    },
    {
        "rule_id": "k8s.deployment.audit.create_kube_system",
        "service": "deployment", "severity": "critical",
        "title": "Deployment: Created in kube-system Namespace",
        "description": "Deployment created in kube-system by a non-cluster-admin — may install malicious components alongside cluster management infrastructure.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence", "privilege_escalation"],
        "mitre_techniques": ["T1610"],
        "risk_score": 90,
        "resource": "k8s_deployment",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "deployments"},
            {"field": "verb",        "op": "equals", "value": "create"},
            {"field": "namespace",   "op": "equals", "value": "kube-system"},
        ]}},
    },
    # ── Secrets / Credentials ────────────────────────────────────────────────
    {
        "rule_id": "k8s.secret.audit.bulk_list",
        "service": "secret", "severity": "high",
        "title": "Secret: Kubernetes Secrets Enumerated",
        "description": "Kubernetes Secrets listed in bulk — attacker enumerating all secrets in a namespace or cluster-wide to harvest credentials, API keys, or TLS certificates.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552.001"],
        "risk_score": 80,
        "resource": "k8s_secret",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "secrets"},
            {"field": "verb",        "op": "equals", "value": "list"},
        ]}},
    },
    {
        "rule_id": "k8s.secret.audit.get_by_unexpected_subject",
        "service": "secret", "severity": "high",
        "title": "Secret: Secret Accessed by Non-Application Subject",
        "description": "Kubernetes Secret directly retrieved (get) by a user or service account outside the owning application — credential theft attempt.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552.001"],
        "risk_score": 78,
        "resource": "k8s_secret",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "secrets"},
            {"field": "verb",        "op": "equals", "value": "get"},
        ]}},
    },
    {
        "rule_id": "k8s.secret.audit.delete",
        "service": "secret", "severity": "medium",
        "title": "Secret: Kubernetes Secret Deleted",
        "description": "Kubernetes Secret deleted — may disrupt application authentication or cover attacker tracks after credential exfiltration.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion", "impact"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 60,
        "resource": "k8s_secret",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "secrets"},
            {"field": "verb",        "op": "equals", "value": "delete"},
        ]}},
    },
    {
        "rule_id": "k8s.configmap.audit.bulk_list",
        "service": "configmap", "severity": "medium",
        "title": "ConfigMap: Bulk ConfigMap Enumeration",
        "description": "ConfigMaps listed in bulk — may contain application credentials, connection strings, or configuration secrets stored outside proper Secrets management.",
        "threat_category": "collection",
        "mitre_tactics": ["collection", "credential_access"],
        "mitre_techniques": ["T1552.001"],
        "risk_score": 60,
        "resource": "k8s_configmap",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "configmaps"},
            {"field": "verb",        "op": "equals", "value": "list"},
        ]}},
    },
    # ── Network ───────────────────────────────────────────────────────────────
    {
        "rule_id": "k8s.service.audit.external_ip_added",
        "service": "service", "severity": "high",
        "title": "Service: External IP Added to Service",
        "description": "Kubernetes Service patched to add externalIPs or change type to LoadBalancer/NodePort — exposes cluster-internal service to the internet, creating unauthorized ingress.",
        "threat_category": "lateral_movement",
        "mitre_tactics": ["command_and_control", "exfiltration"],
        "mitre_techniques": ["T1205"],
        "risk_score": 80,
        "resource": "k8s_service",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "services"},
            {"field": "verb",        "op": "in",     "value": ["create", "update", "patch"]},
        ]}},
    },
    {
        "rule_id": "k8s.networkpolicy.audit.delete",
        "service": "networkpolicy", "severity": "high",
        "title": "NetworkPolicy: NetworkPolicy Deleted",
        "description": "Kubernetes NetworkPolicy deleted — removes pod-level network segmentation, allowing unrestricted pod-to-pod traffic and potential lateral movement.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion", "lateral_movement"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 78,
        "resource": "k8s_network_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "networkpolicies"},
            {"field": "verb",        "op": "equals", "value": "delete"},
        ]}},
    },
    {
        "rule_id": "k8s.ingress.audit.create_modify",
        "service": "ingress", "severity": "medium",
        "title": "Ingress: Ingress Created or Modified",
        "description": "Kubernetes Ingress resource created or modified — may expose internal services externally or redirect traffic to attacker-controlled backends.",
        "threat_category": "lateral_movement",
        "mitre_tactics": ["command_and_control"],
        "mitre_techniques": ["T1205"],
        "risk_score": 62,
        "resource": "k8s_ingress",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "ingresses"},
            {"field": "verb",        "op": "in",     "value": ["create", "update", "patch"]},
        ]}},
    },
    # ── Admission Control / Defense Evasion ───────────────────────────────────
    {
        "rule_id": "k8s.admissionwebhook.audit.delete",
        "service": "admissionwebhook", "severity": "critical",
        "title": "Admission Webhook: ValidatingWebhookConfiguration Deleted",
        "description": "Kubernetes ValidatingWebhookConfiguration deleted — removes policy enforcement (OPA/Gatekeeper, Kyverno, PSA) allowing deployment of any workload including privileged containers.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 95,
        "resource": "k8s_admission_webhook",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "validatingwebhookconfigurations"},
            {"field": "verb",        "op": "equals", "value": "delete"},
        ]}},
    },
    {
        "rule_id": "k8s.admissionwebhook.audit.mutating_delete",
        "service": "admissionwebhook", "severity": "critical",
        "title": "Admission Webhook: MutatingWebhookConfiguration Deleted",
        "description": "MutatingWebhookConfiguration deleted — removes mutation policies that enforce security contexts, sidecar injection, or policy defaults for all pods.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 93,
        "resource": "k8s_admission_webhook",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "mutatingwebhookconfigurations"},
            {"field": "verb",        "op": "equals", "value": "delete"},
        ]}},
    },
    {
        "rule_id": "k8s.audit.audit.policy_configmap_delete",
        "service": "audit", "severity": "high",
        "title": "Audit: Audit Policy ConfigMap Deleted",
        "description": "ConfigMap containing K8s audit policy deleted — audit logging rules destroyed, potentially disabling audit log capture for sensitive resource categories.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.008"],
        "risk_score": 88,
        "resource": "k8s_configmap",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",    "op": "equals",   "value": "k8s_audit"},
            {"field": "resource",       "op": "equals",   "value": "configmaps"},
            {"field": "verb",           "op": "equals",   "value": "delete"},
            {"field": "namespace",      "op": "equals",   "value": "kube-system"},
            {"field": "resource_name",  "op": "contains", "value": "audit"},
        ]}},
    },
    {
        "rule_id": "k8s.podsecuritypolicy.audit.delete",
        "service": "pod_security", "severity": "high",
        "title": "PodSecurityPolicy: PSP Deleted or Pod Security Labels Removed",
        "description": "PodSecurityPolicy deleted or restrictive PSA namespace label removed — removes workload security enforcement, allowing privileged pod deployment.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 85,
        "resource": "k8s_pod_security_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "podsecuritypolicies"},
            {"field": "verb",        "op": "equals", "value": "delete"},
        ]}},
    },
    # ── Node / Namespace ──────────────────────────────────────────────────────
    {
        "rule_id": "k8s.namespace.audit.create",
        "service": "namespace", "severity": "medium",
        "title": "Namespace: New Namespace Created",
        "description": "New Kubernetes namespace created outside standard provisioning — may establish isolated execution environment for attacker workloads outside normal monitoring scope.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1136.003"],
        "risk_score": 55,
        "resource": "k8s_namespace",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "namespaces"},
            {"field": "verb",        "op": "equals", "value": "create"},
        ]}},
    },
    {
        "rule_id": "k8s.namespace.audit.delete",
        "service": "namespace", "severity": "critical",
        "title": "Namespace: Namespace Deleted",
        "description": "Kubernetes namespace deleted — destroys all workloads, services, secrets, and PVCs within; catastrophic data destruction or evidence removal.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 94,
        "resource": "k8s_namespace",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "namespaces"},
            {"field": "verb",        "op": "equals", "value": "delete"},
        ]}},
    },
    {
        "rule_id": "k8s.node.audit.delete",
        "service": "node", "severity": "high",
        "title": "Node: Cluster Node Deleted",
        "description": "Kubernetes node deleted — causes immediate workload eviction and may impact cluster capacity. Mass node deletion indicates ransomware or sabotage.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 85,
        "resource": "k8s_node",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "nodes"},
            {"field": "verb",        "op": "equals", "value": "delete"},
        ]}},
    },
    # ── PersistentVolume ──────────────────────────────────────────────────────
    {
        "rule_id": "k8s.persistentvolume.audit.delete",
        "service": "persistentvolume", "severity": "high",
        "title": "PersistentVolume: PersistentVolume Deleted",
        "description": "PersistentVolume deleted — with reclaim policy Delete, the backing storage (EBS, PD, Azure Disk) is also destroyed; permanent data loss.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 82,
        "resource": "k8s_persistent_volume",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "persistentvolumes"},
            {"field": "verb",        "op": "equals", "value": "delete"},
        ]}},
    },
    # ── Correlation Chains ────────────────────────────────────────────────────
    {
        "rule_id": "k8s.ciem.correlation.container_escape_chain",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "K8s: Container Escape Chain — Privileged Pod + Exec",
        "description": "Correlated container escape attempt: privileged pod or sensitive hostPath pod created, followed immediately by exec into that pod — active container escape scenario.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation", "execution"],
        "mitre_techniques": ["T1611", "T1609"],
        "risk_score": 97,
        "resource": "k8s_pod",
        "check_config": {
            "type": "sequence",
            "window_seconds": 120,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type",         "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",            "op": "equals", "value": "pods"},
                    {"field": "verb",                "op": "equals", "value": "create"},
                    {"field": "privileged_container","op": "equals", "value": True},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",    "op": "equals", "value": "pods"},
                    {"field": "subresource", "op": "equals", "value": "exec"},
                    {"field": "verb",        "op": "equals", "value": "create"},
                ]}},
            ],
        },
    },
    {
        "rule_id": "k8s.ciem.correlation.privilege_escalation_chain",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "K8s: Privilege Escalation Chain — SA Create + ClusterRoleBinding",
        "description": "Correlated privilege escalation: new ServiceAccount created followed immediately by ClusterRoleBinding granting it elevated permissions — classic attacker SA setup.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098.006", "T1136.003"],
        "risk_score": 96,
        "resource": "k8s_cluster_role_binding",
        "check_config": {
            "type": "sequence",
            "window_seconds": 300,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",    "op": "equals", "value": "serviceaccounts"},
                    {"field": "verb",        "op": "equals", "value": "create"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",    "op": "equals", "value": "clusterrolebindings"},
                    {"field": "verb",        "op": "equals", "value": "create"},
                ]}},
            ],
        },
    },
    {
        "rule_id": "k8s.ciem.correlation.defense_evasion_chain",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "K8s: Defense Evasion Chain — Webhook Delete + Privileged Pod",
        "description": "Correlated defense evasion: admission webhook deleted (removing policy enforcement) followed by privileged pod creation — exploiting the enforcement gap to deploy unrestricted workload.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion", "privilege_escalation"],
        "mitre_techniques": ["T1562.001", "T1611"],
        "risk_score": 98,
        "resource": "k8s_admission_webhook",
        "check_config": {
            "type": "sequence",
            "window_seconds": 300,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",    "op": "in",     "value": ["validatingwebhookconfigurations", "mutatingwebhookconfigurations"]},
                    {"field": "verb",        "op": "equals", "value": "delete"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type",          "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",             "op": "equals", "value": "pods"},
                    {"field": "verb",                 "op": "equals", "value": "create"},
                    {"field": "privileged_container", "op": "equals", "value": True},
                ]}},
            ],
        },
    },
    {
        "rule_id": "k8s.ciem.correlation.credential_exfil_chain",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "K8s: Credential Exfiltration Chain — Secret List + External Service",
        "description": "Correlated credential exfiltration: bulk Secrets enumeration followed by Service with external IP creation — secrets harvested and an exfiltration channel established.",
        "threat_category": "data_exfiltration",
        "mitre_tactics": ["credential_access", "exfiltration"],
        "mitre_techniques": ["T1552.001", "T1205"],
        "risk_score": 96,
        "resource": "k8s_secret",
        "check_config": {
            "type": "sequence",
            "window_seconds": 300,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",    "op": "equals", "value": "secrets"},
                    {"field": "verb",        "op": "equals", "value": "list"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",    "op": "equals", "value": "services"},
                    {"field": "verb",        "op": "in",     "value": ["create", "patch"]},
                ]}},
            ],
        },
    },
    {
        "rule_id": "k8s.ciem.correlation.persistence_daemonset_chain",
        "service": "ciem", "severity": "critical",
        "check_type": "log_correlation",
        "title": "K8s: Cluster-Wide Persistence Chain — DaemonSet + RBAC Grant",
        "description": "Correlated cluster-wide persistence: DaemonSet created (cluster-wide execution) followed by ClusterRoleBinding — malicious workload granted ongoing cluster admin access.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence", "privilege_escalation"],
        "mitre_techniques": ["T1543", "T1098.006"],
        "risk_score": 97,
        "resource": "k8s_daemonset",
        "check_config": {
            "type": "sequence",
            "window_seconds": 300,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",    "op": "equals", "value": "daemonsets"},
                    {"field": "verb",        "op": "equals", "value": "create"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",    "op": "equals", "value": "clusterrolebindings"},
                    {"field": "verb",        "op": "equals", "value": "create"},
                ]}},
            ],
        },
    },

    # ── RBAC — additional ────────────────────────────────────────────────────
    {
        "rule_id": "k8s.rbac.audit.cluster_admin_binding_delete",
        "service": "rbac", "severity": "high",
        "title": "RBAC: cluster-admin Binding Deleted (Evidence Cleanup)",
        "description": "ClusterRoleBinding to cluster-admin deleted by a non-CI/CD principal — likely post-exploitation evidence cleanup after privilege escalation.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 80,
        "resource": "k8s_cluster_role_binding",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals",   "value": "k8s_audit"},
            {"field": "resource",    "op": "equals",   "value": "clusterrolebindings"},
            {"field": "verb",        "op": "equals",   "value": "delete"},
            {"field": "role_ref",    "op": "contains", "value": "cluster-admin"},
        ]}},
    },
    {
        "rule_id": "k8s.rbac.audit.secret_access_role_create",
        "service": "rbac", "severity": "high",
        "title": "RBAC: Role Created Granting Secrets Access",
        "description": "ClusterRole or Role created that grants get/list/watch on secrets — enables any bound subject to read cluster credentials.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552.001"],
        "risk_score": 84,
        "resource": "k8s_cluster_role",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "in",     "value": ["clusterroles", "roles"]},
            {"field": "verb",        "op": "equals", "value": "create"},
            {"field": "rules_resources", "op": "contains", "value": "secrets"},
        ]}},
    },
    {
        "rule_id": "k8s.rbac.audit.wildcard_verb_role_create",
        "service": "rbac", "severity": "high",
        "title": "RBAC: Role Created with Wildcard Verbs",
        "description": "ClusterRole or Role created with verbs: [\"*\"] — grants all API operations on matched resources; effectively an admin role.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098.006"],
        "risk_score": 88,
        "resource": "k8s_cluster_role",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",  "op": "equals",   "value": "k8s_audit"},
            {"field": "resource",     "op": "in",       "value": ["clusterroles", "roles"]},
            {"field": "verb",         "op": "equals",   "value": "create"},
            {"field": "rules_verbs",  "op": "contains", "value": "*"},
        ]}},
    },
    {
        "rule_id": "k8s.rbac.audit.exec_role_create",
        "service": "rbac", "severity": "high",
        "title": "RBAC: Role Granting pods/exec Created",
        "description": "Role created granting the pods/exec subresource — enables the bound subject to execute commands in any pod in scope.",
        "threat_category": "execution",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1609"],
        "risk_score": 82,
        "resource": "k8s_cluster_role",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",       "op": "equals",   "value": "k8s_audit"},
            {"field": "resource",          "op": "in",       "value": ["clusterroles", "roles"]},
            {"field": "verb",              "op": "equals",   "value": "create"},
            {"field": "rules_resources",   "op": "contains", "value": "pods/exec"},
        ]}},
    },
    {
        "rule_id": "k8s.rbac.audit.escalate_verb_used",
        "service": "rbac", "severity": "critical",
        "title": "RBAC: escalate Verb Used",
        "description": "Request with verb=escalate detected — allows a principal to create roles with more permissions than they currently hold; bypasses RBAC privilege boundaries.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 95,
        "resource": "k8s_cluster_role",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "verb",        "op": "equals", "value": "escalate"},
        ]}},
    },
    {
        "rule_id": "k8s.rbac.audit.bind_verb_used",
        "service": "rbac", "severity": "critical",
        "title": "RBAC: bind Verb Used",
        "description": "Request with verb=bind detected — allows a principal to bind any Role/ClusterRole to any subject, including roles with higher permissions than they hold.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1548"],
        "risk_score": 95,
        "resource": "k8s_cluster_role",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "verb",        "op": "equals", "value": "bind"},
        ]}},
    },

    # ── Pod — additional ─────────────────────────────────────────────────────
    {
        "rule_id": "k8s.pod.audit.seccomp_unconfined",
        "service": "pod", "severity": "high",
        "title": "Pod: Seccomp Profile Set to Unconfined",
        "description": "Pod created with seccompProfile.type=Unconfined — disables system call filtering, allowing container processes to make any kernel syscall.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1611"],
        "risk_score": 78,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",    "op": "equals", "value": "k8s_audit"},
            {"field": "resource",       "op": "equals", "value": "pods"},
            {"field": "verb",           "op": "equals", "value": "create"},
            {"field": "seccomp_type",   "op": "equals", "value": "Unconfined"},
        ]}},
    },
    {
        "rule_id": "k8s.pod.audit.automount_serviceaccount_token_kube_system",
        "service": "pod", "severity": "high",
        "title": "Pod: Service Account Token Auto-Mounted in kube-system",
        "description": "Pod created in kube-system namespace with automountServiceAccountToken=true — exposes a high-privilege service account token to the container.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552.001"],
        "risk_score": 80,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",                   "op": "equals", "value": "k8s_audit"},
            {"field": "resource",                      "op": "equals", "value": "pods"},
            {"field": "verb",                          "op": "equals", "value": "create"},
            {"field": "namespace",                     "op": "equals", "value": "kube-system"},
            {"field": "automount_service_account_token", "op": "equals", "value": True},
        ]}},
    },
    {
        "rule_id": "k8s.pod.audit.liveness_probe_exec",
        "service": "pod", "severity": "medium",
        "title": "Pod: Liveness Probe Uses Exec Command",
        "description": "Pod created with livenessProbe.exec.command — exec-based probes run arbitrary commands inside containers; can be abused for persistent command execution.",
        "threat_category": "execution",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1609"],
        "risk_score": 60,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",       "op": "equals", "value": "k8s_audit"},
            {"field": "resource",          "op": "equals", "value": "pods"},
            {"field": "verb",              "op": "equals", "value": "create"},
            {"field": "liveness_probe_exec", "op": "equals", "value": True},
        ]}},
    },
    {
        "rule_id": "k8s.pod.audit.init_container_privileged",
        "service": "pod", "severity": "critical",
        "title": "Pod: Privileged Init Container Created",
        "description": "Pod created with a privileged initContainer — init containers run before main containers and with full node capabilities if privileged=true.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1611"],
        "risk_score": 93,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",           "op": "equals", "value": "k8s_audit"},
            {"field": "resource",              "op": "equals", "value": "pods"},
            {"field": "verb",                  "op": "equals", "value": "create"},
            {"field": "init_container_privileged", "op": "equals", "value": True},
        ]}},
    },
    {
        "rule_id": "k8s.pod.audit.delete_kube_system",
        "service": "pod", "severity": "high",
        "title": "Pod: kube-system Pod Deleted",
        "description": "System pod deleted in kube-system namespace — may disrupt cluster control plane components or remove forensic evidence.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 78,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "pods"},
            {"field": "verb",        "op": "equals", "value": "delete"},
            {"field": "namespace",   "op": "equals", "value": "kube-system"},
        ]}},
    },
    {
        "rule_id": "k8s.pod.audit.image_pull_never",
        "service": "pod", "severity": "medium",
        "title": "Pod: imagePullPolicy=Never Allows Stale/Tampered Images",
        "description": "Pod created with imagePullPolicy=Never — bypasses registry pull, allowing pre-loaded malicious or modified images to run without network checks.",
        "threat_category": "supply_chain_compromise",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1610"],
        "risk_score": 62,
        "resource": "k8s_pod",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",      "op": "equals", "value": "k8s_audit"},
            {"field": "resource",         "op": "equals", "value": "pods"},
            {"field": "verb",             "op": "equals", "value": "create"},
            {"field": "image_pull_policy","op": "equals", "value": "Never"},
        ]}},
    },

    # ── Secret — additional ──────────────────────────────────────────────────
    {
        "rule_id": "k8s.secret.audit.watch",
        "service": "secret", "severity": "high",
        "title": "Secrets: Watch Operation (Continuous Credential Monitoring)",
        "description": "Watch operation on Kubernetes Secrets detected — establishes a continuous stream of secret data to the requester; more invasive than a one-time list.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552.001"],
        "risk_score": 82,
        "resource": "k8s_secret",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "secrets"},
            {"field": "verb",        "op": "equals", "value": "watch"},
        ]}},
    },
    {
        "rule_id": "k8s.secret.audit.patch",
        "service": "secret", "severity": "high",
        "title": "Secrets: Secret Patched (Credential Modification)",
        "description": "Kubernetes Secret patched by a non-CI/CD principal — may indicate credential injection or modification for persistence.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1543"],
        "risk_score": 78,
        "resource": "k8s_secret",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "secrets"},
            {"field": "verb",        "op": "in",     "value": ["patch", "update"]},
        ]}},
    },
    {
        "rule_id": "k8s.secret.audit.create_service_account_token",
        "service": "secret", "severity": "high",
        "title": "Secrets: Service Account Token Secret Created Manually",
        "description": "Secret created with type=kubernetes.io/service-account-token — manually creating SA token secrets bypasses token expiry and bound token controls.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552.001"],
        "risk_score": 84,
        "resource": "k8s_secret",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals",   "value": "k8s_audit"},
            {"field": "resource",    "op": "equals",   "value": "secrets"},
            {"field": "verb",        "op": "equals",   "value": "create"},
            {"field": "secret_type", "op": "contains", "value": "service-account-token"},
        ]}},
    },

    # ── ServiceAccount — additional ──────────────────────────────────────────
    {
        "rule_id": "k8s.serviceaccount.audit.automount_token_kube_system",
        "service": "serviceaccount", "severity": "high",
        "title": "ServiceAccount: Auto-Mount Token Enabled in kube-system",
        "description": "ServiceAccount created or updated in kube-system with automountServiceAccountToken=true — any pod using this SA automatically receives a high-privilege token.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552.001"],
        "risk_score": 76,
        "resource": "k8s_service_account",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",                   "op": "equals", "value": "k8s_audit"},
            {"field": "resource",                      "op": "equals", "value": "serviceaccounts"},
            {"field": "verb",                          "op": "in",     "value": ["create", "patch", "update"]},
            {"field": "namespace",                     "op": "equals", "value": "kube-system"},
            {"field": "automount_service_account_token", "op": "equals", "value": True},
        ]}},
    },
    {
        "rule_id": "k8s.serviceaccount.audit.delete_system",
        "service": "serviceaccount", "severity": "high",
        "title": "ServiceAccount: System ServiceAccount Deleted",
        "description": "ServiceAccount in kube-system namespace deleted — may disrupt cluster components or remove forensic identity traces.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 76,
        "resource": "k8s_service_account",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "serviceaccounts"},
            {"field": "verb",        "op": "equals", "value": "delete"},
            {"field": "namespace",   "op": "equals", "value": "kube-system"},
        ]}},
    },
    {
        "rule_id": "k8s.serviceaccount.audit.patch",
        "service": "serviceaccount", "severity": "medium",
        "title": "ServiceAccount: ServiceAccount Patched",
        "description": "ServiceAccount patched by a non-CI/CD principal — image pull secrets, annotations, or automount settings modified; potential persistence mechanism.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1543"],
        "risk_score": 65,
        "resource": "k8s_service_account",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "serviceaccounts"},
            {"field": "verb",        "op": "in",     "value": ["patch", "update"]},
        ]}},
    },

    # ── StatefulSet ──────────────────────────────────────────────────────────
    {
        "rule_id": "k8s.statefulset.audit.create_kube_system",
        "service": "statefulset", "severity": "high",
        "title": "StatefulSet: Created in kube-system Namespace",
        "description": "StatefulSet created in kube-system namespace — persistent workload with stable network identity deployed in sensitive system namespace.",
        "threat_category": "persistence",
        "mitre_tactics": ["persistence"],
        "mitre_techniques": ["T1543"],
        "risk_score": 80,
        "resource": "k8s_statefulset",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "statefulsets"},
            {"field": "verb",        "op": "equals", "value": "create"},
            {"field": "namespace",   "op": "equals", "value": "kube-system"},
        ]}},
    },
    {
        "rule_id": "k8s.statefulset.audit.privileged_spec",
        "service": "statefulset", "severity": "critical",
        "title": "StatefulSet: Created with Privileged Container Spec",
        "description": "StatefulSet created with privileged container spec — provides persistent root-level access on a node that survives pod restarts.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1611"],
        "risk_score": 93,
        "resource": "k8s_statefulset",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",              "op": "equals", "value": "k8s_audit"},
            {"field": "resource",                 "op": "equals", "value": "statefulsets"},
            {"field": "verb",                     "op": "equals", "value": "create"},
            {"field": "privileged_container",     "op": "equals", "value": True},
        ]}},
    },

    # ── Job ──────────────────────────────────────────────────────────────────
    {
        "rule_id": "k8s.job.audit.create_kube_system",
        "service": "job", "severity": "high",
        "title": "Job: Created in kube-system Namespace",
        "description": "Kubernetes Job created in kube-system namespace — ad-hoc batch workload executed in sensitive system namespace; may be used for reconnaissance or cleanup.",
        "threat_category": "execution",
        "mitre_tactics": ["execution"],
        "mitre_techniques": ["T1610"],
        "risk_score": 78,
        "resource": "k8s_job",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "jobs"},
            {"field": "verb",        "op": "equals", "value": "create"},
            {"field": "namespace",   "op": "equals", "value": "kube-system"},
        ]}},
    },
    {
        "rule_id": "k8s.job.audit.create_hostpid",
        "service": "job", "severity": "critical",
        "title": "Job: Created with hostPID Enabled",
        "description": "Kubernetes Job created with hostPID=true — allows job container to see and signal all processes on the host node; enables process injection attacks.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1611"],
        "risk_score": 92,
        "resource": "k8s_job",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "jobs"},
            {"field": "verb",        "op": "equals", "value": "create"},
            {"field": "host_pid",    "op": "equals", "value": True},
        ]}},
    },

    # ── ValidatingWebhook ────────────────────────────────────────────────────
    {
        "rule_id": "k8s.validatingwebhook.audit.delete",
        "service": "validatingwebhook", "severity": "critical",
        "title": "ValidatingWebhookConfiguration Deleted",
        "description": "ValidatingWebhookConfiguration deleted — disables admission validation (OPA/Gatekeeper, Kyverno validate rules), allowing previously blocked workloads to be created.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 95,
        "resource": "k8s_webhook",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "validatingwebhookconfigurations"},
            {"field": "verb",        "op": "equals", "value": "delete"},
        ]}},
    },
    {
        "rule_id": "k8s.validatingwebhook.audit.create_permissive",
        "service": "validatingwebhook", "severity": "high",
        "title": "ValidatingWebhookConfiguration Created with failurePolicy=Ignore",
        "description": "ValidatingWebhookConfiguration created with failurePolicy=Ignore — if the webhook backend is unavailable or slow, admission validation is bypassed entirely.",
        "threat_category": "defense_evasion",
        "mitre_tactics": ["defense_evasion"],
        "mitre_techniques": ["T1562.001"],
        "risk_score": 80,
        "resource": "k8s_webhook",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",  "op": "equals", "value": "k8s_audit"},
            {"field": "resource",     "op": "equals", "value": "validatingwebhookconfigurations"},
            {"field": "verb",         "op": "equals", "value": "create"},
            {"field": "failure_policy","op": "equals", "value": "Ignore"},
        ]}},
    },

    # ── LimitRange ───────────────────────────────────────────────────────────
    {
        "rule_id": "k8s.limitrange.audit.delete",
        "service": "limitrange", "severity": "medium",
        "title": "LimitRange: Deleted (Resource Constraints Removed)",
        "description": "LimitRange deleted from namespace — removes default CPU/memory constraints, enabling resource exhaustion (DoS) or unlimited resource consumption.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 65,
        "resource": "k8s_limit_range",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "limitranges"},
            {"field": "verb",        "op": "equals", "value": "delete"},
        ]}},
    },
    {
        "rule_id": "k8s.limitrange.audit.patch_unlimited",
        "service": "limitrange", "severity": "medium",
        "title": "LimitRange: Patched to Very High Limits",
        "description": "LimitRange patched — resource limits may have been increased to effectively unlimited values, enabling resource exhaustion by tenant workloads.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 60,
        "resource": "k8s_limit_range",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "limitranges"},
            {"field": "verb",        "op": "in",     "value": ["patch", "update"]},
        ]}},
    },

    # ── ResourceQuota ────────────────────────────────────────────────────────
    {
        "rule_id": "k8s.resourcequota.audit.delete",
        "service": "resourcequota", "severity": "medium",
        "title": "ResourceQuota: Deleted (Namespace Limits Removed)",
        "description": "ResourceQuota deleted — removes namespace-level limits on CPU, memory, pod count, and storage; enables resource exhaustion attacks.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 65,
        "resource": "k8s_resource_quota",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "resourcequotas"},
            {"field": "verb",        "op": "equals", "value": "delete"},
        ]}},
    },
    {
        "rule_id": "k8s.resourcequota.audit.patch_unlimited",
        "service": "resourcequota", "severity": "medium",
        "title": "ResourceQuota: Patched to Very High Values",
        "description": "ResourceQuota patched — namespace resource limits may have been increased to allow resource exhaustion by compromised workloads.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 60,
        "resource": "k8s_resource_quota",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "resourcequotas"},
            {"field": "verb",        "op": "in",     "value": ["patch", "update"]},
        ]}},
    },

    # ── StorageClass ─────────────────────────────────────────────────────────
    {
        "rule_id": "k8s.storageclass.audit.create_hostpath_provisioner",
        "service": "storageclass", "severity": "critical",
        "title": "StorageClass: Created with hostPath Provisioner",
        "description": "StorageClass created with a hostPath provisioner — PVCs using this class will mount node filesystem paths, enabling container escape via persistent volume.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1611"],
        "risk_score": 91,
        "resource": "k8s_storage_class",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",  "op": "equals",   "value": "k8s_audit"},
            {"field": "resource",     "op": "equals",   "value": "storageclasses"},
            {"field": "verb",         "op": "equals",   "value": "create"},
            {"field": "provisioner",  "op": "contains", "value": "hostpath"},
        ]}},
    },
    {
        "rule_id": "k8s.storageclass.audit.delete",
        "service": "storageclass", "severity": "high",
        "title": "StorageClass: Deleted (Persistent Storage Disrupted)",
        "description": "StorageClass deleted — any PVCs referencing this class can no longer provision new volumes; may disrupt stateful workloads.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 74,
        "resource": "k8s_storage_class",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "storageclasses"},
            {"field": "verb",        "op": "equals", "value": "delete"},
        ]}},
    },

    # ── ClusterRole — additional ─────────────────────────────────────────────
    {
        "rule_id": "k8s.clusterrole.audit.delete_system",
        "service": "clusterrole", "severity": "critical",
        "title": "ClusterRole: System ClusterRole Deleted",
        "description": "Built-in system ClusterRole deleted (cluster-admin, system:node, system:kube-controller-manager, etc.) — may break cluster functionality or remove RBAC safety rails.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 94,
        "resource": "k8s_cluster_role",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals",   "value": "k8s_audit"},
            {"field": "resource",    "op": "equals",   "value": "clusterroles"},
            {"field": "verb",        "op": "equals",   "value": "delete"},
            {"field": "name",        "op": "contains", "value": "system:"},
        ]}},
    },
    {
        "rule_id": "k8s.clusterrole.audit.wildcard_resource_create",
        "service": "clusterrole", "severity": "high",
        "title": "ClusterRole: Created with Wildcard Resources",
        "description": "ClusterRole created with resources: [\"*\"] — grants all API resource types as scope, giving the role broad access comparable to cluster-admin on matched verbs.",
        "threat_category": "privilege_escalation",
        "mitre_tactics": ["privilege_escalation"],
        "mitre_techniques": ["T1098.006"],
        "risk_score": 87,
        "resource": "k8s_cluster_role",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",     "op": "equals",   "value": "k8s_audit"},
            {"field": "resource",        "op": "equals",   "value": "clusterroles"},
            {"field": "verb",            "op": "equals",   "value": "create"},
            {"field": "rules_resources", "op": "contains", "value": "*"},
        ]}},
    },

    # ── NetworkPolicy — additional ───────────────────────────────────────────
    {
        "rule_id": "k8s.networkpolicy.audit.create_allow_all",
        "service": "networkpolicy", "severity": "high",
        "title": "NetworkPolicy: Allow-All Policy Created",
        "description": "NetworkPolicy created with empty podSelector and no ingress/egress restrictions — effectively allows all traffic to/from all pods in the namespace.",
        "threat_category": "lateral_movement",
        "mitre_tactics": ["lateral_movement"],
        "mitre_techniques": ["T1572"],
        "risk_score": 78,
        "resource": "k8s_network_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",     "op": "equals", "value": "k8s_audit"},
            {"field": "resource",        "op": "equals", "value": "networkpolicies"},
            {"field": "verb",            "op": "equals", "value": "create"},
            {"field": "allow_all_ingress","op": "equals", "value": True},
        ]}},
    },
    {
        "rule_id": "k8s.networkpolicy.audit.update_allow_all",
        "service": "networkpolicy", "severity": "high",
        "title": "NetworkPolicy: Updated to Allow All Traffic",
        "description": "Existing NetworkPolicy updated to allow all ingress/egress — network isolation controls weakened, enabling lateral movement between pods.",
        "threat_category": "lateral_movement",
        "mitre_tactics": ["lateral_movement"],
        "mitre_techniques": ["T1572"],
        "risk_score": 78,
        "resource": "k8s_network_policy",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "networkpolicies"},
            {"field": "verb",        "op": "in",     "value": ["patch", "update"]},
            {"field": "allow_all_ingress","op": "equals", "value": True},
        ]}},
    },

    # ── ConfigMap — additional ───────────────────────────────────────────────
    {
        "rule_id": "k8s.configmap.audit.create_with_credentials",
        "service": "configmap", "severity": "high",
        "title": "ConfigMap: Created in kube-system with Credential Patterns",
        "description": "ConfigMap created in kube-system namespace with data keys matching credential patterns (token, password, key, secret) — may store credentials in cleartext.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access"],
        "mitre_techniques": ["T1552.001"],
        "risk_score": 76,
        "resource": "k8s_config_map",
        "check_config": {"conditions": {"all": [
            {"field": "source_type",   "op": "equals",   "value": "k8s_audit"},
            {"field": "resource",      "op": "equals",   "value": "configmaps"},
            {"field": "verb",          "op": "equals",   "value": "create"},
            {"field": "namespace",     "op": "equals",   "value": "kube-system"},
            {"field": "data_keys",     "op": "contains", "value": "token"},
        ]}},
    },
    {
        "rule_id": "k8s.configmap.audit.delete_kube_system",
        "service": "configmap", "severity": "high",
        "title": "ConfigMap: kube-system ConfigMap Deleted",
        "description": "ConfigMap deleted in kube-system namespace — may disrupt cluster components that depend on this configuration data (kube-proxy, CoreDNS, etc.).",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 76,
        "resource": "k8s_config_map",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "configmaps"},
            {"field": "verb",        "op": "equals", "value": "delete"},
            {"field": "namespace",   "op": "equals", "value": "kube-system"},
        ]}},
    },

    # ── Node — additional ────────────────────────────────────────────────────
    {
        "rule_id": "k8s.node.audit.taint_remove",
        "service": "node", "severity": "medium",
        "title": "Node: Taint Removed (Workload Placement Control Bypassed)",
        "description": "Node taint removed — may allow pods that were previously excluded to schedule on this node, bypassing workload isolation controls.",
        "threat_category": "lateral_movement",
        "mitre_tactics": ["lateral_movement"],
        "mitre_techniques": ["T1205"],
        "risk_score": 62,
        "resource": "k8s_node",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals", "value": "k8s_audit"},
            {"field": "resource",    "op": "equals", "value": "nodes"},
            {"field": "verb",        "op": "in",     "value": ["patch", "update"]},
            {"field": "taint_effect","op": "equals", "value": "NoSchedule"},
        ]}},
    },
    {
        "rule_id": "k8s.node.audit.label_modify_sensitive",
        "service": "node", "severity": "medium",
        "title": "Node: Sensitive Node Label Modified",
        "description": "Node label modified on sensitive labels (kubernetes.io/role, node-role.kubernetes.io) — may affect workload scheduling, pod placement, and node selector targeting.",
        "threat_category": "lateral_movement",
        "mitre_tactics": ["lateral_movement"],
        "mitre_techniques": ["T1205"],
        "risk_score": 60,
        "resource": "k8s_node",
        "check_config": {"conditions": {"all": [
            {"field": "source_type", "op": "equals",   "value": "k8s_audit"},
            {"field": "resource",    "op": "equals",   "value": "nodes"},
            {"field": "verb",        "op": "in",       "value": ["patch", "update"]},
            {"field": "label_key",   "op": "contains", "value": "node-role.kubernetes.io"},
        ]}},
    },

    # ── Additional Correlation Chains ────────────────────────────────────────
    {
        "rule_id": "k8s.ciem.correlation.credential_theft_chain",
        "service": "ciem",
        "check_type": "log_correlation",
        "title": "K8s: Credential Theft Chain — Secret List → Token Create → RBAC Binding",
        "description": "Correlated credential theft: Secrets bulk-listed, followed by service account token creation, followed by new RBAC binding — full credential harvest and persistence.",
        "threat_category": "credential_access",
        "mitre_tactics": ["credential_access", "persistence"],
        "mitre_techniques": ["T1552.001", "T1098.006"],
        "risk_score": 96,
        "resource": "k8s_cluster",
        "check_config": {
            "type": "sequence",
            "window_seconds": 600,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",    "op": "equals", "value": "secrets"},
                    {"field": "verb",        "op": "in",     "value": ["list", "watch"]},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals",     "value": "k8s_audit"},
                    {"field": "resource",    "op": "equals",     "value": "serviceaccounts"},
                    {"field": "subresource", "op": "equals",     "value": "token"},
                    {"field": "verb",        "op": "equals",     "value": "create"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",    "op": "in",     "value": ["clusterrolebindings", "rolebindings"]},
                    {"field": "verb",        "op": "equals", "value": "create"},
                ]}},
            ],
        },
    },
    {
        "rule_id": "k8s.ciem.correlation.supply_chain_attack_chain",
        "service": "ciem",
        "check_type": "log_correlation",
        "title": "K8s: Supply Chain Attack — Never-Pull Image → Privileged Container → Exec",
        "description": "Correlated supply chain attack: Pod using imagePullPolicy=Never launched as privileged, followed by exec session — tampered local image executed with full host access.",
        "threat_category": "supply_chain_compromise",
        "mitre_tactics": ["execution", "privilege_escalation"],
        "mitre_techniques": ["T1610", "T1611", "T1609"],
        "risk_score": 97,
        "resource": "k8s_pod",
        "check_config": {
            "type": "sequence",
            "window_seconds": 300,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type",       "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",          "op": "equals", "value": "pods"},
                    {"field": "verb",              "op": "equals", "value": "create"},
                    {"field": "image_pull_policy", "op": "equals", "value": "Never"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type",       "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",          "op": "equals", "value": "pods"},
                    {"field": "verb",              "op": "equals", "value": "create"},
                    {"field": "privileged_container","op": "equals", "value": True},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",    "op": "equals", "value": "pods"},
                    {"field": "subresource", "op": "equals", "value": "exec"},
                    {"field": "verb",        "op": "equals", "value": "create"},
                ]}},
            ],
        },
    },
    {
        "rule_id": "k8s.ciem.correlation.cluster_destruction_chain",
        "service": "ciem",
        "check_type": "log_correlation",
        "title": "K8s: Cluster Destruction — Admin Binding → Namespace Delete → Node Delete",
        "description": "Correlated cluster destruction: cluster-admin binding created, followed by namespace deletion, followed by node deletion — systematic cluster teardown.",
        "threat_category": "impact",
        "mitre_tactics": ["impact"],
        "mitre_techniques": ["T1485"],
        "risk_score": 99,
        "resource": "k8s_cluster",
        "check_config": {
            "type": "sequence",
            "window_seconds": 900,
            "events": [
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals",   "value": "k8s_audit"},
                    {"field": "resource",    "op": "equals",   "value": "clusterrolebindings"},
                    {"field": "verb",        "op": "equals",   "value": "create"},
                    {"field": "role_ref",    "op": "contains", "value": "cluster-admin"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",    "op": "equals", "value": "namespaces"},
                    {"field": "verb",        "op": "equals", "value": "delete"},
                ]}},
                {"conditions": {"all": [
                    {"field": "source_type", "op": "equals", "value": "k8s_audit"},
                    {"field": "resource",    "op": "equals", "value": "nodes"},
                    {"field": "verb",        "op": "equals", "value": "delete"},
                ]}},
            ],
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Enrichment helpers
# ─────────────────────────────────────────────────────────────────────────────

def _enrich(r: dict) -> dict:
    cat    = r.get("threat_category", "")
    techs  = r.get("mitre_techniques") or []
    tech   = techs[0] if techs else ""
    parent = tech.split(".")[0] if tech else ""

    r.setdefault("provider",         "k8s")
    r.setdefault("check_type",       "log")
    r.setdefault("source",           "default")
    r.setdefault("is_active",        True)
    r.setdefault("version",          "1.0")
    r.setdefault("log_source_type",  "k8s_audit")
    r.setdefault("domain",           DOMAIN_BY_CAT.get(cat, "container_and_kubernetes_security"))
    r.setdefault("action_category",  ACTION_BY_CAT.get(cat, "modify"))
    r.setdefault("posture_category", POSTURE_BY_CAT.get(cat, "threat_posture"))

    rat = RATIONALE.get(tech) or RATIONALE.get(parent)
    if not rat:
        rat = (
            f"Adversaries exploit {r.get('service','Kubernetes')} resources to achieve "
            f"{cat.replace('_', ' ')} in containerized environments. "
            "Detected via Kubernetes API server audit logs."
        )
    r.setdefault("rationale", rat)

    r.setdefault("remediation",         REMEDIATION.get(cat, REMEDIATION["defense_evasion"]))
    refs = REFERENCES.get(tech) or REFERENCES.get(parent) or [
        f"https://attack.mitre.org/techniques/{tech.replace('.', '/')}/" if tech else
        "https://kubernetes.io/docs/concepts/security/",
        "https://www.cisa.gov/sites/default/files/2022-03/kubernetes-hardening-guidance-1.2-508c.pdf",
    ]
    r.setdefault("references", refs)
    r.setdefault("compliance_frameworks", COMPLIANCE.get(cat, {}))

    # threat_tags
    tags = list(techs)
    for t in techs:
        p = t.split(".")[0]
        if p not in tags:
            tags.append(p)
    tags.append(cat)
    svc = r.get("service", "")
    if svc and svc not in tags:
        tags.append(svc)
    tags.append("k8s")
    tags.append("container")
    r.setdefault("threat_tags", tags)

    # risk_indicators
    rid = r.get("rule_id", "")
    is_org = "namespace" in rid or "cluster" in rid
    r.setdefault("risk_indicators", {
        "actor_type":   "k8s_principal",
        "action_type":  ACTION_BY_CAT.get(cat, "write"),
        "target_type":  r.get("resource", "k8s_resource"),
        "blast_radius": "cluster" if is_org else "namespace",
        "stealth_risk": "critical" if r.get("risk_score", 0) >= 90 else
                        "high"     if r.get("risk_score", 0) >= 70 else "medium",
    })

    # iam_security
    is_iam = cat in IAM_CATS or any(s in r.get("service", "") for s in ("rbac","serviceaccount","admission"))
    iam_mods = []
    if is_iam:
        if "binding" in rid:         iam_mods.append("role_management")
        if "serviceaccount" in rid:  iam_mods.append("least_privilege")
        if "impersonat" in rid:      iam_mods.append("access_control")
        if "token" in rid:           iam_mods.append("access_control")
        if not iam_mods:             iam_mods = ["access_control"]
    r.setdefault("iam_security", {"applicable": is_iam, "modules": iam_mods})

    # data_security
    is_data = cat in DATA_CATS
    ds: dict = {"applicable": is_data}
    if is_data:
        ds["modules"]    = ["data_access_governance"]
        ds["categories"] = ["sensitive_data_access"]
        ds["priority"]   = "critical" if r.get("risk_score", 0) >= 85 else "high"
        ds["impact"] = {
            "pci":   "PCI DSS Requirement 3.4 — Protect stored cardholder data from unauthorized access",
            "gdpr":  "GDPR Article 32 — Technical measures to ensure security of personal data processing",
            "hipaa": "§164.312(a)(1) — Implement technical security for unauthorized access to ePHI",
        }
        ds["sensitive_data_context"] = (
            f"Unauthorized {cat.replace('_', ' ')} on Kubernetes {r.get('resource', 'resource')} "
            "must be detected to prevent: credential theft, data exposure, and regulatory violations."
        )
    r.setdefault("data_security", ds)

    return r


# ─────────────────────────────────────────────────────────────────────────────
# YAML writer
# ─────────────────────────────────────────────────────────────────────────────

def _yaml_str(value: str) -> str:
    if "\n" in value:
        lines = value.rstrip("\n").split("\n")
        return "|\n" + "\n".join("  " + ln for ln in lines)
    if any(c in value for c in (':', '#', '[', ']', '{', '}', '&', '*', '!', '|', '>', '"', "'")):
        escaped = value.replace("'", "''")
        return f"'{escaped}'"
    return value


def _dump_rule(r: dict) -> str:
    lines = []

    for f in ("rule_id", "service", "provider", "check_type", "severity"):
        if f in r:
            lines.append(f"{f}: {_yaml_str(str(r[f]))}")

    lines.append(f"title: {_yaml_str(r.get('title', r['rule_id']))}")
    lines.append(f"description: {_yaml_str(r.get('description', ''))}")
    lines.append(f"rationale: {_yaml_str(r.get('rationale', ''))}")

    if "threat_category" in r:
        lines.append(f"threat_category: {r['threat_category']}")

    lines.append("mitre_tactics:")
    for t in (r.get("mitre_tactics") or []):
        lines.append(f"- {t}")

    lines.append("mitre_techniques:")
    for t in (r.get("mitre_techniques") or []):
        lines.append(f"- {t}")

    lines.append(f"risk_score: {r.get('risk_score', 50)}")

    for f in ("resource", "source", "is_active"):
        if f in r:
            v = r[f]
            if isinstance(v, bool):
                lines.append(f"{f}: {'true' if v else 'false'}")
            else:
                lines.append(f"{f}: {_yaml_str(str(v))}")

    for f in ("domain", "action_category", "log_source_type", "posture_category"):
        if r.get(f):
            lines.append(f"{f}: {_yaml_str(str(r[f]))}")

    tags = r.get("threat_tags") or []
    if tags:
        lines.append("threat_tags:")
        for t in tags:
            lines.append(f"- {t}")
    else:
        lines.append("threat_tags: []")

    ri = r.get("risk_indicators") or {}
    if ri:
        lines.append("risk_indicators:")
        for k, v in ri.items():
            lines.append(f"  {k}: {v}")

    iam = r.get("iam_security") or {}
    lines.append("iam_security:")
    lines.append(f"  applicable: {'true' if iam.get('applicable') else 'false'}")
    mods = iam.get("modules", [])
    if mods:
        lines.append("  modules:")
        for m in mods:
            lines.append(f"  - {m}")
    else:
        lines.append("  modules: []")

    ds = r.get("data_security") or {}
    lines.append("data_security:")
    lines.append(f"  applicable: {'true' if ds.get('applicable') else 'false'}")
    if ds.get("applicable"):
        if ds.get("modules"):
            lines.append("  modules:")
            for m in ds["modules"]:
                lines.append(f"  - {m}")
        if ds.get("categories"):
            lines.append("  categories:")
            for c in ds["categories"]:
                lines.append(f"  - {c}")
        if "priority" in ds:
            lines.append(f"  priority: {ds['priority']}")
        impact = ds.get("impact", {})
        if impact:
            lines.append("  impact:")
            for k, v in impact.items():
                lines.append(f"    {k}: {_yaml_str(v)}")
        sc = ds.get("sensitive_data_context", "")
        if sc:
            lines.append(f"  sensitive_data_context: {_yaml_str(sc)}")

    cf = r.get("compliance_frameworks") or {}
    if cf:
        lines.append("compliance_frameworks:")
        for fw, controls in cf.items():
            lines.append(f"  {fw}:")
            for c in (controls or []):
                lines.append(f"  - {c}")
    else:
        lines.append("compliance_frameworks: {}")

    lines.append(f"remediation: {_yaml_str(r.get('remediation', ''))}")

    refs = r.get("references") or []
    if refs:
        lines.append("references:")
        for ref in refs:
            lines.append(f"- {ref}")

    cc_yaml = yaml.dump(
        {"check_config": r.get("check_config", {})},
        default_flow_style=False,
        allow_unicode=True,
    ).rstrip()
    lines.append(cc_yaml)

    lines.append(f"version: '{r.get('version', '1.0')}'")
    return "\n".join(lines) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    written = errors = 0

    for r in RULES:
        r = _enrich(dict(r))
        rule_id  = r["rule_id"]
        service  = r.get("service", "misc")
        out_path = OUT / service / (rule_id + ".yaml")

        if args.dry_run:
            print(f"  DRY  {out_path.relative_to(ROOT)}")
            written += 1
            continue

        try:
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(_dump_rule(r), encoding="utf-8")
            written += 1
        except Exception as exc:
            print(f"  ERROR  {rule_id}: {exc}")
            errors += 1

    print(f"\nGenerated : {written}")
    if errors:
        print(f"Errors    : {errors}")
    if args.dry_run:
        print("(dry-run)")


if __name__ == "__main__":
    main()