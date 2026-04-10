# Kubernetes CSP — Detailed Project Plan

## Context

- **Available cluster:** EKS `arn:aws:eks:ap-south-1:588989875114:cluster/vulnerability-eks-cluster`
  (our own EKS — dogfooding opportunity)
- **Context:** `arn:aws:eks:ap-south-1:588989875114:cluster/vulnerability-eks-cluster`
- **Discovery configs in DB:** 17 (`rule_discoveries WHERE provider='k8s'`)
- **Check rules in DB:** 649
- **Scanner current state:** Stub (293 lines)
- **Key scanner file:** `engines/discoveries/providers/kubernetes/scanner/service_scanner.py`

## Special Consideration

K8s is not a "cloud provider" — it's an orchestration layer that runs ON TOP of clouds.
A K8s scan is always tied to a specific cluster, which itself runs on a cloud account.
This means K8s scans are **additive** to a cloud scan, not standalone.

**Scan model:** When a cloud account (AWS/Azure/GCP) has K8s clusters, the pipeline
automatically chains a K8s sub-scan for each cluster found.

## Milestone 1: Kubernetes Scanner Foundation

**Goal:** K8s scanner reads from `rule_discoveries` DB (provider='k8s'), uses
`kubernetes` Python client, handles all resource types.

**Estimated effort:** 3-4 days

### User Stories

**US-K8S-01: K8s Client Factory**
- As the discovery engine, I need to connect to a K8s cluster using kubeconfig or
  in-cluster service account, so I can enumerate cluster resources.
- **Tasks:**
  - T1: Implement credential types:
    - `kubeconfig`: load from path or base64-encoded string in secret
    - `in_cluster`: use mounted service account token (when engine runs inside K8s)
    - `eks_token`: use `aws eks get-token` → pass to K8s API server
    - `gke_token`: use GCP service account → K8s token
    - `aks_token`: use Azure AD token → K8s token
  - T2: Implement `K8sClientFactory.get_client(cluster_endpoint, credential_type, token)`
  - T3: Set 10s request timeout on all API calls
- **SME:** Kubernetes platform engineer

**US-K8S-02: DB Catalog Reader for K8s**
- As the discovery engine, I need to execute K8s API calls from `rule_discoveries` DB
  and return resources in standard discovery format.
- **Tasks:**
  - T1: Map `rule_discoveries.call` values to `kubernetes` client methods:
    - `list_namespaced_pod` → CoreV1Api
    - `list_namespaced_service` → CoreV1Api
    - `list_namespaced_config_map` → CoreV1Api
    - `list_namespaced_secret` → CoreV1Api
    - `list_cluster_role` → RbacAuthorizationV1Api
    - `list_cluster_role_binding` → RbacAuthorizationV1Api
    - `list_namespaced_network_policy` → NetworkingV1Api
    - `list_pod_security_policy` → PolicyV1Api (deprecated but exists)
    - `list_namespace` → CoreV1Api
    - `list_node` → CoreV1Api
  - T2: Handle K8s pagination (`continue` token in `ListMeta`)
  - T3: Handle `Namespace` as the K8s equivalent of "region" — iterate all namespaces
  - T4: Handle cluster-scoped vs namespace-scoped resources
- **SME:** Python engineer with kubernetes-client library experience

**US-K8S-03: K8s Security Resource Enumeration**
- As the discovery engine, I need to enumerate all security-relevant K8s resources
  so the check engine can evaluate CIS K8s Benchmark rules.
- **Priority resources (keep):**
  - Pods (image, security context, privilege escalation)
  - ServiceAccounts (automountToken)
  - ClusterRoles + ClusterRoleBindings (RBAC)
  - RoleBindings (namespace RBAC)
  - NetworkPolicies (or absence of them)
  - Namespaces (resource quotas, labels)
  - Nodes (kubelet config, version)
  - ConfigMaps (secrets in plaintext check)
  - Secrets (type, usage)
  - PodSecurityPolicies / OPA policies (admission control)
  - Ingress resources (TLS config)
  - ServiceAccounts bound to pods (lateral movement risk)
- **Remove (noise):**
  - Events (high volume, no security value)
  - Endpoints (derived from Services, redundant)
  - ReplicaSets (management only, pods cover security)
  - ControllerRevisions
  - Leases
  - ComponentStatuses

---

## Milestone 2: K8s Security Relationships

### User Stories

**US-K8S-04: K8s Security Graph**
- **Key relationships:**
  - Pod → ServiceAccount → ClusterRoleBinding → ClusterRole (privilege chain)
  - Pod → Node (placement + escape risk)
  - Pod → Namespace → NetworkPolicy (isolation check)
  - Pod → Secret (mounted secrets)
  - Pod → ConfigMap (config injection)
  - Deployment → Pod (lineage)
  - Ingress → Service → Pod (external exposure chain)
  - ServiceAccount → Secret (SA token)
  - Namespace → ResourceQuota (resource abuse)

---

## Milestone 3: Cluster Auto-Discovery Integration

**Goal:** When AWS discovery finds EKS clusters, GCP finds GKE, Azure finds AKS —
automatically trigger a K8s sub-scan for each cluster.

**Tasks:**
- T1: Add post-discovery hook in `DiscoveryEngine`: after cloud scan completes,
  check `discovery_findings WHERE resource_type IN ('EKSCluster','GKECluster','AKSCluster')`
- T2: For each found cluster, enqueue a K8s scan with the cluster endpoint + credentials
- T3: Store K8s findings under the same `scan_run_id` with `provider='k8s'`,
  `account_id=<cluster_arn>`
- T4: Argo pipeline: add optional `k8s-scan` step after discovery that fires if
  clusters were discovered

## K8s-Specific Technical Notes

- **K8s is not a region** — use namespace as the "region" equivalent in findings
- **CIS K8s Benchmark v1.8** — 649 rules already in DB, need actual K8s API data
- **EKS specifics:** Node IAM roles, aws-auth ConfigMap, EKS managed policies
- **Multi-cluster:** One `scan_run_id` per cluster (separate pipeline invocations)
- **RBAC complexity:** K8s RBAC is the primary attack surface — prioritize
  ClusterRoleBinding traversal for IAM engine