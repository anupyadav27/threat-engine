# Kubernetes — Full Stack E2E Plan

## Status
- Credentials: ✓ EKS cluster (current context), minikube (local)
- rule_discoveries in DB: ✓ 17 services (seeded via SQL)
- Scanner code: ✗ Partial stub exists at `engines/discoveries/providers/kubernetes/`
- Check rules: ✗ 0 K8s rules in rule_metadata
- Inventory relationships: ✗ 0 K8s rows in resource_security_relationship_rules
- Compliance frameworks: ✗ No CIS K8s in compliance_frameworks
- Priority: #3 (in-cluster credentials available — dogfood EKS cluster)
- Note: K8s scanning is ADDITIVE — scans the cluster running CSPM, not standalone

---

## Architecture Note

K8s is scanned as a cloud provider but differs from AWS/Azure/GCP:
- **No "account"** — uses namespace + cluster as scope
- **No "region"** — uses cluster name or kubeconfig context as equivalent
- **Credentials**: in-cluster ServiceAccount (preferred) or kubeconfig file
- **Resource hierarchy**: Cluster → Namespace → Workload → Pod
- **account_id field**: use cluster ARN/name (e.g., `arn:aws:eks:ap-south-1:588989875114:cluster/vulnerability-eks-cluster`)
- **region field**: use cloud region where cluster runs (`ap-south-1`) or `in-cluster`

---

## Phase 1 — Discovery (Track A)

### Milestone 1.1: K8s Provider Directory

Check existing stub:

**US-K8S-DISC-01: Provider structure**
- `engines/discoveries/providers/kubernetes/` — check what's there
- Need: `k8s_scanner.py` — KubernetesDiscoveryScanner class
- Need: `client_factory.py` — wraps `kubernetes` Python SDK
- Need: `pagination.py` — K8s uses list with `continue` token
- Register in `run_scan.py`: `PROVIDER_SCANNERS['k8s'] = KubernetesDiscoveryScanner`

**US-K8S-DISC-02: K8s Authentication**

Two modes (controlled by env var `K8S_AUTH_MODE`):
1. **in-cluster** (default when running as pod): `kubernetes.config.load_incluster_config()`
   - Uses ServiceAccount token mounted at `/var/run/secrets/kubernetes.io/serviceaccount/`
   - K8s RBAC: scanner ServiceAccount needs `ClusterRole` with `get`/`list`/`watch` on all resources
2. **kubeconfig** (for external scanning): `kubernetes.config.load_kube_config(config_file=kubeconfig_path)`
   - Kubeconfig stored in K8s secret `k8s-creds`
   - Used for scanning external clusters from within EKS

**RBAC for scanner:**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cspm-scanner-reader
rules:
- apiGroups: [""]
  resources: ["pods","services","serviceaccounts","namespaces","nodes",
              "configmaps","secrets","persistentvolumes","endpoints"]
  verbs: ["get","list","watch"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources: ["clusterroles","clusterrolebindings","roles","rolebindings"]
  verbs: ["get","list","watch"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies","ingresses"]
  verbs: ["get","list","watch"]
- apiGroups: ["apps"]
  resources: ["deployments","daemonsets","statefulsets","replicasets"]
  verbs: ["get","list","watch"]
- apiGroups: ["policy"]
  resources: ["podsecuritypolicies"]
  verbs: ["get","list","watch"]
```

**US-K8S-DISC-03: Client Factory**

K8s uses a single client with typed APIs:
```python
from kubernetes import client, config

class KubernetesClientFactory:
    def __init__(self, auth_mode='in-cluster', kubeconfig_path=None):
        if auth_mode == 'in-cluster':
            config.load_incluster_config()
        else:
            config.load_kube_config(config_file=kubeconfig_path)
        self._api_client = client.ApiClient()

    def get_client(self, resource_group: str):
        CLIENT_MAP = {
            'core':    client.CoreV1Api,
            'apps':    client.AppsV1Api,
            'rbac':    client.RbacAuthorizationV1Api,
            'batch':   client.BatchV1Api,
            'network': client.NetworkingV1Api,
            'policy':  client.PolicyV1Api,
            'autoscaling': client.AutoscalingV1Api,
        }
        return CLIENT_MAP[resource_group](self._api_client)
```

Map `rule_discoveries.service` → API group:
- `pods`, `services`, `serviceaccounts`, `namespaces`, `nodes`, `configmaps`, `secrets` → `core`
- `deployments`, `daemonsets`, `statefulsets` → `apps`
- `clusterroles`, `clusterrolebindings`, `roles`, `rolebindings` → `rbac`
- `networkpolicies`, `ingresses` → `network`
- `podsecuritypolicies` → `policy`

**US-K8S-DISC-04: K8s Pagination**

K8s uses `continue` token for large lists:
```python
def k8s_list_all(list_method, **kwargs) -> List[dict]:
    results, cont = [], None
    while True:
        resp = list_method(_continue=cont, limit=500, **kwargs)
        for item in resp.items:
            results.append(item.to_dict())
        cont = resp.metadata._continue
        if not cont:
            break
    return results
```

**US-K8S-DISC-05: Resource type and UID**
- `resource_type`: `Pod`, `Deployment`, `Service`, `Namespace`, `Node`, `ServiceAccount`, etc.
- `resource_uid`: `{cluster}/{namespace}/{kind}/{name}` e.g., `vulnerability-eks-cluster/kube-system/deployment/coredns`
- For cluster-scoped: `{cluster}/{kind}/{name}` e.g., `vulnerability-eks-cluster/clusterrole/admin`

**Noise removal (from 09_NOISE_REMOVAL.md):**
- Disable in rule_discoveries WHERE provider='k8s' AND service IN:
  - `events` (monitoring)
  - `endpoints` (derived from services)
  - `replicationcontrollers` (deprecated)
  - `componentstatuses` (deprecated)

**Docker:**
- Image: `yadavanup84/engine-discoveries-k8s:v1.k8s.YYYYMMDD`
- SDK: `kubernetes>=28.1`
- Lightweight image — kubernetes SDK only, no cloud SDKs

---

## Phase 2 — Inventory (Track B)

### Milestone 2.1: K8s Relationship Rules

SQL: INSERT 12 rows into `resource_security_relationship_rules` (see 07_INVENTORY_RELATIONSHIPS.md):
- Pod → ServiceAccount (AUTHENTICATES_VIA)
- Pod → Node (CONTAINS)
- Pod → Secret (ACCESSES via volume mount)
- Pod → ConfigMap (ACCESSES via volume mount)
- ClusterRoleBinding → ClusterRole (ACCESSES)
- ClusterRoleBinding → ServiceAccount (GRANTS)
- Namespace → NetworkPolicy (PROTECTED_BY)
- Ingress → Service (EXPOSES)
- Service → Pod (ROUTES_TO via selector)
- Deployment → Pod (CONTAINS via ownerRef)

### Milestone 2.2: K8s Asset Classification

```sql
INSERT INTO service_classification (csp, resource_type, category, subcategory, scope) VALUES
('k8s', 'Pod', 'Compute', 'Pod', 'namespace'),
('k8s', 'Deployment', 'Compute', 'Workload Controller', 'namespace'),
('k8s', 'Service', 'Network', 'Service', 'namespace'),
('k8s', 'Namespace', 'Platform', 'Namespace', 'cluster'),
('k8s', 'Node', 'Infrastructure', 'Node', 'cluster'),
('k8s', 'ServiceAccount', 'Identity', 'Service Account', 'namespace'),
('k8s', 'ClusterRole', 'IAM', 'Role', 'cluster'),
('k8s', 'ClusterRoleBinding', 'IAM', 'Role Binding', 'cluster'),
('k8s', 'NetworkPolicy', 'Network', 'Network Policy', 'namespace'),
('k8s', 'Ingress', 'Network', 'Ingress', 'namespace');
```

---

## Phase 3 — Check Engine (Track C)

### Milestone 3.1: K8s Check Rules

`rule_metadata` entries for ~150 K8s rules:

**Pod Security:**
- Pod: privileged container not running
- Pod: runAsRoot not set
- Pod: hostPID/hostIPC/hostNetwork not enabled
- Pod: allowPrivilegeEscalation=false
- Pod: capabilities dropped (drop ALL, add only needed)
- Pod: read-only root filesystem
- Pod: no hostPath volume mounts to sensitive paths
- Pod: seccomp profile set
- Pod: AppArmor annotation set (Linux nodes)
- Pod: CPU/memory limits set (resource exhaustion risk)
- Pod: image not using :latest tag
- Pod: image from trusted registry only

**RBAC:**
- ClusterRole: no wildcard permissions (`*`) on resources or verbs
- ClusterRole: no `create`/`delete` on pods in production namespaces
- ClusterRole: no access to `secrets` in all namespaces
- ClusterRoleBinding: no `cluster-admin` for service accounts outside kube-system
- ServiceAccount: `automountServiceAccountToken: false` for non-SA workloads
- Role: no escalation verbs (bind, escalate, impersonate)

**Network:**
- NetworkPolicy: every namespace has at least one NetworkPolicy
- NetworkPolicy: default-deny ingress policy present
- Service: no NodePort services in production (exposes ports on all nodes)
- Service: no LoadBalancer services without security annotation
- Ingress: TLS configured (not plain HTTP)

**Secrets:**
- Secrets: not stored in ConfigMaps (check for base64-encoded values)
- Secrets: etcd encryption at rest enabled (node-level check)
- Secrets: no plain-text passwords in environment variables

**Nodes:**
- Node: kubelet read-only port (10255) disabled
- Node: node authorization mode enabled
- Node: admission controllers include PodSecurity
- Node: auto-upgrade enabled (EKS managed node groups)

**Namespaces:**
- Default namespace: no workloads in default namespace
- kube-system: only privileged services

### Milestone 3.2: K8s Check Engine

- `engine_check_k8s/` provider directory
- Reads `discovery_findings WHERE provider='k8s'`
- Rules evaluate K8s resource spec fields (spec.securityContext, spec.containers, etc.)
- No boto3/azure/gcp SDK needed — works on already-discovered JSON resources

---

## Phase 4 — Threat Engine

### Milestone 4.1: K8s Threat Rules

MITRE for K8s (Cloud + Container matrix):
- T1610 — Deploy Container (malicious container deployment)
- T1611 — Escape to Host (privileged container escape)
- T1613 — Container and Resource Discovery
- T1078.001 — Valid Accounts: Default Accounts (default SA)
- T1552.007 — Unsecured Credentials: Container API
- T1609 — Container Administration Command (kubectl exec abuse)
- T1619 — Cloud Storage Object Discovery
- T1110 — Brute Force (against K8s API)
- T1098 — Account Manipulation (modify ClusterRoleBinding)

Add `k8s_checks` column to `mitre_technique_reference` (schema change).
Update per technique with K8s rule IDs.

### Milestone 4.2: K8s Attack Paths

1. **Privileged Pod → Host Escape**: Pod (privileged=true + hostPID) → Node → all pods on node → T1611
2. **Exposed API → Cluster Takeover**: API server (public + no auth) → all namespaces → T1613
3. **Default SA → Cloud Metadata**: Pod (default SA + automount) → IMDS endpoint → AWS role → T1552.007
4. **Wildcard RBAC → Privilege Escalation**: ServiceAccount (wildcard ClusterRole) → all secrets → T1098

### Milestone 4.3: Blast Radius (K8s)

- Compromised Node → all pods on that node
- Compromised cluster-admin SA → all namespaces → all workloads
- Compromised Ingress → all services exposed through it

---

## Phase 5 — IAM Engine (K8s)

### Milestone 5.1: K8s IAM Rules

Provider='k8s', iam_modules=['k8s_rbac']:

RBAC policy analysis:
- Who has cluster-admin? (should be only infra SAs)
- ServiceAccounts with get/list/watch on secrets across namespaces
- Users/SAs with create pods (can deploy arbitrary containers)
- Roles with bind/escalate (privilege escalation vector)
- Cross-namespace binding: Role in namespace A bound from namespace B

**IAM module name**: `k8s_rbac`

---

## Phase 6 — DataSec Engine (K8s)

### Milestone 6.1: K8s DataSec

Focus areas:
- Detect Secrets containing sensitive patterns (detected at rest, not values — just metadata)
- Detect ConfigMaps with embedded credentials (base64 check)
- Detect PersistentVolumes with sensitive data mount paths
- No etcd encryption at rest → treat as high data risk

`datasec_data_store_services` — add K8s entries:
- `secret` — Kubernetes Secrets
- `configmap` — ConfigMaps with sensitive data
- `persistentvolume` — PersistentVolumes

---

## Phase 7 — Compliance Engine (K8s)

### Milestone 7.1: CIS K8s 1.8 Framework

```sql
INSERT INTO compliance_frameworks (framework_id, name, version, provider, description) VALUES
('cis_k8s_1_8', 'CIS Kubernetes Benchmark', '1.8.0', 'k8s',
 'CIS security hardening guide for Kubernetes clusters'),
('nsa_k8s_hardening', 'NSA/CISA Kubernetes Hardening Guidance', '1.2', 'k8s',
 'NSA and CISA Kubernetes security hardening guide');
```

CIS K8s 1.8 sections:
- 1: Control Plane Components (API server, controller manager, scheduler, etcd)
- 2: Etcd (encryption, access control)
- 3: Control Plane Configuration (auth, TLS)
- 4: Worker Nodes (kubelet config, node hardening)
- 5: Policies (RBAC, network policies, pod security)

Note: For managed K8s (EKS, GKE, AKS), control plane checks (1-3) are CSP-responsibility.
Scanner focuses on node-level (4) and policy-level (5) checks.

---

## Phase 8 — API Layer

K8s-specific additions:
- `?provider=k8s&cluster=<cluster-name>` filter
- `?namespace=kube-system` — namespace-level filtering
- Resource display: K8s short names (Pod, Deployment, Service)

**K8s summary endpoint:**
```json
{
  "provider": "k8s",
  "cluster": "vulnerability-eks-cluster",
  "kubernetes_version": "1.29",
  "node_count": 5,
  "namespace_count": 12,
  "compliance_score": 71,
  "frameworks": [{"cis_k8s_1_8": {"score": 68, "controls_passed": 55}}],
  "critical_findings": ["cluster-admin binding to default SA", "3 privileged pods"]
}
```

---

## Phase 9 — BFF / UI

K8s-specific UI:
- **Namespace browser**: dropdown to filter by namespace
- **Workload view**: Deployment → ReplicaSet → Pod hierarchy
- **RBAC graph**: ClusterRoleBinding → ClusterRole → Namespace visualization
- **Node health**: node-level security posture
- **IAM page**: show K8s RBAC terminology (ClusterRole, ServiceAccount)
- **Network**: NetworkPolicy coverage map per namespace

---

## Multi-Cluster Support (Future)

This plan covers single-cluster scanning. Multi-cluster support:
- Each cluster is a separate `account_id` in the DB
- Argo workflow runs one scan per cluster
- Aggregated view: `SELECT * FROM check_findings WHERE provider='k8s'` (all clusters)
- Cluster management: onboarding engine stores kubeconfig per cluster in K8s secrets

---

## Milestone Order

M1: K8s provider directory + scanner code
M2: RBAC ClusterRole for scanner service account
M3: DB seed: relationships + classification + CIS K8s
M4: K8s check rules in rule_metadata
M5: Docker build (lightweight — kubernetes SDK only)
M6: E2E in-cluster discovery scan
M7: Inventory pipeline + K8s graph built
M8: Check engine run
M9: Threat + IAM + DataSec + Compliance
M10: API + BFF/UI

**Estimated effort:** 2-3 weeks (K8s SDK simpler than cloud SDKs; rules align to existing checks)