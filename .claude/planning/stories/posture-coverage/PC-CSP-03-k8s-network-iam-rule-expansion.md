# Story PC-CSP-03: K8s — Network (7 rules) + IAM (5 rules) Rule Expansion

## Status: done

## Metadata
- **Phase**: CSP Coverage Track
- **Sprint**: Posture Coverage Enhancement
- **Points**: 5
- **Priority**: P2
- **Depends on**: PC-CSP-00 (gap baseline), PC-P2-03 (K8s L2 topology deferred status)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-po + bmad-security-reviewer

## Gap Being Closed

**Coverage matrix shows:** K8s `network=7 rules` (vs AWS 454), K8s `iam=5 rules` (vs OCI 28).

K8s has the richest container rule set (802 rules) but almost no network isolation or IAM rules. These are not niche concerns — K8s network policy violations and overpermissive RBAC are the top two K8s attack vectors (MITRE ATT&CK containers matrix).

## K8s Network Rules (expand from 7 to ~30)

**Current 7 rules:** Basic NetworkPolicy existence checks.

**Missing (high-impact):**

| Rule ID | Layer | Check | Severity |
|---------|-------|-------|---------|
| `k8s.namespace.default_deny_ingress_policy` | L3 ACL | Namespace has a default-deny NetworkPolicy | critical |
| `k8s.namespace.default_deny_egress_policy` | L3 ACL | Namespace has egress default-deny policy | high |
| `k8s.service.type_nodeport_not_used` | L5 LB | No Service of type NodePort (use LB or Ingress instead) | medium |
| `k8s.service.loadbalancer_source_ranges_restricted` | L5 LB | LoadBalancer.spec.loadBalancerSourceRanges not 0.0.0.0/0 | high |
| `k8s.ingress.tls_configured` | L5 LB | Ingress resource has TLS spec configured | high |
| `k8s.ingress.class_annotation_present` | L6 WAF | Ingress uses named controller class (not default) | medium |
| `k8s.pod.host_network_not_used` | L1 Isolation | Pod spec.hostNetwork != true | critical |
| `k8s.pod.host_port_not_used` | L1 Isolation | Container.ports[].hostPort not set | high |
| `k8s.networkpolicy.covers_all_pods_in_namespace` | L3 ACL | Every pod matched by at least one NetworkPolicy | high |
| `k8s.namespace.no_pods_without_network_policy` | L3 ACL | No pods exist in namespace without any NetworkPolicy match | critical |
| `k8s.service.cluster_ip_not_exposed_externally` | L4 Firewall | ClusterIP services not exposed via NodePort or LB | medium |
| `k8s.pod.no_host_ipc` | L1 Isolation | Pod spec.hostIPC != true | high |
| `k8s.pod.no_host_pid` | L1 Isolation | Pod spec.hostPID != true | high |

**Mapped to 7-layer model:**
- L1 (Isolation): host_network, host_ipc, host_pid checks
- L3 (ACL): default-deny NetworkPolicy coverage
- L4 (Firewall): NetworkPolicy port-level checks
- L5 (LB): NodePort/LoadBalancer exposure + TLS
- L6 (WAF): Ingress class + ModSecurity annotations

These rules feed both the network engine (L1 check findings) AND the K8s L2 topology provider (PC-P2-03) when it's implemented.

## K8s IAM Rules (expand from 5 to ~20)

K8s IAM = RBAC. Current 5 rules check basic ClusterAdmin binding. Missing:

| Rule ID | Category | Check | Severity |
|---------|----------|-------|---------|
| `k8s.clusterrolebinding.no_anonymous_subjects` | Access Control | system:anonymous and system:unauthenticated not in any ClusterRoleBinding | critical |
| `k8s.clusterrole.no_wildcard_verbs` | Least Privilege | ClusterRole verbs not `["*"]` | critical |
| `k8s.clusterrole.no_wildcard_resources` | Least Privilege | ClusterRole resources not `["*"]` | high |
| `k8s.serviceaccount.not_default` | Credential Hygiene | Pods do not use `default` ServiceAccount | high |
| `k8s.serviceaccount.automount_disabled` | Least Privilege | ServiceAccount automountServiceAccountToken = false (unless needed) | medium |
| `k8s.pod.service_account_token_not_automounted` | Least Privilege | Pod spec.automountServiceAccountToken = false | medium |
| `k8s.role.no_get_secrets_in_kube_system` | Access Control | No Role/ClusterRole grants `get/list secrets` in kube-system namespace | critical |
| `k8s.rolebinding.no_system_masters_group` | Access Control | No RoleBinding grants system:masters group membership | critical |
| `k8s.pod.no_exec_into_pods` | Access Control | RBAC: no Role grants `pods/exec` to non-admin subjects | high |
| `k8s.serviceaccount.least_privilege_scoped` | Least Privilege | ServiceAccount bound only to namespace-scoped Role (not ClusterRole) | medium |
| `k8s.pod.projected_service_account_token` | Credential Hygiene | Pod uses projected ServiceAccount token (not legacy long-lived) | medium |
| `k8s.admission_controller.pod_security_admission_enforced` | Access Control | Namespace has pod-security.kubernetes.io/enforce label | high |

## Discovery Dependencies

| Discovery ID | Status |
|-------------|--------|
| `k8s.rbac.list_cluster_role_bindings` | ✅ Likely exists |
| `k8s.rbac.list_cluster_roles` | ✅ Likely exists |
| `k8s.rbac.list_role_bindings_for_all_namespaces` | ✅ Likely exists |
| `k8s.core.list_service_accounts_for_all_namespaces` | ✅ Likely exists |
| `k8s.networking.list_ingresses_for_all_namespaces` | ✅ Likely exists |
| `k8s.networking.list_network_policies_for_all_namespaces` | ✅ Likely exists |

All required K8s discovery IDs are standard core/networking resources — all exist in the discovery generator data.

## rule_metadata Tags

**Network rules:**
```yaml
rule_metadata:
  network_security:
    applicable: true
    layer: "L3"  # L1/L3/L4/L5/L6 as applicable
  engine: "network-security"
```

**IAM rules:**
```yaml
rule_metadata:
  iam_security:
    applicable: true
    category: "rbac"  # rbac / credential_hygiene / least_privilege / access_control
  engine: "iam"
```

## Acceptance Criteria

- [ ] AC-1: K8s network rule count in `catalog/rule/k8s_rule_check/` grows from 7 to ≥ 25
- [ ] AC-2: K8s IAM rule count grows from 5 to ≥ 18
- [ ] AC-3: `k8s.clusterrolebinding.no_anonymous_subjects` rule produces FAIL for clusters that have `system:anonymous` in any ClusterRoleBinding (verify against EKS cluster)
- [ ] AC-4: `k8s.namespace.default_deny_ingress_policy` fires for namespaces without a default-deny NetworkPolicy
- [ ] AC-5: IAM engine `posture_signals.py` picks up K8s IAM findings and writes `role_has_wildcard_policy=TRUE` for ClusterRoles with wildcard verbs
- [ ] AC-6: Coverage matrix shows K8s network ≥ 25 and K8s IAM ≥ 18
- [ ] AC-7: Rules uploaded to DB via `upload_rule_metadata_all_csps.py`

## MITRE ATT&CK (K8s Container Matrix)
| Technique | Addressed by |
|-----------|-------------|
| T1610 | Deploy Container — RBAC rules limit who can create pods/containers |
| T1613 | Container and Resource Discovery — anonymous access rule prevents unauthenticated enumeration |
| T1611 | Escape to Host — host_network/host_pid/host_ipc rules |
| T1552.007 | Obtain Credentials: Container API — ServiceAccount automount rules |

## Definition of Done
- [ ] All K8s network + IAM YAML rule files committed
- [ ] Rules uploaded to check DB
- [ ] After K8s scan: `SELECT rule_id, COUNT(*) FROM check_findings WHERE provider='k8s' AND rule_id ILIKE '%network%' GROUP BY rule_id LIMIT 10` shows new rules producing findings
