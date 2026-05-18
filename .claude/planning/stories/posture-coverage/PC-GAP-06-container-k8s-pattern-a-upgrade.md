# Story PC-GAP-06: Container Security Engine — K8s Pattern B → Pattern A

## Status: done

## Metadata
- **Phase**: CSP Coverage Track — Provider Pattern Upgrade
- **Sprint**: Posture Coverage Enhancement
- **Points**: 5
- **Priority**: P2 — Medium ROI
- **Depends on**: PC-P1-03 (Container posture writer), PC-P0-01 (migration 024 new columns)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-architect + bmad-security-reviewer (K8s runtime context is high-sensitivity)

## Gap Being Closed

The Container Security engine is **Pattern B** for all CSPs including K8s. For K8s specifically, this is the most impactful gap because:

1. K8s has 802 container check rules (largest of any CSP) but no workload-level analysis from actual Pod specs
2. Pattern B only loads discovery services — it does NOT read Pod `securityContext`, image digests, or namespace labels
3. `has_privileged_container`, `image_has_critical_cve`, `k8s_rbac_overpermissive`, `container_network_policy_missing` columns in `resource_security_posture` are NEVER populated (always null)

**K8s is upgraded first because it's the richest container data source — AWS/Azure/GCP CSP upgrades follow in separate stories.**

## Current State

```python
# engines/container-security/container_security_engine/providers/k8s.py
class K8sContainerProvider(BaseContainerProvider):
    @property
    def discovery_services(self):
        return ["k8s.core.list_pods_for_all_namespaces",
                "k8s.apps.list_deployments_for_all_namespaces",
                "k8s.apps.list_daemon_sets_for_all_namespaces",
                "k8s.apps.list_stateful_sets_for_all_namespaces",
                ...
               ]
    # NO analyze() method — Pattern B only
```

## Pattern Migration (same approach as PC-GAP-05)

Add `analyze()` to `BaseContainerProvider` returning `None` by default. `K8sContainerProvider` overrides it with full implementation. `run_scan.py` falls back to Pattern B for non-K8s providers.

---

## K8s Container Analysis Modules

### Module 1 — Pod Security Context (most critical)

**Discovery IDs:**
- `k8s.core.list_pods_for_all_namespaces` — full Pod spec including `spec.securityContext` and `spec.containers[].securityContext`

**Findings to generate:**

| Rule ID | Severity | Check | Posture signal |
|---------|---------|-------|----------------|
| `k8s.pod.container.not_privileged` | CRITICAL | `securityContext.privileged != true` | `has_privileged_container=True` |
| `k8s.pod.container.no_allow_privilege_escalation` | HIGH | `allowPrivilegeEscalation != true` | `has_privileged_container=True` |
| `k8s.pod.container.read_only_root_filesystem` | HIGH | `readOnlyRootFilesystem=true` | — |
| `k8s.pod.container.run_as_non_root` | HIGH | `runAsNonRoot=true` OR `runAsUser > 0` | — |
| `k8s.pod.container.capabilities_dropped` | MEDIUM | `securityContext.capabilities.drop` includes `ALL` | — |
| `k8s.pod.container.no_root_uid` | CRITICAL | `runAsUser != 0` | — |
| `k8s.pod.no_host_network` | CRITICAL | `spec.hostNetwork != true` | — |
| `k8s.pod.no_host_pid` | HIGH | `spec.hostPID != true` | — |
| `k8s.pod.no_host_ipc` | HIGH | `spec.hostIPC != true` | — |

### Module 2 — Image Security

**Discovery IDs:**
- `k8s.core.list_pods_for_all_namespaces` — `spec.containers[].image` field
- `k8s.apps.list_deployments_for_all_namespaces` — deployment image references

**Findings to generate:**

| Rule ID | Severity | Check | Posture signal |
|---------|---------|-------|----------------|
| `k8s.pod.container.image_digest_pinned` | HIGH | Image reference uses `@sha256:` digest (not mutable tag) | — |
| `k8s.pod.container.image_not_latest_tag` | HIGH | Image tag is not `:latest` or `:` (no tag) | — |
| `k8s.pod.container.image_from_approved_registry` | MEDIUM | Image registry is in allowlist (not arbitrary Docker Hub) | — |

**Image digest check logic:**
```python
image = "nginx:latest"             # FAIL — mutable tag
image = "nginx@sha256:abc123..."   # PASS — pinned digest
image = "nginx:1.25.3"            # WARN — semantic tag (mutable)
```

### Module 3 — RBAC Over-Permission per Workload

**Discovery IDs:**
- `k8s.rbac.list_role_bindings_for_all_namespaces`
- `k8s.rbac.list_cluster_role_bindings`
- `k8s.rbac.list_cluster_roles`
- `k8s.core.list_service_accounts_for_all_namespaces`
- `k8s.core.list_pods_for_all_namespaces` — `spec.serviceAccountName`

**Cross-reference logic:**
```
Pod → serviceAccountName → ServiceAccount → RoleBinding → Role/ClusterRole → rules
```
For each Pod: resolve the full RBAC chain and check if the effective permissions include:
- `verbs: ["*"]` → wildcard verb
- `resources: ["*"]` → wildcard resource
- `pods/exec` → interactive shell access
- `secrets` get/list → credential access

**Findings:**

| Rule ID | Severity | Check | Posture signal |
|---------|---------|-------|----------------|
| `k8s.pod.service_account.no_wildcard_permissions` | CRITICAL | Pod's SA has no `*` verbs or `*` resources | `k8s_rbac_overpermissive=True` |
| `k8s.pod.service_account.no_exec_permission` | HIGH | Pod's SA cannot `pods/exec` | `k8s_rbac_overpermissive=True` |
| `k8s.pod.service_account.no_secrets_list` | HIGH | Pod's SA cannot list all secrets | `k8s_rbac_overpermissive=True` |
| `k8s.pod.service_account.automount_disabled` | MEDIUM | `automountServiceAccountToken=false` unless required | — |

### Module 4 — Network Policy Coverage

**Discovery IDs:**
- `k8s.networking.list_network_policies_for_all_namespaces`
- `k8s.core.list_pods_for_all_namespaces` — `metadata.namespace`, `metadata.labels`

**Coverage logic:**
For each Pod, check if at least one NetworkPolicy in the same namespace selects it via `podSelector`. Also check if the namespace has a default-deny policy.

**Findings:**

| Rule ID | Severity | Check | Posture signal |
|---------|---------|-------|----------------|
| `k8s.pod.has_network_policy` | HIGH | Pod is selected by ≥ 1 NetworkPolicy | `container_network_policy_missing=True` |
| `k8s.namespace.default_deny_policy` | CRITICAL | Namespace has a default-deny NetworkPolicy | `container_network_policy_missing=True` |

### Module 5 — Resource Limits

**Discovery IDs:**
- `k8s.core.list_pods_for_all_namespaces` — `spec.containers[].resources.limits`

**Findings:**

| Rule ID | Severity | Check |
|---------|---------|-------|
| `k8s.pod.container.cpu_limit_set` | MEDIUM | `resources.limits.cpu` present |
| `k8s.pod.container.memory_limit_set` | HIGH | `resources.limits.memory` present — prevents OOM-based noisy neighbor |
| `k8s.pod.container.no_unlimited_resources` | HIGH | Neither CPU nor memory is unlimited |

---

## Posture Signals Written

After this story, the container posture writer (PC-P1-03) will have actual data to populate:

| Column | Source in analyze() |
|--------|-------------------|
| `has_privileged_container` | Module 1: privileged/allowPrivilegeEscalation findings |
| `image_has_critical_cve` | Not from this story — from vulnerability engine cross-ref |
| `k8s_rbac_overpermissive` | Module 3: SA wildcard/exec/secrets permissions |
| `container_network_policy_missing` | Module 4: Pod without NetworkPolicy coverage |
| `container_security_score` | Computed: 100 - (penalty per finding severity) |

## run_scan.py Changes

```python
provider = get_provider(provider_name)
findings = provider.analyze(scan_run_id, tenant_id, account_id)  # None for non-K8s
if findings is None:
    # Pattern B fallback for AWS/Azure/GCP/OCI/AliCloud/IBM
    resources = disc_reader.load_all_container_resources(services=provider.discovery_services)
    findings = _pattern_b_analyze(resources, ...)
save_container_findings(findings)
write_container_posture_signals(scan_run_id, tenant_id, account_id, provider_name)
```

## Acceptance Criteria

- [ ] AC-1: `K8sContainerProvider.analyze()` returns a non-None list (Pattern A active for K8s)
- [ ] AC-2: `has_privileged_container=True` written to `resource_security_posture` for K8s pods with `securityContext.privileged=true`
- [ ] AC-3: `k8s_rbac_overpermissive=True` written for pods whose ServiceAccount has wildcard verbs
- [ ] AC-4: `container_network_policy_missing=True` written for pods in namespaces without a NetworkPolicy
- [ ] AC-5: Image digest pinning check fires: `:latest` tag → HIGH finding
- [ ] AC-6: `container_security_score` populated (0–100 integer) for K8s pod resources
- [ ] AC-7: AWS/Azure/GCP/OCI container scanning still works (Pattern B fallback — no regression)
- [ ] AC-8: After K8s scan: `SELECT has_privileged_container, k8s_rbac_overpermissive, container_network_policy_missing FROM resource_security_posture WHERE provider='k8s' LIMIT 10` shows populated values

## MITRE ATT&CK (Containers Matrix)
| Technique | Addressed by |
|-----------|-------------|
| T1610 | Deploy Container — privileged container detection |
| T1611 | Escape to Host — hostNetwork/hostPID/hostIPC detection |
| T1613 | Container and Resource Discovery — RBAC wildcard prevents enumeration |
| T1552.007 | Obtain Credentials: Container API — ServiceAccount automount detection |
| T1525 | Implant Internal Image — image digest pinning enforces immutability |

## Definition of Done
- [ ] `K8sContainerProvider.analyze()` implemented (5 modules: security context, image, RBAC, NetworkPolicy, resource limits)
- [ ] `BaseContainerProvider.analyze()` returns `None` by default (Pattern B fallback)
- [ ] `run_scan.py` updated to check for `None` before Pattern B fallback
- [ ] Unit tests in `tests/unit/container/test_k8s_container_provider.py`
- [ ] Container security engine rebuilt and deployed
- [ ] After K8s scan: `resource_security_posture` has `has_privileged_container`, `k8s_rbac_overpermissive`, `container_network_policy_missing` populated