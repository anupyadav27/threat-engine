# Story SF-P1-03: Wire Container Security Engine → security_findings

## Status: done

## Metadata
- **Phase**: P1 — Engine Writers
- **Epic**: Security Findings Unified Layer (sub-project of Attack Path Engine Epic)
- **Points**: 3
- **Priority**: P1
- **Depends on**: SF-P0-01 (table exists), SF-P0-02 (writer utility with 'container' in allowlist)
- **Runs alongside**: SF-P1-01, SF-P1-02 (same pattern, same scan hook)
- **Blocks**: SF-P3-01 (attack-path needs K8s violation evidence in findings_lookup), SF-P2-01 (BFF needs K8s data for asset findings endpoint)
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory — container findings include privileged workload data across all K8s providers (EKS/AKS/GKE/OKE/self-managed).

## User Story

As the security_findings layer, I want the container-security engine to write K8s violations, privileged workload findings, and image vulnerabilities as normalized rows into `security_findings` after its scan step completes, so that K8s security evidence is available as first-class findings alongside cloud misconfigs and CVEs.

## Context

The container-security engine covers all K8s providers — EKS (AWS), AKS (Azure), GKE (GCP), OKE (OCI), and self-managed K8s. It runs at pipeline stage 5 (parallel with IAM, network, datasec, vuln). Its findings split into two `finding_type` values:

- `k8s_violation` — RBAC misconfigs, privileged containers, host network pods, missing network policies, insecure pod security contexts
- `container_risk` — image vulnerabilities, unscanned images, images from untrusted registries

These appear in `attack_path_nodes.threat_detections` when K8s resources are on an attack path, and in the asset detail findings tab for K8s resources.

**K8s resource_uid format**: `k8s/{namespace}/{kind}/{name}` (e.g. `k8s/kube-system/daemonset/fluentd`). This is the same format used in Neo4j and inventory — no transformation needed.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [x] DE  [ ] RS  [ ] RC
DE.CM-1 (K8s workload misconfigs detected), PR.AC-4 (K8s RBAC violations recorded), ID.RA-5 (image CVEs in context)

**CSA CCM v4 Domain(s)**
- IVS-01, IAM-09, TVM-09, CCC-04

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | K8s detail JSONB | detail field contains pod spec with env vars (may include secrets) | detail JSONB stripped to: namespace, kind, name, rule_id only — NO raw pod spec or env var values |
| Info Disclosure | cross-cluster | Container engine writes findings without cluster_id scoping — findings from one K8s cluster appear for another | tenant_id + account_id (= cluster ID) always in WHERE; AC-13 verifies |
| DoS | image scan volume | Large cluster with 500 images → 500 container_risk rows per scan | Cap: max 200 container_risk rows per scan_run_id (highest severity first); batch upsert enforced |

## Acceptance Criteria

### Functional — k8s_violation findings
- [ ] AC-1: At the end of the container-security engine's scan handler, `upsert_findings()` called for all K8s violations from current scan_run_id
- [ ] AC-2: Each K8s violation maps to one FindingRow: `source_engine='container'`, `source_finding_id=container_sec_findings.finding_id`, `finding_type='k8s_violation'`, `severity` from container_sec_findings, `rule_id`, `title`, `resource_uid` in `k8s/{namespace}/{kind}/{name}` format, `provider` set to `'k8s'` (CSP-agnostic — not 'aws'/'azure' since this is the workload layer)
- [ ] AC-3: `detail` JSONB contains ONLY: `{'namespace': ..., 'kind': ..., 'name': ..., 'rule_id': ..., 'cluster_provider': 'eks'|'aks'|'gke'|'oke'|'self_managed'}` — NO raw pod spec, NO env var values, NO container image digests in the detail field
- [ ] AC-4: Write appended AFTER existing container_sec_findings inserts — no change to existing container-security behavior
- [ ] AC-5: `account_id` set to cluster_id (the managed K8s cluster resource UID) — this is the cross-tenant isolation boundary for K8s findings

### Functional — container_risk findings
- [ ] AC-6: Image vulnerability findings written as `finding_type='container_risk'`, `source_engine='container'`
- [ ] AC-7: Each image risk row: `rule_id=image_tag_or_digest[:32]`, `title=f"Unscanned image / CVE in {image_name}"`, `severity` from highest CVE severity on that image, `epss_score` and `cvss_score` if available from image scan
- [ ] AC-8: Cap enforced: max 200 `container_risk` rows per scan_run_id per tenant — if more, write the 200 highest-severity rows only (sort by severity_rank DESC before cap)
- [ ] AC-9: engine-container-sec builds new image tagged `v-container-sf1`

### Multi-CSP / Multi-Provider
- [ ] AC-10: Findings written for EKS clusters (provider=k8s, cluster_provider=eks), AKS (cluster_provider=aks), GKE (cluster_provider=gke), OKE (cluster_provider=oke), and self-managed (cluster_provider=self_managed) — no provider hardcoding
- [ ] AC-11: `resource_uid` always uses `k8s/{namespace}/{kind}/{name}` format regardless of which CSP hosts the cluster
- [ ] AC-12: `account_id` = managed cluster resource_uid (e.g. EKS cluster ARN, AKS cluster resource ID) — enables cross-tenant isolation at cluster level

### Integration
- [ ] AC-13: After a full pipeline scan: `SELECT COUNT(*) FROM security_findings WHERE source_engine='container' AND tenant_id='<tenant>'` returns > 0
- [ ] AC-14: `SELECT DISTINCT finding_type FROM security_findings WHERE source_engine='container'` returns 'k8s_violation' and 'container_risk'
- [ ] AC-15: `SELECT detail FROM security_findings WHERE source_engine='container' LIMIT 3` — no detail JSONB contains raw pod spec, env var values, or image digests longer than 32 chars

### Security (must pass bmad-security-reviewer)
- [ ] AC-16: detail JSONB does NOT contain raw pod spec or env var values (AC-3)
- [ ] AC-17: `upsert_findings()` called with `tenant_id` from scan auth context — not from K8s metadata
- [ ] AC-18: No DEV_BYPASS_AUTH in modified container engine files
- [ ] AC-19: `account_id` set to cluster_id, not namespace — namespace alone is NOT sufficient for tenant isolation (multiple tenants may share namespace names across clusters)

## Technical Notes

**FindingRow construction for k8s_violation:**
```python
from engine_common.security_findings_writer import upsert_findings, FindingRow

rows: list[FindingRow] = []
for f in k8s_violations:
    resource_uid = f"k8s/{f['namespace']}/{f['kind'].lower()}/{f['name']}"
    rows.append(FindingRow(
        source_finding_id=f["finding_id"],
        resource_uid=resource_uid,
        finding_type="k8s_violation",
        severity=f["severity"],
        rule_id=f["rule_id"],
        title=f["title"],
        account_id=cluster_id,   # managed cluster resource UID
        provider="k8s",
        resource_type=f["kind"].lower(),
        detail={
            "namespace": f["namespace"],
            "kind": f["kind"],
            "name": f["name"],
            "rule_id": f["rule_id"],
            "cluster_provider": cluster_provider,  # eks|aks|gke|oke|self_managed
        },
    ))
upsert_findings(conn=inventory_conn, findings=rows,
                source_engine="container", tenant_id=tenant_id,
                scan_run_id=scan_run_id)
```

**New image tag**: `yadavanup84/engine-container-sec:v-container-sf1`

**Inventory DB connection**: Container-security engine needs `INVENTORY_DB_*` env vars added to K8s manifest (same ConfigMap/secret as other engines).

## Key Files
- Container-security engine `run_scan.py` (modify — add security_findings write at end)
- `deployment/aws/eks/engines/engine-container-sec.yaml` (add INVENTORY_DB_* env, update image tag)

## Definition of Done
- [ ] Container-security engine `run_scan.py` modified and committed
- [ ] Docker image built and pushed: `v-container-sf1`
- [ ] K8s manifest updated
- [ ] kubectl rollout clean
- [ ] After scan: security_findings has 'container' rows with k8s_violation + container_risk finding_types
- [ ] AC-15 verified: detail JSONB contains only allowed fields
- [ ] MEMORY.md updated for container-sec image tag
- [ ] bmad-security-reviewer: no BLOCKERS