# Story PC-P1-03: Container Security Engine — Write Posture Signals to resource_security_posture

## Status: done

## Metadata
- **Phase**: P1 — Tier A (data available in check_findings today)
- **Sprint**: Posture Coverage Enhancement
- **Points**: 3
- **Priority**: P1
- **Depends on**: PC-P0-01 (new container columns must exist in posture table)
- **Blocks**: PC-P1-07 (composite flags), attack-path K8s traversal edges
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer

## Gap Being Closed

**Current state:** Container security engine produces `container_sec_findings` but has zero posture columns in `resource_security_posture`. The attack-path engine cannot determine if a traversal step lands on a privileged container or an image with a critical CVE. Crown jewel classifier cannot tag K8s API servers.

**Why Tier A:** `container_sec_findings` + `check_findings` (where `rule_metadata.container_security.applicable=true`) already exist. The signals below are derivable purely from `rule_id` pattern matching on existing findings — no new external API calls.

## Data Sources

```
threat_engine_container_sec DB → container_sec_findings
  Fields: resource_uid, resource_type, rule_id, status, severity, finding_data

threat_engine_check DB → check_findings (container rules)
  WHERE rule_metadata->'container_security'->>'applicable' = 'true'
  Fields: resource_uid, rule_id, status, finding_data
```

## Signals to Write (new columns from PC-P0-01)

| Column | Source Logic |
|--------|-------------|
| `has_privileged_container` | `status=FAIL` for `rule_id` matching `privileged\|host_pid\|host_network\|root` |
| `image_has_critical_cve` | `severity='critical'` AND `status=FAIL` for rules matching `cve\|image_scan\|vulnerability` |
| `k8s_rbac_overpermissive` | `status=FAIL` for rules matching `rbac\|cluster_admin\|wildcard_verb\|all_resources` |
| `container_network_policy_missing` | `status=FAIL` for rules matching `network_policy\|pod_network\|egress\|ingress_policy` |
| `container_security_score` | `100 - (fail_count / total_count * 100)` clamped to 0-100; per resource |

## Implementation

**New file:** `engines/container-security/container_security_engine/posture_signals.py`

Pattern: identical to `iam_engine/posture_signals.py` — one aggregate query, one batch upsert.

**Wire into scan:** End of `engines/container-security/run_scan.py`.

**DB connections:** Read from `get_container_conn()` + `get_check_conn()`. Write to `get_inventory_conn()`.

## Acceptance Criteria

- [ ] AC-1: After container scan, EKS nodes and pods have posture rows with container columns populated
- [ ] AC-2: `has_privileged_container=TRUE` for pods running with `privileged: true` (verify against known test pod)
- [ ] AC-3: `k8s_rbac_overpermissive=TRUE` for ServiceAccounts with ClusterAdmin binding (rule FAIL)
- [ ] AC-4: `container_security_score` is between 0–100 for all container resources
- [ ] AC-5: `container_network_policy_missing=TRUE` for namespaces with no NetworkPolicy resource
- [ ] AC-6: Non-fatal pattern — scan completes even if inventory DB unreachable
- [ ] AC-7: New image: `yadavanup84/engine-container-sec:v-container-posture1`

## Definition of Done
- [ ] PC-P0-01 migration applied (columns exist)
- [ ] `posture_signals.py` written and wired
- [ ] Post-deploy verification: container posture columns populated for real scan