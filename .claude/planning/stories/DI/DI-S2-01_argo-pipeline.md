# DI-S2-01 — Argo Pipeline Update (Replace discovery+inventory with di Step)
**Sprint**: DI-S2 | **Points**: 5 | **Status**: Ready for Dev

## Goal
Replace the two Argo pipeline steps (`discovery` + `inventory`) with a single `di` step that
triggers engine-di. Update all downstream engine steps to `depends: "di"` instead of
`depends: "inventory"`.

## Files to Modify
- `deployment/aws/eks/argo/cspm-pipeline.yaml` — replace discovery + inventory steps with di
- `deployment/aws/eks/argo/cspm-templates-primitives.yaml` — add di template if primitives pattern used

## Current Argo DAG (relevant fragment)
```yaml
- name: discovery
  depends: "create-orchestration-record"
  http:
    url: "http://engine-discoveries.threat-engine-engines.svc.cluster.local/api/v1/discovery"
    method: POST
    timeoutSeconds: 7200
    body: '{"scan_run_id": "{{inputs.parameters.scan_run_id}}", ...}'

- name: inventory
  depends: "discovery"
  http:
    url: "http://engine-inventory.threat-engine-engines.svc.cluster.local/api/v1/inventory/scan"
    method: POST
    timeoutSeconds: 14400
    body: '{"scan_run_id": "{{inputs.parameters.scan_run_id}}", ...}'

- name: check
  depends: "inventory"
  ...

- name: threat
  depends: "inventory"
  ...
```

## New Argo DAG (relevant fragment)
```yaml
# REPLACE the discovery + inventory steps with:
- name: di
  depends: "create-orchestration-record"
  http:
    url: "http://engine-di.threat-engine-engines.svc.cluster.local/api/v1/di/scan"
    method: POST
    timeoutSeconds: 10800
    successCondition: "response.statusCode == 202"
    headers:
    - name: X-Internal-Secret
      value: "{{inputs.parameters.internal_secret}}"
    body: |
      {
        "scan_run_id": "{{inputs.parameters.scan_run_id}}",
        "orchestration_id": "{{inputs.parameters.orchestration_id}}"
      }

# ADD: poll step for DI scan completion
- name: di-wait
  depends: "di"
  http:
    url: "http://engine-di.threat-engine-engines.svc.cluster.local/api/v1/di/scan/{{inputs.parameters.scan_run_id}}/status"
    method: GET
    timeoutSeconds: 10800
    successCondition: "response.body contains \"completed\""
    retryStrategy:
      limit: 360
      retryPolicy: "Always"
      backoff:
        duration: "30s"
        factor: 1
    headers:
    - name: X-Internal-Secret
      value: "{{inputs.parameters.internal_secret}}"

# UPDATE all downstream steps: depends: "inventory" → depends: "di-wait"
- name: check
  depends: "di-wait"     # was: depends: "inventory"
  ...

- name: threat
  depends: "di-wait"     # was: depends: "inventory"
  ...

# (same for: iam, datasec, network-security, encryption, dbsec, cdr, container-sec, ai-security, api-security)
```

## Steps Requiring depends Update
Search `cspm-pipeline.yaml` for all steps with `depends: "inventory"` and update to `depends: "di-wait"`.
Also search for `depends: "discovery"` — if any step depends directly on discovery (not inventory), update to `depends: "di-wait"` as well.

## Parallel Run Period
During cutover (DI-S4-03), both old and new steps will temporarily coexist. To support this:
- Add `DI_PIPELINE_ENABLED: "false"` as an Argo parameter
- When `DI_PIPELINE_ENABLED=false`: run old `discovery` + `inventory` steps (skip `di` + `di-wait`)
- When `DI_PIPELINE_ENABLED=true`: run `di` + `di-wait` (skip `discovery` + `inventory`)
- Use Argo `when` conditions to implement this gate

```yaml
- name: di
  when: "{{inputs.parameters.di_pipeline_enabled}} == true"
  ...

- name: discovery
  when: "{{inputs.parameters.di_pipeline_enabled}} != true"
  ...
```

## Acceptance Criteria

### Functional
- [ ] `DI_PIPELINE_ENABLED=true`: Argo runs `di` + `di-wait`; skips `discovery` + `inventory`
- [ ] `DI_PIPELINE_ENABLED=false`: Argo runs `discovery` + `inventory`; skips `di` + `di-wait`
- [ ] All downstream steps (check, threat, iam, datasec, network, encryption, dbsec, cdr, container-sec, ai-security, api-security) updated to `depends: "di-wait"` (behind DI_PIPELINE_ENABLED gate)
- [ ] `di-wait` poll interval: 30s; max retries: 360 (3 hours total)
- [ ] Argo `kubectl apply` dry-run passes: `kubectl apply --dry-run=client -f cspm-pipeline.yaml`
- [ ] Pipeline DAG visualization shows `di → di-wait → [check, threat, iam, ...]`

### Security
- [ ] `X-Internal-Secret` header used for DI engine call (same as other Argo engine calls)
- [ ] No scan_run_id or orchestration_id in log output (Argo logs the full body — keep body minimal)

### Error Handling
- [ ] `di-wait` timeout (10800s) → step marked failed; downstream steps skipped
- [ ] `POST /api/v1/di/scan` returns non-202 → Argo `di` step marked failed
- [ ] Failed `di` step propagates failure to orchestration record (`scan_run_id` status = `failed`)

## Testing Requirements

**Dry-run validation**:
```bash
kubectl apply --dry-run=client -f deployment/aws/eks/argo/cspm-pipeline.yaml
# Expected: no errors

yamllint deployment/aws/eks/argo/cspm-pipeline.yaml
# Expected: no warnings
```

**Integration**: Submit a test Argo workflow with `DI_PIPELINE_ENABLED=true`; verify:
1. `di` step triggers engine-di scan
2. `di-wait` polls until completed
3. `check` step starts after `di-wait` completes

**Integration (legacy path)**: Submit with `DI_PIPELINE_ENABLED=false`; verify `discovery` + `inventory` steps run.

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start |
| Pipeline review | cspm-engine-orchestrator | merge (pipeline change affects all engines) |
| Security review | bmad-security-reviewer | merge |
| QA acceptance | cspm-qa | deploy |

## Definition of Done
- [ ] `cspm-pipeline.yaml` updated with `di` + `di-wait` steps behind `DI_PIPELINE_ENABLED` gate
- [ ] All downstream step `depends` updated (behind gate)
- [ ] `kubectl apply --dry-run=client` passes
- [ ] `DI_PIPELINE_ENABLED=true` pipeline run completes end-to-end on test account
- [ ] `DI_PIPELINE_ENABLED=false` (legacy) pipeline run unaffected
- [ ] MEMORY.md updated: Argo DAG changed — discovery+inventory replaced by di (behind flag)

## Dependencies
- DI-S1-06 (engine-di deployed and responding to POST /api/v1/di/scan)
- `X-Internal-Secret` in Argo workflow parameters (already set for other engines)

## Rollback
```bash
# Revert cspm-pipeline.yaml to previous commit
git checkout main -- deployment/aws/eks/argo/cspm-pipeline.yaml
kubectl apply -f deployment/aws/eks/argo/cspm-pipeline.yaml
```