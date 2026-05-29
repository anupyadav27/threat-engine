# DI-S2-05 — DI_ENGINE_ENABLED Feature Flag (All 16 Downstream Engine Manifests)
**Sprint**: DI-S2 | **Points**: 5 | **Status**: Ready for Dev

## Goal
Add `DI_ENGINE_ENABLED=false` + `DI_DB_*` env vars to all 16 downstream engine K8s manifests.
The flag starts as `false` (no behaviour change). DI-S3 stories flip per-engine reader code to
use `asset_inventory` when the flag is `true`. DI-S4-03 (cutover) flips all to `true`.

## Files to Modify (16 manifests)
```
deployment/aws/eks/engines/
├── engine-check.yaml
├── engine-iam.yaml
├── engine-network-security.yaml
├── engine-datasec.yaml
├── engine-encryption.yaml         (also remove INVENTORY_DB_* block)
├── engine-dbsec.yaml
├── engine-ai-security.yaml
├── engine-api-security.yaml
├── engine-container-sec.yaml
├── engine-attack-path.yaml
├── engine-threat-v1.yaml
├── engine-cdr.yaml
├── engine-risk.yaml
├── engine-pipeline-monitor.yaml
├── engine-threat-narrative.yaml
└── log-collector.yaml (+ log-collector-worker.yaml = 2 files)
```

Plus:
- `deployment/aws/eks/configmaps/threat-engine-db-config.yaml` — add `DI_DB_HOST`, `DI_DB_PORT`, `DI_DB_NAME`, `DI_DB_USER` keys

## Standard Env Block to Add to Each Manifest

```yaml
# Add to every engine's env: section
- name: DI_ENGINE_ENABLED
  value: "false"                    # fliped to "true" in DI-S4-03 cutover
- name: DI_DB_HOST
  valueFrom:
    configMapKeyRef:
      name: threat-engine-db-config
      key: DI_DB_HOST
- name: DI_DB_PORT
  value: "5432"
- name: DI_DB_NAME
  value: threat_engine_di
- name: DI_DB_USER
  value: postgres
- name: DI_DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: threat-engine-db-passwords
      key: DI_DB_PASSWORD
```

## ConfigMap Update (`threat-engine-db-config.yaml`)
```yaml
# Add these keys:
DI_DB_HOST: "postgres-vulnerability-db.cbm92xowvx2t.ap-south-1.rds.amazonaws.com"
DI_DB_PORT: "5432"
DI_DB_NAME: "threat_engine_di"
DI_DB_USER: "postgres"
```

## Secret Update (`threat-engine-db-passwords`)
```bash
# Add DI_DB_PASSWORD key (if threat_engine_di uses the same password as other DBs):
kubectl patch secret threat-engine-db-passwords -n threat-engine-engines \
  --type=merge --patch='{"stringData":{"DI_DB_PASSWORD":"<same-postgres-password>"}}'
```

## Implementation Notes

**VSCode YAML linter warning**: The VSCode YAML linter silently reverts image tag changes in
K8s manifests. After editing 16 files, verify each manifest still has the correct image tag.
If the linter reverted any, use `kubectl set image deployment/<engine> <c>=<tag>` to fix.

**Batch apply**: After all 16 manifests are updated:
```bash
kubectl apply -f deployment/aws/eks/engines/ -n threat-engine-engines
```
This applies all manifests in the directory. Monitor with:
```bash
kubectl get deployments -n threat-engine-engines -w
```

**DI_ENGINE_ENABLED=false initially**: This change adds the env vars but leaves all behaviour
unchanged. Reader code changes happen in DI-S3-01 through DI-S3-07. Cutover happens in DI-S4-03.

**Engine-encryption special case**: Replace existing `DISCOVERIES_DB_*` and `INVENTORY_DB_*`
blocks with the `DI_DB_*` block only — encryption engine already reads from both and the DI path
replaces both connections. Adding DI_DB_* while leaving DISCOVERIES_DB_* + INVENTORY_DB_* would
create 3 DB connection configs. Clean up by removing the old blocks.

## Acceptance Criteria

### Functional
- [ ] All 16 manifests (+ 2 log-collector manifests = 18 files) have `DI_ENGINE_ENABLED=false`
- [ ] All 16 manifests have `DI_DB_HOST/PORT/NAME/USER/PASSWORD` env block
- [ ] ConfigMap has `DI_DB_HOST/PORT/NAME/USER` keys
- [ ] Secret has `DI_DB_PASSWORD` key
- [ ] `kubectl apply` on all 16 manifests produces no errors
- [ ] `kubectl rollout status` passes for all 16 deployments after apply
- [ ] All engines still function identically with `DI_ENGINE_ENABLED=false` (no behaviour change)
- [ ] Health checks green for all 16 engines after manifest update

### Security
- [ ] `DI_DB_PASSWORD` from Secret only (not ConfigMap)
- [ ] No image tags reverted by VSCode YAML linter (verified via pod image check)
- [ ] `DI_ENGINE_ENABLED` is a string `"false"` not a boolean `false` (YAML boolean parsing edge case)

### Error Handling
- [ ] Each engine reads `DI_ENGINE_ENABLED` with `os.getenv("DI_ENGINE_ENABLED", "false").lower() == "true"` — startup does NOT fail if the env var is absent

## Testing Requirements

**Validation** (after apply):
```bash
# Verify DI_ENGINE_ENABLED=false in all running pods
for engine in engine-check engine-iam engine-network-security engine-datasec \
  engine-encryption engine-dbsec engine-ai-security engine-api-security \
  engine-container-sec engine-attack-path engine-threat-v1 engine-cdr \
  engine-risk engine-pipeline-monitor engine-threat-narrative; do
  echo "=== $engine ==="
  kubectl exec -n threat-engine-engines deployment/$engine -- \
    python3 -c "import os; print('DI_ENGINE_ENABLED:', os.getenv('DI_ENGINE_ENABLED', 'NOT_SET'))"
done
# Expected: DI_ENGINE_ENABLED: false for all 16
```

**Regression**: Trigger a full pipeline scan with `DI_PIPELINE_ENABLED=false` (uses old
discovery+inventory engines). Confirm check findings count within 2% of previous baseline.

## Review Gates
| Gate | Agent | Blocks |
|------|-------|--------|
| Pre-dev | bmad-sm | dev start (16-file change — confirm all file paths before starting) |
| QA acceptance | cspm-qa | deploy |
| Post-deploy | cspm-post-deploy | close (run regression pipeline scan) |

## Definition of Done
- [ ] 18 manifest files updated (16 engines + 2 log-collector)
- [ ] ConfigMap updated with DI_DB_* keys
- [ ] Secret updated with DI_DB_PASSWORD
- [ ] All 16 deployments rollout successfully
- [ ] `DI_ENGINE_ENABLED: false` verified in all 16 running pods
- [ ] Regression pipeline scan within 2% of baseline
- [ ] MEMORY.md updated: DI_ENGINE_ENABLED=false added to all 16 downstream engine manifests

## Dependencies
- DI-S1-01 (`threat_engine_di` DB exists on RDS — needed for Secret/ConfigMap values to be real)
- DI-S1-06 (engine-di manifest exists to confirm DI_DB_HOST/PORT values)

## Rollback
Remove `DI_ENGINE_ENABLED`, `DI_DB_*` env blocks from all manifests; redeploy.
Since `DI_ENGINE_ENABLED=false`, removing these vars has zero impact on engine behaviour.