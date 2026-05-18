# JNY-04: Build & push frontend, gateway, threat, inventory, backend images; rollout

## Track
Investigation Journey Unification — Phase A

## Priority
P1 — Working-tree code from prior journey sprint is undeployed; prevents any A/B/C verification (G-32, G-33).

## Status
done — api-gateway→v-bff-technique1 (JNY-01 BFF route), cspm-backend→v-jny03-1 (migrations 0015-0018); engine-threat/inventory/frontend had no Phase A code changes; all deployed and healthy

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | — | — |
| UI / BFF / Gateway dev | `cspm-deploy` | R |
| Security architect (design) | — | — |
| Security reviewer (code) | — + `bmad-security-reviewer` | — |
| BMad lead | — | — |
| QA | `cspm-integration-tester` | R |
| Standards | — | — |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
CP-4 (pre-deploy gate, D27) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Per ADR §2.2 G-32 and G-33, the working tree contains the previously-shipped journey BFF handlers (`asset_context.py`, `ciem_identity.py`, `technique_detail.py`) and frontend pages, but the deployed `cspm-frontend` and `api-gateway` images still point at `v-frontend-journey1` / `v-gateway-journey1`. This story rebuilds and rolls out everything Phase A produced (JNY-01..03) plus the prior unshipped working-tree code.

## What to build
Image tag plan (per Sprint §8):

| Image | Current | New tag |
|---|---|---|
| cspm-frontend | `v-frontend-journey1` | `v-frontend-jny-sprint` |
| api-gateway | `v-gateway-journey1` | `v-gateway-jny-sprint` |
| engine-threat | `v-di-sprint3` | `v-threat-jny-mitre-ref` |
| engine-inventory | `v-inventory-auth` | `v-inventory-jny-blast-radius` |
| cspm-backend | `v-di-sprint3` | `v-backend-jny-ciem-perm` |

Rollout sequence:
1. Build + push each image from repo root with the engine's Dockerfile.
2. Update K8s manifests under `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/*.yaml` and the frontend/gateway manifests to the new tags.
3. `kubectl apply -f` and `kubectl rollout status` each.
4. Tail logs for 5 min looking for startup errors.
5. Run `cspm-scan-status` against the latest scan_run_id to confirm no regressions.
6. Update `MEMORY.md` image tag table per `feedback_doc_update_after_sprint`.

## Acceptance criteria
- [ ] All 5 images built locally (no CI dependency); SHAs recorded
- [ ] All 5 pushed to `yadavanup84/...` registry
- [ ] All 5 K8s manifests updated and committed
- [ ] `kubectl rollout status` returns "successfully rolled out" for each deployment in `threat-engine-engines` and `threat-engine` namespaces
- [ ] `kubectl logs` shows no `ImagePullBackOff`, no startup exceptions for 5 minutes post-rollout
- [ ] Live test: `/inventory/[uid]` Blast Radius tab returns 200 (validates JNY-02 deployed)
- [ ] Live test: TechniqueDetailModal opens (validates JNY-01 deployed)
- [ ] Live test: Inventory Asset CIEM tab returns 200 for admin (validates JNY-03 deployed)
- [ ] `MEMORY.md` image tag table updated

## Dependencies
- Blocks: every story in Phase B/C/D/E/F (per Sprint §3 Hard rules)
- Blocked by: JNY-01, JNY-02, JNY-03

## Constitution check
- Image tags pinned (no `:latest`).
- Rollout zero-downtime (rollingUpdate strategy verified).
- Standard 6-step deploy; no kubectl delete + recreate.

## Out of scope
- Helm chart conversion.
- New namespace creation.
- Resource limit retuning.

## Files touched (estimate)
- `deployment/aws/eks/engines/engine-threat.yaml` — image tag
- `deployment/aws/eks/engines/engine-inventory.yaml` — image tag
- `deployment/aws/eks/frontend/cspm-frontend.yaml` — image tag
- `deployment/aws/eks/gateway/api-gateway.yaml` — image tag
- `deployment/aws/eks/backend/cspm-backend.yaml` — image tag
- `.claude/projects/-Users-apple-Desktop-threat-engine/memory/MEMORY.md` — image tag table

## Test plan
- Unit: each image runs locally via `docker run -it ... /bin/bash` and exits cleanly on `--help`
- Smoke: `kubectl get pods -n threat-engine-engines | grep -v Running` returns nothing
- BFF contract: hit each Phase A endpoint and assert 200
- Integration: `/cspm-scan-trigger` then `/cspm-scan-status` clean run
- Security: `cspm-security-reviewer` confirms no debug endpoint exposed in new images
