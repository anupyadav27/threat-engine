# Story AP-P0-03: Wire Existing Engines to Write Posture Signals

## Status: ready

## Metadata
- **Phase**: P0 — Foundation (data plumbing)
- **Epic**: Attack Path Engine
- **Points**: 5
- **Priority**: P0
- **Depends on**: AP-P0-01 (table exists), AP-P0-02 (posture_writer utility exists)
- **Blocks**: AP-P2-03 (BFS scorer needs posture signals populated), AP-P2-04, AP-P3-02
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer must sign off. Security gate required because this touches 4 engine codebases and their DB write paths.

## User Story

As the attack path engine, I want the IAM, network-security, datasec, and CDR engines to each write their posture signals into `resource_security_posture` after completing their scan step, so that by the time graph-build finishes (pipeline stage 6), every resource has its full security posture pre-computed and I can read it without calling other engines at traversal time.

## Context

The attack-path engine runs at pipeline stage 6.5, after all stage-5 engines (IAM, network, datasec, CDR) have completed. For the P×I scoring formula to work, the `resource_security_posture` table must already contain each engine's signals for the current `scan_run_id`.

This story wires the existing `run_scan.py` (or equivalent scan completion handler) of four engines to call `upsert_posture_signals()` after their primary findings are written. No schema changes are needed in the existing engine tables — only the posture table is written to.

Each engine builds its own new images as part of this story.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [x] DE  [ ] RS  [ ] RC
ID.AM-1 (asset inventory enriched with posture signals), PR.DS-1 (data integrity across engines), DE.CM-1 (detection via CDR signals pre-computed)

**CSA CCM v4 Domain(s)**
- IVS-01 (Infrastructure Security), IAM-09 (Access Control), DSP-07 (Data Classification), SEF-01 (Security Event Analysis)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | posture writes | Engine writes posture row with wrong tenant_id, leaking resource info cross-tenant | tenant_id always taken from the scan's authenticated AuthContext, never from resource metadata |
| Tampering | CDR posture write | CDR cron runs with stale data and overwrites fresh attack-path signals | upsert writes only CDR-owned columns; attack-path columns untouched |
| DoS | mass posture upserts | Engine scanning 50,000 resources calls posture_writer 50,000 times individually | Batch upsert in chunks of 500 using executemany; single transaction per batch |

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | How this story addresses it |
|-------------|------|-----------------------------|
| T1078.004 | Valid Accounts: Cloud Accounts | is_admin_role and has_wildcard_policy signals written by IAM engine enable attack-path to identify identity crown jewels |
| T1190 | Exploit Public-Facing Application | is_internet_exposed written by network engine enables attack-path to identify traversal entry points |
| T1567 | Exfiltration Over Web Service | data_classification and can_access_pii from datasec engine enable impact scoring |

## Acceptance Criteria

### Functional — engine-iam
- [ ] AC-1: After `engine-iam` scan completes for a `scan_run_id`, rows exist in `resource_security_posture` for each IAM resource with: `attached_role_arn`, `is_admin_role`, `has_wildcard_policy`, `has_permission_boundary`, `mfa_required`, `iam_reachable_count`
- [ ] AC-2: Write call is appended AFTER existing iam_findings inserts — does not change existing IAM engine behavior
- [ ] AC-3: engine-iam builds new image tagged `v-iam-posture1`

### Functional — engine-network-security
- [ ] AC-4: After `engine-network-security` scan completes, rows exist in `resource_security_posture` for each resource with: `is_internet_exposed`, `is_onprem_reachable`, `entry_point_type`, `waf_protected`
- [ ] AC-5: Write call appended AFTER existing network_findings inserts — does not change existing behavior
- [ ] AC-6: engine-network-security builds new image tagged `v-net-posture1`

### Functional — engine-datasec
- [ ] AC-7: After `engine-datasec` scan completes, rows exist in `resource_security_posture` with: `data_classification`, `can_access_pii`, `can_write_data`
- [ ] AC-8: Write call appended AFTER existing datasec findings inserts — does not change existing behavior
- [ ] AC-9: engine-datasec builds new image tagged `v-datasec-posture1`

### Functional — engine-cdr
- [ ] AC-10: After each CDR cron run completes, rows are upserted in `resource_security_posture` for resources where a CDR actor was observed, with: `has_active_cdr_actor=true`, `cdr_actor_last_seen`, `cdr_actor_uid`
- [ ] AC-11: Resources with no CDR actor observation are NOT written (do not set has_active_cdr_actor=false for unobserved resources — absence of a CDR row means false by default)
- [ ] AC-12: engine-cdr builds new image tagged `v-cdr-posture1`

### Integration
- [ ] AC-13: After a full pipeline scan (all 4 engines run), `SELECT COUNT(*) FROM resource_security_posture WHERE scan_run_id = '<current>'` returns > 0
- [ ] AC-14: A resource touched by all 4 engines has all 4 column groups populated in a single row (verified manually against a known resource_uid)
- [ ] AC-15: No existing engine findings tables are altered — all changes are additive (new call to posture_writer after existing writes)

### Security (must pass bmad-security-reviewer)
- [ ] AC-16: All posture writes use tenant_id from AuthContext (or from the scan's tenant_id parameter) — never from resource metadata
- [ ] AC-17: No DEV_BYPASS_AUTH in any of the 4 engine changes
- [ ] AC-18: posture_writer called with correct column ownership — no engine writes columns it does not own
- [ ] AC-19: CDR engine does NOT call `json.loads()` on JSONB fields from CDR findings when reading actor data

## Technical Notes

**Where to add the write call** in each engine:
- `engine-iam`: at the end of the scan handler in `engines/iam/iam_engine/run_scan.py` (or equivalent)
- `engine-network-security`: at the end of `engines/network-security/network_security_engine/run_scan.py`
- `engine-datasec`: at the end of `engines/datasec/datasec_engine/run_scan.py`
- `engine-cdr`: in the CDR cron loop after each actor session is finalized, in the cron handler

**Import pattern** (engine_common is available in all engine Docker images):
```python
from engine_common.posture_writer import upsert_posture_signals
```

**CDR cron note**: CDR runs on an independent cron schedule, not tied to a main scan_run_id. For CDR posture writes, use the most recent `scan_run_id` from `scan_orchestration` for the matching tenant_id/account_id. If no scan_run_id is found, skip the posture write for that run.

**Batch pattern**: When writing posture signals for many resources, use `executemany` inside a single transaction (commit per batch of 500) rather than one commit per resource.

**New image tags**:
- engine-iam: `yadavanup84/engine-iam:v-iam-posture1`
- engine-network-security: `yadavanup84/engine-network-security:v-net-posture1`
- engine-datasec: `yadavanup84/engine-datasec:v-datasec-posture1`
- engine-cdr: `yadavanup84/engine-cdr:v-cdr-posture1`

## Key Files (per engine)
- `/Users/apple/Desktop/threat-engine/engines/iam/iam_engine/run_scan.py` (modify — add posture write at end)
- `/Users/apple/Desktop/threat-engine/engines/network-security/network_security_engine/run_scan.py` (modify — add posture write at end)
- `/Users/apple/Desktop/threat-engine/engines/datasec/datasec_engine/run_scan.py` (modify — add posture write at end)
- `/Users/apple/Desktop/threat-engine/engines/cdr/cdr_engine/cron_handler.py` (modify — add posture upsert per actor-observed resource)
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/engine-iam.yaml` (update image tag)
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/engine-network-security.yaml` (update image tag)
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/engine-datasec.yaml` (update image tag)
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/engine-cdr.yaml` (update image tag)

## Definition of Done
- [ ] All 4 engine files modified and committed
- [ ] All 4 Docker images built and pushed with correct version tags (no `latest`)
- [ ] All 4 K8s manifests updated with new image tags
- [ ] kubectl rollout status clean for all 4 deployments
- [ ] kubectl logs show no ERROR in first 50 lines for any of the 4 engines
- [ ] `GET /api/v1/health/live` returns 200 for all 4 engines post-deploy
- [ ] After triggering a scan, `resource_security_posture` contains rows with columns from all 4 engines
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] MEMORY.md production table updated for all 4 changed image tags