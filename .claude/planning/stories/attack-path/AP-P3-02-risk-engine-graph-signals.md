# Story AP-P3-02: Risk Engine — Graph-Derived Signals

## Status: ready

## Metadata
- **Phase**: P3 — BFF + Risk Integration
- **Epic**: Attack Path Engine
- **Points**: 3
- **Priority**: P1
- **Depends on**: AP-P2-07 (attack-path engine writes posture signals before risk runs), AP-P0-01 (posture table with attack-path columns)
- **Blocks**: nothing (terminal story in this phase; enables better risk scores in prod)
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-reviewer mandatory (engine code + DB read path). bmad-security-po must confirm scoring delta values against PRD.

## User Story

As the risk engine, I want to read six additional signals from `resource_security_posture` (attack path membership, choke point status, CDR actor presence, certificate expiry, and blast radius) and incorporate them into risk scenario scoring, so that resources on active attack paths receive meaningfully higher risk scores than equivalent resources not on any path.

## Context

The risk engine currently computes scores using check_findings and iam_findings. It does not know whether a resource is on an actual traversable attack path to a crown jewel. Adding attack-path signals closes this gap — a resource with an SSH misconfiguration that is also on a critical attack path to a PII database should score much higher than a resource with the same misconfiguration that is not on any attack path.

The six new signals are all pre-computed in `resource_security_posture` by upstream engines (attack-path, CDR, encryption). The risk engine reads them via a JOIN and applies score adjustments.

The Argo DAG dependency (risk runs after attack-path) is already set in AP-P2-07. This story only modifies the risk engine's scoring logic and its K8s image.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [ ] DE  [x] RS  [ ] RC
ID.RA-5 (risk quantified with attack-path context), RS.AN-3 (context for response prioritization)

**CSA CCM v4 Domain(s)**
- GRC-05 (Risk Assessment), IVS-01, DSP-07

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Tampering | risk score inflation | Attacker manipulates resource_security_posture to inflate risk score for a competitor's resource | posture table is written by engines with tenant_id scoping; no external write path |
| Info Disclosure | risk score cross-tenant | Risk engine reads posture without tenant_id filter — reveals another tenant's attack path signals | All posture reads include WHERE tenant_id = $tid from AuthContext |

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | How this story addresses it |
|-------------|------|-----------------------------|
| T1190 | Exploit Public-Facing Application | is_on_attack_path signal elevates risk for internet-reachable resources on paths |
| T1078.004 | Valid Accounts: Cloud Accounts | is_choke_point signal elevates risk for IAM roles appearing on most attack paths |

## Acceptance Criteria

### Functional — Risk Engine Score Adjustments
- [ ] AC-1: Risk engine reads `resource_security_posture` for the current `(scan_run_id, tenant_id)` as part of risk scenario computation — add JOIN or separate query to existing risk computation flow
- [ ] AC-2: `is_on_attack_path = true` → +25 added to base risk score
- [ ] AC-3: `attack_path_count > 3` → additional +10 added to risk score
- [ ] AC-4: `is_choke_point = true` → +15 added to risk score
- [ ] AC-5: `has_active_cdr_actor = true` → +30 added to risk score
- [ ] AC-6: `cert_days_remaining < 30` (and cert_days_remaining IS NOT NULL) → +10 added to risk score
- [ ] AC-7: `blast_radius_count > 50` → final risk score multiplied by 1.20 (applied after all additive adjustments)
- [ ] AC-8: Risk score capped at 100 after all adjustments (`min(100, score)`)
- [ ] AC-9: All six signal reads are guarded with `posture_row is None → signals default to 0/False` — scan still works if posture table has no row for a resource (attack-path engine may have failed)

### Validation Tests
- [ ] AC-10: Resource on critical attack path (is_on_attack_path=true, is_choke_point=true, has_active_cdr_actor=true) → risk score ≥ 70 (validated manually against 3 known resources)
- [ ] AC-11: Choke point node shows elevated score compared to equivalent non-choke node with same misconfig severity (verified manually)
- [ ] AC-12: Resource not on any attack path → no score change from these 6 signals

### RBAC Matrix (5 roles × risk endpoints)
- [ ] AC-13: All 5 roles that could previously access risk endpoints can still access them (no regression)
- [ ] AC-14: New posture-derived signals do NOT appear raw in any risk API response — they are incorporated into the score only

### Image Tag (mandatory)
- [ ] AC-15: Risk engine image rebuilt and pushed as `yadavanup84/engine-risk:v-risk-attack-path1`
- [ ] AC-16: No `latest` tag in manifest or Dockerfile

### Health Check (mandatory)
- [ ] AC-17: `GET /api/v1/health/live` returns 200 after risk engine deploy
- [ ] AC-18: `kubectl logs` show no ERROR in first 50 lines

### Security Gate (mandatory)
- [ ] AC-19: bmad-security-reviewer: no BLOCKERS
- [ ] AC-20: bmad-security-po: score delta values (+25, +15, +30, etc.) confirmed against PRD section 6

## Technical Notes

**Engine**: `engine-risk` (existing engine, `engines/risk/`)

The posture table read should be added to the existing risk scenario computation flow. The simplest integration is a `LEFT JOIN resource_security_posture rsp ON rsp.resource_uid = rs.resource_uid AND rsp.scan_run_id = $scan_run_id AND rsp.tenant_id = $tenant_id` added to the existing risk_scenarios query, or a second query populating a `posture_lookup` dict (same pattern as AP-P2-04).

**Score adjustment order**:
1. Start with existing base score (from check_findings + iam_findings)
2. Apply additive adjustments: +25 (on_attack_path) + optional +10 (attack_path_count>3) + +15 (choke_point) + +30 (cdr_actor) + +10 (cert_days<30)
3. Apply multiplicative adjustment: × 1.20 if blast_radius_count > 50
4. Cap at 100

**Guard for missing posture row**:
```python
posture = posture_lookup.get(resource_uid)
if posture:
    if posture.is_on_attack_path:
        score += 25
    # ... etc
```

**Argo dependency already set in AP-P2-07**: risk-scan step has `dependencies: [attack-path-scan]`. This story does not need to modify the Argo DAG.

## Key Files
- `/Users/apple/Desktop/threat-engine/engines/risk/risk_engine/run_scan.py` (modify — add posture signal reads and score adjustments)
- `/Users/apple/Desktop/threat-engine/deployment/aws/eks/engines/engine-risk.yaml` (update image tag to v-risk-attack-path1)

## Definition of Done
- [ ] risk engine modified to read 6 posture signals and apply score adjustments
- [ ] Risk score for a test resource on critical attack path confirmed ≥ 70
- [ ] Missing posture row handled gracefully (no exception, no score change)
- [ ] Engine image built: `yadavanup84/engine-risk:v-risk-attack-path1`
- [ ] Engine image pushed and K8s manifest updated
- [ ] kubectl rollout clean; health/live 200; no ERRORs in first 50 log lines
- [ ] MEMORY.md production table updated for risk engine image tag
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] bmad-security-po: score deltas confirmed