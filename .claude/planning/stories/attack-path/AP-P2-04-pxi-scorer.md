# Story AP-P2-04: P×I Scorer

## Status: ready

## Metadata
- **Phase**: P2 — Attack Path Engine Core
- **Epic**: Attack Path Engine
- **Points**: 3
- **Priority**: P0
- **Depends on**: AP-P2-02 (engine scaffold), AP-P2-03 (RawPath model defined), AP-P0-01 (posture table exists for posture_lookup)
- **Blocks**: AP-P2-05 (deduplicator receives scored paths), AP-P2-07 (run_scan.py orchestrates scoring)
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer must review scoring formula implementation (no auth/endpoint in this story, but formula logic is security-critical).

## User Story

As the attack-path engine, I want a P×I scorer that computes a probability score and an impact score for each raw path using the exact formulas from the architecture document, so that paths are ranked by actual risk (not just hop count) and operators can filter by both dimensions independently.

## Context

The scoring formula is the competitive differentiator of this engine vs. additive scoring. It is defined exactly in architecture doc sections 5.2 and 5.3. The implementation must match those formulas — no deviations without an ADR update.

Key behaviors:
- CDR actor present on ANY path node → multiply final probability by 1.40 (cap 1.0)
- WAF/MFA/permission boundary discounts are multiplicative, never eliminating the path (probability never reaches 0.0)
- Impact is determined by crown jewel type and multiplied by data classification, blast radius, and encryption gap
- Both `probability_score` and `impact_score` stored separately in `attack_paths` so UI can filter on each

The scorer reads posture signals for each node from a `posture_lookup` dict (pre-fetched from `resource_security_posture`) — it does not query the DB itself.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [ ] DE  [ ] RS  [ ] RC
ID.RA-5 (risk determined), ID.RA-6 (risk response)

**CSA CCM v4 Domain(s)**
- IVS-01 (Infrastructure Security), DSP-07 (Data Classification)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Tampering | scorer | Attacker modifies posture_lookup to suppress CDR actor signal (set has_active_cdr_actor=false for their resource) | posture_lookup is built from DB by engine, not from client input; tenant-scoped |
| Info Disclosure | scoring formula | Formula reveals which controls (WAF/MFA) reduce risk — attacker knows exactly what to disable | Formula is published in architecture doc (transparency is a feature, not a risk for posture tools) |

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | How this story addresses it |
|-------------|------|-----------------------------|
| T1190 | Exploit Public-Facing Application | internet entry point base probability 0.90 reflects real-world internet exposure risk |
| T1484.002 | Trust Modification | peer_account entry type base probability 0.40 models cross-account trust exploitation |

## Acceptance Criteria

### Functional
- [ ] AC-1: File `engines/attack-path/attack_path_engine/core/scorer.py` created
- [ ] AC-2: `probability_score(path, posture_lookup) -> float` function implemented matching architecture doc section 5.2 exactly
- [ ] AC-3: `impact_score(path, posture_lookup) -> float` function implemented matching architecture doc section 5.3 exactly
- [ ] AC-4: `path_score = round(min(100, P × I × 100))` formula applied
- [ ] AC-5: Severity buckets: `critical` ≥ 80, `high` 60–79, `medium` 40–59, `low` < 40
- [ ] AC-6: CDR elevation applied — any path with `has_active_cdr_actor=true` on ANY node has final P multiplied by 1.40 (capped at 1.0)
- [ ] AC-7: WAF discount: `waf_protected=true` on any node → P × 0.80
- [ ] AC-8: MFA discount: `mfa_required=true` on any node → P × 0.50
- [ ] AC-9: Permission boundary discount: `has_permission_boundary=true` on any node → P × 0.70
- [ ] AC-10: EPSS > 0.7 on any node → P × 0.95 (exploitability booster, counterintuitively adds risk — more likely to be exploited)
- [ ] AC-11: EPSS 0.30–0.70 on any node → P × 0.80
- [ ] AC-12: critical misconfig on any node → P × 0.85; high misconfig → P × 0.75

### Unit Tests
- [ ] AC-13: `tests/attack_path/test_scorer.py` created with ALL of the following test cases:
  - internet entry → base P = 0.90
  - vpn entry → base P = 0.60
  - peer_account entry → base P = 0.40
  - CDR actor present on one node → P elevated by ×1.40
  - WAF protected → P reduced by ×0.80
  - WAF + MFA + permission boundary → P = 0.90 × 0.80 × 0.50 × 0.70 = ~0.252
  - PII crown jewel type "data" → base I = 1.00 × 1.20 = 1.20 (capped at 1.0)
  - blast_radius_count > 50 → I × 1.30
  - encryption_type "none" → I × 1.10
  - path_score = round(min(100, P × I × 100)) formula verified numerically
  - severity bucket assignment for score 87 → "critical"
  - severity bucket assignment for score 65 → "high"
  - probability never reaches 0.0 even with all three discounts applied

### Security (must pass bmad-security-reviewer)
- [ ] AC-14: `posture_lookup` is a `dict[str, PostureRow]` passed in — scorer does not accept raw DB connections
- [ ] AC-15: No rounding errors that could elevate a medium path to critical (use `round(min(100, ...))` not ceiling)
- [ ] AC-16: EPSS multipliers documented inline with a comment linking to architecture doc section 5.2

## Technical Notes

**File**: `engines/attack-path/attack_path_engine/core/scorer.py`

The `posture_lookup` dict maps `resource_uid → PostureRow` (a dataclass or Pydantic model). It is pre-fetched by `run_scan.py` from `resource_security_posture` for the current `(scan_run_id, tenant_id)` before the scorer is called — the scorer does NOT query the DB.

**`PostureRow` fields** used by scorer (subset of full posture table):
- `entry_point_type: str` (internet, vpn, onprem, peer_account, vendor, k8s_external)
- `max_epss: float | None`
- `critical_misconfig_count: int`
- `high_misconfig_count: int`
- `waf_protected: bool`
- `mfa_required: bool`
- `has_permission_boundary: bool`
- `has_active_cdr_actor: bool`
- `crown_jewel_type: str`
- `data_classification: str | None`
- `blast_radius_count: int`
- `encryption_type: str | None`

**Implementation note**: The per-hop loop in `probability_score()` must apply multipliers in order (EPSS then misconfig boosters, then control discounts). CDR elevation is applied AFTER the loop (not per-hop). See architecture doc section 5.2.

## Key Files
- `/Users/apple/Desktop/threat-engine/engines/attack-path/attack_path_engine/core/scorer.py` (create new)
- `/Users/apple/Desktop/threat-engine/tests/attack_path/test_scorer.py` (create new)

## Definition of Done
- [ ] `scorer.py` committed with both functions
- [ ] All 13 unit test cases pass: `pytest tests/attack_path/test_scorer.py -v`
- [ ] WAF + MFA + boundary combined discount verified numerically: P ≈ 0.252
- [ ] CDR elevation verified: P with active CDR actor always > P without
- [ ] probability never reaches 0.0 — verified by test
- [ ] bmad-security-reviewer: no BLOCKERS (formula implementation review)