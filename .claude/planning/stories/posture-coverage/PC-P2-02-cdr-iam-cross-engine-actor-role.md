# Story PC-P2-02: CDR + IAM Cross-Engine — Link Active Actors to IAM Roles

## Status: done

## Metadata
- **Phase**: P2 — Tier B (data available in both engine DBs; requires join logic across DBs)
- **Sprint**: Posture Coverage Enhancement
- **Points**: 5
- **Priority**: P2
- **Depends on**: AP-P0-03 (both CDR and IAM write to posture table)
- **Blocks**: Attack-path identity theft path detection
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer — cross-engine DB join is a new data access pattern

## Gap Being Closed

**Current state:** CDR engine writes `has_active_cdr_actor=TRUE` to the resource being accessed (e.g. S3 bucket). IAM engine writes `is_admin_role=TRUE` to the IAM role. These are two separate posture rows with no link between them.

**Missing signal:** "This IAM role is currently being used by an actor that CDR flagged as suspicious." This is the identity-theft attack path — attacker compromises a credential (CDR detects the anomalous API call), then escalates using an admin role (IAM signals it).

**Cross-engine join:** `cdr_findings.actor_principal` (e.g. `arn:aws:iam::123:role/DataPipelineRole`) → `iam_findings.resource_uid` (the same ARN). When matched: set `has_active_cdr_actor=TRUE` on the IAM role's posture row.

## Data Sources

```
threat_engine_cdr DB → cdr_findings
  Fields: actor_principal (IAM ARN), resource_uid, event_time, severity, mitre_technique_id

threat_engine_iam DB → iam_findings
  Fields: resource_uid (IAM role/user ARN), is_admin (via rule_id pattern)
```

## Signals to Write

After CDR cron writes its posture signals (to accessed resources), run an additional enrichment pass:

1. Query `cdr_findings` for all `actor_principal` values in this tenant/time window
2. Match `actor_principal` against `iam_findings.resource_uid` (exact ARN match)
3. For matched IAM roles: upsert `has_active_cdr_actor=TRUE` and `cdr_ttps` to the **IAM role's** posture row

This means an IAM role posture row can have `has_active_cdr_actor=TRUE` (the role was used by a detected actor) AND `is_admin_role=TRUE` — a critical cross-engine signal: **admin role actively exploited**.

## New Composite Flag (extend PC-P1-07)

Add to `composite_flags.py`:
```python
"active_cdr_actor_on_admin_role": is_admin_role AND has_active_cdr_actor
```

Add column to migration (extend PC-P0-01 or new migration 026):
```sql
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS active_cdr_actor_on_admin_role BOOLEAN NOT NULL DEFAULT FALSE;
```

Risk engine boost: `+50 exposure_factor` when `active_cdr_actor_on_admin_role=TRUE` (highest single signal — active credential theft on admin identity).

## Implementation

**New function:** `engines/cdr/cdr_engine/posture_signals.py` — add `write_cdr_iam_cross_signal()` called after the existing CDR posture write.

**Timing:** CDR runs on an independent cron, not tied to the main scan pipeline. The IAM posture rows must already exist (main pipeline ran first). Check for their existence before running the join.

## Acceptance Criteria

- [ ] AC-1: When CDR detects `actor_principal=arn:aws:iam::123:role/AdminRole` and IAM engine has a posture row for that ARN, the IAM role's posture row gets `has_active_cdr_actor=TRUE`
- [ ] AC-2: `active_cdr_actor_on_admin_role=TRUE` for any IAM role that is both admin AND has CDR actor activity
- [ ] AC-3: Join is scoped by `tenant_id` — actor from tenant A cannot match IAM role in tenant B
- [ ] AC-4: If IAM posture rows don't exist yet (main scan not run), enrichment is skipped with INFO log
- [ ] AC-5: `cdr_ttps` on the IAM role row contains the MITRE technique IDs observed by the CDR actor
- [ ] AC-6: Risk engine applies +50 boost for `active_cdr_actor_on_admin_role=TRUE` — verify in risk_evaluator.py

## MITRE ATT&CK
| Technique | How addressed |
|-----------|--------------|
| T1078.004 | Valid Accounts: Cloud Accounts — compromised IAM role detected by CDR, flagged in posture |
| T1098 | Account Manipulation — admin role actively used by CDR-detected actor signals privilege abuse |

## Definition of Done
- [ ] `write_cdr_iam_cross_signal()` implemented
- [ ] New migration for `active_cdr_actor_on_admin_role` column applied
- [ ] Composite flag added to attack-path composite_flags.py
- [ ] Risk evaluator updated with +50 boost
- [ ] Post-deploy test: simulate CDR finding with actor_principal = known IAM admin role ARN → verify posture row updated