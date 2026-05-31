# CDR-1-S04: Write Posture Signals for All Sequence Detector Patterns

## Sprint
CDR-1 — Correctness Sprint

## Priority
P1 — `sequence_detector.py` writes `has_exfil_path=True` for S3 exfil only. Three other patterns (identity_pivot, secrets_staging, compute_hijack) produce findings but write NO posture signal. Attack-path and risk engines miss these critical behavioral indicators.

## Story
As the attack-path and risk engines, I need all four sequence detector patterns to write appropriate posture signals to `resource_security_posture`, so that identity pivot, secrets staging, and compute hijack sequences are visible in posture scoring and path elevation.

## Background

The sequence detector (`engines/cdr/cdr_engine/detectors/sequence_detector.py`) detects 4 multi-event attack patterns:

| Pattern | Rule ID | Current posture write | Should write |
|---|---|---|---|
| S3 exfil | RULE_S3_EXFIL | `has_exfil_path=True` ✓ | Already done |
| Identity pivot | RULE_IDENTITY_PIVOT | Nothing | `is_on_attack_path=True` on the pivot source + target roles |
| Secrets staging | RULE_SECRETS_STAGING | Nothing | `secrets_in_env_vars=True` or new `has_secrets_staging=True` on the compute resource |
| Compute hijack | RULE_COMPUTE_HIJACK | Nothing | `is_internet_exposed=True` signal or new `has_compute_hijack=True` on the compute resource |

All posture writes go to `resource_security_posture` in `threat_engine_inventory` DB via `shared/common/posture_writer.py`.

## Files to Read First

- `engines/cdr/cdr_engine/detectors/sequence_detector.py` — all 4 pattern detectors, how they write findings to `cdr_findings`, and where `has_exfil_path` is currently written
- `engines/cdr/cdr_engine/posture_signals.py` — pattern for upsert_posture_signals
- `shared/common/posture_writer.py` — `upsert_posture_signals()` signature
- `shared/database/schemas/resource_security_posture_schema.sql` — existing columns; confirm which columns are available for each signal

## Files to Modify

| File | Change |
|---|---|
| `engines/cdr/cdr_engine/detectors/sequence_detector.py` | Add posture signal writes for identity_pivot, secrets_staging, compute_hijack patterns alongside existing has_exfil_path write |

## Exact Implementation

### Pattern: RULE_IDENTITY_PIVOT

When a pivot sequence is detected (actor assumed role A, then role A assumed role B):
- Write to `resource_security_posture` for the **pivot source role** (role A):
  ```python
  {"resource_uid": role_a_arn, "is_on_attack_path": True, "attack_path_count": 1}
  ```
- Write to `resource_security_posture` for the **pivot target role** (role B):
  ```python
  {"resource_uid": role_b_arn, "is_on_attack_path": True, "is_attack_entry_point": True, "attack_entry_point_category": "identity_pivot"}
  ```

Use `upsert_posture_signals(inv_conn, signals, scan_run_id, tenant_id)` — same function used by `has_exfil_path`.

### Pattern: RULE_SECRETS_STAGING

When secrets were retrieved and then used from compute (Lambda, EC2):
- Write to `resource_security_posture` for the **compute resource**:
  ```python
  {"resource_uid": compute_uid, "secrets_in_env_vars": True}
  ```
  Note: `secrets_in_env_vars` is the closest existing column. If the sequence is secrets-from-Secrets-Manager-to-Lambda, this is the right semantic.

### Pattern: RULE_COMPUTE_HIJACK

When a compute resource was accessed from an anomalous source and performed lateral operations:
- Write to `resource_security_posture` for the **compute resource**:
  ```python
  {"resource_uid": compute_uid, "is_on_attack_path": True, "attack_entry_point_category": "compute_hijack"}
  ```

### Implementation location

Find where `has_exfil_path` is currently written in `sequence_detector.py`. It will look like a direct SQL upsert or a call to `upsert_posture_signals`. Add the three new signal blocks in the same pattern, gated by the respective sequence pattern being detected.

```python
# After detecting identity_pivot sequence
if pivot_chain:
    signals = []
    for (src_role, tgt_role) in pivot_chain:
        signals.append({
            "resource_uid": src_role,
            "resource_type": "iam_role",
            "is_on_attack_path": True,
        })
        signals.append({
            "resource_uid": tgt_role,
            "resource_type": "iam_role",
            "is_on_attack_path": True,
            "is_attack_entry_point": True,
            "attack_entry_point_category": "identity_pivot",
        })
    upsert_posture_signals(inv_conn, signals, scan_run_id, tenant_id)
    logger.info("CDR sequence: wrote identity_pivot posture for %d role pairs", len(pivot_chain))
```

Mirror this pattern for secrets_staging and compute_hijack.

## Acceptance Criteria

- [ ] After CDR scan with an identity_pivot detection, rows in `resource_security_posture` for pivot roles have `is_on_attack_path=TRUE`
- [ ] After CDR scan with a secrets_staging detection, the compute resource row has `secrets_in_env_vars=TRUE`
- [ ] After CDR scan with a compute_hijack detection, the compute resource row has `is_on_attack_path=TRUE` and `attack_entry_point_category='compute_hijack'`
- [ ] S3 exfil behavior unchanged — `has_exfil_path=TRUE` still written for RULE_S3_EXFIL
- [ ] All posture upserts scoped by `tenant_id` from scan context
- [ ] If no sequences detected, no spurious posture rows written
- [ ] No crash if `inv_conn` is not available — log warning and continue

## Security Checklist

- [ ] `tenant_id` from scan context, not from sequence detector state
- [ ] `resource_uid` values come from sequence detector's resolved resource ARNs, not from raw log event fields
- [ ] No string interpolation in SQL — parameterized queries only

## MITRE ATT&CK Coverage
- T1078 Valid Accounts (identity_pivot) — now surfaced as `is_attack_entry_point`
- T1555 Credentials from Password Stores (secrets_staging) — `secrets_in_env_vars`
- T1496 Resource Hijacking (compute_hijack) — `is_on_attack_path`

## Definition of Done

- [ ] `sequence_detector.py` writes posture signals for all 4 patterns
- [ ] Manual verify: trigger test sequences on test-tenant-002 → query `resource_security_posture` for each signal
- [ ] Log lines emitted for each sequence type when signals are written
- [ ] Image tag bumped in `deployment/aws/eks/engines/engine-cdr.yaml`