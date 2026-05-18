# Story PC-P1-07: Attack-Path Engine — Compute Cross-Engine Composite Flags

## Status: done

## Metadata
- **Phase**: P1 — Tier A (pure SQL on merged posture table, no new external data)
- **Sprint**: Posture Coverage Enhancement
- **Points**: 3
- **Priority**: P1
- **Depends on**: PC-P0-01 (composite columns exist), PC-P1-01 (encryption signals), PC-P1-03 (container), PC-P1-04 (vuln signals)
- **Blocks**: Risk engine improvements (composite flags feed FAIR boosts directly)
- **RACI**: R=DEV A=DL C=SA I=PO,QA

## Purpose

The composite flag columns added in PC-P0-01 are **computed by the attack-path engine** after all stage-5 engines have written their posture signals. These flags encode the "dangerous combinations" that no single engine can detect:

| Flag | Meaning | Why dangerous |
|------|---------|---------------|
| `unencrypted_pii_store` | PII data + not encrypted at rest | Breach = immediate regulatory exposure |
| `internet_exposed_with_pii` | PII data + internet-facing | Direct exfil path, no internal pivot needed |
| `admin_role_without_mfa` | Admin IAM role + MFA not enforced | Single stolen credential = full account takeover |
| `exploitable_exposed_resource` | Internet-facing + known exploit (KEV) | Weaponizable entry point, active threat actor interest |
| `cdr_active_on_unencrypted` | Active CDR actor + unencrypted resource | Attacker may already be exfiltrating cleartext data |

The risk engine can read a single boolean flag instead of joining 4 tables, enabling much simpler FAIR boost logic.

## Implementation

**New function in attack-path engine:** `attack_path_engine/composite_flags.py`

```python
def write_composite_flags(scan_run_id: str, tenant_id: str) -> int:
    """Single UPDATE statement to set all 5 composite flags at once."""
```

SQL:
```sql
UPDATE resource_security_posture SET
    unencrypted_pii_store = (
        data_classification IN ('pii', 'phi', 'pci', 'restricted')
        AND is_encrypted_at_rest = FALSE
    ),
    internet_exposed_with_pii = (
        is_internet_exposed = TRUE
        AND data_classification IN ('pii', 'phi', 'pci', 'restricted')
    ),
    admin_role_without_mfa = (
        is_admin_role = TRUE
        AND mfa_enforced = FALSE
    ),
    exploitable_exposed_resource = (
        is_internet_exposed = TRUE
        AND has_known_exploit = TRUE
    ),
    cdr_active_on_unencrypted = (
        has_active_cdr_actor = TRUE
        AND is_encrypted_at_rest = FALSE
    ),
    updated_at = NOW()
WHERE tenant_id = %s
  AND scan_run_id = %s;
```

**Wire into attack-path engine run_scan.py:** Call `write_composite_flags()` AFTER all posture signal aggregation and BEFORE BFS traversal. The BFS scorer reads `internet_exposed_with_pii` and `exploitable_exposed_resource` when deciding traversal weights.

## Risk Engine Integration

Update `engines/risk/evaluator/risk_evaluator.py` to read composite flags directly:
```python
# Replace current multi-column boost logic with composite flag checks:
if posture.get("internet_exposed_with_pii"):
    exposure_factor += 35   # was: is_internet_exposed +25, data_classification check +10
if posture.get("unencrypted_pii_store"):
    exposure_factor += 20
if posture.get("admin_role_without_mfa"):
    exposure_factor += 25
if posture.get("exploitable_exposed_resource"):
    exposure_factor += 40   # highest single boost — weaponizable + exposed
if posture.get("cdr_active_on_unencrypted"):
    exposure_factor += 45   # most dangerous — active attacker + no encryption
```

## Acceptance Criteria

- [ ] AC-1: After attack-path engine runs, `unencrypted_pii_store=TRUE` for S3 buckets with `data_classification='pii'` AND `is_encrypted_at_rest=FALSE`
- [ ] AC-2: `internet_exposed_with_pii=TRUE` for public S3 buckets containing PII
- [ ] AC-3: `admin_role_without_mfa=TRUE` for IAM admin roles with `mfa_enforced=FALSE`
- [ ] AC-4: `exploitable_exposed_resource=FALSE` before PC-P2-01 (KEV) since `has_known_exploit` is always FALSE until then — no false positives
- [ ] AC-5: Composite flags are scoped to `(tenant_id, scan_run_id)` — no cross-tenant leakage
- [ ] AC-6: Risk evaluator reads composite flags and applies correct boosts — verify with a test scenario where `internet_exposed_with_pii=TRUE` and confirm `exposure_factor` includes the +35
- [ ] AC-7: New attack-path image: `yadavanup84/engine-attack-path:v-attack-path-composite1`

## Definition of Done
- [ ] `composite_flags.py` written and wired in run_scan order (before BFS)
- [ ] Risk evaluator updated to use composite flag boosts
- [ ] Both images deployed
- [ ] Post-deploy: `SELECT COUNT(*) FROM resource_security_posture WHERE unencrypted_pii_store=TRUE` > 0 on a real tenant scan