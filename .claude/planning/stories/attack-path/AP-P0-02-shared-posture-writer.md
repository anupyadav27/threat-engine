# Story AP-P0-02: Shared posture_writer Utility

## Status: ready

## Metadata
- **Phase**: P0 — Foundation (data plumbing)
- **Epic**: Attack Path Engine
- **Points**: 3
- **Priority**: P0
- **Depends on**: AP-P0-01 (table must exist before writer can be tested)
- **Blocks**: AP-P0-03, AP-P1-01, AP-P2-06
- **RACI**: R=DEV A=DL C=SA I=PO,QA
- **Security Gate**: bmad-security-reviewer must sign off (DB write path).

## User Story

As an engine developer, I want a shared `posture_writer.py` utility with a single `upsert_posture_signals()` function so that any engine can write its own columns to `resource_security_posture` without knowing about other engines' columns, and without risk of overwriting a different engine's data.

## Context

Multiple engines (IAM, network-security, datasec, CDR, attack-path) need to write disjoint columns to the same `resource_security_posture` table. Each engine runs at a different pipeline stage and must never overwrite columns it does not own.

The correct pattern is INSERT ... ON CONFLICT DO UPDATE, updating ONLY the columns passed as kwargs. Columns not passed must not appear in the SET clause. This requires dynamic SQL construction — a function that builds the UPDATE list from only the non-None kwargs.

The utility lives in `shared/common/` which is already bundled as `engine_common` in Docker builds.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [x] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [ ] ID  [x] PR  [ ] DE  [ ] RS  [ ] RC
PR.DS-1 (data integrity: partial-column upsert prevents overwriting), PR.IP-1 (baseline configuration maintained per-engine column ownership)

**CSA CCM v4 Domain(s)**
- IVS-01 (Infrastructure Security), DSP-07 (Data Classification Handling)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Tampering | posture_writer | Engine A accidentally overwrites Engine B's column with NULL because it passes all columns including ones it doesn't own | Dynamic SET clause built only from non-None kwargs; columns not passed are never in the UPDATE |
| Spoofing | posture_writer | Engine running as wrong tenant writes posture row for another tenant's resource | tenant_id passed as explicit positional arg (not in **kwargs); always in WHERE clause |

## MITRE ATT&CK Techniques Addressed
N/A — shared utility; no finding logic.

## Acceptance Criteria

### Functional
- [ ] AC-1: File `shared/common/posture_writer.py` created
- [ ] AC-2: Function signature: `upsert_posture_signals(conn, resource_uid, scan_run_id, tenant_id, account_id, provider, resource_type, **signals) -> dict`
- [ ] AC-3: Uses `INSERT INTO resource_security_posture (...) ON CONFLICT (resource_uid, scan_run_id, tenant_id) DO UPDATE SET ...` pattern
- [ ] AC-4: SET clause contains ONLY the non-None kwargs — keys with None values are excluded from the UPDATE
- [ ] AC-5: `updated_at = NOW()` always included in UPDATE SET clause
- [ ] AC-6: Returns the updated row as a Python dict (via `RETURNING *`)
- [ ] AC-7: Unit test file `tests/test_posture_writer.py` created with at minimum:
  - Test: calling with only IAM kwargs does not include network columns in the SET clause
  - Test: calling twice for same (resource_uid, scan_run_id, tenant_id) with different kwargs merges values (no data loss)
  - Test: None-valued kwargs are excluded from SET clause
  - Test: tenant_id is always present in the INSERT and WHERE clause
- [ ] AC-8: Function handles psycopg2 connection passed in (does not open its own connection — caller owns the connection lifecycle)

### Security (must pass bmad-security-reviewer)
- [ ] AC-9: No hardcoded tenant_id or resource_uid values in the function
- [ ] AC-10: SQL built using parameterized queries (no string interpolation of user-controlled values)
- [ ] AC-11: Function does not accept `posture_id` as a kwarg — PK is DB-generated only
- [ ] AC-12: Function does not accept `created_at` as a kwarg — set only on first INSERT, never updated
- [ ] AC-13: JSONB kwargs (network_detail, iam_detail, connected_db_uids) passed as `psycopg2.extras.Json(value)` not as string — no double-serialization
- [ ] AC-14: No DEV_BYPASS_AUTH or debug shortcuts in the utility

## Technical Notes

**File**: `shared/common/posture_writer.py`

The function must build the column list and placeholder list dynamically from kwargs:

```python
import psycopg2.extras

def upsert_posture_signals(conn, resource_uid, scan_run_id, tenant_id,
                           account_id=None, provider=None, resource_type=None,
                           **signals):
    # Filter out None values from signals
    non_null = {k: v for k, v in signals.items() if v is not None}
    # ... build INSERT ... ON CONFLICT DO UPDATE dynamically
```

JSONB columns that receive dict values must be wrapped in `psycopg2.extras.Json()` before passing to the cursor. The caller is responsible for this, OR the function can detect dict/list types and wrap automatically.

**JSONB gotcha**: psycopg2 auto-deserializes JSONB to dict on SELECT. Never call `json.loads()` on a JSONB result.

**Column ownership rules** (enforced by kwargs, not by the function itself — documentation only):
- IAM engine kwargs: `attached_role_arn`, `is_admin_role`, `has_wildcard_policy`, `has_permission_boundary`, `mfa_required`, `iam_reachable_count`, `iam_detail`
- Network engine kwargs: `is_internet_exposed`, `is_onprem_reachable`, `entry_point_type`, `waf_protected`, `network_detail`
- DataSec engine kwargs: `data_classification`, `can_access_pii`, `can_write_data`, `exfil_path_exists`
- CDR engine kwargs: `has_active_cdr_actor`, `cdr_actor_last_seen`, `cdr_actor_uid`, `cdr_risk_score`
- Attack-path engine kwargs: `is_crown_jewel`, `crown_jewel_type`, `is_on_attack_path`, `attack_path_count`, `is_choke_point`, `choke_point_path_count`, `blast_radius_count`

## Key Files
- `/Users/apple/Desktop/threat-engine/shared/common/posture_writer.py` (create new)
- `/Users/apple/Desktop/threat-engine/tests/test_posture_writer.py` (create new)

## Definition of Done
- [ ] `posture_writer.py` committed to `shared/common/`
- [ ] Unit tests pass: `pytest tests/test_posture_writer.py -v`
- [ ] Function correctly excludes None kwargs from SET clause (verified by test)
- [ ] Function correctly handles two calls with disjoint kwargs — both sets of columns survive
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] No `json.loads()` calls in the utility (JSONB handled correctly)