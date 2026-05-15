# Story AP-P0-01: DB Migration — resource_security_posture Table

## Status: ready

## Metadata
- **Phase**: P0 — Foundation (data plumbing)
- **Epic**: Attack Path Engine
- **Points**: 3
- **Priority**: P0
- **Depends on**: nothing (prerequisite for all other AP stories)
- **Blocks**: AP-P0-02, AP-P0-03, AP-P1-01, AP-P2-03, AP-P2-04, AP-P2-05, AP-P2-06
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-architect must review DDL before writing. bmad-security-reviewer must sign off before merge.

## User Story

As a platform engineer, I want the `resource_security_posture` table in `threat_engine_inventory` DB so that all security engines (IAM, network, datasec, CDR, attack-path) have a single pre-computed merge table per resource per scan, eliminating N×M cross-engine API calls at query time.

## Context

The Attack Path Engine requires one table that aggregates security signals from multiple upstream engines per resource per scan. Without it, every consumer (attack-path engine, risk engine, BFF asset-detail) must call 4–6 separate engine APIs at query time, adding latency and coupling.

The `resource_security_posture` table lives in the **inventory DB** (`threat_engine_inventory`) because the inventory engine already owns the canonical resource list. Each engine writes only its own columns after completing its scan step; all other columns remain at their defaults until that engine runs.

This story is DDL only. No application code ships in this story.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [ ] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [ ] DE  [ ] RS  [ ] RC
PR.DS-1 (data integrity: unique constraint), ID.AM-1 (asset inventory enriched with posture signals)

**CSA CCM v4 Domain(s)**
- DSP-07 (Data Classification), IVS-01 (Infrastructure Security), IAM-09 (Access Control)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | resource_security_posture | Cross-tenant posture leakage via resource_uid guessing | UNIQUE(resource_uid, scan_run_id, tenant_id) enforces isolation; all queries must include tenant_id |
| Tampering | posture table | Engine writes wrong tenant_id, polluting another tenant's row | NOT NULL on tenant_id; unique constraint prevents collision |
| DoS | posture table | Unbounded inserts per scan create millions of stale rows | Upsert pattern (ON CONFLICT DO UPDATE) keeps one row per (resource_uid, scan_run_id, tenant_id) |

### PASTA
N/A — this story is DDL only; no credential, IAM, or network path changes.

## MITRE ATT&CK Techniques Addressed
| Technique ID | Name | How this story addresses it |
|-------------|------|-----------------------------|
| T1530 | Data from Cloud Storage Object | data_classification column enables attack-path engine to identify storage objects holding PII/credentials as crown jewels |

## Acceptance Criteria

### Functional
- [ ] AC-1: Migration file `shared/database/migrations/023_resource_security_posture.sql` exists
- [ ] AC-2: Schema file `shared/database/schemas/resource_security_posture_schema.sql` exists with identical DDL
- [ ] AC-3: Table `resource_security_posture` created in `threat_engine_inventory` DB with all columns as defined in architecture doc section 7.1
- [ ] AC-4: All column groups present: Network (5 cols), IAM (7 cols), Encryption (6 cols), Data (4 cols), Database (3 cols), CDR (4 cols), Attack Path signals (8 cols), Scoring helpers (3 cols), Computed posture (1 col), timestamps (2 cols)
- [ ] AC-5: UNIQUE constraint exists on `(resource_uid, scan_run_id, tenant_id)`
- [ ] AC-6: Five partial indexes created: idx_rsp_crown_jewel (WHERE is_crown_jewel = TRUE), idx_rsp_attack_path (WHERE is_on_attack_path = TRUE), idx_rsp_choke_point (WHERE is_choke_point = TRUE), plus idx_rsp_tenant_scan and idx_rsp_resource_uid
- [ ] AC-7: Migration is idempotent — running twice does not error (IF NOT EXISTS guards)
- [ ] AC-8: Migration ends with `RAISE NOTICE 'MIGRATION COMPLETE: 023_resource_security_posture'`

### Security (must pass bmad-security-reviewer)
- [ ] AC-9: `tenant_id VARCHAR(255) NOT NULL` — no nullable tenant_id
- [ ] AC-10: No plaintext credentials or secrets in migration SQL
- [ ] AC-11: All boolean columns have explicit `DEFAULT FALSE` — no nullable booleans that could be misread as "no signal" vs "not checked"
- [ ] AC-12: All timestamp columns are TIMESTAMPTZ (not TIMESTAMP without timezone)
- [ ] AC-13: `posture_id UUID DEFAULT gen_random_uuid()` — uses gen_random_uuid(), not serial

## Technical Notes

**Migration filename**: `023_resource_security_posture.sql`
**Target DB**: `threat_engine_inventory` (accessed via inventory engine pod)

Full schema is defined in architecture document section 7.1. Key structural points:
- Primary key: `posture_id UUID DEFAULT gen_random_uuid()`
- Unique constraint: `UNIQUE (resource_uid, scan_run_id, tenant_id)`
- All boolean columns default to FALSE (never NULL)
- All integer counters default to 0
- JSONB columns for detail blobs: `network_detail`, `iam_detail`, `connected_db_uids`

Apply via:
```bash
kubectl cp /tmp/023_resource_security_posture.sql \
  threat-engine-engines/<inventory-pod>:/tmp/023.sql
kubectl exec -n threat-engine-engines <inventory-pod> -- \
  psql -h $INVENTORY_DB_HOST -U $INVENTORY_DB_USER -d $INVENTORY_DB_NAME \
  -f /tmp/023.sql
```

**JSONB gotcha**: Do NOT call `json.loads()` on JSONB columns in psycopg2. They are auto-deserialized to Python dict.

## Key Files
- `/Users/apple/Desktop/threat-engine/shared/database/migrations/023_resource_security_posture.sql` (create new)
- `/Users/apple/Desktop/threat-engine/shared/database/schemas/resource_security_posture_schema.sql` (create new)

## Definition of Done
- [ ] Both SQL files committed to `shared/database/migrations/` and `shared/database/schemas/`
- [ ] Migration applied; `\d resource_security_posture` shows all columns
- [ ] `\di resource_security_posture*` shows all 5 indexes
- [ ] Unique constraint verified: inserting duplicate (resource_uid, scan_run_id, tenant_id) raises error
- [ ] Migration job logs end with "MIGRATION COMPLETE: 023_resource_security_posture"
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] MEMORY.md updated if image is deployed (DDL only — no image for this story)
