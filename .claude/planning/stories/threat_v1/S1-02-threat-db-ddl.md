# Story S1-02: Threat DB DDL Migration (6 New v1 Tables)

## Status: ready

## Metadata
- **Sprint**: 1 — Foundation: Schema + GraphBuilder
- **Points**: 3
- **Priority**: P0
- **Depends on**: S0-05 (coverage gate passed), S1-01 (schema agreed before DDL finalised)
- **Blocks**: S1-07 (needs threat_scan_runs_v1), S1-08 (needs threat_incidents), Sprint 2
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: SR must be consulted before migration SQL is written. SA reviews generated columns.

## Context

Creates 6 new PostgreSQL tables in `threat_engine_threat` DB for the threat_v1 engine. These tables are separate from the existing v0 threat tables — no existing table is modified. The migration follows CSPM_CONSTITUTION §2: standard columns, IMMUTABLE generated columns, all TIMESTAMPTZ, multi-tenant by default.

The `dedup_key` generated column uses `sha256` of text concat — sha256 of a text expression is IMMUTABLE in PostgreSQL (unlike timestamp functions), making it safe for a `GENERATED ALWAYS AS ... STORED` column.

## Technical Notes

### Output files
1. `shared/database/migrations/threat_v1_001_new_tables.sql`
2. `shared/database/schemas/threat_schema.sql` — append new v1 tables

### Tables

| Table | Purpose |
|---|---|
| `threat_incidents` | One row per deduplicated incident. dedup_key prevents flooding. |
| `threat_scenario_patterns` | Pattern YAML definitions + compiled Cypher. Global, not per-tenant. |
| `threat_scan_runs_v1` | Per-scan metadata: node/edge counts, status, timing. |
| `threat_pattern_suppressions` | Per-tenant pattern suppression (NEVER global active=false — CP1-05). |
| `threat_crown_jewels` | Per-tenant crown jewel overrides (manual classification). |
| `threat_incident_feedback` | Analyst FP/TP feedback. INSERT-only audit log. |

### Critical DDL rules

**dedup_key (IMMUTABLE generated column):**
```sql
dedup_key VARCHAR(64) GENERATED ALWAYS AS (
    encode(sha256((incident_class || '|' || entry_resource_uid || '|' || tenant_id)::bytea), 'hex')
) STORED
```
`sha256()` on a text expression is IMMUTABLE — safe for STORED generated columns. Verified: `EXTRACT(HOUR FROM timestamptz)` is NOT immutable (do not use timestamps in generated columns).

**Per-tenant suppression (CP1-05):**
- `threat_pattern_suppressions` stores per-tenant rows with `(tenant_id, pattern_key)` UNIQUE
- `threat_scenario_patterns.active` is a global flag (default true) — never set to false for performance or FP reasons; that goes in `threat_pattern_suppressions`

**Standard columns on `threat_incidents`:** finding_id, scan_run_id, tenant_id, account_id, credential_ref, credential_type, provider, region, resource_uid, resource_type, severity, status, first_seen_at, last_seen_at

## Acceptance Criteria

- [ ] AC-1: Migration file at `shared/database/migrations/threat_v1_001_new_tables.sql`
- [ ] AC-2: All 6 tables created with correct DDL, wrapped in BEGIN/COMMIT
- [ ] AC-3: `threat_incidents.dedup_key` is a GENERATED ALWAYS AS STORED column using sha256
- [ ] AC-4: `threat_pattern_suppressions` has UNIQUE(tenant_id, pattern_key) — no global suppression column
- [ ] AC-5: All tables have `tenant_id VARCHAR(255) NOT NULL` with an index
- [ ] AC-6: All timestamps use TIMESTAMPTZ DEFAULT NOW()
- [ ] AC-7: Verify block at end: SELECT all 6 table names from information_schema.tables
- [ ] AC-8: Migration ends with `RAISE NOTICE 'MIGRATION COMPLETE: threat_v1_001_new_tables'`
- [ ] AC-9: `threat_schema.sql` updated with new tables appended

## Security Acceptance Criteria

- [ ] No `active = false` column or default on `threat_scenario_patterns` that would be used for per-tenant suppression
- [ ] `threat_incident_feedback` has no UPDATE — INSERT-only (immutable audit log), enforced by application logic comment in DDL
- [ ] All FK constraints include ON DELETE CASCADE or ON DELETE SET NULL — no orphaned rows
- [ ] `threat_crown_jewels` has UNIQUE(tenant_id, resource_uid) — prevents duplicate crown jewel records
- [ ] Migration is idempotent: uses CREATE TABLE IF NOT EXISTS, CREATE INDEX IF NOT EXISTS

## Definition of Done

- [ ] Migration SQL committed
- [ ] Applied to `threat_engine_threat` DB via kubectl exec on threat engine pod
- [ ] `kubectl logs -l job-name=threat-v1-migration` ends with "MIGRATION COMPLETE"
- [ ] `threat_schema.sql` updated
- [ ] SR consulted and sign-off recorded
- [ ] All 6 tables verified with `\dt threat_*` in psql
