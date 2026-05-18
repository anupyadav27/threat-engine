# Story SF-P0-01: DB Migration — security_findings Table

## Status: done

## Metadata
- **Phase**: P0 — Foundation
- **Epic**: Security Findings Unified Layer (sub-project of Attack Path Engine Epic)
- **Points**: 3
- **Priority**: P0
- **Depends on**: AP-P0-01 (posture table migration establishes pattern; security_findings goes to same DB)
- **Blocks**: SF-P0-02, SF-P1-01, SF-P1-02, SF-P2-01, SF-P3-01
- **RACI**: R=DEV A=DL C=SA,SR I=PO,QA
- **Security Gate**: bmad-security-architect must review DDL. bmad-security-reviewer must sign off before merge.

## User Story

As a platform engineer, I want the `security_findings` table created in the `threat_engine_inventory` DB so that all engines have a single cross-engine, queryable, paginated findings layer without requiring per-engine API calls at query time.

## Context

`security_findings` stores one row per individual violation (misconfig, CVE, IAM violation, CDR event, data risk). It is NOT a duplicate of `resource_security_posture` (which stores 1 aggregated row per resource). These two tables are complementary: posture is the aggregate state; security_findings is the individual evidence.

The table lives in `threat_engine_inventory` DB because:
1. The attack-path engine already connects to this DB for posture lookup — no additional connection needed
2. The inventory engine owns the canonical resource list — security_findings is a cross-engine enrichment of that list

This story is DDL only. No application code ships in this story.

## Security Framework Tags

**OWASP SAMM Function**
- [ ] Governance  [ ] Design  [x] Implementation  [ ] Verification  [ ] Operations

**NIST CSF 2.0 Function(s)**
- [ ] GV  [x] ID  [x] PR  [ ] DE  [ ] RS  [ ] RC
ID.AM-1 (asset inventory enriched with violation evidence), PR.DS-1 (data integrity via unique constraint)

**CSA CCM v4 Domain(s)**
- DSP-07 (Data Classification — data_risk rows), IVS-01 (Infrastructure Security), IAM-09 (iam_violation rows), SEF-01 (cdr_event rows)

## Threat Model

### STRIDE
| Threat | Component | Attack Scenario | Mitigation |
|--------|-----------|-----------------|------------|
| Info Disclosure | cross-tenant query | source_finding_id is guessable (sequential?) — attacker fetches another tenant's finding | UNIQUE key includes tenant_id; all queries enforce WHERE tenant_id = $tid; source_finding_id is engine's sha256 hash |
| Tampering | bulk upsert | Engine writes wrong tenant_id, polluting another tenant's rows | tenant_id is NOT NULL; upsert uses ON CONFLICT (source_engine, source_finding_id, tenant_id) — cannot collide across tenants |
| DoS | large scan | 100K findings upserted individually — DB overloaded | Batch upsert (executemany, 500 rows per transaction) enforced in writer utility (SF-P0-02) |

## Acceptance Criteria

### Functional
- [ ] AC-1: Migration file `shared/database/migrations/025_security_findings.sql` created
- [ ] AC-2: Schema file `shared/database/schemas/security_findings_schema.sql` created with identical DDL
- [ ] AC-3: Table `security_findings` created in `threat_engine_inventory` DB with all columns from architecture doc section 4.1
- [ ] AC-4: All column groups present: source identity (4 cols), standard columns (6 cols), classification (7 cols), normalized evidence (5 cols), detail JSONB, lifecycle (4 timestamp/status cols)
- [ ] AC-5: UNIQUE constraint exists on `(source_engine, source_finding_id, tenant_id)`
- [ ] AC-6: All 7 indexes created: idx_sf_tenant_scan, idx_sf_resource, idx_sf_severity, idx_sf_type, idx_sf_engine, idx_sf_open (partial WHERE status='open'), idx_sf_epss (partial WHERE epss_score IS NOT NULL)
- [ ] AC-7: Migration is idempotent — CREATE TABLE IF NOT EXISTS, CREATE INDEX IF NOT EXISTS throughout
- [ ] AC-8: Migration wrapped in BEGIN/COMMIT
- [ ] AC-9: Migration ends with `RAISE NOTICE 'MIGRATION COMPLETE: 025_security_findings'`

### Standard Column Check (constitution-mandated)
- [ ] AC-10: `resource_uid VARCHAR(512) NOT NULL`
- [ ] AC-11: `scan_run_id UUID NOT NULL`
- [ ] AC-12: `tenant_id VARCHAR(255) NOT NULL`
- [ ] AC-13: `first_seen_at TIMESTAMPTZ DEFAULT NOW()`
- [ ] AC-14: `last_seen_at TIMESTAMPTZ DEFAULT NOW()`
- [ ] AC-15: `status VARCHAR(20) DEFAULT 'open'`

### Security (must pass bmad-security-reviewer)
- [ ] AC-16: `tenant_id VARCHAR(255) NOT NULL` — no nullable tenant_id
- [ ] AC-17: No plaintext credentials in migration SQL
- [ ] AC-18: All timestamp columns are TIMESTAMPTZ (not TIMESTAMP without timezone)
- [ ] AC-19: `in_kev BOOLEAN DEFAULT FALSE` — not nullable (follows constitution: all booleans explicit DEFAULT)
- [ ] AC-20: `finding_id UUID DEFAULT gen_random_uuid()` — uses gen_random_uuid(), not serial

## Technical Notes

**Migration filename**: `025_security_findings.sql`
**Target DB**: `threat_engine_inventory` (accessed via inventory engine pod)

**source_finding_id values per engine:**
- check: `check_findings.finding_id` (sha256 hash, 32 chars)
- iam: `iam_findings.finding_id`
- network: `network_findings.finding_id`
- datasec: `datasec_findings.finding_id`
- vuln: `sha256(cve_id + "|" + resource_uid)[:32]` (deterministic per CVE+resource pair)
- cdr: `cdr_findings.detection_id` (UUID as string)

Apply via:
```bash
kubectl cp /tmp/025_security_findings.sql \
  threat-engine-engines/<inventory-pod>:/tmp/025.sql
kubectl exec -n threat-engine-engines <inventory-pod> -- \
  psql -h $INVENTORY_DB_HOST -U $INVENTORY_DB_USER -d $INVENTORY_DB_NAME \
  -f /tmp/025.sql
```

**JSONB gotcha**: Do NOT call `json.loads()` on `detail` JSONB column in psycopg2. Auto-deserialized to dict.

## Key Files
- `/Users/apple/Desktop/threat-engine/shared/database/migrations/025_security_findings.sql` (create new)
- `/Users/apple/Desktop/threat-engine/shared/database/schemas/security_findings_schema.sql` (create new)

## Definition of Done
- [ ] Both SQL files committed
- [ ] Migration applied; `\d security_findings` shows all columns
- [ ] `\di security_findings*` shows all 7 indexes
- [ ] UNIQUE constraint verified: inserting duplicate (source_engine, source_finding_id, tenant_id) raises constraint error
- [ ] ON CONFLICT DO UPDATE verified: duplicate insert updates last_seen_at without error
- [ ] Migration logs end with "MIGRATION COMPLETE: 025_security_findings"
- [ ] bmad-security-reviewer: no BLOCKERS
- [ ] bmad-security-architect: DDL sign-off recorded
