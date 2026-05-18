# JNY-01: Threat DB — `mitre_technique_reference` schema migration + seed

## Track
Investigation Journey Unification — Phase A

## Priority
P0 — TechniqueDetailModal returns 500; blocks every threat investigation deep-dive (G-1).

## Status
done — mitre_technique_reference table (110 rows) + threat_finding_techniques already applied; BFF route GET /views/threats/technique/{id} added in v-bff-technique1

## Team Assignment (RACI)

> **R** = Responsible (does the work) · **A** = Accountable (signs off) · **C** = Consulted · **I** = Informed
> Source: [ADR §4.3.1](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#431-per-story-raci)

| Role | Agent(s) | RACI |
|------|----------|------|
| Engine specialist | `threat` + `cspm-db-engineer` | R |
| UI / BFF / Gateway dev | — | — |
| Security architect (design) | `bmad-security-architect` | C |
| Security reviewer (code) | `cspm-security-reviewer` + `bmad-security-reviewer` | R |
| BMad lead | `bmad-dev` | R |
| QA | `bmad-qa` + `cspm-qa-engineer` | R |
| Standards | `cspm-standards-guardian` | A |

**Quality gate chain (all stories):**
`cspm-code-reviewer` → `cspm-security-reviewer` + `bmad-security-reviewer` → `cspm-qa-engineer` + `bmad-qa` → `cspm-deploy` → `cspm-integration-tester`

**Security checkpoints this story participates in:**
CP-1 (design gate, end of D2) — see [ADR §4.3.3](../../documentation/ADR-INVESTIGATION-JOURNEY-UNIFICATION.md#433-sprint-wide-security-review-checkpoints) and [Sprint §4.5](../SPRINT-INVESTIGATION-JOURNEY-UNIFICATION.md).

## Context
Per ADR §2.2 G-1, the `mitre_technique_reference` table does not exist in the threat DB. The TechniqueDetailModal in the Threat Center journey calls a lookup endpoint that joins this table and returns 500. This is a P0 hard blocker for Phase B/C/D — the universal `/finding/[engine]/[id]` route's "Related Threats" tab and the technique badge on every threat detail page rely on it. ADR §3.1 lists `Technique` as a canonical L1 entity at `/threats/technique/[id]` and the table is the source of truth.

## What to build
1. New SQL schema file: `/Users/apple/Desktop/threat-engine/shared/database/schemas/threat_mitre_reference_schema.sql`
2. Forward migration: `/Users/apple/Desktop/threat-engine/shared/database/migrations/threat_mitre_technique_ref_001.sql`
3. Static seed CSV (per Sprint §6 risk mitigation — bundle, do not depend on live MITRE feed): `/Users/apple/Desktop/threat-engine/shared/database/seeds/mitre_technique_reference.csv`
4. Seed loader updated: `/Users/apple/Desktop/threat-engine/engines/threat/scripts/load_mitre_reference.py`
5. Threat engine endpoint fix: `/Users/apple/Desktop/threat-engine/engines/threat/threat_engine/api/technique_detail.py` — read from new table instead of static map.

Schema (target DB: `threat_engine_threat`):

```sql
CREATE TABLE IF NOT EXISTS mitre_technique_reference (
    technique_id      VARCHAR(16) PRIMARY KEY,           -- e.g. T1530, T1078.004
    parent_id         VARCHAR(16),                        -- T1078 for T1078.004
    name              VARCHAR(255) NOT NULL,
    description       TEXT,
    tactic_ids        JSONB NOT NULL DEFAULT '[]'::jsonb, -- ["TA0001"]
    platforms         JSONB NOT NULL DEFAULT '[]'::jsonb,
    data_sources      JSONB NOT NULL DEFAULT '[]'::jsonb,
    detection         TEXT,
    mitigations       JSONB NOT NULL DEFAULT '[]'::jsonb, -- [{"id":"M1041","name":"..."}]
    d3fend_mappings   JSONB NOT NULL DEFAULT '[]'::jsonb,
    url               VARCHAR(512),
    version           VARCHAR(16),                        -- ATT&CK version
    last_modified     TIMESTAMPTZ,
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mtr_parent ON mitre_technique_reference(parent_id);
CREATE INDEX IF NOT EXISTS idx_mtr_tactics_gin ON mitre_technique_reference USING GIN (tactic_ids);
```

## Acceptance criteria
- [ ] `threat_mitre_reference_schema.sql` created and committed
- [ ] Migration `threat_mitre_technique_ref_001.sql` applied to `threat_engine_threat` DB
- [ ] Seed CSV contains at least the ~200 enterprise techniques referenced by existing threat findings (verify via `SELECT DISTINCT technique FROM threat_findings`)
- [ ] `python load_mitre_reference.py` is idempotent (`ON CONFLICT (technique_id) DO UPDATE`)
- [ ] `GET /api/v1/views/threats/technique/T1530` returns 200 with name, description, tactics, mitigations
- [ ] TechniqueDetailModal opens without console error in browser
- [ ] No 500s in `kubectl logs engine-threat` during a fresh threat scan
- [ ] Standard columns rule N/A (this is a reference table) but tenant-agnostic global table is documented in schema header comment

## Dependencies
- Blocks: JNY-04, JNY-05, JNY-06, JNY-09
- Blocked by: none

## Constitution check
- DB-first (no hardcoded technique map). Reference table is global (no `tenant_id`) — documented exception in schema comment. New threat image required → JNY-04.

## Out of scope
- Live MITRE STIX feed cron refresh (deferred per Sprint §6 — static CSV first, cron later).
- D3FEND auto-mapping (seed `d3fend_mappings` empty for technique IDs without an authoritative mapping).
- ATT&CK sub-technique parent rollup logic in UI.

## Files touched (estimate)
- `shared/database/schemas/threat_mitre_reference_schema.sql` — new
- `shared/database/migrations/threat_mitre_technique_ref_001.sql` — new
- `shared/database/seeds/mitre_technique_reference.csv` — new
- `engines/threat/scripts/load_mitre_reference.py` — new
- `engines/threat/threat_engine/api/technique_detail.py` — switch from dict lookup to DB query
- `engines/threat/Dockerfile` — copy seed CSV + loader into image
- `engines/threat/threat_engine/main.py` — call loader on startup if table empty

## Test plan
- Unit: loader idempotency test (run twice, assert same row count)
- Integration: psql query `SELECT count(*) FROM mitre_technique_reference;` ≥ 200
- BFF contract: `curl /api/v1/views/threats/technique/T1530` returns expected schema
- UI smoke: open any threat detail in `/threats/[id]`, click technique badge, modal renders
- Security: SELECT-only role can read table; no PII in seed CSV
