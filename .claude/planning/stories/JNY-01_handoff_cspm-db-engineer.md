# JNY-01 Handoff — cspm-db-engineer (RESPONSIBLE)

**To:** bmad-architect (A), threat-engine (C), bmad-security-architect (C)
**From:** cspm-db-engineer
**Re:** Migration draft for `mitre_technique_reference` + `threat_findings` parent-technique generated column
**Phase:** DESIGN — not yet applied

## 1. Forward migration SQL (full file content)

**Path:** `/Users/apple/Desktop/threat-engine/shared/database/migrations/threat_mitre_technique_ref_001.sql`

```sql
-- =============================================================================
-- Migration: threat_mitre_technique_ref_001
-- Target DB: threat_engine_threat
-- Purpose:   Create mitre_technique_reference (global) + add generated parent
--            column to threat_findings + supporting indexes for technique
--            lookup and per-tenant rollup counts (TechniqueDetailModal — JNY-01).
--
-- Standard-columns rule: EXEMPT.
--   mitre_technique_reference is a GLOBAL reference table — no tenant_id,
--   account_id, scan_run_id, etc. Per-tenant filtering happens on
--   threat_findings only. Documented exception per CSPM_CONSTITUTION
--   (database design / standard columns section).
--
-- Author:    cspm-db-engineer  Date: 2026-05-04
-- Postgres:  >= 15 (RDS confirmed)  Generated columns: STORED
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. Reference table
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS mitre_technique_reference (
    technique_id        VARCHAR(20) PRIMARY KEY,
    parent_id           VARCHAR(20),
    name                VARCHAR(255) NOT NULL,
    description         TEXT,
    is_subtechnique     BOOLEAN      NOT NULL DEFAULT FALSE,
    tactic_ids          JSONB        NOT NULL DEFAULT '[]'::jsonb,
    kill_chain_phases   JSONB        NOT NULL DEFAULT '[]'::jsonb,
    platforms           JSONB        NOT NULL DEFAULT '[]'::jsonb,
    data_sources        JSONB        NOT NULL DEFAULT '[]'::jsonb,
    detection           TEXT,
    mitigations         JSONB        NOT NULL DEFAULT '[]'::jsonb,
    d3fend_mappings     JSONB        NOT NULL DEFAULT '[]'::jsonb,
    url                 VARCHAR(512),
    version             VARCHAR(16),
    revoked             BOOLEAN      NOT NULL DEFAULT FALSE,
    deprecated          BOOLEAN      NOT NULL DEFAULT FALSE,
    last_modified       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT mtr_technique_id_format
        CHECK (technique_id ~ '^T[0-9]{4}(\.[0-9]{3,4})?$'),
    CONSTRAINT mtr_parent_id_format
        CHECK (parent_id IS NULL OR parent_id ~ '^T[0-9]{4}$'),
    CONSTRAINT mtr_subtechnique_consistency
        CHECK ((is_subtechnique = TRUE  AND parent_id IS NOT NULL)
            OR (is_subtechnique = FALSE AND parent_id IS NULL)),
    CONSTRAINT fk_mtr_parent
        FOREIGN KEY (parent_id)
        REFERENCES mitre_technique_reference(technique_id)
        ON DELETE SET NULL
        DEFERRABLE INITIALLY DEFERRED
);

COMMENT ON TABLE  mitre_technique_reference IS
    'Global MITRE ATT&CK technique catalog. No tenant_id by design — reference data shared across all tenants. Seeded from bundled STIX 2.1 snapshot, refreshed monthly by threat engine cron.';
COMMENT ON COLUMN mitre_technique_reference.is_subtechnique IS
    'Denormalized flag: TRUE iff parent_id IS NOT NULL. Avoids self-join on hot path.';
COMMENT ON COLUMN mitre_technique_reference.kill_chain_phases IS
    'Ordered MITRE kill-chain phases for attack-path UI sorting. Distinct from tactic_ids (unordered set).';

-- -----------------------------------------------------------------------------
-- 2. Indexes on reference table
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_mtr_parent
    ON mitre_technique_reference(parent_id);

CREATE INDEX IF NOT EXISTS idx_mtr_tactics_gin
    ON mitre_technique_reference USING GIN (tactic_ids);

CREATE INDEX IF NOT EXISTS idx_mtr_kill_chain_gin
    ON mitre_technique_reference USING GIN (kill_chain_phases);

-- Partial: active (not revoked, not deprecated) — covers UI dropdown lookups
CREATE INDEX IF NOT EXISTS idx_mtr_active
    ON mitre_technique_reference(technique_id)
    WHERE revoked = FALSE AND deprecated = FALSE;

-- -----------------------------------------------------------------------------
-- 3. ALTER threat_findings — generated parent column (STORED)
--    Per threat-engine handoff §3+§4: rollup count is the hottest BFF query.
--    Same migration: index is useless without the column.
-- -----------------------------------------------------------------------------
ALTER TABLE threat_findings
    ADD COLUMN IF NOT EXISTS mitre_parent_technique VARCHAR(20)
    GENERATED ALWAYS AS (split_part(mitre_technique, '.', 1)) STORED;

COMMENT ON COLUMN threat_findings.mitre_parent_technique IS
    'Generated STORED parent technique (e.g. T1078 from T1078.004). Powers per-tenant rollup KPI without LIKE scans.';

-- -----------------------------------------------------------------------------
-- 4. Indexes on threat_findings — partial (status='OPEN') for KPI hot path
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_threat_findings_tenant_technique
    ON threat_findings(tenant_id, mitre_technique)
    WHERE status = 'OPEN';

CREATE INDEX IF NOT EXISTS idx_threat_findings_tenant_parent_technique
    ON threat_findings(tenant_id, mitre_parent_technique)
    WHERE status = 'OPEN';

COMMIT;
```

## 2. Rollback strategy

Sibling file `threat_mitre_technique_ref_001_rollback.sql` (manual apply only):

```sql
BEGIN;
DROP INDEX IF EXISTS idx_threat_findings_tenant_parent_technique;
DROP INDEX IF EXISTS idx_threat_findings_tenant_technique;
ALTER TABLE threat_findings DROP COLUMN IF EXISTS mitre_parent_technique;
DROP INDEX IF EXISTS idx_mtr_active;
DROP INDEX IF EXISTS idx_mtr_kill_chain_gin;
DROP INDEX IF EXISTS idx_mtr_tactics_gin;
DROP INDEX IF EXISTS idx_mtr_parent;
DROP TABLE IF EXISTS mitre_technique_reference;
COMMIT;
```
Reverse order: indexes on `threat_findings` → generated column → reference indexes → reference table. Self-FK drops cleanly with the table.

## 3. Performance impact

**`mitre_technique_reference`** — empty at create, ~700 rows after seed (Enterprise v15.1: ~210 parents + ~470 subs). Disk < 5 MB including JSONB. Negligible.

**`threat_findings` ALTER ADD GENERATED STORED** — full table rewrite under `ACCESS EXCLUSIVE` (Postgres 15 cannot add a STORED generated column as metadata-only).

Pre-migration sizing query (run on apply day, abort if `total > 2 GB`):
```sql
SELECT pg_size_pretty(pg_total_relation_size('threat_findings')) AS total,
       (SELECT count(*) FROM threat_findings) AS rows,
       pg_size_pretty(pg_relation_size('threat_findings')) AS heap;
```

Estimate (sibling ciem table ≈ 1.7M rows; threat_findings typically 10–30%): ~300k–500k rows, ~150–300 MB.
- Full rewrite on RDS gp3: ~30–90 s ACCESS EXCLUSIVE.
- Two partial indexes on 300k rows (in-transaction, non-CONCURRENT): ~5–10 s each.
- **Total estimated lock window: 60–120 seconds.**

**Recommendation:** off-peak only; pause Argo `cspm-pipeline` for the duration. If table > 5M rows, split into JNY-01a using a regular column + backfill batch + trigger to avoid the long lock.

## 4. Standard columns rule check

`mitre_technique_reference` is a global reference table — no `tenant_id`, `account_id`, `scan_run_id`, `provider`, etc. The standard-columns rule applies to *finding* tables (CLAUDE.md "Standardized Column Names — ALL engine finding tables"). Reference/catalog tables are exempt. Documented in:
- Migration header (above)
- `COMMENT ON TABLE` (visible in `\d+`)
- Schema doc at `shared/database/schemas/threat_mitre_reference_schema.sql` (separate file per hard-rule, mirrors CREATE TABLE + rationale).

## 5. Seed loader sketch

**Path:** `/Users/apple/Desktop/threat-engine/engines/threat/scripts/load_mitre_reference.py`

```python
"""Idempotent MITRE ATT&CK reference loader.

Reads bundled CSV (shared/database/seeds/mitre_technique_reference.csv) and
upserts into mitre_technique_reference. Safe to run on every pod start;
no-op when CSV unchanged (last_modified IS DISTINCT FROM short-circuits).
"""
from __future__ import annotations
import csv, json, logging, os
from typing import Iterator
import psycopg2
from psycopg2.extras import execute_values

CHUNK = 500
SEED_PATH = os.environ.get(
    "MITRE_SEED_CSV",
    "/app/shared/database/seeds/mitre_technique_reference.csv",
)

UPSERT_SQL = """
INSERT INTO mitre_technique_reference (
    technique_id, parent_id, name, description, is_subtechnique,
    tactic_ids, kill_chain_phases, platforms, data_sources,
    detection, mitigations, d3fend_mappings, url, version,
    revoked, deprecated, last_modified
) VALUES %s
ON CONFLICT (technique_id) DO UPDATE SET
    parent_id         = EXCLUDED.parent_id,
    name              = EXCLUDED.name,
    description       = EXCLUDED.description,
    is_subtechnique   = EXCLUDED.is_subtechnique,
    tactic_ids        = EXCLUDED.tactic_ids,
    kill_chain_phases = EXCLUDED.kill_chain_phases,
    platforms         = EXCLUDED.platforms,
    data_sources      = EXCLUDED.data_sources,
    detection         = EXCLUDED.detection,
    mitigations       = EXCLUDED.mitigations,
    d3fend_mappings   = EXCLUDED.d3fend_mappings,
    url               = EXCLUDED.url,
    version           = EXCLUDED.version,
    revoked           = EXCLUDED.revoked,
    deprecated        = EXCLUDED.deprecated,
    last_modified     = EXCLUDED.last_modified,
    updated_at        = NOW()
WHERE mitre_technique_reference.last_modified IS DISTINCT FROM EXCLUDED.last_modified;
"""

def _rows(path: str) -> Iterator[tuple]:
    with open(path, newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            yield (
                r["technique_id"], r["parent_id"] or None,
                r["name"], r.get("description") or None,
                r["is_subtechnique"].lower() == "true",
                r["tactic_ids"] or "[]",
                r["kill_chain_phases"] or "[]",
                r["platforms"] or "[]",
                r["data_sources"] or "[]",
                r.get("detection") or None,
                r["mitigations"] or "[]",
                r["d3fend_mappings"] or "[]",
                r.get("url") or None, r.get("version") or None,
                r["revoked"].lower() == "true",
                r["deprecated"].lower() == "true",
                r["last_modified"] or None,
            )

def load(conn) -> int:
    """Single-transaction load — DEFERRABLE FK satisfied at COMMIT."""
    n = 0
    with conn.cursor() as cur:
        batch: list = []
        for row in _rows(SEED_PATH):
            batch.append(row)
            if len(batch) >= CHUNK:
                execute_values(cur, UPSERT_SQL, batch)
                n += len(batch); batch.clear()
        if batch:
            execute_values(cur, UPSERT_SQL, batch); n += len(batch)
    conn.commit()
    logging.info("mitre_technique_reference: upserted %d rows", n)
    return n
```

Idempotency proof: re-running with unchanged CSV → `last_modified IS DISTINCT FROM` is FALSE → zero-row UPDATE → row count stable. Self-FK satisfied because the entire load runs in one transaction with DEFERRABLE INITIALLY DEFERRED; chunk order does not matter.

## 6. Open questions / decisions

- **Q to bmad-architect:** confirm threat_findings size estimate before apply day. If `pg_total_relation_size > 2 GB`, split STORED-column ADD into JNY-01a (regular column + backfill + trigger) to avoid the long ACCESS EXCLUSIVE.
- threat-engine §7 location question: loader lives engine-local (`engines/threat/scripts/`); CSV lives at `shared/database/seeds/` per hard-rule. Loader reads CSV via env-overridable `MITRE_SEED_CSV`.
- threat-engine §7 grep for `threat_scan_id` — out of scope for JNY-01; will file a separate ticket if any references found in BFF/engine.

---

JNY-01 cspm-db-engineer: migration drafted at /Users/apple/Desktop/threat-engine/.claude/planning/stories/JNY-01_handoff_cspm-db-engineer.md. Lock window estimate: 60–120 seconds. Open question: confirm threat_findings total size < 2 GB before apply, else split STORED-column ADD into JNY-01a.
