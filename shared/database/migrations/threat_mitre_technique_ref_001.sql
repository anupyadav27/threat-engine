-- =============================================================================
-- Migration: threat_mitre_technique_ref_001  (REWORKED — additive ALTER)
-- Target DB: threat_engine_threat
-- Phase:     JNY-01 (main) — applied AFTER JNY-01a (threat_findings_mitre_parent_001a.sql).
--
-- Purpose:   Augment the EXISTING `mitre_technique_reference` catalog with
--            columns required by JNY-01 TechniqueDetailModal + MITRE matrix UI.
--
-- IMPORTANT — DO NOT DROP OR REPLACE THE TABLE:
--   `mitre_technique_reference` already exists in production with 102 curated
--   rows and 21 columns (see MV-1 verification 2026-05-04). This migration is
--   strictly ADDITIVE: ALTER ADD COLUMN IF NOT EXISTS, idempotent backfills,
--   guarded constraints, additive indexes. No DROP, no DELETE, no UPDATE that
--   would overwrite curated values.
--
--   The authoritative documented shape lives in
--   shared/database/schemas/threat_mitre_reference_schema.sql (target schema —
--   live schema = legacy CREATE + this migration).
--
-- Standard-columns rule: EXEMPT (global reference catalog — see CSPM_CONSTITUTION).
--
-- Lock window: ~1 second. The table is small (102 rows) and all ALTERs are
--   metadata-only (ADD COLUMN with constant DEFAULT in PG >= 11 = no rewrite).
--   The `VALIDATE CONSTRAINT` step requires a brief SHARE UPDATE EXCLUSIVE lock
--   while it scans 102 rows — sub-second.
--
-- Rollback (sibling file threat_mitre_technique_ref_001_rollback.sql):
--   BEGIN;
--   DROP INDEX IF EXISTS idx_mtr_not_revoked;
--   DROP INDEX IF EXISTS idx_mtr_kill_chain_gin;
--   DROP INDEX IF EXISTS idx_mtr_tactics_gin;
--   DROP INDEX IF EXISTS idx_mtr_parent;
--   ALTER TABLE mitre_technique_reference DROP CONSTRAINT IF EXISTS mtr_technique_id_fmt;
--   ALTER TABLE mitre_technique_reference DROP CONSTRAINT IF EXISTS mtr_parent_fk;
--   ALTER TABLE mitre_technique_reference
--       DROP COLUMN IF EXISTS parent_id,
--       DROP COLUMN IF EXISTS is_subtechnique,
--       DROP COLUMN IF EXISTS kill_chain_phases,
--       DROP COLUMN IF EXISTS mitigations,
--       DROP COLUMN IF EXISTS d3fend_mappings,
--       DROP COLUMN IF EXISTS revoked,
--       DROP COLUMN IF EXISTS deprecated,
--       DROP COLUMN IF EXISTS version,
--       DROP COLUMN IF EXISTS last_modified;
--   COMMIT;
--
-- Author: cspm-db-engineer  Date: 2026-05-04  Postgres: >= 15
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. Add new columns (additive, IF NOT EXISTS-guarded)
-- -----------------------------------------------------------------------------
ALTER TABLE mitre_technique_reference
    ADD COLUMN IF NOT EXISTS parent_id          VARCHAR(20),
    ADD COLUMN IF NOT EXISTS is_subtechnique    BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS kill_chain_phases  JSONB       NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS mitigations        JSONB       NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS d3fend_mappings    JSONB       NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS revoked            BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS deprecated         BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS version            VARCHAR(16),
    ADD COLUMN IF NOT EXISTS last_modified      TIMESTAMPTZ;

COMMENT ON COLUMN mitre_technique_reference.parent_id IS
    'Soft self-FK to parent technique for sub-techniques (e.g. T1078.004 -> T1078). NULL for parent techniques.';
COMMENT ON COLUMN mitre_technique_reference.is_subtechnique IS
    'Denormalized flag: TRUE iff technique_id is a sub-technique. Avoids recursive CTEs on parent-only listings.';
COMMENT ON COLUMN mitre_technique_reference.kill_chain_phases IS
    'Ordered MITRE kill-chain phases for attack-path UI sorting. Distinct from `tactics` (unordered set).';
COMMENT ON COLUMN mitre_technique_reference.mitigations IS
    'Per-technique MITRE mitigations (e.g. M1018). Distinct from `remediation_guidance` which is per-rule.';
COMMENT ON COLUMN mitre_technique_reference.d3fend_mappings IS
    'D3FEND countermeasure mappings for this technique.';
COMMENT ON COLUMN mitre_technique_reference.revoked IS
    'STIX revoked flag — technique was withdrawn from the framework.';
COMMENT ON COLUMN mitre_technique_reference.deprecated IS
    'STIX deprecated flag — technique still exists but is superseded.';
COMMENT ON COLUMN mitre_technique_reference.version IS
    'ATT&CK feed version this row was sourced from (e.g. v15.1).';
COMMENT ON COLUMN mitre_technique_reference.last_modified IS
    'STIX last-modified timestamp for the technique.';

-- -----------------------------------------------------------------------------
-- 2. Idempotent backfills (run once, WHERE clauses make re-runs no-ops)
-- -----------------------------------------------------------------------------

-- 2a. Mark existing sub-techniques (technique_id contains '.')
UPDATE mitre_technique_reference
SET    is_subtechnique = TRUE
WHERE  technique_id ~ '\.[0-9]{3,4}$'
  AND  is_subtechnique = FALSE;

-- 2b. Populate parent_id for sub-techniques (split on '.')
UPDATE mitre_technique_reference
SET    parent_id = split_part(technique_id, '.', 1)
WHERE  technique_id ~ '\.[0-9]{3,4}$'
  AND  parent_id IS NULL;

-- -----------------------------------------------------------------------------
-- 3. Soft self-FK on parent_id (guarded — IF NOT EXISTS via DO block)
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'mtr_parent_fk'
    ) THEN
        ALTER TABLE mitre_technique_reference
            ADD CONSTRAINT mtr_parent_fk
            FOREIGN KEY (parent_id)
            REFERENCES mitre_technique_reference(technique_id)
            ON DELETE SET NULL
            DEFERRABLE INITIALLY DEFERRED;
    END IF;
END $$;

-- -----------------------------------------------------------------------------
-- 4. Format CHECK on technique_id
--    Added NOT VALID first (avoids scanning live data with an exclusive lock),
--    then VALIDATE separately. Existing rows are MITRE-curated so they pass; if
--    any historical row violated, the VALIDATE step would fail loudly and we'd
--    know without losing the constraint definition.
-- -----------------------------------------------------------------------------
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'mtr_technique_id_fmt'
    ) THEN
        ALTER TABLE mitre_technique_reference
            ADD CONSTRAINT mtr_technique_id_fmt
            CHECK (technique_id ~ '^T[0-9]{4}(\.[0-9]{3,4})?$')
            NOT VALID;
    END IF;
END $$;

-- Validate against the existing 102 rows. This will fail the migration if any
-- legacy row has a malformed technique_id — that is the desired behaviour.
ALTER TABLE mitre_technique_reference
    VALIDATE CONSTRAINT mtr_technique_id_fmt;

-- -----------------------------------------------------------------------------
-- 5. Indexes (additive, IF NOT EXISTS)
-- -----------------------------------------------------------------------------

-- Hot path: parent rollup lookups (TechniqueDetailModal sub-technique list)
CREATE INDEX IF NOT EXISTS idx_mtr_parent
    ON mitre_technique_reference(parent_id)
    WHERE parent_id IS NOT NULL;

-- GIN on existing `tactics` JSONB column — only created if absent.
-- (Existing schema may not have one; safe additive.)
CREATE INDEX IF NOT EXISTS idx_mtr_tactics_gin
    ON mitre_technique_reference USING GIN (tactics);

-- GIN on the new kill_chain_phases column for attack-path UI sorting.
CREATE INDEX IF NOT EXISTS idx_mtr_kill_chain_gin
    ON mitre_technique_reference USING GIN (kill_chain_phases);

-- Partial: not revoked AND not deprecated — covers UI dropdown / matrix lookups.
CREATE INDEX IF NOT EXISTS idx_mtr_not_revoked
    ON mitre_technique_reference(technique_id)
    WHERE revoked = FALSE AND deprecated = FALSE;

COMMIT;
