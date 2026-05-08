-- =============================================================================
-- Migration: threat_finding_techniques_001a
-- Target DB: threat_engine_threat
-- Phase:     JNY-01a — junction table redesign (replaces _mitre_parent_001a).
--
-- Background:
--   Production schema (verified 2026-05-04 via psql):
--     threat_findings.mitre_techniques  jsonb DEFAULT '[]'  -- list of strings
--     threat_findings.finding_id        VARCHAR(255) UNIQUE (FK target)
--     threat_findings.tenant_id         VARCHAR(255) NOT NULL
--   Earlier design assumed a singular VARCHAR mitre_technique column. That
--   column does NOT exist; the live data is a JSONB array. Adding a generated
--   STORED column on top of jsonb_array_elements is not possible in Postgres
--   15 (generated expressions cannot be SET-RETURNING), so we model the M:N
--   relation explicitly via a junction table.
--
-- Why a junction table (final decision, not subject to alternative proposals):
--   - Supports both EXACT match (technique_id = 'T1078') and PARENT ROLLUP
--     (parent_technique_id = 'T1078') in O(log n) via plain btree indexes.
--   - No JSONB path operators, no LIKE scans, no GIN over arrays of strings.
--   - Trivially extensible (e.g. add provenance, confidence per technique).
--   - Sync kept atomic via AFTER trigger on threat_findings (see below).
--
-- Lock window:
--   - CREATE TABLE / INDEX / FUNCTION / TRIGGER: short, metadata-only.
--   - Backfill is a single INSERT … SELECT scanning ~9k rows. With 25 mapping
--     rows produced (verified pre-flight), expected duration < 1 second.
--   - No ACCESS EXCLUSIVE on threat_findings beyond the trigger creation
--     itself (which is metadata-only, sub-second).
--
-- Pre-flight (already executed against production 2026-05-04):
--   total threat_findings rows .................. 9285
--   findings with non-empty mitre_techniques .... 32
--   junction rows the backfill will produce ..... 25  (3 stripped by regex)
--
-- Rollback:
--   BEGIN;
--   DROP TRIGGER IF EXISTS trg_sync_threat_finding_techniques ON threat_findings;
--   DROP FUNCTION IF EXISTS sync_threat_finding_techniques();
--   DROP TABLE IF EXISTS threat_finding_techniques;
--   COMMIT;
--
-- Author: cspm-db-engineer + threat-engine specialist  Date: 2026-05-04
-- =============================================================================

BEGIN;

-- 1. Junction table -----------------------------------------------------------
--    technique_id format gate is enforced via CHECK; bad rows from upstream
--    would fail the INSERT, but the backfill + trigger both filter via the
--    same regex first, so this is belt-and-braces.
CREATE TABLE IF NOT EXISTS threat_finding_techniques (
    finding_id           VARCHAR(255) NOT NULL,
    tenant_id            VARCHAR(255) NOT NULL,    -- matches threat_findings.tenant_id type
    technique_id         VARCHAR(20)  NOT NULL,
    parent_technique_id  VARCHAR(20)  NOT NULL,    -- = split_part(technique_id,'.',1)
    is_subtechnique      BOOLEAN      NOT NULL,
    created_at           TIMESTAMPTZ  NOT NULL DEFAULT now(),
    PRIMARY KEY (finding_id, technique_id),
    CONSTRAINT fk_tft_finding
        FOREIGN KEY (finding_id) REFERENCES threat_findings(finding_id) ON DELETE CASCADE,
    CONSTRAINT chk_tft_technique_id_format
        CHECK (technique_id ~ '^T[0-9]{4}(\.[0-9]{3,4})?$'),
    CONSTRAINT chk_tft_parent_consistency
        CHECK (parent_technique_id = split_part(technique_id, '.', 1)),
    CONSTRAINT chk_tft_subtech_flag
        CHECK (is_subtechnique = (technique_id LIKE '%.%'))
);

COMMENT ON TABLE threat_finding_techniques IS
    'M:N junction between threat_findings and MITRE technique IDs. Kept in sync '
    'with threat_findings.mitre_techniques (JSONB) by trigger '
    'trg_sync_threat_finding_techniques. Powers TechniqueDetailModal exact-match '
    'and parent-rollup counts without scanning JSONB arrays. Added by migration '
    'threat_finding_techniques_001a (replaces threat_findings_mitre_parent_001a, '
    'which was withdrawn after the singular-column assumption failed in production).';

-- 2. Indexes ------------------------------------------------------------------
--    Covering both exact-match and parent-rollup query paths. tenant_id leads
--    every index because all reads are tenant-scoped (RLS-by-convention).
CREATE INDEX IF NOT EXISTS idx_tft_tenant_technique
    ON threat_finding_techniques(tenant_id, technique_id);

CREATE INDEX IF NOT EXISTS idx_tft_tenant_parent_technique
    ON threat_finding_techniques(tenant_id, parent_technique_id);

-- Reverse lookup (a finding's technique set) — used by the trigger's DELETE.
CREATE INDEX IF NOT EXISTS idx_tft_finding_id
    ON threat_finding_techniques(finding_id);

-- 3. Backfill from existing threat_findings.mitre_techniques ------------------
--    Defensive: regex filter drops any non-conforming element so a single bad
--    row cannot abort the whole migration. ON CONFLICT DO NOTHING keeps the
--    migration idempotent if re-applied.
INSERT INTO threat_finding_techniques (
    finding_id, tenant_id, technique_id, parent_technique_id, is_subtechnique
)
SELECT
    tf.finding_id,
    tf.tenant_id,
    elem AS technique_id,
    split_part(elem, '.', 1) AS parent_technique_id,
    (elem LIKE '%.%') AS is_subtechnique
FROM threat_findings tf,
     jsonb_array_elements_text(tf.mitre_techniques) AS elem
WHERE tf.mitre_techniques IS NOT NULL
  AND jsonb_typeof(tf.mitre_techniques) = 'array'
  AND elem ~ '^T[0-9]{4}(\.[0-9]{3,4})?$'
ON CONFLICT (finding_id, technique_id) DO NOTHING;

-- 4. Sync trigger -------------------------------------------------------------
--    Chosen over engine-writer code change because:
--      a) atomic with the threat_findings write (same transaction);
--      b) covers ALL writers (threat engine, future fix engines, manual SQL);
--      c) zero engine deploy needed; rollback is purely a SQL drop.
--    Trade-off: small per-row overhead. With < 50 techniques per finding
--    typical, well below the JSONB write cost itself.
CREATE OR REPLACE FUNCTION sync_threat_finding_techniques() RETURNS TRIGGER AS $$
BEGIN
    -- Replace strategy: simpler than diffing old vs new arrays, and the
    -- junction is small per row. PK conflict still impossible because of
    -- the prior DELETE.
    DELETE FROM threat_finding_techniques WHERE finding_id = NEW.finding_id;

    IF NEW.mitre_techniques IS NOT NULL
       AND jsonb_typeof(NEW.mitre_techniques) = 'array' THEN
        INSERT INTO threat_finding_techniques (
            finding_id, tenant_id, technique_id, parent_technique_id, is_subtechnique
        )
        SELECT
            NEW.finding_id,
            NEW.tenant_id,
            elem,
            split_part(elem, '.', 1),
            (elem LIKE '%.%')
        FROM jsonb_array_elements_text(NEW.mitre_techniques) AS elem
        WHERE elem ~ '^T[0-9]{4}(\.[0-9]{3,4})?$'
        ON CONFLICT (finding_id, technique_id) DO NOTHING;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_sync_threat_finding_techniques ON threat_findings;
CREATE TRIGGER trg_sync_threat_finding_techniques
    AFTER INSERT OR UPDATE OF mitre_techniques ON threat_findings
    FOR EACH ROW EXECUTE FUNCTION sync_threat_finding_techniques();

COMMIT;
