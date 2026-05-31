-- Migration: di_012_attack_ontology
-- Adds the attack ontology two-axis framework:
--   Axis A: Attack Entry Points (is_attack_entry_point, attack_entry_point_category)
--   Axis B: Attack Targets     (is_attack_target, attack_target_category)
--
-- Renames:
--   is_internet_exposed → is_attack_entry_point  (broader: covers all 6 entry types)
--   is_crown_jewel      → is_attack_target        (ontology term)
--   crown_jewel_type    → attack_target_category  (symmetric naming)
--
-- Old columns kept as deprecated read aliases. Dropped in di_013 after all engines updated.

BEGIN;

-- ── 1. New table: resource_ontology_catalog ─────────────────────────────────────
-- DB-driven classification rules (same pattern as resource_relationship_catalog).
-- condition_* columns make classification logic fully data-driven.
CREATE TABLE IF NOT EXISTS resource_ontology_catalog (
    id                     BIGSERIAL    PRIMARY KEY,
    csp                    VARCHAR(64)  NOT NULL,
    resource_type          VARCHAR(255) NOT NULL,
    entry_point_category   VARCHAR(64),
    attack_target_category VARCHAR(64),
    is_conditional         BOOLEAN      NOT NULL DEFAULT FALSE,
    condition_field        VARCHAR(255),
    condition_value        VARCHAR(255),
    condition_operator     VARCHAR(32)  NOT NULL DEFAULT 'eq',
    description            TEXT,
    is_active              BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at             TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- Unique index using COALESCE to handle NULLs in the category columns
CREATE UNIQUE INDEX IF NOT EXISTS uq_roc_csp_type_categories
    ON resource_ontology_catalog (
        csp,
        resource_type,
        COALESCE(entry_point_category,   ''),
        COALESCE(attack_target_category, '')
    );

CREATE INDEX IF NOT EXISTS idx_roc_csp_type_active
    ON resource_ontology_catalog (csp, resource_type)
    WHERE is_active = TRUE;

-- ── 2. asset_relationships: promote JSONB fields to real columns ─────────────────
ALTER TABLE asset_relationships
    ADD COLUMN IF NOT EXISTS relationship_category VARCHAR(64),
    ADD COLUMN IF NOT EXISTS attack_path_category  VARCHAR(64),
    ADD COLUMN IF NOT EXISTS evidence_field_path   TEXT,
    ADD COLUMN IF NOT EXISTS evidence_value        TEXT,
    ADD COLUMN IF NOT EXISTS resolution_status     VARCHAR(32) NOT NULL DEFAULT 'unresolved',
    ADD COLUMN IF NOT EXISTS confidence            VARCHAR(20) NOT NULL DEFAULT 'medium';

CREATE INDEX IF NOT EXISTS idx_ar_resolution_status
    ON asset_relationships (tenant_id, resolution_status);

CREATE INDEX IF NOT EXISTS idx_ar_attack_path_category
    ON asset_relationships (tenant_id, attack_path_category)
    WHERE attack_path_category IS NOT NULL;

-- Backfill existing rows from relation_metadata JSONB
UPDATE asset_relationships
SET
    attack_path_category = relation_metadata->>'attack_path_category',
    resolution_status    = 'resolved'
WHERE relation_metadata IS NOT NULL
  AND relation_metadata->>'attack_path_category' IS NOT NULL
  AND resolution_status = 'unresolved';

-- ── 3. resource_security_posture: add new columns + backfill ────────────────────

-- Axis A: Attack Entry Point
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS is_attack_entry_point       BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS attack_entry_point_category VARCHAR(64);

-- Backfill from deprecated is_internet_exposed
UPDATE resource_security_posture
SET
    is_attack_entry_point       = TRUE,
    attack_entry_point_category = 'INTERNET_ENTRY'
WHERE is_internet_exposed = TRUE;

-- Axis B: Attack Target
ALTER TABLE resource_security_posture
    ADD COLUMN IF NOT EXISTS is_attack_target       BOOLEAN     NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS attack_target_category VARCHAR(64);

-- Backfill from deprecated is_crown_jewel / crown_jewel_type
UPDATE resource_security_posture
SET
    is_attack_target       = TRUE,
    attack_target_category = crown_jewel_type
WHERE is_crown_jewel = TRUE;

-- Indexes on new posture columns
CREATE INDEX IF NOT EXISTS idx_rsp_is_attack_entry_point
    ON resource_security_posture (tenant_id, is_attack_entry_point)
    WHERE is_attack_entry_point = TRUE;

CREATE INDEX IF NOT EXISTS idx_rsp_entry_point_category
    ON resource_security_posture (tenant_id, attack_entry_point_category)
    WHERE attack_entry_point_category IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_rsp_is_attack_target
    ON resource_security_posture (tenant_id, is_attack_target)
    WHERE is_attack_target = TRUE;

CREATE INDEX IF NOT EXISTS idx_rsp_attack_target_category
    ON resource_security_posture (tenant_id, attack_target_category)
    WHERE attack_target_category IS NOT NULL;

-- ── 4. resource_relationship_catalog: add resolver metadata columns ──────────────
ALTER TABLE resource_relationship_catalog
    ADD COLUMN IF NOT EXISTS source_identifier_field VARCHAR(255),
    ADD COLUMN IF NOT EXISTS target_value_transform  VARCHAR(255) NOT NULL DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS resolution_required     BOOLEAN      NOT NULL DEFAULT TRUE,
    ADD COLUMN IF NOT EXISTS confidence              VARCHAR(20)  NOT NULL DEFAULT 'high';

COMMIT;

-- Verification
SELECT
    'resource_ontology_catalog'    AS tbl, COUNT(*) AS col_count
    FROM information_schema.columns WHERE table_name = 'resource_ontology_catalog'
UNION ALL
SELECT
    'asset_relationships new cols' AS tbl,
    COUNT(*) FROM information_schema.columns
    WHERE table_name = 'asset_relationships'
      AND column_name IN ('relationship_category','attack_path_category',
                          'evidence_field_path','evidence_value',
                          'resolution_status','confidence')
UNION ALL
SELECT
    'posture new cols' AS tbl,
    COUNT(*) FROM information_schema.columns
    WHERE table_name = 'resource_security_posture'
      AND column_name IN ('is_attack_entry_point','attack_entry_point_category',
                          'is_attack_target','attack_target_category')
UNION ALL
SELECT
    'catalog new cols' AS tbl,
    COUNT(*) FROM information_schema.columns
    WHERE table_name = 'resource_relationship_catalog'
      AND column_name IN ('source_identifier_field','target_value_transform',
                          'resolution_required','confidence');
