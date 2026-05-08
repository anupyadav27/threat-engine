-- =============================================================================
-- Schema: mitre_technique_reference  (canonical reference DDL)
-- Database: threat_engine_threat
--
-- This file is the canonical schema-of-record for the MITRE ATT&CK technique
-- reference table. The migration at
--   shared/database/migrations/threat_mitre_technique_ref_001.sql
-- applies it. Edits here MUST be paired with a forward migration; never run
-- this file directly against a non-empty database.
--
-- Standard-columns rule: EXEMPT.
--   This is a GLOBAL reference / catalog table. The standard-columns rule
--   (finding_id, scan_run_id, tenant_id, account_id, credential_ref,
--    credential_type, provider, region, resource_uid, resource_type,
--    severity, status, first_seen_at, last_seen_at) applies to engine
--   FINDING tables only. Reference tables are explicitly exempt — see
--   .claude/documentation/CSPM_CONSTITUTION.md (database design section).
--   Per-tenant filtering for MITRE views happens on threat_findings, which
--   carries the standard columns and joins to this catalog by technique_id.
-- =============================================================================

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

CREATE INDEX IF NOT EXISTS idx_mtr_parent
    ON mitre_technique_reference(parent_id);

CREATE INDEX IF NOT EXISTS idx_mtr_tactics_gin
    ON mitre_technique_reference USING GIN (tactic_ids);

CREATE INDEX IF NOT EXISTS idx_mtr_kill_chain_gin
    ON mitre_technique_reference USING GIN (kill_chain_phases);

CREATE INDEX IF NOT EXISTS idx_mtr_not_revoked
    ON mitre_technique_reference(technique_id)
    WHERE revoked = FALSE AND deprecated = FALSE;
