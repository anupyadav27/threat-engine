-- ============================================================================
-- Schema: threat_v1 tables (canonical schema-of-record)
-- Database: threat_engine_threat
-- Purpose: Defines the 6 new tables introduced by the threat_v1 engine.
--
-- This file is the authoritative schema definition. The migration at
--   shared/database/migrations/threat_v1_001_new_tables.sql
-- applies it. Do not run this file directly against a live database —
-- use the migration file which wraps DDL in BEGIN/COMMIT and includes
-- post-migration verification checks.
--
-- Tables defined here:
--   threat_incidents             — primary finding table (standard columns)
--   threat_scenario_patterns     — global pattern catalog (runtime YAML copy)
--   threat_scan_runs_v1          — per-scan execution metadata
--   threat_pattern_suppressions  — per-tenant pattern suppression (CP1-05)
--   threat_crown_jewels          — crown jewel overrides per tenant (CP1-03)
--   threat_incident_feedback     — immutable analyst feedback audit log
--
-- Security constraints:
--   CP1-02  actor_principal is PII; stored in evidence JSONB only, never
--           a bare column accessible without cdr:sensitive permission
--   CP1-03  crown jewel resource_uid validated against resource_inventory
--           at API layer before INSERT
--   CP1-05  threat_scenario_patterns.active=false is a GLOBAL flag;
--           automated quarantine writes to threat_pattern_suppressions only
--   SR-001  PerformanceGuard uses threat_pattern_suppressions, not active=false
--
-- Existing tables NOT touched by this migration:
--   threat_report, threat_findings, threat_detections, threat_analysis,
--   threat_intelligence, threat_hunt_queries, threat_hunt_results,
--   mitre_technique_reference  (all defined in the v0 engine schema)
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- threat_scenario_patterns
-- Global table — no tenant_id. Patterns apply to all tenants.
-- Per-tenant suppression is in threat_pattern_suppressions.
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_scenario_patterns (
    pattern_id              UUID                        PRIMARY KEY DEFAULT gen_random_uuid(),
    pattern_key             VARCHAR(100)                NOT NULL,
    tier                    SMALLINT                    NOT NULL
                                CHECK (tier IN (1, 2, 3)),
    severity_base           VARCHAR(20)
                                CHECK (severity_base IN ('critical', 'high', 'medium', 'low')),
    confidence              VARCHAR(20)
                                CHECK (confidence IN ('confirmed', 'theoretical', 'emerging')),
    pattern_yaml            TEXT                        NOT NULL,
    compiled_cypher         TEXT,
    mitre_techniques        JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    mitre_tactics           JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    tactic_chain_order      JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    csps                    JSONB                       NOT NULL DEFAULT '["aws","azure","gcp","oci","alicloud"]'::jsonb,
    -- GLOBAL active flag. CP1-05: NEVER set to false via automated code.
    active                  BOOLEAN                     NOT NULL DEFAULT true,
    version                 VARCHAR(20)                 NOT NULL DEFAULT '1.0',
    deprecated_at           TIMESTAMPTZ,
    created_at              TIMESTAMPTZ                 NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ                 NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_threat_scenario_pattern_key UNIQUE (pattern_key)
);

CREATE INDEX IF NOT EXISTS idx_tsp_active
    ON threat_scenario_patterns(active) WHERE active = true;
CREATE INDEX IF NOT EXISTS idx_tsp_tier
    ON threat_scenario_patterns(tier);
CREATE INDEX IF NOT EXISTS idx_tsp_csps_gin
    ON threat_scenario_patterns USING GIN(csps);
CREATE INDEX IF NOT EXISTS idx_tsp_mitre_techniques_gin
    ON threat_scenario_patterns USING GIN(mitre_techniques);
CREATE INDEX IF NOT EXISTS idx_tsp_updated_at
    ON threat_scenario_patterns(updated_at DESC);


-- ============================================================================
-- threat_incidents
-- Primary finding table. Standard CSPM_CONSTITUTION §2 columns.
-- dedup_key is GENERATED ALWAYS AS STORED (IMMUTABLE sha256 expression).
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_incidents (
    incident_id             UUID                        PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Standard finding columns (CSPM_CONSTITUTION §2)
    scan_run_id             VARCHAR(255),
    tenant_id               VARCHAR(255)                NOT NULL,
    account_id              VARCHAR(512),
    credential_ref          VARCHAR(512),
    credential_type         VARCHAR(50),
    provider                VARCHAR(50),
    region                  VARCHAR(100),
    entry_resource_uid      TEXT,
    resource_uid            TEXT
                                GENERATED ALWAYS AS (entry_resource_uid) STORED,
    resource_type           VARCHAR(100),
    severity                VARCHAR(20)                 NOT NULL
                                CHECK (severity IN ('critical', 'high', 'medium', 'low')),
    status                  VARCHAR(20)                 NOT NULL DEFAULT 'open'
                                CHECK (status IN ('new', 'open', 'suspicious', 'active', 'resolved', 'reopened')),
    first_seen_at           TIMESTAMPTZ                 NOT NULL DEFAULT NOW(),
    last_seen_at            TIMESTAMPTZ                 NOT NULL DEFAULT NOW(),
    -- threat_v1 specific
    incident_class          VARCHAR(50)                 NOT NULL
                                CHECK (incident_class IN ('posture', 'suspicious', 'active')),
    tier                    SMALLINT                    CHECK (tier IN (1, 2, 3)),
    title                   TEXT,
    risk_score              INTEGER                     NOT NULL DEFAULT 50
                                CHECK (risk_score >= 0 AND risk_score <= 100),
    score_breakdown         JSONB                       NOT NULL DEFAULT '{}'::jsonb,
    pattern_id              UUID                        REFERENCES threat_scenario_patterns(pattern_id) ON DELETE SET NULL,
    pattern_version         SMALLINT,
    matched_pattern_ids     JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    target_resource_uid     TEXT,
    attack_path             JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    mitre_tactics           JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    mitre_techniques        JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    tactic_chain            JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    misconfig_finding_ids   JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    vuln_finding_ids        JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    cdr_event_ids           JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    input_scan_runs         JSONB                       NOT NULL DEFAULT '{}'::jsonb,
    evidence                JSONB                       NOT NULL DEFAULT '{"_schema_version":1}'::jsonb,
    story_text              TEXT,
    -- actor_principal is PII (CP1-02): stripped from list responses; detail
    -- endpoint requires cdr:sensitive permission. ADR-005.
    actor_principal         VARCHAR(512),
    recommendations         JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    resolved_at             TIMESTAMPTZ,
    -- IMMUTABLE sha256 GENERATED STORED column (CSPM_CONSTITUTION §2)
    dedup_key               VARCHAR(64)
                                GENERATED ALWAYS AS (
                                    encode(
                                        sha256(
                                            (incident_class || '|' ||
                                             COALESCE(entry_resource_uid, '') || '|' ||
                                             tenant_id
                                            )::bytea
                                        ),
                                        'hex'
                                    )
                                ) STORED,
    CONSTRAINT uq_threat_incidents_dedup_key UNIQUE (dedup_key)
);

CREATE INDEX IF NOT EXISTS idx_ti_tenant_id        ON threat_incidents(tenant_id);
CREATE INDEX IF NOT EXISTS idx_ti_scan_run_id       ON threat_incidents(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_ti_tenant_account    ON threat_incidents(tenant_id, account_id);
CREATE INDEX IF NOT EXISTS idx_ti_severity          ON threat_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_ti_status            ON threat_incidents(status);
CREATE INDEX IF NOT EXISTS idx_ti_incident_class    ON threat_incidents(incident_class);
CREATE INDEX IF NOT EXISTS idx_ti_tier              ON threat_incidents(tier);
CREATE INDEX IF NOT EXISTS idx_ti_status_severity   ON threat_incidents(status, severity);
CREATE INDEX IF NOT EXISTS idx_ti_entry_resource_uid ON threat_incidents(entry_resource_uid);
CREATE INDEX IF NOT EXISTS idx_ti_target_resource_uid ON threat_incidents(target_resource_uid);
CREATE INDEX IF NOT EXISTS idx_ti_dedup_key         ON threat_incidents(dedup_key);
CREATE INDEX IF NOT EXISTS idx_ti_pattern_id        ON threat_incidents(pattern_id);
CREATE INDEX IF NOT EXISTS idx_ti_last_seen_at      ON threat_incidents(last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_ti_first_seen_at     ON threat_incidents(first_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_ti_risk_score        ON threat_incidents(risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_ti_evidence_gin      ON threat_incidents USING GIN(evidence);
CREATE INDEX IF NOT EXISTS idx_ti_mitre_techniques_gin ON threat_incidents USING GIN(mitre_techniques);
CREATE INDEX IF NOT EXISTS idx_ti_mitre_tactics_gin ON threat_incidents USING GIN(mitre_tactics);
CREATE INDEX IF NOT EXISTS idx_ti_matched_patterns_gin ON threat_incidents USING GIN(matched_pattern_ids);


-- ============================================================================
-- threat_scan_runs_v1
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_scan_runs_v1 (
    id                          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id                 VARCHAR(255)    NOT NULL,
    tenant_id                   VARCHAR(255)    NOT NULL,
    account_id                  VARCHAR(512),
    mode                        VARCHAR(20)     NOT NULL DEFAULT 'full'
                                    CHECK (mode IN ('full', 'cdr-update')),
    status                      VARCHAR(20)     NOT NULL DEFAULT 'running'
                                    CHECK (status IN ('running', 'completed', 'failed')),
    graph_node_count            INTEGER,
    graph_edge_count            INTEGER,
    graph_build_duration_s      INTEGER,
    pattern_execution_duration_s INTEGER,
    incident_count              INTEGER         NOT NULL DEFAULT 0,
    patterns_evaluated          INTEGER         NOT NULL DEFAULT 0,
    patterns_fired              INTEGER         NOT NULL DEFAULT 0,
    patterns_timed_out          INTEGER         NOT NULL DEFAULT 0,
    patterns_suppressed         INTEGER         NOT NULL DEFAULT 0,
    started_at                  TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    completed_at                TIMESTAMPTZ,
    error_detail                TEXT,
    CONSTRAINT uq_threat_scan_run_tenant UNIQUE (scan_run_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_tsrv1_tenant_id      ON threat_scan_runs_v1(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tsrv1_scan_run_id    ON threat_scan_runs_v1(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_tsrv1_status         ON threat_scan_runs_v1(status);
CREATE INDEX IF NOT EXISTS idx_tsrv1_started_at     ON threat_scan_runs_v1(started_at DESC);
CREATE INDEX IF NOT EXISTS idx_tsrv1_tenant_started ON threat_scan_runs_v1(tenant_id, started_at DESC);


-- ============================================================================
-- threat_pattern_suppressions
-- Per-tenant suppression (CP1-05 / ADR-003).
-- Auto-quarantine (FeedbackProcessor + PerformanceGuard) writes here only.
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_pattern_suppressions (
    suppression_id          UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               VARCHAR(255)    NOT NULL,
    pattern_key             VARCHAR(100)    NOT NULL,
    reason                  TEXT,
    auto_generated          BOOLEAN         NOT NULL DEFAULT false,
    created_by              VARCHAR(255),
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    expires_at              TIMESTAMPTZ,
    CONSTRAINT uq_threat_pattern_suppression UNIQUE (tenant_id, pattern_key)
);

CREATE INDEX IF NOT EXISTS idx_tps_tenant_id        ON threat_pattern_suppressions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tps_pattern_key      ON threat_pattern_suppressions(pattern_key);
CREATE INDEX IF NOT EXISTS idx_tps_tenant_pattern   ON threat_pattern_suppressions(tenant_id, pattern_key);
CREATE INDEX IF NOT EXISTS idx_tps_expires_at       ON threat_pattern_suppressions(expires_at) WHERE expires_at IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_tps_auto_generated   ON threat_pattern_suppressions(auto_generated);


-- ============================================================================
-- threat_crown_jewels
-- Per-tenant crown jewel overrides.
-- Ownership validation at API layer before INSERT (CP1-03).
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_crown_jewels (
    id                      UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               VARCHAR(255)    NOT NULL,
    resource_uid            TEXT            NOT NULL,
    classification_source   VARCHAR(50)     NOT NULL DEFAULT 'auto'
                                CHECK (classification_source IN ('auto', 'manual')),
    reason                  TEXT,
    created_by              VARCHAR(255),
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_threat_crown_jewels_tenant_resource UNIQUE (tenant_id, resource_uid)
);

CREATE INDEX IF NOT EXISTS idx_tcj_tenant_id        ON threat_crown_jewels(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tcj_resource_uid     ON threat_crown_jewels(resource_uid);
CREATE INDEX IF NOT EXISTS idx_tcj_tenant_resource  ON threat_crown_jewels(tenant_id, resource_uid);
CREATE INDEX IF NOT EXISTS idx_tcj_source           ON threat_crown_jewels(classification_source);


-- ============================================================================
-- threat_incident_feedback
-- Immutable analyst feedback audit log. INSERT-only — no UPDATEs.
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_incident_feedback (
    feedback_id             UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id             UUID            NOT NULL
                                REFERENCES threat_incidents(incident_id) ON DELETE CASCADE,
    tenant_id               VARCHAR(255)    NOT NULL,
    feedback_type           VARCHAR(20)     NOT NULL
                                CHECK (feedback_type IN ('true_positive', 'false_positive', 'acknowledged')),
    analyst_id              VARCHAR(255),
    reason                  TEXT,
    created_at              TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tif_incident_id          ON threat_incident_feedback(incident_id);
CREATE INDEX IF NOT EXISTS idx_tif_tenant_id            ON threat_incident_feedback(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tif_tenant_incident      ON threat_incident_feedback(tenant_id, incident_id);
CREATE INDEX IF NOT EXISTS idx_tif_tenant_type_created  ON threat_incident_feedback(tenant_id, feedback_type, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_tif_analyst_created      ON threat_incident_feedback(analyst_id, created_at DESC) WHERE analyst_id IS NOT NULL;


-- ============================================================================
-- TRIGGERS
-- ============================================================================
CREATE OR REPLACE FUNCTION update_threat_v1_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_tsp_updated_at ON threat_scenario_patterns;
CREATE TRIGGER trg_tsp_updated_at
    BEFORE UPDATE ON threat_scenario_patterns
    FOR EACH ROW EXECUTE FUNCTION update_threat_v1_updated_at();

DROP TRIGGER IF EXISTS trg_tcj_updated_at ON threat_crown_jewels;
CREATE TRIGGER trg_tcj_updated_at
    BEFORE UPDATE ON threat_crown_jewels
    FOR EACH ROW EXECUTE FUNCTION update_threat_v1_updated_at();
