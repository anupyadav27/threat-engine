-- ============================================================================
-- Migration: threat_v1_001_new_tables
-- Database:  threat_engine_threat
-- Purpose:   Create threat_v1 new tables for the threat detection engine v1.
--            Adds: threat_incidents, threat_scenario_patterns,
--                  threat_scan_runs_v1, threat_pattern_suppressions,
--                  threat_crown_jewels, threat_incident_feedback
--
-- References:
--   ARCHITECTURE.md §5.2    — table column definitions
--   SPRINT_PLAN.md S1-02    — story requirements
--   CSPM_CONSTITUTION §2    — standard columns, IMMUTABLE generated columns
--   SECURITY_REVIEW_PRE_IMPL.md SR-001 — per-tenant suppression only
--   SECURITY_REVIEW_PRE_IMPL.md CP1-05 — global active=false forbidden on
--                                         auto-quarantine
--
-- DDL Rules applied:
--   1. Standard finding-table columns where applicable (per CONSTITUTION §2):
--        finding_id, scan_run_id, tenant_id, account_id, provider, region,
--        resource_uid, resource_type, severity, status, first_seen_at, last_seen_at
--      threat_incidents satisfies the standard columns pattern as the primary
--      finding table for this engine.
--
--   2. GENERATED ALWAYS AS ... STORED requires an IMMUTABLE expression.
--      sha256() on a text concatenation IS immutable — safe for STORED columns.
--      DO NOT use EXTRACT(HOUR FROM timestamptz_col) — that is NOT immutable.
--
--   3. All timestamps: TIMESTAMPTZ DEFAULT NOW()
--
--   4. Multi-tenant: every table has tenant_id NOT NULL with an index.
--
--   5. threat_pattern_suppressions is the ONLY place where per-tenant
--      pattern suppression is written. The threat_scenario_patterns.active
--      column is a GLOBAL flag that may only be set to false by a human
--      with Security Architect approval (CP1-05 / ADR-003).
--
-- Apply via:
--   kubectl cp /tmp/threat_v1_001_new_tables.sql \
--       threat-engine-engines/<pod>:/tmp/threat_v1_001_new_tables.sql
--   kubectl exec -n threat-engine-engines <pod> -- psql \
--       -h $THREAT_DB_HOST -U $THREAT_DB_USER -d $THREAT_DB_NAME \
--       -f /tmp/threat_v1_001_new_tables.sql
--
-- Post-apply check:
--   kubectl logs -l job-name=threat-v1-migration-001 | tail -5
--   Last line must be: MIGRATION COMPLETE: threat_v1_001_new_tables
-- ============================================================================

BEGIN;

-- Ensure pgcrypto is available for sha256() — already present in threat DB
-- but we guard idempotently.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- TABLE 1: threat_scenario_patterns
-- Runtime copy of YAML pattern catalog loaded by upload_scenario_patterns.py.
-- This is a GLOBAL table (no tenant_id) — patterns apply to all tenants.
-- Per-tenant suppression is in threat_pattern_suppressions (separate table).
-- active=false is a GLOBAL flag — only set by human with SA approval (CP1-05).
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_scenario_patterns (
    -- Primary key: stable pattern identifier from YAML id field (e.g. 'PAT-AWS-001')
    pattern_id              UUID                        PRIMARY KEY DEFAULT gen_random_uuid(),
    pattern_key             VARCHAR(100)                NOT NULL,
    tier                    SMALLINT                    NOT NULL
                                CHECK (tier IN (1, 2, 3)),
    severity_base           VARCHAR(20)
                                CHECK (severity_base IN ('critical', 'high', 'medium', 'low')),
    confidence              VARCHAR(20)
                                CHECK (confidence IN ('confirmed', 'theoretical', 'emerging')),
    -- Full YAML source text — source of truth; Postgres is the runtime copy
    pattern_yaml            TEXT                        NOT NULL,
    -- Parameterized Cypher template populated by PatternCompiler (S2-02)
    compiled_cypher         TEXT,
    mitre_techniques        JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    mitre_tactics           JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    tactic_chain_order      JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    csps                    JSONB                       NOT NULL DEFAULT '["aws","azure","gcp","oci","alicloud"]'::jsonb,
    -- GLOBAL active flag.
    -- CP1-05 / ADR-003: this must NEVER be set to false by automated code.
    -- Auto-quarantine (FeedbackProcessor, PerformanceGuard) writes to
    -- threat_pattern_suppressions instead. Only a human with SA approval
    -- may set active=false here.
    active                  BOOLEAN                     NOT NULL DEFAULT true,
    version                 VARCHAR(20)                 NOT NULL DEFAULT '1.0',
    deprecated_at           TIMESTAMPTZ,
    created_at              TIMESTAMPTZ                 NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ                 NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_threat_scenario_pattern_key UNIQUE (pattern_key)
);

COMMENT ON TABLE threat_scenario_patterns IS
    'Runtime copy of YAML threat detection patterns. Global table — no tenant_id. '
    'Per-tenant suppression is in threat_pattern_suppressions. '
    'active=false requires Security Architect approval (CP1-05/ADR-003).';

COMMENT ON COLUMN threat_scenario_patterns.active IS
    'GLOBAL flag. CP1-05: NEVER set to false via automated code. '
    'Use threat_pattern_suppressions for per-tenant auto-quarantine.';

CREATE INDEX IF NOT EXISTS idx_tsp_active
    ON threat_scenario_patterns(active)
    WHERE active = true;

CREATE INDEX IF NOT EXISTS idx_tsp_tier
    ON threat_scenario_patterns(tier);

CREATE INDEX IF NOT EXISTS idx_tsp_csps_gin
    ON threat_scenario_patterns USING GIN(csps);

CREATE INDEX IF NOT EXISTS idx_tsp_mitre_techniques_gin
    ON threat_scenario_patterns USING GIN(mitre_techniques);

CREATE INDEX IF NOT EXISTS idx_tsp_updated_at
    ON threat_scenario_patterns(updated_at DESC);


-- ============================================================================
-- TABLE 2: threat_incidents
-- Primary finding table for threat_v1. One row per deduplicated incident.
-- Satisfies CSPM_CONSTITUTION §2 standard columns requirement.
--
-- dedup_key is a GENERATED STORED column. The expression:
--   encode(sha256((incident_class||'|'||entry_resource_uid||'|'||tenant_id)::bytea), 'hex')
-- is IMMUTABLE because:
--   - sha256() from pgcrypto is IMMUTABLE
--   - string concatenation with || on text/varchar is IMMUTABLE
--   - CAST to bytea of a text expression is IMMUTABLE
-- This satisfies CSPM_CONSTITUTION §2 and SPRINT_PLAN.md S1-02 DoD item 3.
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_incidents (
    -- Standard PK
    incident_id             UUID                        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- -----------------------------------------------------------------------
    -- Standard finding-table columns (CSPM_CONSTITUTION §2)
    -- -----------------------------------------------------------------------
    -- finding_id is the canonical "finding" identifier for this engine.
    -- We alias it to incident_id via a generated column for cross-engine
    -- compatibility while keeping incident_id as the primary concept.
    scan_run_id             VARCHAR(255),
    tenant_id               VARCHAR(255)                NOT NULL,
    account_id              VARCHAR(512),
    -- credential_ref is not applicable for threat_v1 (reads other DBs,
    -- does not perform cloud API scans) — kept NULL per ARCHITECTURE.md §2
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

    -- -----------------------------------------------------------------------
    -- threat_v1 specific columns
    -- -----------------------------------------------------------------------
    incident_class          VARCHAR(50)                 NOT NULL
                                CHECK (incident_class IN ('posture', 'suspicious', 'active')),
    tier                    SMALLINT                    CHECK (tier IN (1, 2, 3)),
    title                   TEXT,
    risk_score              INTEGER                     NOT NULL DEFAULT 50
                                CHECK (risk_score >= 0 AND risk_score <= 100),
    score_breakdown         JSONB                       NOT NULL DEFAULT '{}'::jsonb,

    -- Pattern references
    pattern_id              UUID                        REFERENCES threat_scenario_patterns(pattern_id) ON DELETE SET NULL,
    pattern_version         SMALLINT,
    matched_pattern_ids     JSONB                       NOT NULL DEFAULT '[]'::jsonb,

    -- Attack path columns
    target_resource_uid     TEXT,
    attack_path             JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    mitre_tactics           JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    mitre_techniques        JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    tactic_chain            JSONB                       NOT NULL DEFAULT '[]'::jsonb,

    -- Evidence linking (IDs from source engine tables)
    misconfig_finding_ids   JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    vuln_finding_ids        JSONB                       NOT NULL DEFAULT '[]'::jsonb,
    cdr_event_ids           JSONB                       NOT NULL DEFAULT '[]'::jsonb,

    -- input_scan_runs tracks which scan_run_id per engine contributed to
    -- this incident: {check: id, vuln: id, cdr: id, inventory: id}
    input_scan_runs         JSONB                       NOT NULL DEFAULT '{}'::jsonb,

    -- Full evidence blob with schema versioning (W-08: _schema_version=1)
    evidence                JSONB                       NOT NULL DEFAULT '{"_schema_version":1}'::jsonb,

    -- Human-readable narrative (populated by StoryBuilder S2-09)
    story_text              TEXT,

    -- actor_principal is PII — stored in evidence JSONB under cdr_events[].
    -- It is gated behind cdr:sensitive permission at the API layer (CP1-02).
    -- It is NOT a direct column here to enforce structural PII separation.
    -- The ARCHITECTURE.md §5.2 column listing is for evidence JSONB, not a
    -- bare column — this design choice aligns with ADR-005.
    actor_principal         VARCHAR(512),               -- PII: only populated from CDR; stripped from list responses by IncidentListItem model (CP1-02)

    -- Recommendations list (ordered action items)
    recommendations         JSONB                       NOT NULL DEFAULT '[]'::jsonb,

    -- Lifecycle timestamps
    resolved_at             TIMESTAMPTZ,

    -- -----------------------------------------------------------------------
    -- Deduplication key — GENERATED STORED (IMMUTABLE expression)
    -- sha256 of text concat is IMMUTABLE; pgcrypto sha256() is IMMUTABLE.
    -- dedup_key identifies one "attack scenario" per tenant:
    --   incident_class | entry_resource_uid | tenant_id
    -- This grouping means two patterns detecting the same resource in the same
    -- class are rolled up (multi-pattern roll-up per S2-07).
    -- -----------------------------------------------------------------------
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

COMMENT ON TABLE threat_incidents IS
    'Primary finding table for threat_v1. One row per deduplicated incident. '
    'dedup_key is a sha256 GENERATED STORED column grouping incident_class + '
    'entry_resource_uid + tenant_id. Standard CSPM_CONSTITUTION §2 columns present.';

COMMENT ON COLUMN threat_incidents.actor_principal IS
    'PII (IAM ARN / email). Stripped from IncidentListItem responses (CP1-02). '
    'Only returned on IncidentDetail endpoint with cdr:sensitive permission.';

COMMENT ON COLUMN threat_incidents.dedup_key IS
    'IMMUTABLE sha256 of (incident_class|entry_resource_uid|tenant_id). '
    'Used by IncidentDeduper for ON CONFLICT DO UPDATE upsert (S2-08).';

COMMENT ON COLUMN threat_incidents.evidence IS
    'Full evidence JSONB. Always contains _schema_version=1 (W-08). '
    'Fields: misconfig_findings[], vuln_findings[], cdr_events[] (PII-gated), '
    'path_resources[], matched_patterns[].';

-- Standard tenant + scan indexes
CREATE INDEX IF NOT EXISTS idx_ti_tenant_id
    ON threat_incidents(tenant_id);

CREATE INDEX IF NOT EXISTS idx_ti_scan_run_id
    ON threat_incidents(scan_run_id);

CREATE INDEX IF NOT EXISTS idx_ti_tenant_account
    ON threat_incidents(tenant_id, account_id);

-- List query indexes (Zone B incident list in BFF threat_center view)
CREATE INDEX IF NOT EXISTS idx_ti_severity
    ON threat_incidents(severity);

CREATE INDEX IF NOT EXISTS idx_ti_status
    ON threat_incidents(status);

CREATE INDEX IF NOT EXISTS idx_ti_incident_class
    ON threat_incidents(incident_class);

CREATE INDEX IF NOT EXISTS idx_ti_tier
    ON threat_incidents(tier);

-- Status + severity compound (most common filter combo in Zone A)
CREATE INDEX IF NOT EXISTS idx_ti_status_severity
    ON threat_incidents(status, severity);

-- Resource lookups (inventory Threat tab: find incidents by resource_uid)
CREATE INDEX IF NOT EXISTS idx_ti_entry_resource_uid
    ON threat_incidents(entry_resource_uid);

CREATE INDEX IF NOT EXISTS idx_ti_target_resource_uid
    ON threat_incidents(target_resource_uid);

-- Dedup key lookup (IncidentDeduper ON CONFLICT)
CREATE INDEX IF NOT EXISTS idx_ti_dedup_key
    ON threat_incidents(dedup_key);

-- Pattern lookups
CREATE INDEX IF NOT EXISTS idx_ti_pattern_id
    ON threat_incidents(pattern_id);

-- Time-based queries (last_seen_at DESC for BFF list ordering)
CREATE INDEX IF NOT EXISTS idx_ti_last_seen_at
    ON threat_incidents(last_seen_at DESC);

CREATE INDEX IF NOT EXISTS idx_ti_first_seen_at
    ON threat_incidents(first_seen_at DESC);

-- Risk score (prominent display per CONSTITUTION §3.2)
CREATE INDEX IF NOT EXISTS idx_ti_risk_score
    ON threat_incidents(risk_score DESC);

-- JSONB GIN indexes for evidence and MITRE fields
CREATE INDEX IF NOT EXISTS idx_ti_evidence_gin
    ON threat_incidents USING GIN(evidence);

CREATE INDEX IF NOT EXISTS idx_ti_mitre_techniques_gin
    ON threat_incidents USING GIN(mitre_techniques);

CREATE INDEX IF NOT EXISTS idx_ti_mitre_tactics_gin
    ON threat_incidents USING GIN(mitre_tactics);

CREATE INDEX IF NOT EXISTS idx_ti_matched_patterns_gin
    ON threat_incidents USING GIN(matched_pattern_ids);


-- ============================================================================
-- TABLE 3: threat_scan_runs_v1
-- Per-scan run metadata for the threat_v1 engine.
-- Records graph build and pattern execution metrics per (scan_run_id, tenant_id).
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_scan_runs_v1 (
    id                          UUID                PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id                 VARCHAR(255)        NOT NULL,
    tenant_id                   VARCHAR(255)        NOT NULL,
    account_id                  VARCHAR(512),
    -- 'full' = triggered by main Argo pipeline after Check+Vuln
    -- 'cdr-update' = triggered by CDR CronWorkflow (ARCHITECTURE.md §10.2)
    mode                        VARCHAR(20)         NOT NULL DEFAULT 'full'
                                    CHECK (mode IN ('full', 'cdr-update')),
    status                      VARCHAR(20)         NOT NULL DEFAULT 'running'
                                    CHECK (status IN ('running', 'completed', 'failed')),

    -- Graph build metrics
    graph_node_count            INTEGER,
    graph_edge_count            INTEGER,
    graph_build_duration_s      INTEGER,

    -- Pattern execution metrics
    pattern_execution_duration_s INTEGER,
    incident_count              INTEGER             NOT NULL DEFAULT 0,
    patterns_evaluated          INTEGER             NOT NULL DEFAULT 0,
    patterns_fired              INTEGER             NOT NULL DEFAULT 0,
    patterns_timed_out          INTEGER             NOT NULL DEFAULT 0,
    patterns_suppressed         INTEGER             NOT NULL DEFAULT 0,

    started_at                  TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    completed_at                TIMESTAMPTZ,
    error_detail                TEXT,

    CONSTRAINT uq_threat_scan_run_tenant UNIQUE (scan_run_id, tenant_id)
);

COMMENT ON TABLE threat_scan_runs_v1 IS
    'Per-scan execution record for threat_v1. One row per (scan_run_id, tenant_id). '
    'status=completed required for S5-06 smoke test assertion.';

CREATE INDEX IF NOT EXISTS idx_tsrv1_tenant_id
    ON threat_scan_runs_v1(tenant_id);

CREATE INDEX IF NOT EXISTS idx_tsrv1_scan_run_id
    ON threat_scan_runs_v1(scan_run_id);

CREATE INDEX IF NOT EXISTS idx_tsrv1_status
    ON threat_scan_runs_v1(status);

CREATE INDEX IF NOT EXISTS idx_tsrv1_started_at
    ON threat_scan_runs_v1(started_at DESC);

CREATE INDEX IF NOT EXISTS idx_tsrv1_tenant_started
    ON threat_scan_runs_v1(tenant_id, started_at DESC);


-- ============================================================================
-- TABLE 4: threat_pattern_suppressions
-- Per-tenant pattern suppression — NOT global.
-- This is the ONLY mechanism for automated pattern quarantine (SR-001, CP1-05).
--
-- Created by:
--   - FeedbackProcessor: when rolling-30d FP rate > 30% for a tenant (S2-10)
--   - PerformanceGuard:  when pattern exceeds p99 budget 3 consecutive runs (S2-06)
--     NOTE (SR-001 fix): PerformanceGuard inserts here with auto_generated=true,
--     reason='performance_p99_exceeded'. It MUST NOT set active=false on the
--     shared threat_scenario_patterns row.
--   - Analyst API: manual suppression via POST /api/v1/patterns/{id}/suppress
--
-- PatternRegistry.load_active_patterns(tenant_id) excludes pattern_keys found
-- in this table for the given tenant. Other tenants are unaffected.
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_pattern_suppressions (
    suppression_id          UUID                PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               VARCHAR(255)        NOT NULL,
    -- pattern_key references threat_scenario_patterns.pattern_key
    -- FK on pattern_key (not pattern_id UUID) so suppressions survive
    -- pattern re-imports (which may regenerate UUIDs).
    pattern_key             VARCHAR(100)        NOT NULL,
    reason                  TEXT,
    -- auto_generated=true: inserted by FeedbackProcessor or PerformanceGuard
    -- auto_generated=false: inserted by analyst via API
    auto_generated          BOOLEAN             NOT NULL DEFAULT false,
    created_by              VARCHAR(255),
    created_at              TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    -- expires_at=NULL means indefinite suppression
    expires_at              TIMESTAMPTZ,

    CONSTRAINT uq_threat_pattern_suppression UNIQUE (tenant_id, pattern_key)
);

COMMENT ON TABLE threat_pattern_suppressions IS
    'Per-tenant pattern suppression. CP1-05 / ADR-003: auto-quarantine ALWAYS '
    'writes here, never to threat_scenario_patterns.active. '
    'PatternRegistry joins this table on (tenant_id, pattern_key) when loading '
    'active patterns — suppressed patterns are excluded for that tenant only.';

COMMENT ON COLUMN threat_pattern_suppressions.auto_generated IS
    'true = created by FeedbackProcessor (FP rate > 30%) or PerformanceGuard '
    '(p99 exceeded 3 consecutive runs). false = analyst manual suppression.';

CREATE INDEX IF NOT EXISTS idx_tps_tenant_id
    ON threat_pattern_suppressions(tenant_id);

CREATE INDEX IF NOT EXISTS idx_tps_pattern_key
    ON threat_pattern_suppressions(pattern_key);

CREATE INDEX IF NOT EXISTS idx_tps_tenant_pattern
    ON threat_pattern_suppressions(tenant_id, pattern_key);

CREATE INDEX IF NOT EXISTS idx_tps_expires_at
    ON threat_pattern_suppressions(expires_at)
    WHERE expires_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_tps_auto_generated
    ON threat_pattern_suppressions(auto_generated);


-- ============================================================================
-- TABLE 5: threat_crown_jewels
-- Crown jewel classification overrides per tenant.
-- auto-classification comes from CrownJewelClassifier; manual from API.
-- Ownership validated at API layer (CP1-03): resource_uid must exist in
--   resource_inventory WHERE tenant_id = auth_ctx.tenant_id before INSERT.
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_crown_jewels (
    id                      UUID                PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               VARCHAR(255)        NOT NULL,
    resource_uid            TEXT                NOT NULL,
    -- 'auto' = set by CrownJewelClassifier (DB-driven logic)
    -- 'manual' = set by analyst via POST /api/v1/crown-jewels (CP1-03)
    classification_source   VARCHAR(50)         NOT NULL DEFAULT 'auto'
                                CHECK (classification_source IN ('auto', 'manual')),
    reason                  TEXT,
    created_by              VARCHAR(255),
    created_at              TIMESTAMPTZ         NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ         NOT NULL DEFAULT NOW(),

    CONSTRAINT uq_threat_crown_jewels_tenant_resource UNIQUE (tenant_id, resource_uid)
);

COMMENT ON TABLE threat_crown_jewels IS
    'Crown jewel resource overrides per tenant. '
    'Ownership validation required before INSERT (CP1-03): '
    'resource_uid must exist in resource_inventory WHERE tenant_id = auth_ctx.tenant_id. '
    'Returns 404 (not 403) on mismatch to avoid confirming foreign resource existence.';

CREATE INDEX IF NOT EXISTS idx_tcj_tenant_id
    ON threat_crown_jewels(tenant_id);

CREATE INDEX IF NOT EXISTS idx_tcj_resource_uid
    ON threat_crown_jewels(resource_uid);

CREATE INDEX IF NOT EXISTS idx_tcj_tenant_resource
    ON threat_crown_jewels(tenant_id, resource_uid);

CREATE INDEX IF NOT EXISTS idx_tcj_source
    ON threat_crown_jewels(classification_source);


-- ============================================================================
-- TABLE 6: threat_incident_feedback
-- Analyst FP/TP feedback per incident.
-- INSERT-only (immutable audit log) — no UPDATE ever.
-- Rate-limited at endpoint: 10 verdicts/user/24h (W-09).
-- FeedbackProcessor reads rolling 30d FP rate from this table per (tenant_id, pattern_key).
-- ============================================================================
CREATE TABLE IF NOT EXISTS threat_incident_feedback (
    feedback_id             UUID                PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id             UUID                NOT NULL
                                REFERENCES threat_incidents(incident_id) ON DELETE CASCADE,
    tenant_id               VARCHAR(255)        NOT NULL,
    -- verdict: analyst's classification of the incident
    feedback_type           VARCHAR(20)         NOT NULL
                                CHECK (feedback_type IN ('true_positive', 'false_positive', 'acknowledged')),
    -- analyst_id from AuthContext (user ID, not email — avoids PII in audit log)
    analyst_id              VARCHAR(255),
    reason                  TEXT,
    created_at              TIMESTAMPTZ         NOT NULL DEFAULT NOW()
    -- No updated_at — INSERT-only table. FeedbackProcessor reads, never updates.
);

COMMENT ON TABLE threat_incident_feedback IS
    'Immutable analyst feedback audit log. INSERT-only — no UPDATEs ever. '
    'Rate limit: 10 verdicts/user/24h enforced at endpoint layer (W-09). '
    'FeedbackProcessor reads rolling 30d FP rate per (tenant_id, pattern_key) '
    'and inserts into threat_pattern_suppressions when rate > 30% (CP1-05).';

COMMENT ON COLUMN threat_incident_feedback.analyst_id IS
    'User ID from AuthContext. Not raw email (avoids PII in audit log). '
    'Maps to platform users table for display purposes.';

CREATE INDEX IF NOT EXISTS idx_tif_incident_id
    ON threat_incident_feedback(incident_id);

CREATE INDEX IF NOT EXISTS idx_tif_tenant_id
    ON threat_incident_feedback(tenant_id);

CREATE INDEX IF NOT EXISTS idx_tif_tenant_incident
    ON threat_incident_feedback(tenant_id, incident_id);

-- FeedbackProcessor rolling 30d FP rate query needs this compound index:
-- WHERE tenant_id = :tid AND feedback_type = 'false_positive'
--   AND created_at >= NOW() - INTERVAL '30 days'
CREATE INDEX IF NOT EXISTS idx_tif_tenant_type_created
    ON threat_incident_feedback(tenant_id, feedback_type, created_at DESC);

-- Rate limit check: 10 verdicts/user/24h — endpoint reads by analyst_id + tenant
CREATE INDEX IF NOT EXISTS idx_tif_analyst_created
    ON threat_incident_feedback(analyst_id, created_at DESC)
    WHERE analyst_id IS NOT NULL;


-- ============================================================================
-- UPDATED_AT TRIGGER for threat_scenario_patterns and threat_crown_jewels
-- (other tables are either INSERT-only or use explicit column updates)
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


-- ============================================================================
-- TABLE COMMENTS SUMMARY
-- ============================================================================
COMMENT ON TABLE threat_scenario_patterns IS
    'Global pattern catalog (runtime copy of YAML files). '
    'active=false = global deactivation, requires SA approval (CP1-05).';

COMMENT ON TABLE threat_incidents IS
    'Primary threat_v1 finding table. Standard CSPM_CONSTITUTION §2 columns. '
    'dedup_key = sha256 GENERATED STORED (IMMUTABLE). UNIQUE ON (dedup_key).';

COMMENT ON TABLE threat_scan_runs_v1 IS
    'One row per (scan_run_id, tenant_id) execution of the threat_v1 engine.';

COMMENT ON TABLE threat_pattern_suppressions IS
    'Per-tenant suppression table. CP1-05: auto-quarantine writes here only.';

COMMENT ON TABLE threat_crown_jewels IS
    'Crown jewel overrides. Ownership-validated at API (CP1-03).';

COMMENT ON TABLE threat_incident_feedback IS
    'Immutable analyst feedback audit log. INSERT-only.';


-- ============================================================================
-- VERIFY: confirm all 6 new tables exist
-- ============================================================================
DO $$
DECLARE
    table_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO table_count
    FROM information_schema.tables
    WHERE table_schema = 'public'
      AND table_name IN (
          'threat_incidents',
          'threat_scenario_patterns',
          'threat_scan_runs_v1',
          'threat_pattern_suppressions',
          'threat_crown_jewels',
          'threat_incident_feedback'
      );

    IF table_count < 6 THEN
        RAISE EXCEPTION 'MIGRATION FAILED: only % of 6 expected tables found', table_count;
    END IF;

    RAISE NOTICE 'Verification passed: % / 6 threat_v1 tables present', table_count;
END $$;


-- ============================================================================
-- VERIFY: dedup_key is a GENERATED STORED column on threat_incidents
-- ============================================================================
DO $$
DECLARE
    col_generation TEXT;
BEGIN
    SELECT generation_expression INTO col_generation
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'threat_incidents'
      AND column_name = 'dedup_key';

    IF col_generation IS NULL THEN
        RAISE EXCEPTION 'MIGRATION FAILED: dedup_key is not a GENERATED STORED column on threat_incidents';
    END IF;

    RAISE NOTICE 'dedup_key GENERATED STORED column confirmed on threat_incidents';
END $$;


-- ============================================================================
-- FULL TABLE LIST: verify query (returns all threat_* tables in public schema)
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE '--- threat_v1 table inventory ---';
END $$;

SELECT table_name
FROM information_schema.tables
WHERE table_name LIKE 'threat_%'
  AND table_schema = 'public'
ORDER BY table_name;


COMMIT;


-- ============================================================================
-- MIGRATION COMPLETE MARKER
-- The kubectl logs check looks for this exact string:
--   kubectl logs -l job-name=threat-v1-migration | tail -3
-- ============================================================================
DO $$
BEGIN
    RAISE NOTICE 'MIGRATION COMPLETE: threat_v1_001_new_tables';
END $$;
