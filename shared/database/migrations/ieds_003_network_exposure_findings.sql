-- =============================================================================
-- IEDS-M03: Internet & External Exposure Detection System
-- Database: threat_engine_network
-- Table:    network_exposure_findings
-- =============================================================================
-- Stores per-resource exposure findings produced by the network engine IEDS
-- evaluator. Written during each network scan, read by:
--   - attack-path engine BFS (replaces _mark_internet_exposed_from_discoveries)
--   - resource_security_posture updates (is_internet_exposed flag)
--   - security_findings unified layer (origin_type=internet findings)
--   - BFF /views/network for exposure summary cards
-- =============================================================================

BEGIN;

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS network_exposure_findings (
    finding_id          UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_run_id         VARCHAR(255) NOT NULL,
    tenant_id           VARCHAR(255) NOT NULL,
    account_id          VARCHAR(255),
    credential_ref      VARCHAR(255),
    credential_type     VARCHAR(100),
    provider            VARCHAR(50)  NOT NULL,
    region              VARCHAR(50),

    -- Resource identification
    resource_uid        TEXT         NOT NULL,
    resource_type       VARCHAR(128) NOT NULL,
    resource_name       VARCHAR(512),

    -- Exposure classification
    exposure_tier       SMALLINT     NOT NULL,
    origin_type         VARCHAR(64)  NOT NULL,
    rule_id             VARCHAR(64),
    exposure_reason     VARCHAR(255),

    -- Evidence: field values that triggered the rule (Tier 2) or chain hops (Tier 3)
    exposure_detail     JSONB        DEFAULT '{}'::jsonb,
    chain_hops          JSONB        DEFAULT '[]'::jsonb,

    -- Severity and lifecycle
    severity            VARCHAR(20)  NOT NULL DEFAULT 'high',
    status              VARCHAR(20)  NOT NULL DEFAULT 'OPEN',

    first_seen_at       TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    last_seen_at        TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT chk_nef_tier     CHECK (exposure_tier IN (1, 2, 3)),
    CONSTRAINT chk_nef_status   CHECK (status IN ('OPEN','CLOSED','SUPPRESSED')),
    CONSTRAINT chk_nef_severity CHECK (severity IN ('critical','high','medium','low','info')),
    CONSTRAINT chk_nef_origin   CHECK (origin_type IN (
        'internet','vpn','connected_network','direct_connect','external_iam','supply_chain')),

    UNIQUE (scan_run_id, resource_uid, rule_id, origin_type)
);

CREATE INDEX IF NOT EXISTS idx_nef_scan         ON network_exposure_findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_nef_tenant       ON network_exposure_findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_nef_resource     ON network_exposure_findings(resource_uid);
CREATE INDEX IF NOT EXISTS idx_nef_tier         ON network_exposure_findings(exposure_tier);
CREATE INDEX IF NOT EXISTS idx_nef_origin       ON network_exposure_findings(origin_type);
CREATE INDEX IF NOT EXISTS idx_nef_severity     ON network_exposure_findings(severity, status);
CREATE INDEX IF NOT EXISTS idx_nef_open         ON network_exposure_findings(tenant_id, scan_run_id)
    WHERE status = 'OPEN';

COMMENT ON TABLE network_exposure_findings IS
    'Per-resource internet/external exposure findings from IEDS evaluator. Written by network engine, read by attack-path BFS.';
COMMENT ON COLUMN network_exposure_findings.chain_hops IS
    'Tier 3 traversal evidence: [{resource_uid, resource_type, relation, detail}]';
COMMENT ON COLUMN network_exposure_findings.exposure_detail IS
    'Tier 2 field evidence: {field_name: field_value, ...} that matched the exposure condition';

COMMIT;
