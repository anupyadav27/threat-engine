-- =============================================================================
-- Encryption Security Engine Database Schema
-- Database: threat_engine_encryption
-- Port: 8006 | Layer 3 (post-threat, parallel with compliance/iam/datasec)
-- =============================================================================
-- Purpose: Unified encryption posture analysis — aggregates KMS key management,
--          certificate lifecycle, secrets rotation, and per-resource encryption
--          coverage from discovery, check, datasec, and inventory engines.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- CORE TABLES
-- =============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- encryption_report — Scan-level summary (one row per scan_run_id)
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS encryption_report (
    scan_run_id             VARCHAR(255) PRIMARY KEY,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    status                  VARCHAR(50) NOT NULL DEFAULT 'running',
    error_message           TEXT,

    -- Posture score (0-100, weighted composite)
    posture_score           INTEGER DEFAULT 0,
    coverage_score          INTEGER DEFAULT 0,
    rotation_score          INTEGER DEFAULT 0,
    algorithm_score         INTEGER DEFAULT 0,
    transit_score           INTEGER DEFAULT 0,

    -- Counts
    total_resources         INTEGER DEFAULT 0,
    encrypted_resources     INTEGER DEFAULT 0,
    unencrypted_resources   INTEGER DEFAULT 0,
    total_keys              INTEGER DEFAULT 0,
    total_certificates      INTEGER DEFAULT 0,
    total_secrets           INTEGER DEFAULT 0,
    total_findings          INTEGER DEFAULT 0,
    critical_findings       INTEGER DEFAULT 0,
    high_findings           INTEGER DEFAULT 0,
    medium_findings         INTEGER DEFAULT 0,
    low_findings            INTEGER DEFAULT 0,

    -- Breakdowns (JSONB for flexible drill-down)
    coverage_by_service     JSONB DEFAULT '{}'::jsonb,
    severity_breakdown      JSONB DEFAULT '{}'::jsonb,
    domain_breakdown        JSONB DEFAULT '{}'::jsonb,
    report_data             JSONB DEFAULT '{}'::jsonb,

    -- Timing
    started_at              TIMESTAMP WITH TIME ZONE,
    completed_at            TIMESTAMP WITH TIME ZONE,
    scan_duration_ms        INTEGER,
    generated_at            TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_encryption_report_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- encryption_findings — Per-resource encryption posture findings
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS encryption_findings (
    finding_id              VARCHAR(255) PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    credential_ref          VARCHAR(255),
    credential_type         VARCHAR(100),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    region                  VARCHAR(50),

    -- Resource identification
    resource_uid            TEXT NOT NULL,
    resource_type           VARCHAR(100) NOT NULL,

    -- Encryption posture
    encryption_domain       VARCHAR(100),
    encryption_status       VARCHAR(50),
    key_type                VARCHAR(50),
    algorithm               VARCHAR(50),
    rotation_compliant      BOOLEAN,
    transit_enforced        BOOLEAN,

    -- Finding metadata
    severity                VARCHAR(20) NOT NULL,
    status                  VARCHAR(20) NOT NULL,
    rule_id                 VARCHAR(255),
    finding_data            JSONB DEFAULT '{}'::jsonb,

    -- Timestamps
    first_seen_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_encryption_finding_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- encryption_key_inventory — Unified KMS key inventory
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS encryption_key_inventory (
    id                      BIGSERIAL PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    region                  VARCHAR(50),

    -- Key identification
    key_arn                 TEXT NOT NULL,
    key_id                  VARCHAR(255),
    key_alias               VARCHAR(255),

    -- Key properties
    key_state               VARCHAR(50),
    key_manager             VARCHAR(50),
    key_spec                VARCHAR(50),
    key_usage               VARCHAR(50),
    encryption_algorithms   TEXT[],
    origin                  VARCHAR(50),
    multi_region            BOOLEAN DEFAULT FALSE,
    enabled                 BOOLEAN DEFAULT TRUE,

    -- Rotation & lifecycle
    rotation_enabled        BOOLEAN DEFAULT FALSE,
    rotation_interval_days  INTEGER,
    creation_date           TIMESTAMP WITH TIME ZONE,
    deletion_date           TIMESTAMP WITH TIME ZONE,
    pending_deletion_days   INTEGER,

    -- Policy analysis
    key_policy_principals   JSONB DEFAULT '[]'::jsonb,
    grant_count             INTEGER DEFAULT 0,
    cross_account_access    BOOLEAN DEFAULT FALSE,

    -- Dependency tracking
    dependent_resource_count INTEGER DEFAULT 0,

    -- Metadata
    tags                    JSONB DEFAULT '{}'::jsonb,
    raw_data                JSONB DEFAULT '{}'::jsonb,
    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_key_inv_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- encryption_cert_inventory — Unified certificate inventory
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS encryption_cert_inventory (
    id                      BIGSERIAL PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    region                  VARCHAR(50),

    -- Certificate identification
    cert_arn                TEXT NOT NULL,
    domain_name             VARCHAR(500),
    subject_alternative_names TEXT[],

    -- Certificate properties
    cert_status             VARCHAR(50),
    cert_type               VARCHAR(50),
    key_algorithm           VARCHAR(50),
    issuer                  VARCHAR(500),
    serial_number           VARCHAR(255),

    -- Lifecycle
    not_before              TIMESTAMP WITH TIME ZONE,
    not_after               TIMESTAMP WITH TIME ZONE,
    days_until_expiry       INTEGER,
    renewal_eligibility     VARCHAR(50),
    in_use                  BOOLEAN DEFAULT FALSE,

    -- Validation
    is_wildcard             BOOLEAN DEFAULT FALSE,
    is_self_signed          BOOLEAN DEFAULT FALSE,
    chain_valid             BOOLEAN,

    -- Metadata
    tags                    JSONB DEFAULT '{}'::jsonb,
    raw_data                JSONB DEFAULT '{}'::jsonb,
    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_cert_inv_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- encryption_secrets_inventory — Secrets Manager inventory
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS encryption_secrets_inventory (
    id                      BIGSERIAL PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    region                  VARCHAR(50),

    -- Secret identification
    secret_arn              TEXT NOT NULL,
    secret_name             VARCHAR(500),

    -- Encryption & rotation
    kms_key_id              VARCHAR(255),
    rotation_enabled        BOOLEAN DEFAULT FALSE,
    rotation_interval_days  INTEGER,
    last_rotated_date       TIMESTAMP WITH TIME ZONE,
    last_accessed_date      TIMESTAMP WITH TIME ZONE,
    days_since_rotation     INTEGER,

    -- Metadata
    tags                    JSONB DEFAULT '{}'::jsonb,
    raw_data                JSONB DEFAULT '{}'::jsonb,
    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_secret_inv_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- =============================================================================
-- INDEXES
-- =============================================================================

-- encryption_report
CREATE INDEX IF NOT EXISTS idx_enc_report_tenant ON encryption_report(tenant_id);
CREATE INDEX IF NOT EXISTS idx_enc_report_status ON encryption_report(status);
CREATE INDEX IF NOT EXISTS idx_enc_report_generated ON encryption_report(generated_at DESC);

-- encryption_findings
CREATE INDEX IF NOT EXISTS idx_enc_findings_scan ON encryption_findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_enc_findings_tenant ON encryption_findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_enc_findings_severity ON encryption_findings(severity, status);
CREATE INDEX IF NOT EXISTS idx_enc_findings_domain ON encryption_findings(encryption_domain);
CREATE INDEX IF NOT EXISTS idx_enc_findings_resource ON encryption_findings(resource_uid);
CREATE INDEX IF NOT EXISTS idx_enc_findings_enc_status ON encryption_findings(encryption_status);
CREATE INDEX IF NOT EXISTS idx_enc_findings_data_gin ON encryption_findings USING gin(finding_data);

-- encryption_key_inventory
CREATE INDEX IF NOT EXISTS idx_enc_keys_scan ON encryption_key_inventory(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_enc_keys_tenant ON encryption_key_inventory(tenant_id);
CREATE INDEX IF NOT EXISTS idx_enc_keys_arn ON encryption_key_inventory(key_arn);
CREATE INDEX IF NOT EXISTS idx_enc_keys_state ON encryption_key_inventory(key_state);
CREATE INDEX IF NOT EXISTS idx_enc_keys_manager ON encryption_key_inventory(key_manager);

-- encryption_cert_inventory
CREATE INDEX IF NOT EXISTS idx_enc_certs_scan ON encryption_cert_inventory(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_enc_certs_tenant ON encryption_cert_inventory(tenant_id);
CREATE INDEX IF NOT EXISTS idx_enc_certs_arn ON encryption_cert_inventory(cert_arn);
CREATE INDEX IF NOT EXISTS idx_enc_certs_expiry ON encryption_cert_inventory(days_until_expiry);
CREATE INDEX IF NOT EXISTS idx_enc_certs_status ON encryption_cert_inventory(cert_status);

-- encryption_secrets_inventory
CREATE INDEX IF NOT EXISTS idx_enc_secrets_scan ON encryption_secrets_inventory(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_enc_secrets_tenant ON encryption_secrets_inventory(tenant_id);
CREATE INDEX IF NOT EXISTS idx_enc_secrets_rotation ON encryption_secrets_inventory(rotation_enabled);

-- =============================================================================
-- COMMENTS
-- =============================================================================

COMMENT ON TABLE encryption_report IS 'Encryption scan summary with posture scores and coverage breakdowns';
COMMENT ON TABLE encryption_findings IS 'Per-resource encryption posture findings with standard columns';
COMMENT ON TABLE encryption_key_inventory IS 'Unified KMS key inventory across all cloud providers';
COMMENT ON TABLE encryption_cert_inventory IS 'Unified TLS/SSL certificate inventory with expiry tracking';
COMMENT ON TABLE encryption_secrets_inventory IS 'Secrets Manager inventory with rotation and KMS binding status';
