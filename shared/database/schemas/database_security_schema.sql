-- =============================================================================
-- Database Security Engine Schema
-- Database: threat_engine_database_security
-- Port: 8007 | Layer 3 (post-threat, parallel with compliance/iam/datasec)
-- =============================================================================
-- Purpose: Unified database security posture — aggregates access control,
--          encryption, audit logging, backup/recovery, network security,
--          and configuration compliance across all database services.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   VARCHAR(255) PRIMARY KEY,
    tenant_name VARCHAR(255),
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- dbsec_report — Scan-level summary
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dbsec_report (
    scan_run_id             VARCHAR(255) PRIMARY KEY,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    status                  VARCHAR(50) NOT NULL DEFAULT 'running',
    error_message           TEXT,

    -- Posture scores (0-100)
    posture_score           INTEGER DEFAULT 0,
    access_control_score    INTEGER DEFAULT 0,
    encryption_score        INTEGER DEFAULT 0,
    audit_logging_score     INTEGER DEFAULT 0,
    backup_recovery_score   INTEGER DEFAULT 0,
    network_security_score  INTEGER DEFAULT 0,
    configuration_score     INTEGER DEFAULT 0,

    -- Counts
    total_databases         INTEGER DEFAULT 0,
    total_findings          INTEGER DEFAULT 0,
    critical_findings       INTEGER DEFAULT 0,
    high_findings           INTEGER DEFAULT 0,
    medium_findings         INTEGER DEFAULT 0,
    low_findings            INTEGER DEFAULT 0,
    pass_count              INTEGER DEFAULT 0,
    fail_count              INTEGER DEFAULT 0,

    -- Breakdowns
    findings_by_service     JSONB DEFAULT '{}'::jsonb,
    findings_by_domain      JSONB DEFAULT '{}'::jsonb,
    coverage_by_service     JSONB DEFAULT '{}'::jsonb,
    report_data             JSONB DEFAULT '{}'::jsonb,

    -- Timing
    started_at              TIMESTAMP WITH TIME ZONE,
    completed_at            TIMESTAMP WITH TIME ZONE,
    scan_duration_ms        INTEGER,
    generated_at            TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_dbsec_report_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- dbsec_findings — Per-resource database security findings
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dbsec_findings (
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
    db_engine               VARCHAR(50),            -- mysql, postgres, aurora-mysql, redis, etc.
    db_service              VARCHAR(50),            -- rds, dynamodb, redshift, elasticache, etc.

    -- Security domain
    security_domain         VARCHAR(50) NOT NULL,   -- access_control, encryption, audit_logging,
                                                    -- backup_recovery, network_security, configuration
    -- Finding metadata
    severity                VARCHAR(20) NOT NULL,
    status                  VARCHAR(20) NOT NULL,   -- PASS, FAIL
    rule_id                 VARCHAR(255),
    title                   TEXT,
    description             TEXT,
    remediation             TEXT,
    finding_data            JSONB DEFAULT '{}'::jsonb,

    -- Timestamps
    first_seen_at           TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at            TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_dbsec_finding_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- dbsec_inventory — Unified database instance inventory
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS dbsec_inventory (
    id                      BIGSERIAL PRIMARY KEY,
    scan_run_id             VARCHAR(255) NOT NULL,
    tenant_id               VARCHAR(255) NOT NULL,
    account_id              VARCHAR(255),
    provider                VARCHAR(50) NOT NULL DEFAULT 'aws',
    region                  VARCHAR(50),

    -- Database identification
    resource_uid            TEXT NOT NULL,
    resource_name           VARCHAR(500),
    db_service              VARCHAR(50) NOT NULL,   -- rds, dynamodb, redshift, etc.
    db_engine               VARCHAR(50),            -- mysql, postgres, aurora-mysql, redis, etc.
    db_engine_version       VARCHAR(50),
    instance_class          VARCHAR(100),

    -- Security posture summary
    posture_score           INTEGER DEFAULT 0,
    publicly_accessible     BOOLEAN DEFAULT FALSE,
    encryption_at_rest      BOOLEAN,
    encryption_in_transit   BOOLEAN,
    iam_auth_enabled        BOOLEAN,
    audit_logging_enabled   BOOLEAN,
    backup_enabled          BOOLEAN,
    backup_retention_days   INTEGER,
    deletion_protection     BOOLEAN,
    multi_az                BOOLEAN,
    vpc_id                  VARCHAR(100),

    -- Counts
    total_checks            INTEGER DEFAULT 0,
    passed_checks           INTEGER DEFAULT 0,
    failed_checks           INTEGER DEFAULT 0,
    critical_checks         INTEGER DEFAULT 0,

    -- Data sensitivity (from datasec cross-ref)
    data_classification     VARCHAR(50),
    has_sensitive_data      BOOLEAN DEFAULT FALSE,

    -- Metadata
    tags                    JSONB DEFAULT '{}'::jsonb,
    raw_data                JSONB DEFAULT '{}'::jsonb,
    created_at              TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

    CONSTRAINT fk_dbsec_inv_tenant
        FOREIGN KEY (tenant_id) REFERENCES tenants(tenant_id) ON DELETE CASCADE
);

-- =============================================================================
-- INDEXES
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_dbsec_report_tenant ON dbsec_report(tenant_id);
CREATE INDEX IF NOT EXISTS idx_dbsec_report_status ON dbsec_report(status);
CREATE INDEX IF NOT EXISTS idx_dbsec_report_generated ON dbsec_report(generated_at DESC);

CREATE INDEX IF NOT EXISTS idx_dbsec_findings_scan ON dbsec_findings(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_dbsec_findings_tenant ON dbsec_findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_dbsec_findings_severity ON dbsec_findings(severity, status);
CREATE INDEX IF NOT EXISTS idx_dbsec_findings_domain ON dbsec_findings(security_domain);
CREATE INDEX IF NOT EXISTS idx_dbsec_findings_service ON dbsec_findings(db_service);
CREATE INDEX IF NOT EXISTS idx_dbsec_findings_resource ON dbsec_findings(resource_uid);
CREATE INDEX IF NOT EXISTS idx_dbsec_findings_data_gin ON dbsec_findings USING gin(finding_data);

CREATE INDEX IF NOT EXISTS idx_dbsec_inv_scan ON dbsec_inventory(scan_run_id);
CREATE INDEX IF NOT EXISTS idx_dbsec_inv_tenant ON dbsec_inventory(tenant_id);
CREATE INDEX IF NOT EXISTS idx_dbsec_inv_service ON dbsec_inventory(db_service);
CREATE INDEX IF NOT EXISTS idx_dbsec_inv_resource ON dbsec_inventory(resource_uid);
CREATE INDEX IF NOT EXISTS idx_dbsec_inv_public ON dbsec_inventory(publicly_accessible) WHERE publicly_accessible = TRUE;

COMMENT ON TABLE dbsec_report IS 'Database security scan summary with domain-level posture scores';
COMMENT ON TABLE dbsec_findings IS 'Per-resource database security findings with security domain categorization';
COMMENT ON TABLE dbsec_inventory IS 'Unified database instance inventory with posture summary';
