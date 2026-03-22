-- =============================================================================
-- DataSec Enhanced Engine Schema
-- Database: threat_engine_datasec_enhanced
-- Port: 8033 | Layer 3
-- =============================================================================

-- -----------------------------------------------------------------------------
-- datasec_enhanced_rules — Advanced data security rule definitions
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS datasec_enhanced_rules (
    rule_id         VARCHAR(50) PRIMARY KEY,
    title           VARCHAR(500) NOT NULL,
    description     TEXT,
    severity        VARCHAR(20) NOT NULL DEFAULT 'medium',
    category        VARCHAR(100) NOT NULL,     -- dlp, encryption_posture, data_lineage, data_minimization, cross_border, classification, access_audit
    subcategory     VARCHAR(100),
    condition       JSONB NOT NULL,
    condition_type  VARCHAR(50) DEFAULT 'field_check',
    frameworks      TEXT[] DEFAULT '{}',        -- GDPR, HIPAA, PCI_DSS, CCPA, LGPD, PIPEDA, SOC2
    remediation     TEXT,
    is_active       BOOLEAN DEFAULT true,
    csp             TEXT[] DEFAULT '{aws,azure,gcp,oci,alicloud,ibm}',
    created_at      TIMESTAMP DEFAULT NOW(),
    updated_at      TIMESTAMP DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- datasec_enhanced_input_transformed — Stage 1 ETL output
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS datasec_enhanced_input_transformed (
    id                          BIGSERIAL PRIMARY KEY,
    datasec_enhanced_scan_id    UUID NOT NULL,
    tenant_id                   VARCHAR(255),
    orchestration_id            UUID NOT NULL,

    -- Resource identification
    resource_id                 VARCHAR(500),
    resource_type               VARCHAR(100),     -- s3_bucket, rds_instance, dynamodb_table, etc.
    resource_arn                VARCHAR(1000),
    resource_name               VARCHAR(500),
    data_store_service          VARCHAR(100),     -- s3, rds, dynamodb, redshift, etc.

    -- Classification (ML-enhanced)
    data_classification         VARCHAR(50),       -- restricted, confidential, internal, public
    detected_pii_types          TEXT[] DEFAULT '{}',  -- SSN, EMAIL, PHONE, CREDIT_CARD, etc.
    detected_phi_types          TEXT[] DEFAULT '{}',  -- DIAGNOSIS, MEDICATION, MRN, etc.
    detected_pci_types          TEXT[] DEFAULT '{}',  -- PAN, CVV, EXPIRY, etc.
    classification_confidence   DECIMAL(5,2) DEFAULT 0,
    classification_method       VARCHAR(50),       -- regex, ml_ner, macie, manual
    estimated_record_count      INTEGER DEFAULT 0,
    sample_matched_count        INTEGER DEFAULT 0,

    -- Encryption posture
    encryption_at_rest          BOOLEAN DEFAULT false,
    encryption_algorithm        VARCHAR(50),       -- AES-256, AES-128, etc.
    kms_key_type                VARCHAR(50),       -- aws_managed, customer_managed, none
    kms_key_rotation            BOOLEAN DEFAULT false,
    encryption_in_transit       BOOLEAN DEFAULT false,
    tls_version                 VARCHAR(20),       -- TLS1.2, TLS1.3, etc.
    ssl_certificate_valid       BOOLEAN DEFAULT true,

    -- Access control
    is_public                   BOOLEAN DEFAULT false,
    public_access_block         BOOLEAN DEFAULT false,
    bucket_policy_allows_public BOOLEAN DEFAULT false,
    cross_account_access        BOOLEAN DEFAULT false,
    access_logging_enabled      BOOLEAN DEFAULT false,
    last_accessed_days_ago      INTEGER,

    -- Data lifecycle
    versioning_enabled          BOOLEAN DEFAULT false,
    lifecycle_policy_exists     BOOLEAN DEFAULT false,
    backup_enabled              BOOLEAN DEFAULT false,
    retention_days              INTEGER,
    replication_enabled         BOOLEAN DEFAULT false,

    -- Data lineage
    data_sources                JSONB DEFAULT '[]',   -- [{source_arn, source_type, direction}]
    data_destinations           JSONB DEFAULT '[]',   -- [{dest_arn, dest_type, direction}]
    cross_region_transfer       BOOLEAN DEFAULT false,
    cross_cloud_transfer        BOOLEAN DEFAULT false,
    data_residency_regions      TEXT[] DEFAULT '{}',

    -- Compliance context
    applicable_regulations      TEXT[] DEFAULT '{}',
    data_residency_compliant    BOOLEAN DEFAULT true,
    has_dpa                     BOOLEAN DEFAULT false,  -- Data Processing Agreement
    retention_compliant         BOOLEAN DEFAULT true,

    -- Runtime (from log_collector)
    access_events_24h           INTEGER DEFAULT 0,
    unique_accessors_24h        INTEGER DEFAULT 0,
    failed_access_24h           INTEGER DEFAULT 0,
    data_egress_bytes_24h       BIGINT DEFAULT 0,

    -- Metadata
    account_id                  VARCHAR(255),
    region                      VARCHAR(50),
    csp                         VARCHAR(20) DEFAULT 'aws',
    tags                        JSONB DEFAULT '{}',
    created_at                  TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_dse_transformed_scan ON datasec_enhanced_input_transformed (datasec_enhanced_scan_id);
CREATE INDEX idx_dse_transformed_classification ON datasec_enhanced_input_transformed (data_classification);

-- -----------------------------------------------------------------------------
-- datasec_enhanced_findings — Stage 2 evaluation results
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS datasec_enhanced_findings (
    finding_id                  BIGSERIAL PRIMARY KEY,
    datasec_enhanced_scan_id    UUID NOT NULL,
    tenant_id                   VARCHAR(255),
    orchestration_id            UUID NOT NULL,
    rule_id                     VARCHAR(50) NOT NULL,
    resource_id                 VARCHAR(500),
    resource_type               VARCHAR(100),
    resource_arn                VARCHAR(1000),
    data_store_service          VARCHAR(100),
    data_classification         VARCHAR(50),
    severity                    VARCHAR(20) NOT NULL,
    status                      VARCHAR(20) NOT NULL DEFAULT 'FAIL',
    category                    VARCHAR(100),
    title                       VARCHAR(500),
    detail                      TEXT,
    remediation                 TEXT,
    frameworks                  TEXT[] DEFAULT '{}',
    detected_data_types         TEXT[] DEFAULT '{}',
    account_id                  VARCHAR(255),
    region                      VARCHAR(50),
    csp                         VARCHAR(20) DEFAULT 'aws',
    created_at                  TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_dse_findings_scan ON datasec_enhanced_findings (datasec_enhanced_scan_id);
CREATE INDEX idx_dse_findings_severity ON datasec_enhanced_findings (severity, status);
CREATE INDEX idx_dse_findings_classification ON datasec_enhanced_findings (data_classification);

-- -----------------------------------------------------------------------------
-- datasec_enhanced_data_catalog — Comprehensive data store inventory
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS datasec_enhanced_data_catalog (
    id                          BIGSERIAL PRIMARY KEY,
    datasec_enhanced_scan_id    UUID NOT NULL,
    tenant_id                   VARCHAR(255),
    orchestration_id            UUID NOT NULL,
    resource_arn                VARCHAR(1000),
    resource_name               VARCHAR(500),
    data_store_service          VARCHAR(100),
    data_classification         VARCHAR(50),
    detected_pii_types          TEXT[] DEFAULT '{}',
    estimated_record_count      INTEGER DEFAULT 0,
    encryption_status           VARCHAR(50),       -- encrypted_cmk, encrypted_managed, unencrypted
    is_public                   BOOLEAN DEFAULT false,
    cross_region_transfer       BOOLEAN DEFAULT false,
    data_residency_regions      TEXT[] DEFAULT '{}',
    applicable_regulations      TEXT[] DEFAULT '{}',
    risk_score                  INTEGER DEFAULT 0,
    lineage_sources             INTEGER DEFAULT 0,
    lineage_destinations        INTEGER DEFAULT 0,
    last_accessed_days_ago      INTEGER,
    account_id                  VARCHAR(255),
    region                      VARCHAR(50),
    csp                         VARCHAR(20) DEFAULT 'aws',
    created_at                  TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_dse_catalog_scan ON datasec_enhanced_data_catalog (datasec_enhanced_scan_id);

-- -----------------------------------------------------------------------------
-- datasec_enhanced_lineage — Data flow relationships
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS datasec_enhanced_lineage (
    id                          BIGSERIAL PRIMARY KEY,
    datasec_enhanced_scan_id    UUID NOT NULL,
    tenant_id                   VARCHAR(255),
    source_arn                  VARCHAR(1000),
    source_service              VARCHAR(100),
    source_region               VARCHAR(50),
    source_csp                  VARCHAR(20),
    destination_arn             VARCHAR(1000),
    destination_service         VARCHAR(100),
    destination_region          VARCHAR(50),
    destination_csp             VARCHAR(20),
    transfer_type               VARCHAR(50),       -- replication, etl, streaming, backup, export
    is_cross_region             BOOLEAN DEFAULT false,
    is_cross_cloud              BOOLEAN DEFAULT false,
    is_cross_border             BOOLEAN DEFAULT false,
    data_volume_bytes           BIGINT,
    created_at                  TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_dse_lineage_scan ON datasec_enhanced_lineage (datasec_enhanced_scan_id);

-- -----------------------------------------------------------------------------
-- datasec_enhanced_report — Stage 3 scan summary
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS datasec_enhanced_report (
    datasec_enhanced_scan_id    UUID PRIMARY KEY,
    orchestration_id            UUID NOT NULL,
    tenant_id                   VARCHAR(255),
    account_id                  VARCHAR(255),
    provider                    VARCHAR(50) DEFAULT 'aws',

    -- Counts
    total_data_stores           INTEGER DEFAULT 0,
    total_findings              INTEGER DEFAULT 0,
    critical_findings           INTEGER DEFAULT 0,
    high_findings               INTEGER DEFAULT 0,
    medium_findings             INTEGER DEFAULT 0,
    low_findings                INTEGER DEFAULT 0,
    pass_count                  INTEGER DEFAULT 0,
    fail_count                  INTEGER DEFAULT 0,

    -- Classification summary
    restricted_stores           INTEGER DEFAULT 0,
    confidential_stores         INTEGER DEFAULT 0,
    internal_stores             INTEGER DEFAULT 0,
    public_stores               INTEGER DEFAULT 0,
    pii_detected_count          INTEGER DEFAULT 0,
    phi_detected_count          INTEGER DEFAULT 0,
    pci_detected_count          INTEGER DEFAULT 0,

    -- Coverage
    encryption_rest_pct         DECIMAL(5,2) DEFAULT 0,
    encryption_transit_pct      DECIMAL(5,2) DEFAULT 0,
    cmk_encryption_pct          DECIMAL(5,2) DEFAULT 0,
    access_logging_pct          DECIMAL(5,2) DEFAULT 0,
    versioning_pct              DECIMAL(5,2) DEFAULT 0,
    backup_pct                  DECIMAL(5,2) DEFAULT 0,

    -- Lineage
    total_data_flows            INTEGER DEFAULT 0,
    cross_region_flows          INTEGER DEFAULT 0,
    cross_cloud_flows           INTEGER DEFAULT 0,
    cross_border_flows          INTEGER DEFAULT 0,

    -- Breakdowns
    category_breakdown          JSONB DEFAULT '{}',
    service_breakdown           JSONB DEFAULT '{}',
    classification_breakdown    JSONB DEFAULT '{}',
    framework_compliance        JSONB DEFAULT '{}',
    top_failing_rules           JSONB DEFAULT '[]',
    risk_score                  INTEGER DEFAULT 0,

    -- Timing
    started_at                  TIMESTAMP,
    completed_at                TIMESTAMP,
    scan_duration_ms            INTEGER,
    status                      VARCHAR(50) DEFAULT 'completed',
    error_message               TEXT,
    created_at                  TIMESTAMP DEFAULT NOW()
);
